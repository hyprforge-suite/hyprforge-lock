//! Unlocking with a finger, through fprintd.
//!
//! Not through PAM, which is where a reader would normally be wired in —
//! and the reason is structural rather than a preference. PAM asks its
//! modules in order: with `pam_fprintd` first in the stack, the password
//! prompt does not appear until the reader gives up, and with it second
//! the reader is never asked until a password has already been refused.
//! The mockup's "place your finger, or start typing a password" is both
//! at once, which PAM cannot express. So, like hyprlock, this talks to
//! fprintd directly on the system bus and runs beside the password
//! conversation rather than inside it.
//!
//! What that must not do is become a way round PAM's *policy*. A match
//! here is followed by PAM's account stack ([`crate::pam::account_permits`])
//! before anything is reported as verified, so an account PAM would bar
//! on a correct password is barred on a correct finger too.
//!
//! Every call is bounded ([`CALL`]), because fprintd is another process
//! and can stop answering. The one wait that is not bounded is the wait
//! for a finger, which is the point of it; it ends when the lock does.

use calloop::ping::Ping;
use futures_util::StreamExt;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

const SERVICE: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER: &str = "net.reactivated.Fprint.Manager";
const DEVICE: &str = "net.reactivated.Fprint.Device";

/// How long one call to fprintd may take.
const CALL: Duration = Duration::from_secs(5);

/// Unrecognised touches before the reader stops listening.
///
/// Three, which is `pam_fprintd`'s own `max-tries` default. fprintd keeps
/// no failure count of its own and `pam_faillock` never sees these, so
/// without a limit a sensor would take guesses forever.
pub const MAX_MISSES: u32 = 3;

/// What the reader has to say, in the order it can say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Claimed and listening.
    Ready,
    /// A touch that was not accepted, and the reader is listening again.
    Retry(String),
    /// Too many misses; the reader has been released.
    Exhausted,
    /// No reader to use — fprintd not running, no device, nothing
    /// enrolled for this user, or another program holds the device.
    /// Never shown as an error: most machines have no reader, and a lock
    /// screen that complained about one would be complaining at everyone.
    Unavailable,
    /// A finger matched *and* the account check passed. The only event
    /// that unlocks.
    Verified,
    /// A finger matched and the account check refused. What PAM said.
    Refused(String),
}

/// The reader, running on its own thread.
pub struct Reader {
    events: Receiver<Event>,
    /// Dropped when the lock ends, which tells the worker to stop
    /// verifying and release the device rather than leave it claimed.
    _stop: tokio::sync::oneshot::Sender<()>,
}

impl Reader {
    /// Starts listening for `username`'s finger. The ping fires whenever
    /// there is an event to collect.
    pub fn start(service: &'static str, username: String) -> (Reader, calloop::ping::PingSource) {
        let (to_ui, events) = std::sync::mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (ping, source) = calloop::ping::make_ping().expect("failed to create a wakeup pipe");
        let spawned = std::thread::Builder::new().name("fingerprint".into()).spawn({
            let (to_ui, ping) = (to_ui.clone(), ping.clone());
            move || run(service, username, to_ui, ping, stopped)
        });
        if spawned.is_err() {
            // No thread, no reader. The password still works; say
            // nothing about a sensor that will never be asked.
            let _ = to_ui.send(Event::Unavailable);
            ping.ping();
        }
        (Reader { events, _stop: stop }, source)
    }

    /// The next event, if one is waiting. Never blocks.
    pub fn poll(&mut self) -> Option<Event> {
        self.events.try_recv().ok()
    }
}

fn run(
    service: &'static str,
    username: String,
    to_ui: Sender<Event>,
    ping: Ping,
    stopped: tokio::sync::oneshot::Receiver<()>,
) {
    let say = |event: Event| {
        let _ = to_ui.send(event);
        ping.ping();
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        say(Event::Unavailable);
        return;
    };
    runtime.block_on(async {
        if let Err(why) = listen(service, &username, &say, stopped).await {
            // Why is worth a line on stderr — "no enrolled prints" and
            // "device busy" look the same on screen — and it names
            // nothing typed or touched.
            eprintln!("fingerprint: {why}");
            say(Event::Unavailable);
        }
    });
}

/// Bounds a call to fprintd, turning a timeout into an error like any
/// other so a reader that stopped answering is simply unavailable.
async fn bounded<T>(what: &str, call: impl std::future::Future<Output = zbus::Result<T>>) -> Result<T, String> {
    match tokio::time::timeout(CALL, call).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: fprintd didn't answer within {}s", CALL.as_secs())),
    }
}

async fn listen(
    service: &'static str,
    username: &str,
    say: &impl Fn(Event),
    mut stopped: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), String> {
    let bus = bounded("connecting to the system bus", zbus::Connection::system()).await?;
    let (device, path, fingers) = reach(&bus, username).await?;
    // Asked before claiming, so a machine with a reader and no enrolled
    // finger never sees the sensor offered.
    if fingers.is_empty() {
        return Err("no fingers enrolled".into());
    }

    // Whose signals count. A `VerifyStatus` is what unlocks this
    // session, so it is accepted only from the process that owns
    // fprintd's name on the system bus, and only about the device that
    // was claimed. The bus already routes by that rule; checking it
    // again here costs nothing and does not depend on the match rule
    // having been written correctly.
    let dbus = bounded("reaching the bus", zbus::fdo::DBusProxy::new(&bus)).await?;
    let owner = bounded(
        "finding fprintd",
        async { dbus.get_name_owner(SERVICE.try_into()?).await.map_err(zbus::Error::from) },
    )
    .await?;

    let mut statuses = bounded("watching the reader", device.receive_signal("VerifyStatus")).await?;
    bounded("claiming the reader", device.call::<_, _, ()>("Claim", &(username,))).await?;

    let mut misses = 0;
    let outcome = 'verifying: loop {
        bounded("starting to listen", device.call::<_, _, ()>("VerifyStart", &("any",))).await?;
        if misses == 0 {
            say(Event::Ready);
        }
        loop {
            let message = tokio::select! {
                _ = &mut stopped => break 'verifying Outcome::Stopped,
                message = statuses.next() => match message {
                    Some(message) => message,
                    None => break 'verifying Outcome::Lost,
                },
            };
            let header = message.header();
            let genuine = header.sender().is_some_and(|sender| sender.as_str() == owner.as_str())
                && header.path().is_some_and(|p| p.as_str() == path.as_str());
            if !genuine {
                continue;
            }
            let Ok((result, done)) = message.body().deserialize::<(String, bool)>() else {
                continue;
            };
            match step(&result, done, misses) {
                Step::Matched => break 'verifying Outcome::Matched,
                Step::Retry(why) => say(Event::Retry(why.into())),
                Step::Miss(why) => {
                    misses += 1;
                    say(Event::Retry(why.into()));
                    // A finished verification must be stopped before it
                    // can be started again — fprintd's own rule.
                    bounded("stopping", device.call::<_, _, ()>("VerifyStop", &())).await?;
                    continue 'verifying;
                }
                Step::Again(why) => {
                    say(Event::Retry(why.into()));
                    bounded("stopping", device.call::<_, _, ()>("VerifyStop", &())).await?;
                    continue 'verifying;
                }
                Step::GiveUp => break 'verifying Outcome::Exhausted,
                Step::Lost => break 'verifying Outcome::Lost,
            }
        }
    };

    // Whatever happened, the device is handed back — a claimed reader is
    // one no other program can use until this process exits.
    let _ = bounded("stopping", device.call::<_, _, ()>("VerifyStop", &())).await;
    let _ = bounded("releasing the reader", device.call::<_, _, ()>("Release", &())).await;

    match outcome {
        Outcome::Matched => {
            let user = username.to_string();
            let permitted = tokio::task::spawn_blocking(move || crate::pam::account_permits(service, &user))
                .await
                .unwrap_or_else(|_| Err("the account check stopped".into()));
            match permitted {
                Ok(()) => say(Event::Verified),
                Err(why) => say(Event::Refused(why)),
            }
            Ok(())
        }
        Outcome::Exhausted => {
            say(Event::Exhausted);
            Ok(())
        }
        Outcome::Stopped => Ok(()),
        Outcome::Lost => Err("the reader went away".into()),
    }
}

/// The read-only half of [`listen`]: find the default reader and ask
/// which of `username`'s fingers it knows. Shared with the live test,
/// so what that test checks is the code path the lock actually runs —
/// the wrong manager path this was first written with passed every unit
/// test and failed the first time it met fprintd.
async fn reach(
    bus: &zbus::Connection,
    username: &str,
) -> Result<(zbus::Proxy<'static>, zbus::zvariant::OwnedObjectPath, Vec<String>), String> {
    let manager = bounded("reaching fprintd", zbus::Proxy::new(bus, SERVICE, MANAGER_PATH, MANAGER)).await?;
    let path: zbus::zvariant::OwnedObjectPath =
        bounded("asking for a reader", manager.call("GetDefaultDevice", &())).await?;
    let device = bounded("opening the reader", zbus::Proxy::new(bus, SERVICE, path.clone(), DEVICE)).await?;
    // fprintd answers "none enrolled" as an error rather than an empty
    // list; both mean the same thing here.
    let fingers: Vec<String> = match device.call("ListEnrolledFingers", &(username,)).await {
        Ok(fingers) => fingers,
        Err(zbus::Error::MethodError(name, _, _)) if name.as_str().ends_with("NoEnrolledPrints") => Vec::new(),
        Err(e) => return Err(format!("listing enrolled fingers: {e}")),
    };
    Ok((device, path, fingers))
}

enum Outcome {
    Matched,
    Exhausted,
    Stopped,
    Lost,
}

/// What one `VerifyStatus` means for the loop.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Matched,
    /// Not accepted, still listening.
    Retry(&'static str),
    /// A finger that is not this user's, and this verification is over.
    Miss(&'static str),
    /// Not accepted and over, but not a miss — a bad scan is not a guess.
    Again(&'static str),
    GiveUp,
    Lost,
}

/// fprintd's result strings, from its D-Bus documentation, turned into
/// what the loop does and what the person reads.
///
/// Only an unrecognised finger counts against [`MAX_MISSES`]. A swipe
/// that was too short or a finger off-centre is the sensor failing to
/// read, not someone else's finger, and counting those would lock a
/// person out of their own reader for touching it badly.
fn step(result: &str, done: bool, misses: u32) -> Step {
    let unread = |why: &'static str| if done { Step::Again(why) } else { Step::Retry(why) };
    match result {
        "verify-match" => Step::Matched,
        "verify-no-match" if misses + 1 >= MAX_MISSES => Step::GiveUp,
        "verify-no-match" => Step::Miss("Not recognised — try again"),
        "verify-retry-scan" => unread("Couldn't read that — try again"),
        "verify-swipe-too-short" => unread("Swipe was too short — try again"),
        "verify-finger-not-centered" => unread("Finger not centred — try again"),
        "verify-remove-and-retry" => unread("Lift your finger and try again"),
        // `verify-disconnected`, `verify-unknown-error`, and anything a
        // later fprintd invents: the reader is not usable, and guessing
        // otherwise risks a loop against a device that is gone.
        _ => Step::Lost,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_match_unlocks() {
        for result in [
            "verify-no-match",
            "verify-retry-scan",
            "verify-swipe-too-short",
            "verify-finger-not-centered",
            "verify-remove-and-retry",
            "verify-disconnected",
            "verify-unknown-error",
            "verify-match-but-not-really",
            "",
        ] {
            for done in [false, true] {
                assert_ne!(step(result, done, 0), Step::Matched, "{result} done={done}");
            }
        }
        assert_eq!(step("verify-match", true, 2), Step::Matched);
    }

    #[test]
    fn the_third_unrecognised_finger_stops_the_reader() {
        assert!(matches!(step("verify-no-match", true, 0), Step::Miss(_)));
        assert!(matches!(step("verify-no-match", true, 1), Step::Miss(_)));
        assert_eq!(step("verify-no-match", true, 2), Step::GiveUp);
    }

    /// A bad read is the sensor's failure, not a guess, and must never
    /// spend one of the three tries.
    #[test]
    fn a_bad_read_is_not_a_miss() {
        for result in ["verify-retry-scan", "verify-swipe-too-short", "verify-finger-not-centered", "verify-remove-and-retry"] {
            assert!(matches!(step(result, false, 2), Step::Retry(_)), "{result}");
            assert!(matches!(step(result, true, 2), Step::Again(_)), "{result}");
        }
    }

    /// Live and read-only: asks the running fprintd the questions this
    /// module asks before it claims anything, and checks the one signal
    /// it trusts to unlock has the shape it deserializes. Never claims
    /// the device and never starts a verification — the sensor does not
    /// even light. Run by `check.sh` when fprintd is reachable.
    #[test]
    #[ignore = "needs fprintd; check.sh runs it"]
    fn live_fprintd_answers_what_the_lock_asks() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let bus = zbus::Connection::system().await.expect("system bus");
            let user = std::env::var("USER").expect("USER");
            let (device, path, fingers) = match reach(&bus, &user).await {
                Ok(found) => found,
                Err(why) if why.contains("NoSuchDevice") => {
                    eprintln!("HYPRFORGE-SKIP: fprintd is running but has no reader ({why})");
                    return;
                }
                Err(why) => panic!("the lock's own calls failed against fprintd: {why}"),
            };
            assert!(path.as_str().starts_with("/net/reactivated/Fprint/Device/"), "{path}");
            if fingers.is_empty() {
                eprintln!("HYPRFORGE-SKIP: no fingers enrolled for {user}, so the list's contents went unchecked");
            }
            for finger in &fingers {
                assert!(finger.contains('-'), "fprintd names fingers like right-thumb, got {finger}");
            }

            let introspectable = zbus::fdo::IntrospectableProxy::builder(&bus)
                .destination(SERVICE)
                .unwrap()
                .path(path.as_str())
                .unwrap()
                .build()
                .await
                .unwrap();
            let xml = introspectable.introspect().await.expect("introspect the reader");
            // Read as text rather than with an XML crate this project
            // does not otherwise need: the introspection format is
            // fixed, and the question is one signal's argument types.
            let interface = xml
                .split(&format!("<interface name=\"{DEVICE}\">"))
                .nth(1)
                .and_then(|rest| rest.split("</interface>").next())
                .expect("the reader implements the device interface");
            let signal = interface
                .split("<signal name=\"VerifyStatus\">")
                .nth(1)
                .and_then(|rest| rest.split("</signal>").next())
                .expect("VerifyStatus exists");
            let signature: String = signal
                .split("type=\"")
                .skip(1)
                .filter_map(|rest| rest.split('"').next())
                .collect();
            assert_eq!(signature, "sb", "the lock deserializes VerifyStatus as (String, bool)");
            for method in ["Claim", "Release", "VerifyStart", "VerifyStop", "ListEnrolledFingers"] {
                assert!(
                    interface.contains(&format!("<method name=\"{method}\"")),
                    "{method} is gone from fprintd's device interface"
                );
            }
            drop(device);
        });
    }

    #[test]
    fn an_unknown_result_is_treated_as_a_reader_that_went_away() {
        assert_eq!(step("verify-disconnected", true, 0), Step::Lost);
        assert_eq!(step("verify-something-new", false, 0), Step::Lost);
    }
}

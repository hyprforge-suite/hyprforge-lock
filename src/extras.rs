//! Everything on the lock screen that is not the lock: the battery, the
//! network, what is playing, who has been in touch, and the power menu.
//!
//! All of it is somebody else's daemon — UPower, NetworkManager, an MPRIS
//! player, the notification server, systemd-logind — so all of it runs on
//! one worker thread with its own tokio runtime, and reaches the screen
//! the way PAM's answers do: posted to a channel, with a ping to wake the
//! event loop. Nothing here can make the lock screen wait. A daemon that
//! is not running is a part of the screen that is simply not drawn, never
//! an error on a lock screen, and never cached as "gone" — each poll
//! tries again, so a service started while locked shows up.
//!
//! None of it can unlock anything. The one command the screen can send
//! that has an effect beyond this process is a power action, which logind
//! authorises on its own terms (see [`Command::Power`]).

use calloop::ping::Ping;
use futures_util::StreamExt;
use hyprforge_authui::scene::{Battery, Media, PowerAction};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;
use zbus::zvariant::OwnedValue;

/// How long one call to any daemon may take.
const CALL: Duration = Duration::from_secs(3);
/// How often the battery and network are read. Both change slowly, and a
/// lock screen that woke the radio's daemon every second would cost
/// battery to report on it.
const STATUS_EVERY: Duration = Duration::from_secs(20);
/// How often the player is read — often enough for the progress bar to
/// move.
const MEDIA_EVERY: Duration = Duration::from_secs(1);

/// Something new to show.
#[derive(Debug, Clone, PartialEq)]
pub enum Update {
    /// `None`: no battery, or UPower not answering. Both draw as nothing.
    Battery(Option<Battery>),
    /// The connected network's name — the SSID, or "Wired".
    Network(Option<String>),
    Media(Option<Media>),
    /// One more notification from this application since the lock began.
    /// The app's name and nothing else: the summary and body are dropped
    /// the moment they are parsed, and never logged.
    Notification(String),
    /// What logind says this machine can do right now.
    Power(Vec<PowerAction>),
}

/// Something the screen asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    MediaPrevious,
    MediaPlayPause,
    MediaNext,
    /// Always sent with `interactive = false`. From a locked screen
    /// nobody can answer a polkit prompt, so logind either permits the
    /// action outright — its rule for the active local session — or
    /// refuses it, and a refusal is logged rather than prompted for.
    Power(PowerAction),
}

pub struct Extras {
    updates: Receiver<Update>,
    commands: tokio::sync::mpsc::UnboundedSender<Command>,
}

impl Extras {
    /// `rehearse` logs power actions instead of performing them — for a
    /// test lock in a nested compositor, which still talks to the real
    /// system bus: "shut down" there would shut down the machine the
    /// test is running on.
    pub fn start(rehearse: bool) -> (Extras, calloop::ping::PingSource) {
        let (to_ui, updates) = std::sync::mpsc::channel();
        let (commands, incoming) = tokio::sync::mpsc::unbounded_channel();
        let (ping, source) = calloop::ping::make_ping().expect("failed to create a wakeup pipe");
        // A thread that cannot start is a screen without extras, which
        // is a screen that still unlocks.
        let _ = std::thread::Builder::new()
            .name("extras".into())
            .spawn(move || run(to_ui, ping, incoming, rehearse));
        (Extras { updates, commands }, source)
    }

    pub fn poll(&mut self) -> Option<Update> {
        self.updates.try_recv().ok()
    }

    pub fn send(&self, command: Command) {
        let _ = self.commands.send(command);
    }
}

#[derive(Clone)]
struct Say {
    to_ui: Sender<Update>,
    ping: Ping,
}

impl Say {
    fn say(&self, update: Update) {
        let _ = self.to_ui.send(update);
        self.ping.ping();
    }
}

fn run(to_ui: Sender<Update>, ping: Ping, commands: tokio::sync::mpsc::UnboundedReceiver<Command>, rehearse: bool) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return;
    };
    let say = Say { to_ui, ping };
    runtime.block_on(async move {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                tokio::task::spawn_local(status(say.clone()));
                tokio::task::spawn_local(notifications(say.clone()));
                tokio::task::spawn_local(power(say.clone()));
                media(say, commands, rehearse).await;
            })
            .await;
    });
}

async fn bounded<T, E: std::fmt::Display>(call: impl std::future::Future<Output = Result<T, E>>) -> Option<T> {
    match tokio::time::timeout(CALL, call).await {
        Ok(Ok(value)) => Some(value),
        _ => None,
    }
}

/// Battery and network, every [`STATUS_EVERY`], sent only when changed.
async fn status(say: Say) {
    use hyprforge_network::NetworkBackend;
    use hyprforge_power::BatteryBackend;

    let (mut battery, mut network) = (None, None);
    let mut first = true;
    loop {
        // Connected per round rather than once: a daemon that was down
        // at lock time is reached the next time round, not never.
        let reading = match bounded(hyprforge_power::UPowerBackend::connect()).await {
            Some(upower) => bounded(upower.battery()).await.flatten().map(|info| Battery {
                percent: info.percentage,
                charging: matches!(
                    info.state,
                    hyprforge_power::BatteryState::Charging | hyprforge_power::BatteryState::FullyCharged
                ),
                low: info.is_low(),
            }),
            None => None,
        };
        if first || reading != battery {
            battery = reading;
            say.say(Update::Battery(battery));
        }

        let name = match bounded(hyprforge_network::NetworkManagerBackend::connect()).await {
            Some(nm) => {
                let wifi = bounded(nm.status()).await.and_then(|s| s.connected_to).map(|ssid| ssid.to_display_string());
                match wifi {
                    Some(ssid) => Some(ssid),
                    None => bounded(nm.wired())
                        .await
                        .unwrap_or_default()
                        .iter()
                        .any(|w| w.state == hyprforge_network::WiredState::Connected)
                        .then(|| "Wired".to_string()),
                }
            }
            None => None,
        };
        if first || name != network {
            network = name;
            say.say(Update::Network(network.clone()));
        }
        first = false;
        tokio::time::sleep(STATUS_EVERY).await;
    }
}

/// What logind can do, read once: whether a machine can hibernate does
/// not change while it is locked.
async fn power(say: Say) {
    let Some(bus) = bounded(zbus::Connection::system()).await else {
        return;
    };
    let Some(logind) = bounded(zbus::Proxy::new(
        &bus,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    ))
    .await
    else {
        return;
    };
    let mut answers = Vec::new();
    for action in PowerAction::ALL {
        let answer: Option<String> = bounded(logind.call(can_method(action), &())).await;
        answers.push((action, answer.unwrap_or_default()));
    }
    say.say(Update::Power(offered(&answers)));
}

fn can_method(action: PowerAction) -> &'static str {
    match action {
        PowerAction::Suspend => "CanSuspend",
        PowerAction::Hibernate => "CanHibernate",
        PowerAction::Reboot => "CanReboot",
        PowerAction::PowerOff => "CanPowerOff",
    }
}

fn do_method(action: PowerAction) -> &'static str {
    match action {
        PowerAction::Suspend => "Suspend",
        PowerAction::Hibernate => "Hibernate",
        PowerAction::Reboot => "Reboot",
        PowerAction::PowerOff => "PowerOff",
    }
}

/// Which actions to offer, from logind's `Can*` answers.
///
/// `yes` only. `challenge` needs a polkit prompt nobody at a locked
/// screen can answer; `na` is a machine that cannot (hibernate with no
/// swap); `no` is policy. And `inhibited` — some program holds a block
/// inhibitor — is left out too: offering an action logind will refuse is
/// a button that only fails, which on a lock screen reads as broken.
fn offered(answers: &[(PowerAction, String)]) -> Vec<PowerAction> {
    answers
        .iter()
        .filter(|(_, answer)| answer == "yes")
        .map(|(action, _)| *action)
        .collect()
}

async fn perform(action: PowerAction) {
    let Some(bus) = bounded(zbus::Connection::system()).await else {
        eprintln!("power: couldn't reach the system bus");
        return;
    };
    let result = async {
        let logind = zbus::Proxy::new(
            &bus,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        logind.call::<_, _, ()>(do_method(action), &(false,)).await
    };
    match tokio::time::timeout(CALL, result).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("power: logind refused {}: {e}", action.label()),
        Err(_) => eprintln!("power: logind didn't answer {}", action.label()),
    }
}

/// The player to show and command, and its commands, every
/// [`MEDIA_EVERY`].
async fn media(say: Say, mut commands: tokio::sync::mpsc::UnboundedReceiver<Command>, rehearse: bool) {
    let mut shown: Option<Media> = None;
    let mut player: Option<String> = None;
    let mut first = true;
    let mut tick = tokio::time::interval(MEDIA_EVERY);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let (name, now) = match read_media().await {
                    Some((name, media)) => (Some(name), Some(media)),
                    None => (None, None),
                };
                player = name;
                if first || now != shown {
                    shown = now;
                    say.say(Update::Media(shown.clone()));
                }
                first = false;
            }
            command = commands.recv() => {
                let Some(command) = command else { return };
                match command {
                    Command::Power(action) if rehearse => {
                        eprintln!("power: would {} now (a test lock rehearses, never acts)", action.label());
                    }
                    Command::Power(action) => perform(action).await,
                    other => {
                        if let Some(name) = &player {
                            command_player(name, other).await;
                            // Read straight back, so the button's effect
                            // shows now and not up to a second later.
                            tick.reset_immediately();
                        }
                    }
                }
            }
        }
    }
}

const MPRIS: &str = "org.mpris.MediaPlayer2.";
const MPRIS_PATH: &str = "/org/mpris/MediaPlayer2";

async fn session() -> Option<zbus::Connection> {
    // One connection for the life of the thread would be tidier, but a
    // session bus that restarts would leave it dead forever; a fresh one
    // per read is a socket connect, once a second, on a local machine.
    bounded(zbus::Connection::session()).await
}

async fn read_media() -> Option<(String, Media)> {
    let bus = session().await?;
    let dbus = bounded(zbus::fdo::DBusProxy::new(&bus)).await?;
    let names = bounded(dbus.list_names()).await?;

    let mut candidates = Vec::new();
    for name in names.iter().map(|n| n.as_str()).filter(|n| n.starts_with(MPRIS)) {
        // playerctld re-publishes whichever player it is tracking, so
        // counting it would show one player twice.
        if name == "org.mpris.MediaPlayer2.playerctld" {
            continue;
        }
        let Some(proxy) = bounded(zbus::Proxy::new(&bus, name.to_string(), MPRIS_PATH, "org.mpris.MediaPlayer2.Player")).await
        else {
            continue;
        };
        let status: String = bounded(proxy.get_property("PlaybackStatus")).await.unwrap_or_default();
        candidates.push((name.to_string(), status, proxy));
    }
    let chosen = choose(candidates.iter().map(|(n, s, _)| (n.as_str(), s.as_str())))?;
    let (name, status, proxy) = candidates.iter().find(|(n, _, _)| n == chosen)?;

    let metadata: HashMap<String, OwnedValue> = bounded(proxy.get_property("Metadata")).await.unwrap_or_default();
    let position: Option<i64> = bounded(proxy.get_property("Position")).await;
    let can_previous: bool = bounded(proxy.get_property("CanGoPrevious")).await.unwrap_or(false);
    let can_next: bool = bounded(proxy.get_property("CanGoNext")).await.unwrap_or(false);
    let identity: String = match bounded(zbus::Proxy::new(&bus, name.clone(), MPRIS_PATH, "org.mpris.MediaPlayer2")).await {
        Some(root) => bounded(root.get_property("Identity")).await.unwrap_or_default(),
        None => String::new(),
    };

    let title = text(&metadata, "xesam:title").unwrap_or_default();
    let artist = artists(&metadata);
    let length = micros(&metadata, "mpris:length");
    Some((
        name.clone(),
        Media {
            title: if title.is_empty() { identity.clone() } else { title },
            artist,
            player: identity,
            playing: status == "Playing",
            progress: progress(position, length),
            can_previous,
            can_next,
        },
    ))
}

/// The player worth showing: one that is playing, else one that is
/// paused. A stopped player has nothing to show and is left out, so a
/// browser that once played a video does not park a card on the screen
/// for ever.
fn choose<'a>(players: impl Iterator<Item = (&'a str, &'a str)>) -> Option<&'a str> {
    let mut paused = None;
    for (name, status) in players {
        match status {
            "Playing" => return Some(name),
            "Paused" if paused.is_none() => paused = Some(name),
            _ => {}
        }
    }
    paused
}

fn text(metadata: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    metadata.get(key).and_then(|v| String::try_from(v.try_clone().ok()?).ok())
}

fn artists(metadata: &HashMap<String, OwnedValue>) -> String {
    metadata
        .get("xesam:artist")
        .and_then(|v| Vec::<String>::try_from(v.try_clone().ok()?).ok())
        .map(|names| names.join(", "))
        .unwrap_or_default()
}

/// `mpris:length` is specified as a 64-bit signed integer of
/// microseconds, and players disagree about signedness in practice.
fn micros(metadata: &HashMap<String, OwnedValue>, key: &str) -> Option<i64> {
    let value = metadata.get(key)?;
    i64::try_from(value.try_clone().ok()?)
        .ok()
        .or_else(|| u64::try_from(value.try_clone().ok()?).ok().and_then(|v| i64::try_from(v).ok()))
}

fn progress(position: Option<i64>, length: Option<i64>) -> Option<f32> {
    match (position, length) {
        (Some(p), Some(l)) if l > 0 && p >= 0 => Some((p as f64 / l as f64).clamp(0.0, 1.0) as f32),
        _ => None,
    }
}

async fn command_player(name: &str, command: Command) {
    let method = match command {
        Command::MediaPrevious => "Previous",
        Command::MediaPlayPause => "PlayPause",
        Command::MediaNext => "Next",
        Command::Power(_) => return,
    };
    let Some(bus) = session().await else { return };
    if let Some(player) = bounded(zbus::Proxy::new(&bus, name.to_string(), MPRIS_PATH, "org.mpris.MediaPlayer2.Player")).await {
        let _ = bounded(player.call::<_, _, ()>(method, &())).await;
    }
}

/// Counts notifications that arrive while the screen is locked.
///
/// The notification server on this machine (and most) keeps no list it
/// will share — the freedesktop protocol has no "how many unread" call —
/// so the lock screen watches `Notify` calls go past on the session bus
/// instead, as a D-Bus monitor. Which also makes the count mean the
/// right thing for a lock screen: what arrived while you were away.
///
/// A monitor sees the whole call, summary and body included; they are
/// dropped as soon as the application's name has been read out, and
/// never logged.
async fn notifications(say: Say) {
    let Some(bus) = session().await else { return };
    let Ok(rule) = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::MethodCall)
        .interface("org.freedesktop.Notifications")
        .and_then(|b| b.member("Notify"))
        .map(|b| b.build())
    else {
        return;
    };
    let Some(monitoring) = bounded(zbus::fdo::MonitoringProxy::new(&bus)).await else { return };
    if bounded(monitoring.become_monitor(&[rule], 0)).await.is_none() {
        return;
    }
    let mut stream = zbus::MessageStream::from(&bus);
    while let Some(Ok(message)) = stream.next().await {
        type Notify = (String, u32, String, String, String, Vec<String>, HashMap<String, OwnedValue>, i32);
        let Ok(call) = message.body().deserialize::<Notify>() else {
            continue;
        };
        let (app, replaces) = (call.0, call.1);
        drop(message);
        if let Some(app) = counted(app, replaces) {
            say.say(Update::Notification(app));
        }
    }
}

/// Whether a `Notify` call is a new notification, and under what name.
///
/// A non-zero `replaces_id` updates one already on screen — a download's
/// progress, a timer — and counting each update would turn one
/// notification into dozens.
fn counted(app: String, replaces_id: u32) -> Option<String> {
    if replaces_id != 0 {
        return None;
    }
    let app = app.trim();
    Some(if app.is_empty() { "Notifications".to_string() } else { app.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_what_logind_says_yes_to_is_offered() {
        let answers = [
            (PowerAction::Suspend, "inhibited".to_string()),
            (PowerAction::Hibernate, "na".to_string()),
            (PowerAction::Reboot, "yes".to_string()),
            (PowerAction::PowerOff, "challenge".to_string()),
        ];
        assert_eq!(offered(&answers), vec![PowerAction::Reboot]);
    }

    #[test]
    fn a_playing_player_wins_and_a_stopped_one_is_never_shown() {
        let players = [("a", "Paused"), ("b", "Stopped"), ("c", "Playing")];
        assert_eq!(choose(players.into_iter()), Some("c"));
        assert_eq!(choose([("a", "Paused"), ("b", "Paused")].into_iter()), Some("a"));
        assert_eq!(choose([("a", "Stopped")].into_iter()), None);
        assert_eq!(choose(std::iter::empty()), None);
    }

    #[test]
    fn progress_needs_a_length_and_stays_inside_the_bar() {
        assert_eq!(progress(Some(30), Some(120)), Some(0.25));
        assert_eq!(progress(Some(500), Some(120)), Some(1.0));
        assert_eq!(progress(Some(30), Some(0)), None, "a live stream has no length");
        assert_eq!(progress(None, Some(120)), None);
        assert_eq!(progress(Some(-5), Some(120)), None);
    }

    #[test]
    fn an_updated_notification_is_not_counted_again() {
        assert_eq!(counted("Signal".into(), 0), Some("Signal".into()));
        assert_eq!(counted("Signal".into(), 42), None);
        assert_eq!(counted("  ".into(), 0), Some("Notifications".into()));
    }

    #[test]
    fn metadata_is_read_whatever_width_the_player_used() {
        let mut metadata = HashMap::new();
        metadata.insert("xesam:title".to_string(), OwnedValue::try_from(zbus::zvariant::Value::from("Nightcall")).unwrap());
        metadata.insert(
            "xesam:artist".to_string(),
            OwnedValue::try_from(zbus::zvariant::Value::from(vec!["Kavinsky".to_string(), "Lovefoxxx".to_string()])).unwrap(),
        );
        metadata.insert("mpris:length".to_string(), OwnedValue::from(258_000_000u64));
        assert_eq!(text(&metadata, "xesam:title").as_deref(), Some("Nightcall"));
        assert_eq!(artists(&metadata), "Kavinsky, Lovefoxxx");
        assert_eq!(micros(&metadata, "mpris:length"), Some(258_000_000));
        metadata.insert("mpris:length".to_string(), OwnedValue::from(12i64));
        assert_eq!(micros(&metadata, "mpris:length"), Some(12));
    }
}

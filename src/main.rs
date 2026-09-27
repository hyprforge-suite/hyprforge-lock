//! A lock screen for Hyprland, sharing its look with the greeter.
//!
//! Runs as you, so it reads your own theme directly. The greeter reads
//! an exported copy — see `hyprforge_look::theme`.

mod backdrop;
mod extras;
mod fingerprint;
mod layout;
mod logind;
mod pam;
mod surface;

use clap::Parser;
#[cfg(debug_assertions)]
use hyprforge_authui::conversation::{Backend, Prompt, Response};
use hyprforge_authui::Theme;
use surface::{LockScreen, Outcome, Workers};

#[derive(Parser)]
#[command(about = "Lock the session")]
struct Args {
    /// Authenticate against a fixed password instead of PAM.
    ///
    /// For testing the Wayland and drawing paths in a nested compositor
    /// without touching real credentials. On this machine that isn't
    /// merely tidier: pam_faillock is enabled with a failure already
    /// recorded, so a couple of deliberately wrong passwords would lock
    /// the account.
    ///
    /// Refuses to run against the session you are actually using, and
    /// does not exist at all in a release build — see `main`.
    #[cfg(debug_assertions)]
    #[arg(long, value_name = "PASSWORD")]
    fake_password: Option<String>,

    /// Which Wayland display to lock. Defaults to $WAYLAND_DISPLAY.
    #[arg(long)]
    display: Option<String>,

    /// Type this in automatically once a frame has been drawn, then
    /// press Enter.
    ///
    /// This is how the unlock path gets tested without a keyboard: it
    /// proves lock, draw, authenticate and unlock end to end. Passing
    /// something other than the fake password exercises the failure
    /// path just as honestly — and against the fake backend rather than
    /// PAM, so no real account gets a failed attempt recorded against
    /// it. Only meaningful alongside `--fake-password`, and so inherits
    /// its refusal to run against the session you are using.
    #[cfg(debug_assertions)]
    #[arg(long, value_name = "TEXT", requires = "fake_password")]
    type_in: Option<String>,

    /// Make the fake backend take this many milliseconds to answer.
    ///
    /// Stands in for `pam_unix`, which deliberately sleeps for about two
    /// seconds after a wrong password. The screen has to keep drawing
    /// and keep accepting input throughout — a surface that stops
    /// repainting for two seconds is indistinguishable from one that
    /// crashed, and on a lock screen the user's only other option is a
    /// hard reboot.
    #[cfg(debug_assertions)]
    #[arg(long, value_name = "MS", requires = "fake_password")]
    fake_delay: Option<u64>,
}

/// A backend that accepts one fixed password. Testing only.
///
/// Compiled out of release builds entirely. A lock screen that opens to
/// a known string must not be one command-line flag away in the binary
/// people install, however carefully that flag is guarded.
///
/// Answers through a channel and a ping exactly as the PAM backend
/// does, rather than returning inline. That is deliberate: it means
/// `--fake-delay` exercises the real waking path instead of a shortcut,
/// so what it demonstrates about the UI staying alive is also true of
/// PAM.
#[cfg(debug_assertions)]
struct Fake {
    password: String,
    delay: std::time::Duration,
    to_ui: std::sync::mpsc::Sender<Response>,
    from_worker: std::sync::mpsc::Receiver<Response>,
    ping: calloop::ping::Ping,
}

#[cfg(debug_assertions)]
impl Fake {
    fn new(password: String, delay: std::time::Duration) -> (Fake, calloop::ping::PingSource) {
        let (to_ui, from_worker) = std::sync::mpsc::channel();
        let (ping, source) = calloop::ping::make_ping().expect("failed to create a wakeup pipe");
        (Fake { password, delay, to_ui, from_worker, ping }, source)
    }

    /// Posts a response, after the configured delay if there is one.
    fn emit(&self, response: Response) {
        if self.delay.is_zero() {
            let _ = self.to_ui.send(response);
            self.ping.ping();
            return;
        }
        let (to_ui, ping, delay) = (self.to_ui.clone(), self.ping.clone(), self.delay);
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            let _ = to_ui.send(response);
            ping.ping();
        });
    }
}

#[cfg(debug_assertions)]
impl Backend for Fake {
    fn start(&mut self, _username: &str) {
        self.emit(Response::Ask(Prompt::secret("Password:")));
    }

    fn answer(&mut self, answer: &str) {
        self.emit(if answer == self.password {
            Response::Success
        } else {
            Response::Failure { reason: "Incorrect password".into() }
        });
    }

    fn proceed(&mut self) {
        self.emit(Response::Ask(Prompt::secret("Password:")));
    }

    fn poll(&mut self) -> Option<Response> {
        self.from_worker.try_recv().ok()
    }
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();

    // Captured before `--display` can overwrite it, because "the session
    // you are actually using" is defined by what this process would have
    // connected to on its own. Only the testing path needs it, and that
    // path does not exist in a release build.
    #[cfg(debug_assertions)]
    let ambient = std::env::var("WAYLAND_DISPLAY").ok();

    if let Some(display) = &args.display {
        // SAFETY: single-threaded, before anything reads the environment.
        unsafe { std::env::set_var("WAYLAND_DISPLAY", display) };
    }
    let display = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();

    let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    // Nothing from the theme file reaches the renderer unchecked. A zero
    // font size or an undecodable wallpaper panics it — see
    // `renderable` — and a panic here leaves the session locked with
    // nothing running to unlock it.
    let theme = hyprforge_authui::screen::renderable(Theme::load(&theme_path()).unwrap_or_default());

    // The fake backend, in debug builds only. Two conditions, because
    // the first one on its own was not the guarantee its own comment
    // claimed: requiring `--display` proves the caller named a display,
    // not that they named a *different* one, so
    // `--display $WAYLAND_DISPLAY --fake-password x` locked the real
    // session with a known password.
    #[cfg(debug_assertions)]
    if let Some(password) = args.fake_password.clone() {
        let named_a_display = args.display.is_some();
        let same_session = args.display.is_none() || args.display == ambient;
        if !named_a_display || same_session {
            eprintln!(
                "--fake-password must name a different display than the session you're \
                 using ({}). Start a nested compositor and point at its display.",
                ambient.as_deref().unwrap_or("none")
            );
            return std::process::ExitCode::FAILURE;
        }

        let connection = match wayland_client::Connection::connect_to_env() {
            Ok(connection) => connection,
            Err(e) => {
                eprintln!("couldn't connect to the compositor on {display}: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        eprintln!("locking {display} with a fake password (testing only)");
        let delay = std::time::Duration::from_millis(args.fake_delay.unwrap_or(0));
        let (fake, wake) = Fake::new(password, delay);
        // The reader stays on for a hand-driven nested test, so the
        // fingerprint card can be seen and a real finger tried against
        // a session that is not the real one. A self test turns it off:
        // its result must not depend on whether someone touched the
        // sensor while it ran.
        let fingerprint = args.type_in.is_none().then(pam::service_name);
        return report(LockScreen::run(
            connection,
            fake,
            username,
            theme,
            Some(wake),
            args.type_in,
            // A test lock still talks to the real system bus, so its
            // power menu only rehearses.
            Workers { fingerprint, rehearse_power: true },
        ));
    }

    let connection = match wayland_client::Connection::connect_to_env() {
        Ok(connection) => connection,
        Err(e) => {
            eprintln!("couldn't connect to the compositor on {display}: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let service = pam::service_name();
    eprintln!("locking {display}, authenticating against PAM service {service:?}");
    // The backend is handed over unstarted on purpose: it only begins
    // talking to PAM once the session is locked. The ping is what lets it
    // answer later without the screen waiting.
    let (backend, wake) = pam::PamBackend::new(service);
    let workers = Workers { fingerprint: Some(service), rehearse_power: false };
    report(LockScreen::run(connection, backend, username, theme, Some(wake), None, workers))
}

/// Turns an outcome into an exit code, saying only what the layers below
/// could not.
fn report(outcome: Result<Outcome, surface::LockError>) -> std::process::ExitCode {
    match outcome {
        Ok(Outcome::Unlocked) => std::process::ExitCode::SUCCESS,
        // Both causes are already reported where they're diagnosed, and
        // in detail this layer doesn't have. The exit code is the part
        // that differs: a refusal means nothing got locked.
        Ok(Outcome::Refused) => std::process::ExitCode::FAILURE,
        Ok(Outcome::Revoked) => std::process::ExitCode::SUCCESS,
        Ok(Outcome::Disconnected) => {
            eprintln!("lost the connection; the session stays locked");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("couldn't lock: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The user's own theme, which the greeter gets an exported copy of.
fn theme_path() -> std::path::PathBuf {
    hyprforge_paths::lock_toml_path()
}

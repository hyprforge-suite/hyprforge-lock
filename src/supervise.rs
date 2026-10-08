//! Relaunching the lock screen when it crashes, from a parent that cannot.
//!
//! A lock client that dies leaves the session locked — Hyprland's choice,
//! and the right one, since the alternative is a crash that unlocks. What
//! it leaves on screen is Hyprland's "lockscreen app died" page, and the
//! way past that is `hl.clear_crashed_lockscreen()` from another VT: a
//! user locked out of their own session by a bug in this code. The
//! renderer underneath is not written defensively (see
//! `hyprforge_authui::screen::renderable` and the panic sweep that holds
//! it), so prevention alone is not a guarantee.
//!
//! So `main` runs this first. It re-runs its own binary as a child with
//! `--child` and waits; the child does all the work. The parent never
//! connects to Wayland and never renders, so nothing iced or tiny-skia
//! does can reach it. When the child crashes, the parent starts another
//! one, and Hyprland hands the dead lock to it — provided
//! `misc:allow_session_lock_restore` is on, which Set up's `lock-restore`
//! item turns on. Off (Hyprland's default), the new child's request is
//! answered with `finished` before `locked`, which `surface` already
//! reports as [`Outcome::Refused`](crate::surface::Outcome::Refused) —
//! the child exits [`EXIT_REFUSED`], and the parent stops and says which
//! option to turn on.
//!
//! What it decides is [`Supervisor::decide`], a pure function, tested
//! below. What it never does is unlock: every way out of here leaves the
//! session as locked as the crash left it.
//!
//! `pidof hyprforge-lock || hyprforge-lock`, the idle lock command,
//! matches this parent while a child is being replaced, so hypridle
//! cannot start a second lock in the gap.

use std::time::{Duration, Instant};

/// The child's exit code when the compositor refused the lock: it never
/// granted one, so nothing was locked by this attempt. Distinct from a
/// crash (101, or a signal) and from the generic failure (1), because it
/// is the one answer the parent acts on differently.
pub const EXIT_REFUSED: u8 = 3;
/// The parent's exit code when it stopped relaunching after too many
/// crashes. The session stays locked behind Hyprland's own screen.
pub const EXIT_GAVE_UP: u8 = 4;
/// What a Rust panic exits with.
const PANIC: i32 = 101;
/// More crashes than this inside [`WINDOW`] and the parent gives up: a
/// screen that cannot stay up is not made better by a fifth attempt, and
/// a tight crash loop is its own way of making the machine unusable.
const MAX_CRASHES: usize = 3;
const WINDOW: Duration = Duration::from_secs(60);

/// How a child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    Code(i32),
    /// Killed by this signal — a segfault, an abort, the OOM killer.
    Signal(i32),
}

/// What the parent does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Exit with this code: the child finished, one way or another, and
    /// there is nothing to recover.
    Finish(u8),
    /// Start another child. `safe` drops everything but the conversation
    /// — see [`Supervisor`].
    Relaunch { safe: bool },
    /// Too many crashes; exit [`EXIT_GAVE_UP`].
    GiveUp,
    /// A relaunch was refused the lock. Exit [`EXIT_REFUSED`], naming the
    /// option that would have let it through.
    RestoreRefused,
}

/// Crash history, and what follows from it.
///
/// The first crash is relaunched as it was. The second, and every one
/// after it, is relaunched with `--safe`: the default theme (so no
/// wallpaper), no avatar, no status worker and no fingerprint reader —
/// each an input a crash could have come from, and none of them needed
/// to unlock. Safe mode is sticky: a crash that safe mode did not cause
/// is no reason to put the inputs back.
#[derive(Debug, Default)]
pub struct Supervisor {
    crashes: Vec<Instant>,
    relaunched: bool,
    safe: bool,
}

impl Supervisor {
    pub fn decide(&mut self, exit: ChildExit, now: Instant) -> Decision {
        match exit {
            ChildExit::Code(0) => Decision::Finish(0),
            ChildExit::Code(code) if code == i32::from(EXIT_REFUSED) => {
                if self.relaunched {
                    Decision::RestoreRefused
                } else {
                    // The first attempt refused: another lock already
                    // holds the session. Nothing crashed; pass it on.
                    Decision::Finish(EXIT_REFUSED)
                }
            }
            ChildExit::Code(PANIC) | ChildExit::Signal(_) => {
                self.crashes.retain(|t| now.duration_since(*t) < WINDOW);
                self.crashes.push(now);
                if self.crashes.len() > MAX_CRASHES {
                    return Decision::GiveUp;
                }
                self.relaunched = true;
                self.safe |= self.crashes.len() >= 2;
                Decision::Relaunch { safe: self.safe }
            }
            ChildExit::Code(code) => Decision::Finish(u8::try_from(code).unwrap_or(1)),
        }
    }
}

/// The program to run as the child: this one.
///
/// By its real path while that still names this binary, so the child's
/// process name is `hyprforge-lock` — exec'd through `/proc/self/exe` it
/// would be `exe`, and `pgrep -x hyprforge-lock` would not find the
/// process actually holding the lock. Once the file has been replaced on
/// disk (an upgrade while locked; the kernel then reports the path with
/// ` (deleted)`), `/proc/self/exe` instead, so the relaunch is the same
/// program that took the lock rather than a new version nobody has
/// unlocked with yet.
fn program() -> std::path::PathBuf {
    match std::env::current_exe() {
        Ok(path) if !path.to_string_lossy().ends_with(" (deleted)") => path,
        _ => "/proc/self/exe".into(),
    }
}

/// Runs children until one finishes, and exits as [`Supervisor`] decides.
pub fn run() -> std::process::ExitCode {
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    // Everything the user passed, so a relaunch locks the same display
    // with the same backend. `--child` and `--safe` are ours to add.
    let args: Vec<std::ffi::OsString> =
        std::env::args_os().skip(1).filter(|a| a != "--child" && a != "--safe").collect();
    let mut supervisor = Supervisor::default();
    let mut safe = false;
    loop {
        let mut command = std::process::Command::new(program());
        command.arg0("hyprforge-lock").args(&args).arg("--child");
        if safe {
            command.arg("--safe");
        }
        let status = match command.status() {
            Ok(status) => status,
            Err(e) => {
                // Nothing was started, so nothing new is locked; a lock an
                // earlier child took stays held by the compositor.
                eprintln!("couldn't start the lock screen: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let exit = match (status.code(), status.signal()) {
            (Some(code), _) => ChildExit::Code(code),
            (None, Some(signal)) => ChildExit::Signal(signal),
            (None, None) => ChildExit::Code(1),
        };
        match supervisor.decide(exit, Instant::now()) {
            Decision::Finish(code) => return std::process::ExitCode::from(code),
            Decision::Relaunch { safe: next } => {
                eprintln!(
                    "the lock screen exited abnormally ({}); starting it again{}",
                    describe(exit),
                    if next { " in safe mode" } else { "" }
                );
                safe = next;
            }
            Decision::GiveUp => {
                eprintln!(
                    "the lock screen crashed {} times within {}s; not starting it again. \
                     The session stays locked behind Hyprland's own screen.",
                    MAX_CRASHES + 1,
                    WINDOW.as_secs()
                );
                return std::process::ExitCode::from(EXIT_GAVE_UP);
            }
            Decision::RestoreRefused => {
                eprintln!(
                    "Hyprland refused the restarted lock screen: misc:allow_session_lock_restore \
                     is off (or another lock screen holds the session). The session stays \
                     locked. Turn it on with Settings' Set up page (\"Restart the lock screen \
                     if it crashes\") so a crash can be recovered from."
                );
                return std::process::ExitCode::from(EXIT_REFUSED);
            }
        }
    }
}

fn describe(exit: ChildExit) -> String {
    match exit {
        ChildExit::Code(PANIC) => "it panicked".to_string(),
        ChildExit::Code(code) => format!("exit code {code}"),
        ChildExit::Signal(signal) => format!("signal {signal}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEGV: i32 = 11;

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    #[test]
    fn an_unlock_ends_the_supervisor_with_success() {
        let mut s = Supervisor::default();
        assert_eq!(s.decide(ChildExit::Code(0), Instant::now()), Decision::Finish(0));
    }

    #[test]
    fn a_panic_or_a_signal_is_relaunched_as_it_was_the_first_time() {
        let now = Instant::now();
        assert_eq!(Supervisor::default().decide(ChildExit::Code(PANIC), now), Decision::Relaunch { safe: false });
        assert_eq!(Supervisor::default().decide(ChildExit::Signal(SEGV), now), Decision::Relaunch { safe: false });
    }

    #[test]
    fn the_second_crash_relaunches_in_safe_mode_and_safe_mode_stays() {
        let start = Instant::now();
        let mut s = Supervisor::default();
        assert_eq!(s.decide(ChildExit::Signal(SEGV), at(start, 0)), Decision::Relaunch { safe: false });
        assert_eq!(s.decide(ChildExit::Code(PANIC), at(start, 5)), Decision::Relaunch { safe: true });
        // The first two have aged out of the window, so this is one crash
        // in it — and still safe: safe mode is not taken back.
        assert_eq!(s.decide(ChildExit::Signal(SEGV), at(start, 200)), Decision::Relaunch { safe: true });
    }

    #[test]
    fn a_fourth_crash_inside_a_minute_gives_up_and_leaves_the_session_locked() {
        let start = Instant::now();
        let mut s = Supervisor::default();
        for secs in [0, 1, 2] {
            assert!(matches!(s.decide(ChildExit::Signal(SEGV), at(start, secs)), Decision::Relaunch { .. }));
        }
        assert_eq!(s.decide(ChildExit::Signal(SEGV), at(start, 3)), Decision::GiveUp);
    }

    #[test]
    fn crashes_spread_beyond_the_window_never_add_up_to_giving_up() {
        let start = Instant::now();
        let mut s = Supervisor::default();
        for minute in 0..10 {
            assert!(matches!(
                s.decide(ChildExit::Signal(SEGV), at(start, minute * 61)),
                Decision::Relaunch { .. }
            ));
        }
    }

    /// The first attempt being refused is another lock already holding
    /// the session — passed on, never retried. A relaunch refused is the
    /// restore option being off, and is named as such.
    #[test]
    fn a_refusal_is_only_blamed_on_the_restore_option_after_a_relaunch() {
        let now = Instant::now();
        let mut first = Supervisor::default();
        assert_eq!(first.decide(ChildExit::Code(EXIT_REFUSED.into()), now), Decision::Finish(EXIT_REFUSED));

        let mut relaunched = Supervisor::default();
        relaunched.decide(ChildExit::Signal(SEGV), now);
        assert_eq!(relaunched.decide(ChildExit::Code(EXIT_REFUSED.into()), now), Decision::RestoreRefused);
    }

    /// A failure that is not a crash — the compositor gone, no display
    /// to connect to — is passed on rather than retried: relaunching
    /// cannot fix it, and nothing about the lock changes by trying.
    #[test]
    fn an_ordinary_failure_is_passed_on_not_retried() {
        let mut s = Supervisor::default();
        assert_eq!(s.decide(ChildExit::Code(1), Instant::now()), Decision::Finish(1));
    }

    /// Nothing a supervisor decides unlocks: the only success is a child
    /// that unlocked itself.
    #[test]
    fn no_decision_but_a_childs_own_success_exits_zero() {
        let start = Instant::now();
        let mut s = Supervisor::default();
        for (i, exit) in [
            ChildExit::Signal(SEGV),
            ChildExit::Code(PANIC),
            ChildExit::Code(EXIT_REFUSED.into()),
            ChildExit::Code(1),
            ChildExit::Code(255),
        ]
        .into_iter()
        .enumerate()
        {
            let decision = s.decide(exit, at(start, i as u64));
            assert_ne!(decision, Decision::Finish(0), "{exit:?}");
        }
    }
}

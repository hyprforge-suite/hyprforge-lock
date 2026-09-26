//! Authenticating against PAM.
//!
//! PAM is a conversation: it calls back with prompts and expects answers,
//! driven from inside `authenticate()`. The UI is a state machine driven
//! from outside. Those two don't compose directly — one wants to own the
//! call stack, the other wants to be polled — so PAM runs on its own
//! thread and the two talk over channels.
//!
//! That indirection is not incidental. It is what keeps the lock screen
//! **drawing** while PAM is busy: `pam_unix` deliberately sleeps for
//! roughly two seconds after a wrong password, and a surface that stops
//! repainting for two seconds is indistinguishable from one that has
//! crashed. On a lock screen that distinction matters more than usual,
//! because the user's only other option is a hard reboot.
//!
//! Two things are needed for that to actually hold, and an earlier
//! version of this file had only the first. The thread stops PAM owning
//! the call stack; the **ping** is what stops the UI thread waiting on
//! it. Without the ping, `answer` would post a request and then block on
//! a reply, and the surface would freeze for exactly as long as PAM took
//! — the thread notwithstanding. So nothing here waits: requests are
//! posted, `poll` collects whatever has arrived, and the ping wakes the
//! event loop when there is something to collect.
//!
//! **What this deliberately does not do:** decide policy. It reports what
//! PAM said. Rate limiting, lockouts and delays belong to PAM's own
//! configuration (`/etc/pam.d/`), where a system administrator can see
//! and change them — not hidden inside a settings app.

use hyprforge_authui::conversation::{Backend, Prompt, Response};
use std::sync::mpsc::{Receiver, Sender};

/// The PAM service to authenticate against.
///
/// `hyprforge-lock` if it exists, falling back to `hyprlock` and then
/// `login`. Falling back matters: PAM refuses to authenticate against a
/// service with no configuration file, so a missing
/// `/etc/pam.d/hyprforge-lock` would mean nobody can unlock — and on a
/// machine that already runs hyprlock, its config is exactly the right
/// shape to borrow.
pub fn service_name() -> &'static str {
    for candidate in ["hyprforge-lock", "hyprlock"] {
        if std::path::Path::new("/etc/pam.d").join(candidate).exists() {
            // Leaked once at startup; the process is a lock screen and
            // this string outlives everything else in it anyway.
            return Box::leak(candidate.to_string().into_boxed_str());
        }
    }
    "login"
}

/// What the UI thread asks the PAM thread to do.
enum Request {
    Start(String),
    Answer(String),
    Proceed,
}

/// PAM, running on its own thread.
pub struct PamBackend {
    to_pam: Sender<Request>,
    from_pam: Receiver<Response>,
    /// Queued for the next `poll` when the thread can't be reached at
    /// all. Reported through the same path as any other failure so the
    /// UI has one way of hearing bad news.
    lost: Option<Response>,
    /// Whether the thread's death has already been reported.
    ///
    /// Without this, `poll` answered a disconnected channel with
    /// `Some(Failure)` *every* time, and `Conversation::pump` loops
    /// while `poll` keeps yielding — so a dead PAM thread span the lock
    /// screen at 100% CPU and stopped it ever drawing again. The comment
    /// below always said "once"; this is what makes it once.
    reported_loss: bool,
    /// When the outstanding request was posted, if one is outstanding.
    ///
    /// PAM modules can block indefinitely — `pam_sss` against an
    /// unreachable directory server, `pam_krb5`, a fingerprint reader
    /// waiting on a finger that never arrives — and `authenticate` is a
    /// blocking C call on another thread that cannot be cancelled. What
    /// *can* be bounded is how long this side waits before telling the
    /// person in front of the screen something.
    ///
    /// The greeter has bounded greetd at 60s since it was written; the
    /// lock screen bounded nothing, so a hung module left it on
    /// "Checking…" forever — and `State::Working` refuses all input, so
    /// no key helped. The only way out was another TTY.
    waiting_since: Option<std::time::Instant>,
    /// Set once the wait has been given up on.
    ///
    /// The PAM thread may still answer afterwards. That answer is about
    /// a question the user has already been told failed, and a late
    /// `Success` must never unlock a session — so once abandoned, this
    /// transaction is over and nothing it says is read again.
    abandoned: bool,
}

/// How long the lock screen waits for PAM before saying so.
///
/// Longer than the greeter's 60s greetd bound, because `pam_unix`
/// deliberately sleeps for seconds after a wrong password and a stacked
/// module can legitimately take a while. Short enough that someone
/// standing at a locked screen gets an answer rather than a machine they
/// assume has crashed.
const PAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

impl PamBackend {
    /// Builds the backend and the event source that wakes the host.
    ///
    /// The two come together because they are two halves of one thing:
    /// the ping is fired by the PAM thread whenever it posts a response,
    /// and a host that dropped it would never learn that `poll` had
    /// something to give.
    pub fn new(service: &'static str) -> (PamBackend, calloop::ping::PingSource) {
        let (to_pam, requests) = std::sync::mpsc::channel::<Request>();
        let (responses, from_pam) = std::sync::mpsc::channel::<Response>();
        let (ping, source) = calloop::ping::make_ping().expect("failed to create a wakeup pipe");

        std::thread::Builder::new()
            .name("pam".into())
            .spawn(move || run(service, requests, responses, ping))
            .expect("failed to start the PAM thread");

        (
            PamBackend {
                to_pam,
                from_pam,
                lost: None,
                reported_loss: false,
                waiting_since: None,
                abandoned: false,
            },
            source,
        )
    }

    /// Posts a request without waiting for the answer.
    ///
    /// A dead PAM thread reports failure rather than panicking or
    /// hanging. Neither alternative is acceptable here: a panic in the
    /// lock screen leaves the compositor locked with no way in, and a
    /// hang looks identical to one.
    fn post(&mut self, request: Request) {
        if self.abandoned {
            // Nothing more is asked of a transaction that was given up
            // on; the thread may still be inside the previous call.
            return;
        }
        self.waiting_since = Some(std::time::Instant::now());
        if self.to_pam.send(request).is_err() {
            // A failed send and a disconnected receiver are the same
            // fact — the thread is gone — so they share one "already
            // said" flag. Reporting it twice would be harmless here but
            // the point is that it is reported a bounded number of
            // times, and two mechanisms each counting to one is how
            // that stops being true.
            self.reported_loss = true;
            self.lost = Some(Response::Failure {
                reason: "the authentication service stopped responding".into(),
            });
        }
    }
}

impl Backend for PamBackend {
    fn start(&mut self, username: &str) {
        self.post(Request::Start(username.to_string()));
    }

    fn answer(&mut self, answer: &str) {
        self.post(Request::Answer(answer.to_string()));
    }

    fn proceed(&mut self) {
        self.post(Request::Proceed);
    }

    fn poll(&mut self) -> Option<Response> {
        if let Some(lost) = self.lost.take() {
            return Some(lost);
        }
        if self.abandoned {
            return None;
        }
        if self.waiting_since.is_some_and(|at| at.elapsed() >= PAM_TIMEOUT) {
            self.abandoned = true;
            self.waiting_since = None;
            return Some(Response::Failure {
                reason: "the authentication service didn't answer".into(),
            });
        }
        match self.from_pam.try_recv() {
            Ok(response) => {
                // An answer arrived, so nothing is outstanding. A prompt
                // is an answer too: it means the far side is alive and
                // the clock restarts when the reply goes back.
                self.waiting_since = None;
                Some(response)
            }
            // Empty means "not yet"; the ping will bring the host back.
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            // Disconnected means the thread is gone for good. Saying so
            // once beats a lock screen that waits forever for an answer
            // nobody is going to give.
            Err(std::sync::mpsc::TryRecvError::Disconnected) if !self.reported_loss => {
                self.reported_loss = true;
                Some(Response::Failure {
                    reason: "the authentication service stopped responding".into(),
                })
            }
            // Already said. Saying it again forever is a spin, not a
            // report.
            Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
        }
    }
}

/// The PAM thread.
///
/// Split out and kept simple: everything here runs with the ability to
/// authenticate, so the less of it there is, the better.
fn run(
    service: &str,
    requests: Receiver<Request>,
    responses: Sender<Response>,
    ping: calloop::ping::Ping,
) {
    // Every send is followed by a ping. Posting a response the host
    // never wakes up to read is the same, from the user's side, as not
    // answering at all.
    let reply = |response: Response| -> bool {
        let sent = responses.send(response).is_ok();
        ping.ping();
        sent
    };

    while let Ok(request) = requests.recv() {
        let Request::Start(username) = request else {
            // Anything before a Start has nothing to answer.
            reply(Response::Failure { reason: "no authentication in progress".into() });
            continue;
        };
        let outcome = authenticate(service, &username, &requests, &responses, &ping);
        if !reply(outcome) {
            return;
        }
    }
}

/// One authentication attempt, from `start` to a verdict.
fn authenticate(
    service: &str,
    username: &str,
    requests: &Receiver<Request>,
    responses: &Sender<Response>,
    ping: &calloop::ping::Ping,
) -> Response {
    // The conversation handler runs inside PAM's call, so it forwards
    // each prompt to the UI and blocks for the answer.
    let conversation = UiConversation {
        requests,
        responses,
        ping,
        username: username.to_string(),
    };

    let mut context = match pam_client2::Context::new(service, Some(username), conversation) {
        Ok(context) => context,
        Err(e) => {
            return Response::Failure {
                reason: format!("couldn't start authentication: {e}"),
            }
        }
    };

    if let Err(e) = context.authenticate(pam_client2::Flag::NONE) {
        return Response::Failure { reason: describe(e.code(), &e) };
    }
    // Authentication is not authorisation: an account can be valid and
    // still be expired, locked, or barred from this host. Skipping this
    // would unlock a session PAM had refused.
    //
    // Reported separately from the password check, because the two mean
    // opposite things to the person standing there. Saying "incorrect
    // password" when the password was right sends someone typing it
    // again and again — which is exactly what a misconfigured account
    // stack produced here: `/etc/pam.d/hyprlock` declares only an auth
    // stack, so the account check fell through to `other`'s pam_deny
    // and refused every correct password.
    if let Err(e) = context.acct_mgmt(pam_client2::Flag::NONE) {
        return Response::Failure { reason: describe_account(e.code(), &e, service) };
    }
    Response::Success
}

/// The account half of PAM on its own, for an unlock that did not come
/// through PAM's auth stack at all — a fingerprint matched by fprintd.
///
/// Not optional, and the reason is the same as in [`authenticate`]: a
/// finger proves who is standing there, not that the account is still
/// allowed in. An expired or barred account must not be unlockable by
/// touching a sensor when typing its password would be refused.
///
/// Blocking — PAM is — so it runs on the fingerprint worker's thread,
/// never the event loop. The conversation is `conv_null`: the account
/// stack has nothing to ask, and a module that tried would get a refusal
/// rather than a prompt nobody is shown.
pub fn account_permits(service: &str, username: &str) -> Result<(), String> {
    let mut context =
        pam_client2::Context::new(service, Some(username), pam_client2::conv_null::Conversation::default())
            .map_err(|e| format!("couldn't start the account check: {e}"))?;
    context
        .acct_mgmt(pam_client2::Flag::NONE)
        .map_err(|e| describe_account(e.code(), &e, service))
}

/// PAM's errors, in words a person can act on.
///
/// The common one is deliberately plain: "Incorrect password" rather than
/// PAM's "Authentication failure", which reads like the program broke.
///
/// Takes the code separately from the error so the mapping can be tested:
/// `pam_client2::Error` can't be constructed outside its own crate, and a
/// message this load-bearing shouldn't go unchecked because of that.
fn describe(code: pam_client2::ErrorCode, error: &dyn std::fmt::Display) -> String {
    use pam_client2::ErrorCode;
    match code {
        ErrorCode::AUTH_ERR => "Incorrect password".into(),
        ErrorCode::CRED_INSUFFICIENT => "Not permitted to unlock this session".into(),
        ErrorCode::MAXTRIES => "Too many attempts — wait before trying again".into(),
        ErrorCode::ACCT_EXPIRED => "This account has expired".into(),
        ErrorCode::NEW_AUTHTOK_REQD => "Your password has expired and must be changed".into(),
        ErrorCode::USER_UNKNOWN => "Unknown user".into(),
        ErrorCode::AUTHINFO_UNAVAIL => "Authentication service unavailable".into(),
        _ => format!("Authentication failed: {error}"),
    }
}

/// The account check's failures, which are not password failures.
///
/// The password was already accepted by the time this runs, so none of
/// these may say "incorrect password". The common case in practice is
/// not an expired account at all but a service with no account stack —
/// worth naming outright, because "authentication failed" sends a user
/// retyping a password that was right the first time, and on a machine
/// with `pam_faillock` that costs them attempts they cannot spare.
fn describe_account(
    code: pam_client2::ErrorCode,
    error: &dyn std::fmt::Display,
    service: &str,
) -> String {
    use pam_client2::ErrorCode;
    match code {
        ErrorCode::ACCT_EXPIRED => "This account has expired".into(),
        ErrorCode::NEW_AUTHTOK_REQD => "Your password has expired and must be changed".into(),
        ErrorCode::USER_UNKNOWN => "Unknown user".into(),
        // pam_deny in the account stack, which is what an unconfigured
        // service falls through to.
        ErrorCode::PERM_DENIED | ErrorCode::AUTH_ERR => format!(
            "Password accepted, but the account check failed. \
             /etc/pam.d/{service} probably has no `account` rules — \
             install the one shipped with hyprforge-lock."
        ),
        _ => format!("Password accepted, but the account check failed: {error}"),
    }
}

/// Forwards PAM's prompts to the UI and waits for answers.
struct UiConversation<'a> {
    requests: &'a Receiver<Request>,
    responses: &'a Sender<Response>,
    ping: &'a calloop::ping::Ping,
    username: String,
}

impl UiConversation<'_> {
    /// Sends a prompt and blocks until the UI answers.
    fn ask(&self, prompt: Prompt) -> Result<String, ()> {
        self.responses.send(Response::Ask(prompt)).map_err(|_| ())?;
        self.ping.ping();
        match self.requests.recv() {
            Ok(Request::Answer(answer)) => Ok(answer),
            // A Start while a conversation is running means the user gave
            // up on this attempt; abandoning it is correct.
            _ => Err(()),
        }
    }

    fn tell(&self, text: String, error: bool) {
        let _ = self.responses.send(Response::Tell { text, error });
        self.ping.ping();
        // Waits for the acknowledgement so the message is actually seen
        // before PAM moves on and replaces it.
        let _ = self.requests.recv();
    }
}

impl pam_client2::ConversationHandler for UiConversation<'_> {
    fn prompt_echo_on(&mut self, prompt: &std::ffi::CStr) -> Result<std::ffi::CString, pam_client2::ErrorCode> {
        let text = prompt.to_string_lossy().to_string();
        // PAM asks for the username with echo on. The lock screen already
        // knows who is logged in, so it answers rather than asking.
        if text.to_lowercase().contains("login") || text.to_lowercase().contains("username") {
            return std::ffi::CString::new(self.username.clone())
                .map_err(|_| pam_client2::ErrorCode::CONV_ERR);
        }
        let answer = self
            .ask(Prompt::visible(text))
            .map_err(|_| pam_client2::ErrorCode::CONV_ERR)?;
        std::ffi::CString::new(answer).map_err(|_| pam_client2::ErrorCode::CONV_ERR)
    }

    fn prompt_echo_off(&mut self, prompt: &std::ffi::CStr) -> Result<std::ffi::CString, pam_client2::ErrorCode> {
        let answer = self
            .ask(Prompt::secret(prompt.to_string_lossy().to_string()))
            .map_err(|_| pam_client2::ErrorCode::CONV_ERR)?;
        std::ffi::CString::new(answer).map_err(|_| pam_client2::ErrorCode::CONV_ERR)
    }

    fn text_info(&mut self, message: &std::ffi::CStr) {
        self.tell(message.to_string_lossy().to_string(), false);
    }

    fn error_msg(&mut self, message: &std::ffi::CStr) {
        self.tell(message.to_string_lossy().to_string(), true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PAM refuses to authenticate against a service with no config
    /// file, so a missing one would mean nobody can unlock.
    #[test]
    fn the_service_name_falls_back_to_one_that_exists() {
        let service = service_name();
        assert!(
            std::path::Path::new("/etc/pam.d").join(service).exists() || service == "login",
            "{service} has no PAM configuration and isn't the last-resort fallback"
        );
    }

    /// The message a user sees most often should read as "you typed it
    /// wrong", not as "the program broke".
    #[test]
    fn a_wrong_password_is_described_plainly() {
        assert_eq!(
            describe(pam_client2::ErrorCode::AUTH_ERR, &"Authentication failure"),
            "Incorrect password"
        );
    }

    /// An expired password is a different problem with a different
    /// remedy, and saying "incorrect" would send someone typing the
    /// right password over and over.
    #[test]
    fn each_failure_a_user_can_act_on_says_something_different() {
        use pam_client2::ErrorCode;
        let messages: Vec<String> = [
            ErrorCode::AUTH_ERR,
            ErrorCode::MAXTRIES,
            ErrorCode::ACCT_EXPIRED,
            ErrorCode::NEW_AUTHTOK_REQD,
            ErrorCode::USER_UNKNOWN,
        ]
        .into_iter()
        .map(|code| describe(code, &"raw"))
        .collect();

        let unique: std::collections::HashSet<&String> = messages.iter().collect();
        assert_eq!(unique.len(), messages.len(), "{messages:?}");
        assert!(messages.iter().all(|m| !m.contains("raw")), "{messages:?}");
    }

    /// An unmapped code still has to say something, and including PAM's
    /// own text is the only clue available.
    #[test]
    fn an_unmapped_error_still_reports_something() {
        let message = describe(pam_client2::ErrorCode::ABORT, &"aborted");
        assert!(message.contains("aborted"), "{message}");
    }

    /// A dead thread is reported once, not forever.
    ///
    /// `poll` used to answer a disconnected channel with the same
    /// failure every time, and `Conversation::pump` loops while `poll`
    /// yields — so a dead PAM thread span the lock screen instead of
    /// drawing it. The comment always claimed "once"; nothing enforced
    /// it.
    #[test]
    fn a_dead_thread_is_reported_once_and_then_stays_quiet() {
        let (to_pam, requests) = std::sync::mpsc::channel::<Request>();
        let (responses, from_pam) = std::sync::mpsc::channel::<Response>();
        drop(requests);
        drop(responses);

        let mut backend = PamBackend {
            to_pam,
            from_pam,
            lost: None,
            reported_loss: false,
            waiting_since: None,
            abandoned: false,
        };
        backend.start("apost");
        assert!(matches!(backend.poll(), Some(Response::Failure { .. })), "said once");
        assert!(backend.poll().is_none(), "and then stops, or the host spins");
        assert!(backend.poll().is_none());
    }

    /// The account check runs *after* the password was accepted, so
    /// none of its failures may talk about the password. Saying
    /// "incorrect password" for a correct one is what sent a real user
    /// retyping a password that was right — and on a machine with
    /// pam_faillock, retrying costs attempts that are not free.
    #[test]
    fn an_account_failure_never_blames_the_password() {
        use pam_client2::ErrorCode;
        for code in [
            ErrorCode::PERM_DENIED,
            ErrorCode::AUTH_ERR,
            ErrorCode::ACCT_EXPIRED,
            ErrorCode::NEW_AUTHTOK_REQD,
            ErrorCode::ABORT,
        ] {
            let message = describe_account(code, &"raw", "hyprlock");
            let lowered = message.to_lowercase();
            assert!(
                !lowered.contains("incorrect password"),
                "{code:?} blamed the password: {message}"
            );
        }
    }

    /// A service with no `account` rules is the failure people will
    /// actually hit, so the message has to name the file to fix rather
    /// than describe a permissions problem.
    #[test]
    fn a_missing_account_stack_says_which_file_is_wrong() {
        let message = describe_account(pam_client2::ErrorCode::PERM_DENIED, &"raw", "hyprlock");
        assert!(message.contains("/etc/pam.d/hyprlock"), "{message}");
        assert!(message.contains("account"), "{message}");
    }

    /// The PAM file shipped with the crate has to declare both stacks:
    /// shipping one that only did `auth` would recreate the exact bug
    /// it exists to fix.
    #[test]
    fn the_shipped_pam_file_declares_both_stacks() {
        let shipped = include_str!("../pam/hyprforge-lock");
        let rule = |kind: &str| {
            shipped
                .lines()
                .filter(|line| !line.trim_start().starts_with('#'))
                .any(|line| line.split_whitespace().next() == Some(kind))
        };
        assert!(rule("auth"), "no auth stack:\n{shipped}");
        assert!(rule("account"), "no account stack:\n{shipped}");
    }

    /// A dead PAM thread must report failure rather than panicking or
    /// hanging — either would leave the session locked with no way in.
    #[test]
    fn a_dead_backend_reports_failure_rather_than_hanging() {
        let (to_pam, requests) = std::sync::mpsc::channel::<Request>();
        let (responses, from_pam) = std::sync::mpsc::channel::<Response>();
        drop(requests);
        drop(responses);

        let mut backend = PamBackend {
            to_pam,
            from_pam,
            lost: None,
            reported_loss: false,
            waiting_since: None,
            abandoned: false,
        };
        backend.start("apost");
        assert!(
            matches!(backend.poll(), Some(Response::Failure { .. })),
            "a backend that cannot be reached has to say so"
        );

        // And again for an answer, since that is the one a user is
        // waiting on when the thread dies mid-attempt.
        backend.answer("x");
        assert!(matches!(backend.poll(), Some(Response::Failure { .. })));
    }
}

#[cfg(test)]
mod waiting {
    use super::*;

    /// A backend whose PAM thread is alive but stuck inside
    /// `authenticate` — no answer, no disconnect. This is the case a
    /// dead-thread check cannot see.
    fn stuck() -> PamBackend {
        let (to_pam, requests) = std::sync::mpsc::channel::<Request>();
        let (responses, from_pam) = std::sync::mpsc::channel::<Response>();
        // Both far ends leaked, so neither channel ever reads as
        // disconnected. That is the whole point: a thread wedged inside
        // `authenticate` is alive, and the dead-thread check cannot see
        // it.
        std::mem::forget(requests);
        std::mem::forget(responses);
        PamBackend {
            to_pam,
            from_pam,
            lost: None,
            reported_loss: false,
            waiting_since: None,
            abandoned: false,
        }
    }

    #[test]
    fn a_pam_module_that_never_answers_is_eventually_reported() {
        let mut backend = stuck();
        backend.answer("anything");
        assert!(backend.poll().is_none(), "not yet — it may simply be slow");

        // Reach back past the bound rather than sleeping for it.
        backend.waiting_since = Some(std::time::Instant::now() - PAM_TIMEOUT);

        match backend.poll() {
            Some(Response::Failure { reason }) => {
                assert!(!reason.is_empty());
                assert!(
                    !reason.to_lowercase().contains("password"),
                    "a service that didn't answer must never be blamed on the password: {reason}"
                );
            }
            other => panic!("expected a failure once the bound passed, got {other:?}"),
        }
    }

    /// Once given up on, the transaction is over. A late `Success` is an
    /// answer to a question the user has already been told failed, and
    /// acting on it would unlock the session.
    #[test]
    fn a_late_answer_after_giving_up_is_never_read() {
        let (to_pam, requests) = std::sync::mpsc::channel::<Request>();
        let (responses, from_pam) = std::sync::mpsc::channel::<Response>();
        std::mem::forget(requests);
        let mut backend = PamBackend {
            to_pam,
            from_pam,
            lost: None,
            reported_loss: false,
            waiting_since: Some(std::time::Instant::now() - PAM_TIMEOUT),
            abandoned: false,
        };

        assert!(matches!(backend.poll(), Some(Response::Failure { .. })));

        // PAM finally finishes, and says yes.
        responses.send(Response::Success).unwrap();

        assert!(
            backend.poll().is_none(),
            "a success for an abandoned transaction must never reach the screen"
        );
    }

    /// The bound must not fire on a conversation that is progressing —
    /// a prompt is evidence the far side is alive.
    #[test]
    fn an_answered_prompt_restarts_the_clock() {
        let (to_pam, requests) = std::sync::mpsc::channel::<Request>();
        let (responses, from_pam) = std::sync::mpsc::channel::<Response>();
        std::mem::forget(requests);
        let mut backend = PamBackend {
            to_pam,
            from_pam,
            lost: None,
            reported_loss: false,
            waiting_since: Some(std::time::Instant::now() - PAM_TIMEOUT / 2),
            abandoned: false,
        };

        responses
            .send(Response::Ask(hyprforge_authui::conversation::Prompt::secret("Password:")))
            .unwrap();
        assert!(matches!(backend.poll(), Some(Response::Ask(_))));
        assert!(backend.waiting_since.is_none(), "nothing is outstanding after an answer");
        assert!(!backend.abandoned);
    }
}

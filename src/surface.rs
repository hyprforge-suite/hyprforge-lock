//! Holding the session locked, and drawing on the surfaces the
//! compositor hands back.
//!
//! `ext-session-lock-v1` is unusual among Wayland protocols in that the
//! compositor trusts the client with the session's security, and is
//! built so that trust survives the client failing:
//!
//! - Once `locked` arrives, the session **stays** locked. If this process
//!   crashes, the compositor keeps everything hidden rather than falling
//!   open. That is the property that makes writing your own lock screen
//!   reasonable instead of reckless.
//! - The compositor sends a surface **per output**, and expects every one
//!   of them to be drawn on. An output left blank is a monitor showing
//!   whatever was there before.
//! - `finished` means the compositor has refused or revoked the lock. The
//!   only correct response is to exit immediately without unlocking —
//!   something else is already handling the session.
//!
//! Because a crash keeps the session locked, the failure to avoid is not
//! "crashing" but **hanging**: a surface that stops repainting looks
//! exactly like one that died, except the compositor still thinks
//! everything is fine. Every path here is written to keep drawing.

use smithay_client_toolkit::compositor::{CompositorHandler, CompositorState};
use smithay_client_toolkit::output::{OutputHandler, OutputState};
use smithay_client_toolkit::registry::{ProvidesRegistryState, RegistryState};
use smithay_client_toolkit::seat::keyboard::{KeyEvent, KeyboardHandler, Keysym, Modifiers};
use smithay_client_toolkit::seat::{Capability, SeatHandler, SeatState};
use smithay_client_toolkit::session_lock::{
    SessionLock, SessionLockHandler, SessionLockState, SessionLockSurface,
    SessionLockSurfaceConfigure,
};
use smithay_client_toolkit::shm::slot::SlotPool;
use smithay_client_toolkit::shm::{Shm, ShmHandler};
use smithay_client_toolkit::{
    delegate_compositor, delegate_keyboard, delegate_output, delegate_registry, delegate_seat,
    delegate_session_lock, delegate_shm, registry_handlers,
};
use calloop_wayland_source::WaylandSource;
use wayland_client::globals::registry_queue_init;
use wayland_client::protocol::{wl_keyboard, wl_output, wl_seat, wl_shm, wl_surface};
use wayland_client::{Connection, QueueHandle};

use hyprforge_authui::conversation::{Backend, Conversation, Press, State};
use hyprforge_authui::Theme;
use iced_runtime::core::{mouse, renderer, Rectangle, Size};
use iced_runtime::user_interface::{Cache, UserInterface};
use iced_tiny_skia::graphics::Viewport;

/// The screen sends no messages: input reaches the conversation through
/// `key` rather than through iced, because the compositor hands
/// keystrokes to this process directly.
#[derive(Debug, Clone)]
enum Nothing {}

/// The shared colour type as iced wants it.
fn iced_color(c: hyprforge_look::Color) -> iced_runtime::core::Color {
    iced_runtime::core::Color::from_rgba8(c.r, c.g, c.b, c.a as f32 / 255.0)
}

/// How often the surface repaints while the authenticator is busy.
///
/// Only while busy — an idle lock screen still draws nothing at all.
const PULSE: std::time::Duration = std::time::Duration::from_millis(100);

/// How often the surface repaints otherwise — enough to keep the clock
/// from being visibly wrong.
const CLOCK_TICK: std::time::Duration = std::time::Duration::from_secs(1);

/// How long to wait for the compositor to answer the lock request before
/// saying out loud that it hasn't.
///
/// Deliberately a warning and not a timeout. If this process gave up and
/// exited, the lock request would still be outstanding, and a compositor
/// that answered a moment later would lock the session with no client
/// left to draw on it or unlock it — trading a rare hang for a
/// guaranteed lockout. So it complains and keeps waiting, which at least
/// makes a silent hang diagnosable instead of invisible.
const GRANT_WARNING: std::time::Duration = std::time::Duration::from_secs(5);

/// Why the lock screen stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Authenticated and unlocked.
    Unlocked,
    /// The compositor never granted the lock, so the session was never
    /// locked at all. Kept separate from `Revoked` because the caller's
    /// situation is completely different: whatever asked for a lock
    /// hasn't got one, and reporting success would leave an unlocked
    /// machine looking like a locked one.
    Refused,
    /// The compositor took the lock away after granting it. Something
    /// else owns the session now; exiting without unlocking is the only
    /// safe move, and the session is still secured.
    Revoked,
    /// The connection died. The compositor keeps the session locked.
    Disconnected,
}

/// One output's surface and the size the compositor asked for.
struct Locked {
    surface: SessionLockSurface,
    width: u32,
    height: u32,
    /// Kept so a monitor plugged in while locked can be matched against
    /// the surfaces that already exist.
    output: wl_output::WlOutput,
}

pub struct LockScreen<B: Backend + 'static> {
    registry: RegistryState,
    outputs: OutputState,
    seats: SeatState,
    shm: Shm,
    compositor: CompositorState,
    pool: SlotPool,

    lock: Option<SessionLock>,
    surfaces: Vec<Locked>,
    keyboard: Option<wl_keyboard::WlKeyboard>,

    /// `None` until the compositor has actually granted the lock.
    ///
    /// Building it starts PAM talking, and that must not happen while
    /// the session is still open: a PAM module that takes its time — or
    /// hangs — would otherwise hold the screen unlocked for exactly as
    /// long as it took. Lock first, ask questions second.
    conversation: Option<Conversation<B>>,
    theme: Theme,
    outcome: Option<Outcome>,
    /// Set whenever something changed that the user should see. Drawing
    /// is driven by this rather than by a timer, so an idle lock screen
    /// costs nothing.
    dirty: bool,
    /// Frames actually committed. Zero after a configure means the
    /// session is locked with nothing on screen — the failure worth
    /// noticing loudly.
    frames: u64,
    /// Whether the compositor ever granted the lock. Recorded rather
    /// than inferred from the surfaces: a grant with no outputs attached
    /// has none either, and mistaking that for "never locked" would
    /// report the session as open when it is held.
    granted: bool,
    /// Whether Caps Lock is on, so the screen can say so.
    caps_lock: bool,
    /// When the lock was requested, so a compositor that never answers
    /// can be reported rather than waited on in silence.
    requested_at: std::time::Instant,
    warned_about_grant: bool,
    /// Kept across frames so glyph rasterisation and layout are not
    /// redone from scratch every repaint.
    renderer: iced_tiny_skia::Renderer,
    cache: Cache,
    /// Shown on the screen, so it has to be here rather than only in the
    /// conversation — which does not exist until the lock is granted.
    username: String,
    /// Text to type in by itself once something has been drawn, for
    /// testing against a nested compositor. `None` in every real run;
    /// `main` refuses to set it without an explicit `--display`.
    self_test: Option<String>,
    /// Whether this run is a self test, kept after `self_test` is
    /// consumed so the frame count can be reported at the end.
    self_testing: bool,
}

impl<B: Backend + 'static> LockScreen<B> {
    /// Locks the session and runs until it unlocks.
    ///
    /// Takes the connection rather than opening one so a caller can point
    /// it at a nested compositor — which is the only safe way to test a
    /// lock screen, since a mistake against the real session is a machine
    /// you have to power-cycle.
    ///
    /// Takes the backend rather than a built `Conversation` so that
    /// nothing asks the user anything until the session is actually
    /// locked — see the `conversation` field.
    ///
    /// `wake` fires when the backend may have an answer ready; `None`
    /// suits a backend that always answers immediately.
    pub fn run(
        connection: Connection,
        backend: B,
        username: impl Into<String>,
        theme: Theme,
        wake: Option<calloop::ping::PingSource>,
        self_test: Option<String>,
    ) -> Result<Outcome, LockError> {
        let username = username.into();
        let theme_font_size = theme.font_size;
        let screen_font = hyprforge_authui::screen::font(&theme);
        let mut pending = Some(backend);
        let (globals, mut queue) = registry_queue_init(&connection)?;
        let qh = queue.handle();

        let shm = Shm::bind(&globals, &qh)?;
        // One page is plenty to start: the pool grows when a real size
        // arrives, and guessing the output size here would be wrong on
        // the first configure anyway.
        let pool = SlotPool::new(4096, &shm).map_err(|e| LockError::Buffer(e.to_string()))?;
        let lock_state = SessionLockState::new(&globals, &qh);

        let mut screen = LockScreen {
            registry: RegistryState::new(&globals),
            outputs: OutputState::new(&globals, &qh),
            seats: SeatState::new(&globals, &qh),
            compositor: CompositorState::bind(&globals, &qh)?,
            shm,
            pool,
            lock: None,
            surfaces: Vec::new(),
            keyboard: None,
            conversation: None,
            theme,
            outcome: None,
            dirty: true,
            frames: 0,
            granted: false,
            caps_lock: false,
            requested_at: std::time::Instant::now(),
            warned_about_grant: false,
            renderer: iced_tiny_skia::Renderer::new(
                screen_font,
                iced_runtime::core::Pixels(theme_font_size),
            ),
            cache: Cache::default(),
            username: username.clone(),
            self_testing: self_test.is_some(),
            self_test,
        };

        // The outputs have to be known *before* locking. `locked` can
        // arrive in the same batch as the lock request, and creating
        // surfaces from an output list that hasn't been filled in yet
        // produces a locked session with nothing drawn on it — which
        // looks exactly like the lock screen having crashed, except
        // nothing has crashed and nothing will recover.
        queue.roundtrip(&mut screen).map_err(|_| LockError::Disconnected)?;
        screen.lock = Some(lock_state.lock(&qh)?);

        // Immediately, not on `locked`. The protocol says the compositor
        // "must not send locked until a new locked frame has been
        // presented on all outputs" — so it is waiting for these. Waiting
        // for `locked` before creating them is a standoff, and the only
        // thing that breaks it is the compositor giving up after five
        // seconds and showing its "lockscreen app died" screen instead.
        screen.cover_every_output(&qh);

        // From here on the loop waits on calloop rather than on the
        // Wayland queue alone. That is what lets the authenticator
        // answer on its own schedule: the backend's ping is just another
        // source, so a reply wakes the loop exactly like a keystroke
        // does, and nothing has to sit blocked waiting for PAM.
        let mut event_loop: calloop::EventLoop<LockScreen<B>> =
            calloop::EventLoop::try_new().map_err(|e| LockError::EventLoop(e.to_string()))?;
        let handle = event_loop.handle();
        WaylandSource::new(connection.clone(), queue)
            .insert(handle.clone())
            .map_err(|e| LockError::EventLoop(e.to_string()))?;

        if let Some(wake) = wake {
            handle
                .insert_source(wake, |_, _, screen: &mut LockScreen<B>| {
                    if let Some(conversation) = screen.conversation.as_mut() {
                        if conversation.pump() {
                            screen.dirty = true;
                        }
                    }
                })
                .map_err(|e| LockError::EventLoop(e.to_string()))?;
        }

        // A heartbeat while the authenticator is busy, so the surface
        // visibly keeps moving. Without it the screen would be correct
        // and responsive but look frozen, which on a lock screen is the
        // thing a user cannot tell apart from a crash.
        let pulse = calloop::timer::Timer::from_duration(PULSE);
        handle
            .insert_source(pulse, |_, _, screen: &mut LockScreen<B>| {
                // A lock that was requested and never granted means the
                // session is still open while something upstream
                // believes it is locked. Nothing here can fix that, but
                // it must not be invisible.
                if !screen.granted
                    && !screen.warned_about_grant
                    && screen.requested_at.elapsed() >= GRANT_WARNING
                {
                    screen.warned_about_grant = true;
                    eprintln!(
                        "the compositor still hasn't granted the lock after {}s — \
                         the session is NOT locked yet",
                        GRANT_WARNING.as_secs()
                    );
                }
                // Pump here too, not only on the backend's ping. The ping
                // is the fast path and it is the *only* other caller — so
                // a backend that stops pinging is a backend nobody ever
                // asks again. `PamBackend::poll` reports a dead PAM
                // thread exactly once, and that report was unreachable
                // from the lock screen: the machinery built to say "the
                // authentication service stopped responding" could never
                // run. The greeter has pumped from its own tick all
                // along, for this reason.
                if let Some(conversation) = screen.conversation.as_mut() {
                    conversation.pump();
                }
                screen.dirty = true;
                // Fast while the authenticator is busy so the screen is
                // visibly alive through pam_unix's deliberate pause;
                // otherwise slow, which is what the clock needs. An idle
                // lock screen no longer costs *nothing* — it costs one
                // repaint a second — but a clock that does not tick is
                // worse than the saving.
                calloop::timer::TimeoutAction::ToDuration(
                    if matches!(screen.state(), State::Working) { PULSE } else { CLOCK_TICK },
                )
            })
            .map_err(|e| LockError::EventLoop(e.to_string()))?;

        while screen.outcome.is_none() {
            event_loop
                .dispatch(None, &mut screen)
                .map_err(|_| LockError::Disconnected)?;
            // The session is now genuinely locked, so it is safe to let
            // the authenticator start talking.
            if screen.granted && screen.conversation.is_none() {
                if let Some(backend) = pending.take() {
                    screen.conversation = Some(Conversation::new(backend, username.clone()));
                    screen.mark_dirty();
                }
            }
            // Before drawing, not after: typing marks the screen dirty,
            // and doing it afterwards would leave the result unpainted
            // until some unrelated event happened to wake the loop.
            //
            // Waits for two things. Something must have been drawn — the
            // point is to prove the whole path, and typing into a lock
            // screen that never painted would prove half of it. And the
            // conversation must actually be asking: a backend that takes
            // a moment to produce its first prompt would otherwise be
            // typed at while still working, and the conversation would
            // correctly ignore every keystroke.
            if screen.frames > 0 && screen.state().accepts_input() {
                if let Some(text) = screen.self_test.take() {
                    eprintln!("self test: typing {} character(s)", text.chars().count());
                    for character in text.chars() {
                        screen.key(Keysym::NoSymbol, Some(character.to_string()));
                    }
                    screen.key(Keysym::Return, None);
                    eprintln!("self test: submitted, state is {:?}", screen.state());
                }
            }
            if screen.dirty {
                let before = screen.frames;
                screen.draw_all();
                // Only the first frame is worth a line. It is the one
                // that proves there is something on screen; the rest
                // are just a person typing.
                if before == 0 && screen.frames > 0 {
                    eprintln!("first frame drawn (+{}ms)", screen.requested_at.elapsed().as_millis());
                }
            }
            // Checked after dispatching rather than inside a handler:
            // unlocking has to be the last thing that happens, and doing
            // it from inside an event callback risks drawing afterwards
            // on a surface that no longer exists.
            //
            // Only when nothing else has already decided how this ends.
            // `finished` and the last keystroke can arrive in the same
            // batch, and without this guard a revoked lock would be
            // overwritten with `Unlocked` — reporting a successful
            // unlock for a session this process never held and never
            // released.
            if let Some(end) = conclude(
                screen.outcome,
                screen.state().is_authenticated(),
                screen.lock.is_some(),
            ) {
                if let Some(lock) = screen.lock.take() {
                    // Before `unlock`, because after it the session is
                    // open and this process is on its way out. Ordering
                    // it this way means the window in which the hint
                    // disagrees with reality contains a locked screen,
                    // never an unlocked one.
                    crate::logind::clear_locked_hint();
                    lock.unlock();
                    // The unlock request has to reach the compositor
                    // before this process exits, or the session stays
                    // locked with nothing left to unlock it.
                    connection.roundtrip().ok();
                }
                screen.outcome = Some(end);
            }
        }
        if screen.self_testing {
            // The number that matters when a backend is slow: a screen
            // that drew once and then sat there is the failure this
            // whole arrangement exists to prevent.
            eprintln!("self test: {} frame(s) drawn in total", screen.frames);
        }
        Ok(screen.outcome.unwrap_or(Outcome::Disconnected))
    }

    /// A lock surface on every output the compositor has told us about.
    ///
    /// One per output, because an output without one keeps showing
    /// whatever was on it — which on a second monitor is the desktop of
    /// a machine that is supposed to be locked.
    fn cover_every_output(&mut self, qh: &QueueHandle<Self>) {
        let Some(lock) = self.lock.clone() else {
            return;
        };
        for output in self.outputs.outputs() {
            if self.surfaces.iter().any(|l| l.output == output) {
                continue;
            }
            let surface = self.compositor.create_surface(qh);
            let locked = lock.create_lock_surface(surface, &output, qh);
            self.surfaces.push(Locked { surface: locked, width: 0, height: 0, output });
        }
        if self.surfaces.is_empty() {
            // No outputs means nothing can be drawn on, so the
            // compositor will never see a locked frame and will never
            // send `locked`. Say so rather than sit in a standoff.
            eprintln!("no outputs to cover — the compositor cannot lock the session");
        }
        self.mark_dirty();
    }

    fn draw_all(&mut self) {
        self.dirty = false;
        for index in 0..self.surfaces.len() {
            self.draw(index);
        }
    }

    /// Paints one surface.
    ///
    /// Deliberately software-rendered and deliberately simple. This is
    /// the surface that stands between a locked machine and its user; it
    /// has no business depending on a GPU being in a good mood.
    fn draw(&mut self, index: usize) {
        // Destructured rather than reached through `self`, because the
        // shm buffer borrows the pool for as long as it is being painted
        // and the renderer has to be usable at the same time. These are
        // disjoint fields; only the compiler needs telling.
        let LockScreen {
            pool,
            renderer,
            cache,
            theme,
            username,
            conversation,
            surfaces,
            frames,
            caps_lock,
            ..
        } = self;

        let Some(locked) = surfaces.get(index) else {
            return;
        };
        // Nothing is drawn before the compositor says how big the surface
        // is. Drawing into a guessed size is what produced the first
        // panic here, when a 1px-wide canvas met a panel with a minimum
        // width.
        let (width, height) = (locked.width, locked.height);
        if width == 0 || height == 0 {
            return;
        }

        let Ok((buffer, canvas)) =
            pool.create_buffer(width as i32, height as i32, width as i32 * 4, wl_shm::Format::Argb8888)
        else {
            // Out of memory for a buffer. Leaving the previous frame up
            // is right: the surface stays as it was rather than going
            // blank, and the next event tries again.
            return;
        };

        // `Argb8888` is `[31:0] A:R:G:B` little endian, so the bytes in
        // memory are B, G, R, A — which is exactly what iced_tiny_skia
        // writes, because its `into_color` swaps red and blue on
        // purpose. The buffer needs no channel shuffle at all, and
        // adding one "to fix" it would break every colour. There is a
        // test.
        let Some(mut pixels) = tiny_skia::PixmapMut::from_bytes(canvas, width, height) else {
            return;
        };
        let Some(mut mask) = tiny_skia::Mask::new(width, height) else {
            return;
        };

        let state = conversation
            .as_ref()
            .map_or(&State::Working, |c| c.state());
        let size = Size::new(width as f32, height as f32);

        let mut ui = UserInterface::<Nothing, iced_widget::Theme, iced_tiny_skia::Renderer>::build(
            hyprforge_authui::screen::view(
                state,
                username,
                theme,
                chrono::Local::now(),
                *caps_lock,
            ),
            size,
            std::mem::take(cache),
            renderer,
        );
        ui.draw(
            renderer,
            &iced_widget::Theme::Dark,
            &renderer::Style { text_color: iced_color(theme.foreground) },
            mouse::Cursor::Unavailable,
        );
        *cache = ui.into_cache();

        renderer.draw(
            &mut pixels,
            &mut mask,
            &Viewport::with_physical_size(Size::new(width, height), 1.0),
            &[Rectangle::with_size(size)],
            iced_color(theme.background),
        );

        let surface = locked.surface.wl_surface();
        surface.damage_buffer(0, 0, width as i32, height as i32);
        if buffer.attach_to(surface).is_ok() {
            surface.commit();
            *frames += 1;
        }
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// The conversation's state, or `Working` before there is one.
    ///
    /// `Working` rather than anything else because it is true: the lock
    /// is being set up, nothing is being asked yet, and it is the one
    /// state that accepts no input and claims no success. In particular
    /// it can never read as authenticated, so the window before the lock
    /// is granted cannot unlock anything.
    fn state(&self) -> &State {
        const STARTING: &State = &State::Working;
        self.conversation.as_ref().map_or(STARTING, |c| c.state())
    }
}

/// How the loop should end this iteration, if it should end at all.
///
/// Pulled out of the loop because it is the one decision in this program
/// that can be wrong in a dangerous direction: reporting a successful
/// unlock for a session that was never unlocked. In the loop it needed a
/// live compositor to exercise; here it can just be checked.
///
/// `decided` is whatever a handler already concluded — `finished` in
/// particular — and it always wins. A revoked lock and the last
/// keystroke can arrive in the same batch, and the revocation is the
/// truth about the session.
fn conclude(decided: Option<Outcome>, authenticated: bool, holds_lock: bool) -> Option<Outcome> {
    if decided.is_some() || !authenticated {
        return None;
    }
    // Authenticated while holding nothing means there is nothing to
    // unlock and nothing was unlocked. Whatever asked for a lock hasn't
    // got one, which is exactly what `Refused` reports.
    Some(if holds_lock { Outcome::Unlocked } else { Outcome::Refused })
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("couldn't talk to the compositor: {0}")]
    Connect(#[from] wayland_client::globals::GlobalError),
    /// Nearly always: this compositor doesn't implement
    /// `ext-session-lock-v1`, so there is no way to lock at all.
    #[error("this compositor can't lock the session (needs ext-session-lock-v1): {0}")]
    CannotLock(#[from] smithay_client_toolkit::error::GlobalError),
    /// Most often: this compositor doesn't implement
    /// `ext-session-lock-v1`, so there is nothing to lock with.
    #[error("this compositor is missing something the lock screen needs: {0}")]
    Missing(#[from] smithay_client_toolkit::reexports::client::globals::BindError),
    #[error("couldn't set up a drawing buffer: {0}")]
    Buffer(String),
    #[error("couldn't set up the event loop: {0}")]
    EventLoop(String),
    #[error("the connection to the compositor was lost")]
    Disconnected,
}

impl<B: Backend + 'static> SessionLockHandler for LockScreen<B> {
    fn locked(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _lock: SessionLock) {
        // The surfaces already exist — see `cover_every_output`, called
        // as soon as the lock was requested. By the time this arrives the
        // compositor has presented a locked frame on every output, which
        // is precisely what it was waiting for.
        //
        // So there is nothing to create here. What changes is that the
        // session is now genuinely locked, and stays locked whatever
        // happens to this process.
        self.granted = true;
        // Only now, not when the lock was requested. Between the two the
        // compositor may still refuse, and a hint saying "locked" for a
        // session that never locked is worse than no hint: it is the one
        // reading that would make a caller stop checking.
        crate::logind::set_locked_hint(true);
        eprintln!(
            "locked: session secured with {} surface(s) (+{}ms)",
            self.surfaces.len(),
            self.requested_at.elapsed().as_millis()
        );
        self.mark_dirty();
    }

    fn finished(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _lock: SessionLock) {
        // The compositor refused or revoked the lock. Never unlock here:
        // something else owns the session now, and unlocking would be
        // taking a decision that isn't ours.
        //
        // Which of the two it was matters, and only this handler can
        // tell them apart: arriving before `locked` means the request
        // was refused outright — almost always because another lock
        // client already holds the session. Saying so is the difference
        // between a one-line diagnosis and an afternoon of guessing.
        self.outcome = Some(if !self.granted {
            eprintln!(
                "the compositor refused the lock — another lock client probably \
                 already holds this session"
            );
            Outcome::Refused
        } else {
            eprintln!("the compositor revoked the lock");
            Outcome::Revoked
        });
        self.lock = None;
    }

    fn configure(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        surface: SessionLockSurface,
        configure: SessionLockSurfaceConfigure,
        _serial: u32,
    ) {
        let (width, height) = configure.new_size;
        if let Some(locked) = self
            .surfaces
            .iter_mut()
            .find(|l| l.surface.wl_surface() == surface.wl_surface())
        {
            locked.width = width;
            locked.height = height;
            eprintln!("configure: {width}x{height} (+{}ms)", self.requested_at.elapsed().as_millis());
        }
        self.mark_dirty();
    }
}

impl<B: Backend + 'static> KeyboardHandler for LockScreen<B> {
    fn enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: &wl_surface::WlSurface,
        _: u32,
        _: &[u32],
        _: &[Keysym],
    ) {
        eprintln!("keyboard focus entered a lock surface");
    }

    fn leave(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: &wl_surface::WlSurface,
        _: u32,
    ) {
    }

    fn press_key(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        event: KeyEvent,
    ) {
        self.key(event.keysym, event.utf8);
    }

    fn release_key(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        _: KeyEvent,
    ) {
    }

    fn update_modifiers(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        modifiers: Modifiers,
        _: smithay_client_toolkit::seat::keyboard::RawModifiers,
        _: u32,
    ) {
        // Caps Lock is the one modifier this screen has to show. Without
        // it a stuck key looks exactly like a forgotten password, and
        // where pam_faillock is configured that costs attempts against
        // the account rather than just the screen.
        if self.caps_lock != modifiers.caps_lock {
            self.caps_lock = modifiers.caps_lock;
            self.mark_dirty();
        }
    }

    /// Held keys repeat, so a held backspace clears a password the way
    /// it does in every other text field.
    fn repeat_key(
        &mut self,
        conn: &Connection,
        qh: &QueueHandle<Self>,
        keyboard: &wl_keyboard::WlKeyboard,
        serial: u32,
        event: KeyEvent,
    ) {
        self.press_key(conn, qh, keyboard, serial, event);
    }
}

impl<B: Backend + 'static> LockScreen<B> {
    /// One key, as the conversation sees it.
    ///
    /// Split out from the Wayland handler so a key can be delivered
    /// without a compositor sending it. That is what makes the unlock
    /// path testable at all: everything from the keystroke to the
    /// compositor releasing the session runs here, and only the
    /// `wl_keyboard` delivery is left out.
    fn key(&mut self, keysym: Keysym, utf8: Option<String>) {
        // Nothing is being asked until the lock is granted, so a key
        // pressed in that window has nowhere to go.
        let Some(conversation) = self.conversation.as_mut() else {
            return;
        };
        dispatch_key(conversation, keysym, utf8);
        self.mark_dirty();
    }
}

/// The keystroke rules, over a `Conversation` alone.
///
/// Split out from [`LockScreen::key`] so they can be tested without a
/// Wayland connection. Every decision about what a key means lives here;
/// the method above only supplies the conversation and repaints.
fn dispatch_key<B: hyprforge_authui::conversation::Backend>(
    conversation: &mut Conversation<B>,
    keysym: Keysym,
    utf8: Option<String>,
) {
    // Nothing about a keystroke is logged here, ever. A keysym name *is*
    // the character — `XK_a` for `a`, `XK_comma` for `,` — so logging
    // "just the keysym" to debug input writes the password to disk in a
    // barely-encoded form. This comment exists because that mistake was
    // made here once already.
    //
    // What a key *means* is `conversation::apply_press`, shared with the
    // greeter — including that Escape and Backspace must dismiss a
    // failed attempt, which was fixed here and not there for as long as
    // there were two copies of it. This function is the translation
    // from xkb and nothing else.
    let press = match keysym {
        Keysym::Return | Keysym::KP_Enter => Press::Enter,
        Keysym::Escape => Press::Escape,
        Keysym::BackSpace => Press::Backspace,
        _ => match utf8 {
            Some(text) => Press::Text(text),
            // A modifier or a function key: nothing this prompt has a
            // meaning for.
            None => return,
        },
    };
    hyprforge_authui::conversation::apply_press(conversation, press);
}

impl<B: Backend + 'static> SeatHandler for LockScreen<B> {
    fn seat_state(&mut self) -> &mut SeatState {
        &mut self.seats
    }

    fn new_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat) {}

    fn new_capability(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        seat: wl_seat::WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard && self.keyboard.is_none() {
            self.keyboard = self.seats.get_keyboard(qh, &seat, None).ok();
            eprintln!("keyboard bound: {}", self.keyboard.is_some());
        }
    }

    fn remove_capability(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: wl_seat::WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard {
            if let Some(keyboard) = self.keyboard.take() {
                keyboard.release();
            }
        }
    }

    fn remove_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat) {}
}

impl<B: Backend + 'static> CompositorHandler for LockScreen<B> {
    fn scale_factor_changed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: i32,
    ) {
    }

    fn transform_changed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: wl_output::Transform,
    ) {
    }

    fn frame(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_surface::WlSurface, _: u32) {
        self.mark_dirty();
    }

    fn surface_enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: &wl_output::WlOutput,
    ) {
    }

    fn surface_leave(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: &wl_output::WlOutput,
    ) {
    }
}

impl<B: Backend + 'static> OutputHandler for LockScreen<B> {
    fn output_state(&mut self) -> &mut OutputState {
        &mut self.outputs
    }

    /// A monitor plugged in while the session is locked needs a surface
    /// of its own, or it shows whatever was on it before the lock — on a
    /// laptop being docked, that is the desktop of a locked machine.
    fn new_output(&mut self, _: &Connection, qh: &QueueHandle<Self>, output: wl_output::WlOutput) {
        let Some(lock) = &self.lock else {
            return;
        };
        if self.surfaces.iter().any(|l| l.output == output) {
            return;
        }
        let surface = self.compositor.create_surface(qh);
        let locked = lock.create_lock_surface(surface, &output, qh);
        self.surfaces.push(Locked { surface: locked, width: 0, height: 0, output });
        self.mark_dirty();
    }

    fn update_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}

    fn output_destroyed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        output: wl_output::WlOutput,
    ) {
        self.surfaces.retain(|l| l.output != output);
    }
}

impl<B: Backend + 'static> ShmHandler for LockScreen<B> {
    fn shm_state(&mut self) -> &mut Shm {
        &mut self.shm
    }
}

impl<B: Backend + 'static> ProvidesRegistryState for LockScreen<B> {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry
    }

    registry_handlers![OutputState, SeatState];
}

delegate_compositor!(@<B: Backend + 'static> LockScreen<B>);
delegate_output!(@<B: Backend + 'static> LockScreen<B>);
delegate_seat!(@<B: Backend + 'static> LockScreen<B>);
delegate_keyboard!(@<B: Backend + 'static> LockScreen<B>);
delegate_shm!(@<B: Backend + 'static> LockScreen<B>);
delegate_session_lock!(@<B: Backend + 'static> LockScreen<B>);
delegate_registry!(@<B: Backend + 'static> LockScreen<B>);

#[cfg(test)]
mod tests {
    use super::*;
    use hyprforge_authui::conversation::Response;

    /// Asks for a password once, then rejects whatever it is given.
    ///
    /// Enough to reach `State::Failed`, which is the only state these
    /// tests are about.
    struct AlwaysRejects {
        queued: Vec<Response>,
    }

    impl hyprforge_authui::conversation::Backend for AlwaysRejects {
        fn start(&mut self, _username: &str) {
            self.queued.push(Response::Ask(hyprforge_authui::conversation::Prompt::secret(
                "Password:",
            )));
        }
        fn answer(&mut self, _answer: &str) {
            self.queued.push(Response::Failure { reason: "wrong".to_string() });
        }
        fn proceed(&mut self) {}
        fn poll(&mut self) -> Option<Response> {
            if self.queued.is_empty() {
                None
            } else {
                Some(self.queued.remove(0))
            }
        }
    }

    fn failed_conversation() -> Conversation<AlwaysRejects> {
        // `new` already calls `start`, so the fixture only has to type a
        // wrong answer and send it.
        let mut conversation =
            Conversation::new(AlwaysRejects { queued: Vec::new() }, "someone");
        dispatch_key(&mut conversation, Keysym::NoSymbol, Some("x".to_string()));
        dispatch_key(&mut conversation, Keysym::Return, None);
        assert!(
            matches!(conversation.state(), State::Failed { .. }),
            "the fixture must actually reach a failure"
        );
        conversation
    }

    /// After a wrong password, Escape and Backspace are the two keys a
    /// person actually reaches for — and `clear` and `type_into` are both
    /// no-ops in `Failed`, so they did nothing at all. The error stayed on
    /// screen and the lock read as frozen, on the one screen where that is
    /// frightening. Every *other* key already dismissed it, which made the
    /// two that didn't harder to explain rather than easier.
    #[test]
    fn a_failed_password_is_dismissed_by_the_keys_people_actually_press() {
        for key in [Keysym::Escape, Keysym::BackSpace] {
            let mut conversation = failed_conversation();
            dispatch_key(&mut conversation, key, None);
            assert!(
                !matches!(conversation.state(), State::Failed { .. }),
                "{key:?} left the failure on screen"
            );
        }
    }

    /// Dismissing must not also submit. After `retry` the conversation is
    /// asking again with an empty field, and an Enter that carried on into
    /// `submit` would send an empty answer to PAM — spending a `faillock`
    /// slot for a password nobody typed.
    #[test]
    fn dismissing_a_failure_never_sends_an_answer_of_its_own() {
        let mut conversation = failed_conversation();
        dispatch_key(&mut conversation, Keysym::Escape, None);
        assert_eq!(conversation.entered(), "", "the fresh prompt must start empty");
        assert_eq!(conversation.failures(), 1, "dismissing must not count as an attempt");
    }

    /// The behaviour that was already right, pinned so the fix above
    /// doesn't cost it: a character key dismisses the error *and* is kept,
    /// so the user can just start typing their password again.
    #[test]
    fn typing_after_a_failure_keeps_the_first_character() {
        let mut conversation = failed_conversation();
        dispatch_key(&mut conversation, Keysym::NoSymbol, Some("h".to_string()));
        assert_eq!(conversation.entered(), "h");
    }

    /// A theme file whose colours don't parse falls back to the default
    /// theme *as a whole*, rather than rendering some fields black.
    ///
    /// That moved when the colour type became typed: parsing now happens
    /// once, when the file loads, instead of on every draw. A single
    /// typo therefore discards the file — which is the better failure
    /// for a lock screen, since the alternative was invisible black text
    /// on a dark panel.
    #[test]
    fn a_theme_with_an_unparseable_colour_falls_back_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock.toml");
        std::fs::write(&path, "accent = \"not a colour\"\n").unwrap();
        assert!(Theme::load(&path).is_err(), "a bad colour must not be silently ignored");
        assert_eq!(
            Theme::load(&path).unwrap_or_default().accent,
            Theme::default().accent
        );
    }




    /// The lock copies iced_tiny_skia's output straight into a Wayland
    /// `Argb8888` buffer with no channel shuffle, and that is only
    /// correct because iced_tiny_skia writes B, G, R, A — its
    /// `into_color` swaps red and blue deliberately.
    ///
    /// It looks like a bug. Someone will eventually "fix" it by adding
    /// a swizzle, at which point every colour on the lock screen is
    /// wrong and nothing else fails. So it is pinned here: render a
    /// known red and assert the bytes are the ones `Argb8888` wants.
    #[test]
    fn iced_writes_the_byte_order_a_wayland_buffer_wants() {
        let red = iced_runtime::core::Color::from_rgb8(0xff, 0x00, 0x00);
        let mut pixmap = tiny_skia::Pixmap::new(1, 1).expect("1x1 pixmap");
        let mut mask = tiny_skia::Mask::new(1, 1).expect("1x1 mask");
        let mut renderer = iced_tiny_skia::Renderer::new(
            iced_runtime::core::Font::DEFAULT,
            iced_runtime::core::Pixels(14.0),
        );
        renderer.draw(
            &mut pixmap.as_mut(),
            &mut mask,
            &Viewport::with_physical_size(Size::new(1, 1), 1.0),
            &[Rectangle::with_size(Size::new(1.0, 1.0))],
            red,
        );

        // Argb8888 is [31:0] A:R:G:B little endian, so red is
        // 0xffff0000, whose bytes in memory are 00 00 ff ff.
        assert_eq!(
            pixmap.data()[0..4],
            0xffff_0000u32.to_le_bytes(),
            "red must land where Argb8888 keeps red; if this fails, do not add a swizzle \
             without checking what iced_tiny_skia::engine::into_color does"
        );
    }

    /// Reporting a successful unlock for a session that was never
    /// unlocked is the worst thing this program could do: something
    /// upstream would treat an open machine as a locked one.
    #[test]
    fn a_revoked_lock_is_never_reported_as_an_unlock() {
        // The batch that cost this a bug: `finished` and the last
        // keystroke arriving together.
        assert_eq!(conclude(Some(Outcome::Revoked), true, false), None);
        assert_eq!(conclude(Some(Outcome::Refused), true, false), None);
        assert_eq!(conclude(Some(Outcome::Disconnected), true, true), None);
    }

    /// Authenticating without a lock in hand unlocked nothing, so it
    /// must not claim to have.
    #[test]
    fn authenticating_without_the_lock_does_not_claim_success() {
        assert_eq!(conclude(None, true, false), Some(Outcome::Refused));
    }

    #[test]
    fn the_ordinary_unlock_still_concludes() {
        assert_eq!(conclude(None, true, true), Some(Outcome::Unlocked));
    }

    /// Not authenticated is not an ending. A lock screen that concluded
    /// anything here would let go of a session nobody proved they own.
    #[test]
    fn nothing_concludes_while_the_user_has_not_authenticated() {
        assert_eq!(conclude(None, false, true), None);
        assert_eq!(conclude(None, false, false), None);
    }



}

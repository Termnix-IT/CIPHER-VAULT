//! The only live key and the lifetime of every operation that uses it, following
//! apps/api/src/services/vault-session.ts. Every lock, even of a locked vault, changes the session
//! id, so a request started before the lock can no longer finish.

use crate::crypto::Secret;
use crate::error::{Result, VaultError, changed, locked};
use serde_json::Value;
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SESSION_ID_BYTES: usize = 128;

/// Both clocks, because each one misses something: the monotonic clock can pause during
/// suspend, and the wall clock can be moved by the user.
#[derive(Clone, Copy, Debug)]
pub struct Stamp {
    pub monotonic: Instant,
    pub wall: SystemTime,
}

impl Stamp {
    pub fn now() -> Self {
        Self { monotonic: Instant::now(), wall: SystemTime::now() }
    }
}

/// The lock reasons of VaultLockReason in packages/shared/src/types.ts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockReason {
    Manual,
    Idle,
    ClockChange,
    Reset,
    WindowClosed,
    RendererGone,
    Update,
    ScreenLock,
    ScreenUnlock,
    Suspend,
    Resume,
}

impl LockReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Idle => "idle",
            Self::ClockChange => "clock-change",
            Self::Reset => "reset",
            Self::WindowClosed => "window-closed",
            Self::RendererGone => "renderer-gone",
            Self::Update => "update",
            Self::ScreenLock => "screen-lock",
            Self::ScreenUnlock => "screen-unlock",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionState {
    pub session_id: String,
    pub is_unlocked: bool,
    pub lock_reason: Option<LockReason>,
}

pub struct Session {
    key: Option<Secret>,
    id: String,
    lock_reason: Option<LockReason>,
    activity: Stamp,
    observed: Stamp,
}

/// parseSessionId: anything but a short non-empty string asks the screen to read the state again.
pub fn parse_session_id(value: Option<&Value>) -> Result<String> {
    match value.and_then(Value::as_str) {
        Some(id) if !id.is_empty() && id.len() <= SESSION_ID_BYTES => Ok(id.to_string()),
        _ => Err(VaultError::conflict("保管庫の状態を再取得してください")),
    }
}

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

impl Session {
    pub fn new(now: Stamp) -> Self {
        Self { key: None, id: new_id(), lock_reason: None, activity: now, observed: now }
    }

    pub fn state(&mut self, now: Stamp) -> SessionState {
        self.expire(now);
        SessionState { session_id: self.id.clone(), is_unlocked: self.key.is_some(), lock_reason: self.lock_reason }
    }

    pub fn id(&mut self, now: Stamp) -> String {
        self.expire(now);
        self.id.clone()
    }

    /// Installs a key and starts a new session. The previous key is dropped, and `Zeroizing` clears it.
    pub fn unlock(&mut self, key: Secret, now: Stamp) {
        self.key = Some(key);
        self.id = new_id();
        self.lock_reason = None;
        self.activity = now;
        self.observed = now;
    }

    /// Even a lock while already locked invalidates pending setup, unlock and reset requests.
    pub fn lock(&mut self, reason: LockReason) {
        self.key = None;
        self.id = new_id();
        self.lock_reason = Some(reason);
    }

    pub fn require_generation(&mut self, expected: &str, now: Stamp) -> Result<()> {
        self.expire(now);
        if expected == self.id { Ok(()) } else { Err(changed()) }
    }

    /// A locked vault reports the lock first, before a stale session id.
    pub fn require_unlocked(&mut self, expected: Option<&str>, now: Stamp) -> Result<String> {
        self.expire(now);
        if self.key.is_none() {
            return Err(locked());
        }
        match expected {
            Some(expected) if expected != self.id => Err(changed()),
            _ => Ok(self.id.clone()),
        }
    }

    /// A copy of the key for one operation. The copy is cleared when the caller drops it.
    pub fn key(&mut self, expected: &str, now: Stamp) -> Result<Secret> {
        self.require_unlocked(Some(expected), now)?;
        Ok(self.key.clone().expect("checked above"))
    }

    /// Checks expiry before touching the deadline, so late traffic cannot revive a key.
    pub fn record_activity(&mut self, expected: &str, now: Stamp) -> Result<()> {
        self.require_unlocked(Some(expected), now)?;
        self.activity = now;
        self.observed = now;
        Ok(())
    }

    /// Locks once the idle time has passed. A clock moving backwards locks at once, because it
    /// could otherwise extend the deadline.
    pub fn expire(&mut self, now: Stamp) {
        if self.key.is_none() {
            return;
        }
        let Some(wall) = now.wall.duration_since(self.observed.wall).ok().and(now.wall.duration_since(self.activity.wall).ok()) else {
            self.lock(LockReason::ClockChange);
            return;
        };
        if now.monotonic < self.observed.monotonic {
            self.lock(LockReason::ClockChange);
            return;
        }
        self.observed = now;
        // Wall time covers suspend on platforms where the monotonic clock pauses.
        if now.monotonic.saturating_duration_since(self.activity.monotonic).max(wall) >= IDLE_TIMEOUT {
            self.lock(LockReason::Idle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn unlocked(start: Stamp) -> Session {
        let mut session = Session::new(start);
        session.unlock(Zeroizing::new(vec![1; 32]), start);
        session
    }

    fn later(start: Stamp, monotonic: Duration, wall: Duration) -> Stamp {
        Stamp { monotonic: start.monotonic + monotonic, wall: start.wall + wall }
    }

    #[test]
    fn idle_time_on_either_clock_destroys_the_key() {
        let start = Stamp::now();
        let mut session = unlocked(start);
        let id = session.id(start);
        session.expire(later(start, IDLE_TIMEOUT - Duration::from_millis(1), Duration::from_secs(1)));
        assert!(session.state(later(start, IDLE_TIMEOUT - Duration::from_millis(1), Duration::from_secs(1))).is_unlocked);
        let state = session.state(later(start, IDLE_TIMEOUT, IDLE_TIMEOUT));
        assert!(!state.is_unlocked);
        assert_eq!(state.lock_reason, Some(LockReason::Idle));
        assert_ne!(state.session_id, id, "a lock starts a new session");

        // A suspended machine: the monotonic clock paused while the wall clock moved on.
        let mut session = unlocked(start);
        assert_eq!(session.state(later(start, Duration::from_secs(1), IDLE_TIMEOUT)).lock_reason, Some(LockReason::Idle));
    }

    #[test]
    fn a_clock_moving_backwards_locks_at_once() {
        let start = Stamp::now();
        let mut session = unlocked(start);
        let moved = Stamp { monotonic: start.monotonic + Duration::from_secs(1), wall: start.wall - Duration::from_secs(1) };
        let state = session.state(moved);
        assert!(!state.is_unlocked);
        assert_eq!(state.lock_reason, Some(LockReason::ClockChange));
    }

    #[test]
    fn activity_moves_the_deadline_but_cannot_revive_an_expired_key() {
        let start = Stamp::now();
        let mut session = unlocked(start);
        let id = session.id(start);
        let minute = Duration::from_secs(60);
        session.record_activity(&id, later(start, 4 * minute, 4 * minute)).unwrap();
        assert!(session.state(later(start, 8 * minute, 8 * minute)).is_unlocked, "the deadline moved");
        assert_eq!(session.record_activity(&id, later(start, 9 * minute + minute, 10 * minute)).unwrap_err(), locked());
    }

    #[test]
    fn stale_and_locked_sessions_are_refused_in_the_app_order() {
        let start = Stamp::now();
        let mut session = Session::new(start);
        let first = session.id(start);
        assert_eq!(session.require_unlocked(Some(&first), start).unwrap_err(), locked());
        assert_eq!(session.require_generation("other", start).unwrap_err(), changed());
        session.unlock(Zeroizing::new(vec![2; 32]), start);
        assert_eq!(session.require_unlocked(Some(&first), start).unwrap_err(), changed());
        let current = session.id(start);
        assert_eq!(session.key(&current, start).unwrap().as_slice(), &[2; 32]);
        session.lock(LockReason::Manual);
        assert_eq!(session.require_unlocked(Some(&current), start).unwrap_err(), locked(), "locked comes before stale");
        assert_eq!(session.state(start).lock_reason, Some(LockReason::Manual));
    }

    #[test]
    fn session_ids_must_be_short_non_empty_text() {
        let refused = VaultError::conflict("保管庫の状態を再取得してください");
        for value in [None, Some(Value::Null), Some(Value::from(1)), Some(Value::from("")), Some(Value::from("x".repeat(129)))] {
            assert_eq!(parse_session_id(value.as_ref()).unwrap_err(), refused, "{value:?}");
        }
        assert_eq!(parse_session_id(Some(&Value::from("x".repeat(128)))).unwrap(), "x".repeat(128));
    }
}

//! Expiring clipboard, following apps/electron/src/expiring-clipboard.ts. Only a digest and a
//! random owner token are retained, never the copied text.

use crate::clock::Stamp;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const CLEAR_AFTER: Duration = Duration::from_secs(30);
const BUSY: &str = "コピー処理の完了を待ってください";
const WRITE_FAILED: &str = "クリップボードへコピーできませんでした";
const CHANGED_DURING_COPY: &str = "コピー中に保管庫の状態または期限が変わりました";

#[derive(Debug)]
pub struct ClipboardUnavailable;

pub trait ClipboardPort: Send + Sync {
    fn write(&self, text: &str, owner: &str) -> Result<(), ClipboardUnavailable>;
    /// Clears only when the marker and the text still match, returning whether it cleared.
    /// A replacement by another application is not an error and must be left alone.
    fn clear_if_owned(&self, owner: &str, digest: &[u8; 32]) -> Result<bool, ClipboardUnavailable>;
}

/// Readers of CF_UNICODETEXT stop at the first NUL, so that is the text being compared.
pub fn visible_text_digest(text: &str) -> [u8; 32] {
    let visible = text.split('\0').next().unwrap_or_default();
    let mut hasher = Sha256::new();
    for unit in visible.encode_utf16() {
        hasher.update(unit.to_le_bytes());
    }
    hasher.finalize().into()
}

struct Lease {
    owner: String,
    digest: Zeroizing<[u8; 32]>,
    started: Stamp,
}

impl Lease {
    fn expired_at(&self, now: Stamp) -> bool {
        self.started.elapsed_at(now).is_none_or(|elapsed| elapsed >= CLEAR_AFTER)
    }
}

pub struct ExpiringClipboard {
    port: Box<dyn ClipboardPort>,
    lease: Mutex<Option<Lease>>,
}

impl ExpiringClipboard {
    pub fn new(port: Box<dyn ClipboardPort>) -> Self {
        Self { port, lease: Mutex::new(None) }
    }

    pub fn copy(&self, text: &str, assert_current: impl Fn() -> Result<(), String>) -> Result<(), String> {
        self.copy_at(text, assert_current, Stamp::now)
    }

    fn copy_at(&self, text: &str, assert_current: impl Fn() -> Result<(), String>, now: impl Fn() -> Stamp) -> Result<(), String> {
        // Duplicate copies are refused instead of being queued with their text.
        let mut lease = self.lease.try_lock().map_err(|_| BUSY)?;
        assert_current()?;
        let candidate = Lease { owner: Uuid::new_v4().to_string(), digest: Zeroizing::new(visible_text_digest(text)), started: now() };
        // A failed write leaves the previous lease and its original deadline in place.
        self.port.write(text, &candidate.owner).map_err(|_| WRITE_FAILED)?;
        *lease = Some(candidate);
        let verdict = assert_current();
        let expired = lease.as_ref().is_some_and(|current| current.expired_at(now()));
        if verdict.is_ok() && !expired {
            return Ok(());
        }
        self.clear_lease(&mut lease);
        Err(verdict.err().unwrap_or_else(|| CHANGED_DURING_COPY.to_string()))
    }

    /// Returns false when the clipboard could not be read. The lease stays for a retry and
    /// nothing is cleared, because an unread clipboard may belong to someone else.
    pub fn clear_owned(&self) -> bool {
        let mut lease = self.lease.lock().unwrap();
        self.clear_lease(&mut lease)
    }

    /// Called periodically. A clipboard that was busy at the deadline is retried here.
    pub fn tick(&self) {
        self.tick_with(Stamp::now);
    }

    #[cfg(test)]
    fn tick_at(&self, now: Stamp) {
        self.tick_with(|| now);
    }

    /// The time is read once the lease is held. A time read before that can be older than the
    /// start of a copy that finished meanwhile, which would look like a clock moving backwards
    /// and clear the new copy at once.
    fn tick_with(&self, now: impl Fn() -> Stamp) {
        let Ok(mut lease) = self.lease.try_lock() else {
            return;
        };
        if lease.as_ref().is_some_and(|current| current.expired_at(now())) {
            self.clear_lease(&mut lease);
        }
    }

    fn clear_lease(&self, lease: &mut Option<Lease>) -> bool {
        let Some(current) = lease.as_ref() else {
            return true;
        };
        if self.port.clear_if_owned(&current.owner, &current.digest).is_err() {
            return false;
        }
        *lease = None;
        true
    }
}

/// Stands in for the real clipboard in UI checks, which must not overwrite the user's clipboard.
#[cfg(any(test, feature = "e2e"))]
pub mod fake {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    pub struct FakeClipboard {
        pub value: Arc<Mutex<Option<(String, String)>>>,
        pub clears: Arc<Mutex<u32>>,
        pub fail_write: Arc<Mutex<bool>>,
        pub fail_clear: Arc<Mutex<bool>>,
    }

    impl ClipboardPort for FakeClipboard {
        fn write(&self, text: &str, owner: &str) -> Result<(), ClipboardUnavailable> {
            if *self.fail_write.lock().unwrap() {
                return Err(ClipboardUnavailable);
            }
            *self.value.lock().unwrap() = Some((text.to_string(), owner.to_string()));
            crate::trace("clipboard-write");
            Ok(())
        }

        fn clear_if_owned(&self, owner: &str, digest: &[u8; 32]) -> Result<bool, ClipboardUnavailable> {
            if *self.fail_clear.lock().unwrap() {
                return Err(ClipboardUnavailable);
            }
            let mut value = self.value.lock().unwrap();
            let owned = value.as_ref().is_some_and(|(text, current)| current == owner && visible_text_digest(text) == *digest);
            if owned {
                *value = None;
                *self.clears.lock().unwrap() += 1;
                crate::trace("clipboard-clear");
            }
            Ok(owned)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeClipboard;
    use super::*;
    use std::cell::Cell;

    fn fixture() -> (ExpiringClipboard, FakeClipboard) {
        let port = FakeClipboard::default();
        (ExpiringClipboard::new(Box::new(port.clone())), port)
    }

    fn current() -> Result<(), String> {
        Ok(())
    }

    fn later(start: Stamp, by: Duration) -> Stamp {
        Stamp { monotonic: start.monotonic + by, wall: start.wall + by }
    }

    fn text_of(port: &FakeClipboard) -> Option<String> {
        port.value.lock().unwrap().as_ref().map(|(text, _)| text.clone())
    }

    #[test]
    fn owned_text_clears_at_thirty_seconds_and_not_before() {
        let (clipboard, port) = fixture();
        let start = Stamp::now();
        clipboard.copy_at("synthetic", current, || start).unwrap();
        clipboard.tick_at(later(start, CLEAR_AFTER - Duration::from_millis(1)));
        assert_eq!(text_of(&port).as_deref(), Some("synthetic"));
        clipboard.tick_at(later(start, CLEAR_AFTER));
        assert_eq!(text_of(&port), None);
    }

    #[test]
    fn the_periodic_check_reads_the_time_while_it_holds_the_lease() {
        let (clipboard, port) = fixture();
        let start = Stamp::now();
        clipboard.copy_at("synthetic", current, || start).unwrap();
        let read = Cell::new(false);
        clipboard.tick_with(|| {
            read.set(true);
            assert!(clipboard.lease.try_lock().is_err(), "no copy can finish between the reading and the check");
            later(start, Duration::from_secs(1))
        });
        assert!(read.get());
        assert_eq!(text_of(&port).as_deref(), Some("synthetic"));
    }

    #[test]
    fn suspend_and_clock_rollback_count_as_expired() {
        for change in [
            |start: Stamp| Stamp { monotonic: start.monotonic + Duration::from_secs(1), wall: start.wall + CLEAR_AFTER },
            |start: Stamp| Stamp { monotonic: start.monotonic + Duration::from_secs(1), wall: start.wall - Duration::from_secs(1) },
        ] {
            let (clipboard, port) = fixture();
            let start = Stamp::now();
            clipboard.copy_at("synthetic", current, || start).unwrap();
            clipboard.tick_at(change(start));
            assert_eq!(text_of(&port), None);
        }
    }

    #[test]
    fn another_applications_copy_is_preserved() {
        for replacement in [("someone else's text", "other-owner"), ("same owner but different text", "KEEP")] {
            let (clipboard, port) = fixture();
            clipboard.copy("synthetic", current).unwrap();
            let owner = port.value.lock().unwrap().as_ref().unwrap().1.clone();
            let next_owner = if replacement.1 == "KEEP" { owner } else { replacement.1.to_string() };
            *port.value.lock().unwrap() = Some((replacement.0.to_string(), next_owner));
            assert!(clipboard.clear_owned());
            assert_eq!(text_of(&port).as_deref(), Some(replacement.0));
            assert_eq!(*port.clears.lock().unwrap(), 0);
        }
    }

    #[test]
    fn a_new_copy_replaces_the_lease_and_a_failed_write_keeps_the_old_deadline() {
        let (clipboard, port) = fixture();
        let start = Stamp::now();
        clipboard.copy_at("first", current, || start).unwrap();
        let second = later(start, Duration::from_secs(10));
        clipboard.copy_at("second", current, || second).unwrap();
        clipboard.tick_at(later(start, CLEAR_AFTER));
        assert_eq!(text_of(&port).as_deref(), Some("second"), "the first deadline no longer applies");

        *port.fail_write.lock().unwrap() = true;
        let failed = later(start, Duration::from_secs(20));
        assert_eq!(clipboard.copy_at("failed", current, || failed).unwrap_err(), WRITE_FAILED);
        clipboard.tick_at(later(second, CLEAR_AFTER));
        assert_eq!(text_of(&port), None, "the second copy keeps its own deadline");
    }

    #[test]
    fn a_session_change_during_the_write_clears_the_late_text() {
        let (clipboard, port) = fixture();
        let calls = Cell::new(0);
        let result = clipboard.copy("late secret", || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 { Ok(()) } else { Err("session changed".to_string()) }
        });
        assert_eq!(result.unwrap_err(), "session changed");
        assert_eq!(text_of(&port), None);
    }

    #[test]
    fn a_session_that_is_already_gone_never_writes() {
        let (clipboard, port) = fixture();
        assert_eq!(clipboard.copy("secret", || Err("locked".to_string())).unwrap_err(), "locked");
        assert_eq!(text_of(&port), None);
    }

    #[test]
    fn a_write_outlasting_the_deadline_never_starts_a_fresh_lifetime() {
        let (clipboard, port) = fixture();
        let start = Stamp::now();
        let calls = Cell::new(0);
        let result = clipboard.copy_at("slow", current, || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 { start } else { later(start, CLEAR_AFTER) }
        });
        assert_eq!(result.unwrap_err(), CHANGED_DURING_COPY);
        assert_eq!(text_of(&port), None);
    }

    #[test]
    fn an_unreadable_clipboard_is_left_alone_and_retried() {
        let (clipboard, port) = fixture();
        let start = Stamp::now();
        clipboard.copy_at("synthetic", current, || start).unwrap();
        *port.fail_clear.lock().unwrap() = true;
        assert!(!clipboard.clear_owned());
        clipboard.tick_at(later(start, CLEAR_AFTER));
        assert_eq!(text_of(&port).as_deref(), Some("synthetic"));
        *port.fail_clear.lock().unwrap() = false;
        clipboard.tick_at(later(start, CLEAR_AFTER + Duration::from_secs(1)));
        assert_eq!(text_of(&port), None);
    }

    #[test]
    fn a_second_copy_during_a_copy_is_refused_without_writing() {
        let (clipboard, port) = fixture();
        let result = clipboard.copy("outer", || clipboard.copy("inner", current));
        assert_eq!(result.unwrap_err(), BUSY);
        assert_eq!(text_of(&port), None, "the first copy also gave up before writing");
    }

    #[test]
    fn the_digest_covers_only_what_a_reader_sees() {
        assert_eq!(visible_text_digest("before\0after"), visible_text_digest("before"));
        assert_ne!(visible_text_digest("before"), visible_text_digest("other"));
    }
}

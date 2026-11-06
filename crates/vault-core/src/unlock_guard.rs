//! Setup and unlock run one at a time and slow down after repeated wrong passwords, following
//! apps/api/src/services/vault-unlock-guard.ts. A second request is refused rather than queued,
//! so a password never waits in memory for its turn.

use crate::error::{Result, VaultError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const FREE_FAILURES: u32 = 5;
const MAX_COUNTED_FAILURES: u32 = 10;
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Default)]
struct State {
    busy: bool,
    failures: u32,
    retry_at: Option<Instant>,
}

#[derive(Default)]
pub struct UnlockGuard {
    state: Mutex<State>,
}

impl UnlockGuard {
    pub fn run<T>(&self, now: impl Fn() -> Instant, action: impl FnOnce() -> Result<T>) -> Result<T> {
        {
            let mut state = self.state.lock().unwrap();
            if state.busy {
                return Err(VaultError::conflict("初期設定・解除処理の完了を待ってください"));
            }
            if let Some(remaining) = state.retry_at.and_then(|retry_at| retry_at.checked_duration_since(now())).filter(|remaining| !remaining.is_zero()) {
                // Math.ceil of the remaining milliseconds in seconds, as the app shows it.
                let seconds = remaining.as_millis().div_ceil(1000);
                return Err(VaultError::new(429, format!("認証の失敗が続いています。{seconds}秒後にもう一度お試しください")));
            }
            state.busy = true;
        }
        // Clears the busy flag even when the action panics.
        struct Release<'a>(&'a Mutex<State>);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                if let Ok(mut state) = self.0.lock() {
                    state.busy = false;
                }
            }
        }
        let release = Release(&self.state);
        let result = action();
        {
            let mut state = self.state.lock().unwrap();
            match &result {
                Ok(_) => {
                    state.failures = 0;
                    state.retry_at = None;
                }
                Err(error) if error.status == 401 => {
                    state.failures = (state.failures + 1).min(MAX_COUNTED_FAILURES);
                    if state.failures >= FREE_FAILURES {
                        let backoff = Duration::from_secs(1u64 << (state.failures - FREE_FAILURES)).min(MAX_BACKOFF);
                        state.retry_at = Some(now() + backoff);
                    }
                }
                Err(_) => {}
            }
        }
        drop(release);
        result
    }

    #[cfg(test)]
    pub(crate) fn is_busy(&self) -> bool {
        self.state.lock().unwrap().busy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn wrong() -> Result<()> {
        Err(VaultError::new(401, "wrong"))
    }

    #[test]
    fn repeated_wrong_passwords_back_off_up_to_thirty_seconds() {
        let start = Instant::now();
        let offset = Cell::new(Duration::ZERO);
        let now = || start + offset.get();
        let guard = UnlockGuard::default();
        for _ in 0..4 {
            assert_eq!(guard.run(now, wrong).unwrap_err().status, 401);
        }
        assert_eq!(guard.run(now, wrong).unwrap_err().status, 401, "the fifth failure is still answered");
        let refused = guard.run(now, || Ok(())).unwrap_err();
        assert_eq!(refused, VaultError::new(429, "認証の失敗が続いています。1秒後にもう一度お試しください"));
        offset.set(Duration::from_millis(1000));
        assert_eq!(guard.run(now, wrong).unwrap_err().status, 401);
        offset.set(Duration::from_millis(1001));
        assert!(guard.run(now, || Ok(())).unwrap_err().message.contains("2秒後"), "the sixth failure doubles the wait");
        for step in 0..10 {
            offset.set(Duration::from_secs(100 * (step + 2)));
            let _ = guard.run(now, wrong);
        }
        assert!(guard.run(now, || Ok(())).unwrap_err().message.contains("30秒後"));
        offset.set(Duration::from_secs(5000));
        guard.run(now, || Ok(())).unwrap();
        assert_eq!(guard.run(now, wrong).unwrap_err().status, 401, "success resets the count");
        guard.run(now, || Ok(())).unwrap();
    }

    #[test]
    fn other_errors_do_not_count_and_a_second_request_is_refused() {
        let guard = UnlockGuard::default();
        for _ in 0..10 {
            let _ = guard.run(Instant::now, || Err::<(), _>(VaultError::conflict("changed")));
        }
        guard.run(Instant::now, || Ok(())).unwrap();
        let nested = guard.run(Instant::now, || guard.run(Instant::now, || Ok(())));
        assert_eq!(nested.unwrap_err(), VaultError::conflict("初期設定・解除処理の完了を待ってください"));
        guard.run(Instant::now, || Ok(())).unwrap();
    }
}

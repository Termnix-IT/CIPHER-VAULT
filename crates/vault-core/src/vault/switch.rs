//! runVaultMaintenance in vault-maintenance-service.ts, with the IPC handler's session check: the
//! request is checked, the vault in use is closed, the switch runs on the files, and whatever the
//! data directory then selects is opened again, always locked.
//!
//! While it runs, any lock of the session cancels the switch: the screen's cancel button locks,
//! and so do closing the window and the idle timer. Each step checks before it continues.

use super::{Busy, Storage, Vault, open_storage, recovery_required};
use crate::crypto::{self, CryptoError, Secret};
use crate::error::{self, Result, VaultError};
use crate::maintenance::{self, Code, Credentials, Hint, Operation, Outcome, Start, Stop, translate};
use crate::selection::{self, Selection};
use crate::session::{LockReason, parse_session_id};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const SWITCHING: &str = "保管庫の切り替えが進行中です";
const CANCELLED: &str = "保管庫の切り替えは取り消されました";
/// How long a closed vault may still be in use by a call that started before the switch.
const RELEASE_WAIT: Duration = Duration::from_secs(5);

impl Vault {
    /// The vault:maintenance handler: the session must be the current one, and the status after
    /// the switch is the answer.
    pub fn run_maintenance(&self, session_id: Option<&Value>, payload: Option<&Value>) -> Result<Value> {
        self.available()?;
        let expected = parse_session_id(session_id)?;
        self.require_generation(&expected)?;
        let _busy = Busy::claim(&self.switching).ok_or_else(|| VaultError::conflict(SWITCHING))?;
        let request = maintenance::parse(payload)?;
        self.require_generation(&expected)?;
        let recovering = request.operation == Operation::Recover;
        if recovering != matches!(*self.storage(), Storage::RecoveryRequired { .. }) {
            return Err(VaultError::conflict("現在の保管庫ではこの操作を実行できません"));
        }
        let (hint, selected) = if recovering {
            (Some(maintenance::recovery_hint(&self.root).map_err(translate)?), None)
        } else {
            (None, Some(maintenance::selected(&self.root).map_err(translate)?))
        };
        if selected.as_ref().is_some_and(Option::is_none) {
            return Err(VaultError::conflict("保管庫を作成してから操作してください"));
        }
        let reset_hint = hint.as_ref().is_some_and(|hint| hint.mode() == "reset");
        if reset_hint && !request.confirmation {
            return Err(VaultError::bad_request("空の保管庫への切り替え確認が必要です"));
        }
        if !reset_hint && recovering && request.confirmation {
            return Err(VaultError::bad_request("復旧内容に対応しない確認項目です"));
        }
        let owner_key = if recovering {
            None
        } else {
            self.assert_current()?;
            self.require_unlocked(Some(&expected))?;
            Some(self.key(&expected)?)
        };

        // closeVaultStorage, then the running state the screen shows.
        let format = if selected.is_some() { "v2" } else { "unknown" };
        let running = Storage::Running { format, operation: request.operation.as_str(), source_session_id: expected.clone() };
        let previous = std::mem::replace(&mut *self.storage.write().unwrap(), Arc::new(running));
        self.lock_for(LockReason::Manual);
        release(previous);
        let generation = self.session_at(|session, now| session.id(now));

        let credentials = Credentials { master: &request.master_password, new: &request.new_master_password, passphrase: &request.backup_passphrase };
        let aborted = || self.session_at(|session, now| session.id(now)) != generation;
        let outer = || -> Outcome<()> { if aborted() { Err(Stop::Error(VaultError::conflict(CANCELLED))) } else { Ok(()) } };
        let inner = || -> Outcome<()> { if aborted() { Err(Stop::Code(Code::Busy)) } else { Ok(()) } };
        let guarded = |action: &dyn Fn() -> Result<Secret>| self.guard.run(|| self.now().monotonic, action);
        let root = self.root.as_path();

        let outcome = (|| -> Result<()> {
            outer().map_err(translate)?;
            match (&hint, &selected) {
                (Some(Hint { source, target, reset }), _) => {
                    let key = self.guard.run(|| self.now().monotonic, || authenticate_v2(root, source, credentials.master, &outer).map_err(translate))?;
                    outer().map_err(translate)?;
                    let start = Start::Recover { source: source.clone(), target: target.clone(), reset: *reset };
                    maintenance::replace(root, start, &credentials, &key, &guarded, &inner).map_err(translate)
                }
                (None, Some(Some(source))) => {
                    let start = Start::Replace { source: source.clone(), reset: request.operation == Operation::Reset };
                    let owner = owner_key.as_ref().ok_or_else(error::locked)?;
                    maintenance::replace(root, start, &credentials, owner, &guarded, &inner).map_err(translate)
                }
                (None, _) => Err(translate(Code::Failed.into())),
            }
        })();
        drop(owner_key);

        // Whatever the files now select, opened locked; a vault that disappeared needs recovery.
        let reopened = match selection::inspect(root) {
            Ok(Selection::V2 { .. }) => open_storage(root).ok().filter(|storage| matches!(storage, Storage::V2 { .. })),
            _ => None,
        };
        self.failed.store(false, Ordering::SeqCst);
        *self.storage.write().unwrap() = Arc::new(reopened.unwrap_or_else(|| recovery_required(root)));
        self.lock_for(LockReason::Manual);
        outcome?;
        self.available()?;
        self.status()
    }
}

/// Waits until no call that began before the switch still holds the closed vault, so its file
/// is closed before the switch reads it. Such a call holds the file itself rather than the
/// storage around it, so both are waited for.
pub(super) fn release(storage: Arc<Storage>) {
    let deadline = Instant::now() + RELEASE_WAIT;
    if let Some(Storage::V2 { store, .. }) = sole(storage, deadline) {
        drop(sole(store, deadline));
    }
}

/// The value once nothing else holds it, or None when it is still shared at the deadline.
fn sole<T>(mut shared: Arc<T>, deadline: Instant) -> Option<T> {
    loop {
        match Arc::try_unwrap(shared) {
            Ok(value) => return Some(value),
            Err(still) if Instant::now() < deadline => {
                shared = still;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
}

/// authenticateSource for the source of an interrupted replacement.
fn authenticate_v2(root: &std::path::Path, source: &maintenance::Context, master: &str, active: maintenance::Active<'_>) -> Outcome<Secret> {
    active()?;
    let store = maintenance::open_store(root, source)?;
    let key = crypto::unwrap_v2_root(store.password_slot(), master.as_bytes(), &source.vault_id, &source.key_id, 1)
        .map_err(|error| Stop::Code(if error == CryptoError::Authentication { Code::Authentication } else { Code::Failed }))?;
    active()?;
    Ok(key)
}

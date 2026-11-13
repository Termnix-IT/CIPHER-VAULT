//! The vault services the screen calls, following apps/api/src/services/vault-service.ts,
//! v2-vault-service.ts, entry-service.ts, db/vault-context.ts and the IPC handlers in
//! apps/electron/src/desktop-main.ts. Every method takes the screen's arguments as they arrive and
//! returns the same result or the same message as the TypeScript app.
//!
//! The vault opened at startup stays the one in use until a switch (vault/switch.rs) replaces it.
//! Before each operation, and again under the write lock, the data directory must still select
//! the same file; otherwise the vault fails closed until the app restarts, as in the TypeScript app.

mod switch;

use crate::audit;
use crate::backup;
use crate::crypto::{self, CryptoError, Secret};
use crate::error::{self, Result, VaultError, changed, context_failed, not_found};
use crate::files::{self, FileIdentity};
use crate::icons;
use crate::input::{self, MAX_ENTRIES, now_iso};
use crate::maintenance;
use crate::password;
use crate::selection::{self, Selection};
use crate::session::{IDLE_TIMEOUT, LockReason, Session, Stamp, parse_session_id};
use crate::unlock_guard::UnlockGuard;
use crate::v2::{StoreError, V2Store};
use chrono::Utc;
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

const KDF_FAILED: &str = "鍵を導出できませんでした";
const EMPTY_ONLY: &str = "復元できるのは空の保管庫のみです";
/// The copy of a vault before list icons moved into its entries, beside the vault file.
pub const BEFORE_V4: &str = "before-v4.sqlite";
const SWITCH_PENDING: &str = "保管庫の切り替えが完了するまでお待ちください";
/// How long the steps of one read go on without looking at the vault's files again.
const READ_CONTEXT_INTERVAL: Duration = Duration::from_millis(50);

enum Storage {
    /// No vault has been created yet. A legacy file may be there, which this release does not open.
    Empty { legacy_found: bool },
    V2 { store: Arc<Mutex<V2Store>>, identity: FileIdentity, vault_id: String, key_id: String },
    /// A switch between formats was interrupted, or the files do not agree. The vault stays locked.
    /// `operation` names the switch that can finish it, when the files tell.
    RecoveryRequired { operation: Option<&'static str> },
    /// A switch is running and no vault file is open.
    Running { format: &'static str, operation: &'static str, source_session_id: String },
}

/// The vault the data directory selects.
fn open_storage(root: &Path) -> Result<Storage> {
    Ok(match selection::inspect(root) {
        Ok(Selection::Empty { legacy_found }) => Storage::Empty { legacy_found },
        Ok(Selection::V2 { database, vault_id, key_id }) => match V2Store::open(&database, &vault_id, &key_id) {
            Some(store) => Storage::V2 { identity: files::identity(&database).map_err(|_| open_failed())?, store: Arc::new(Mutex::new(store)), vault_id, key_id },
            None => recovery_required(root),
        },
        Err(_) => recovery_required(root),
    })
}

fn recovery_required(root: &Path) -> Storage {
    Storage::RecoveryRequired { operation: maintenance::recovery_hint(root).ok().map(|hint| hint.mode()) }
}

/// A failure inside a v2 operation: a message for the screen, or a storage outcome to translate.
enum Failure {
    User(VaultError),
    Store(StoreError),
}

impl From<VaultError> for Failure {
    fn from(error: VaultError) -> Self {
        Self::User(error)
    }
}

impl From<StoreError> for Failure {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

type Clock = Box<dyn Fn() -> Stamp + Send + Sync>;

/// The desktop's own refusal of vault operations, such as while the screen is locked
/// (assertAvailable in desktop-main.ts). Without one, every operation is available.
pub type Availability = Box<dyn Fn() -> Result<()> + Send + Sync>;

pub struct Vault {
    root: PathBuf,
    storage: RwLock<Arc<Storage>>,
    session: Mutex<Session>,
    guard: UnlockGuard,
    clock: Clock,
    failed: AtomicBool,
    writing: AtomicBool,
    backing_up: AtomicBool,
    auditing: AtomicBool,
    switching: AtomicBool,
    availability: OnceLock<Availability>,
    #[cfg(test)]
    context_checks: std::sync::atomic::AtomicUsize,
}

/// Holds a one-at-a-time flag until dropped, also when the work fails.
struct Busy<'a>(&'a AtomicBool);

impl<'a> Busy<'a> {
    fn claim(flag: &'a AtomicBool) -> Option<Self> {
        (!flag.swap(true, Ordering::SeqCst)).then_some(Self(flag))
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn random_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::fill(bytes.as_mut()).map_err(|_| VaultError::new(500, "乱数を取得できませんでした"))?;
    Ok(bytes)
}

fn open_failed() -> VaultError {
    VaultError::new(500, "保管庫の保存先を開けません。アクセス権・使用状況・復旧の必要性を確認してください")
}

/// The newer of now and the stored time, so an entry never moves back in time. ISO text in this
/// one form sorts by time.
fn not_before(stored: &Value) -> String {
    now_iso().max(stored.as_str().unwrap_or_default().to_string())
}

fn v2_summary(entry: &Value) -> Value {
    let mut summary = json!({ "id": entry["id"], "serviceName": entry["serviceName"], "tags": entry["tags"], "group": entry["group"], "updatedAt": entry["updatedAt"] });
    match entry["type"].as_str() {
        Some(kind @ ("apiKey" | "financial")) => summary["type"] = json!(kind),
        Some("creditCard") => {
            let number: Vec<char> = entry["card"]["number"].as_str().unwrap_or_default().chars().collect();
            summary["type"] = json!("creditCard");
            summary["cardLast4"] = json!(number[number.len().saturating_sub(4)..].iter().collect::<String>());
        }
        _ => summary["loginId"] = entry["loginId"].clone(),
    }
    if let Some(icon) = entry.get("icon") {
        summary["icon"] = icon.clone();
    }
    summary
}

/// A new v2 entry in the field order the TypeScript service writes.
fn v2_entry(id: &str, fields: &Value, created_at: &Value, updated_at: &str, password_changed_at: Option<Value>) -> Value {
    let mut entry = Map::new();
    entry.insert("id".into(), json!(id));
    let order: &[&str] = if fields.get("type").is_some() { &["serviceName", "notes", "url", "tags", "group", "type", "apiKey", "card", "financial"] } else { &["serviceName", "notes", "url", "tags", "group", "loginId", "password"] };
    for field in order {
        if let Some(value) = fields.get(*field) {
            entry.insert((*field).into(), value.clone());
        }
    }
    entry.insert("createdAt".into(), created_at.clone());
    entry.insert("updatedAt".into(), json!(updated_at));
    if let Some(changed) = password_changed_at {
        entry.insert("passwordChangedAt".into(), changed);
    }
    Value::Object(entry)
}

fn invalid_entry() -> VaultError {
    VaultError::bad_request(input::INVALID_ENTRY)
}

impl Vault {
    /// Opens the vault in `data_directory`, creating the directory when there is none. Without a
    /// vault the app waits for setup, and a vault that needs recovery opens locked.
    pub fn open(data_directory: &Path) -> Result<Self> {
        Self::open_with_clock(data_directory, Box::new(Stamp::now))
    }

    pub fn open_with_clock(data_directory: &Path, clock: Clock) -> Result<Self> {
        if !data_directory.exists() {
            std::fs::create_dir_all(data_directory).map_err(|_| open_failed())?;
        }
        let root = files::data_root(data_directory).map_err(|_| open_failed())?;
        let storage = RwLock::new(Arc::new(open_storage(&root)?));
        // Opening the storage locks once, as openVaultStorage does, so the first status says "manual".
        let mut session = Session::new(clock());
        session.lock(LockReason::Manual);
        let session = Mutex::new(session);
        Ok(Self { root, storage, session, guard: UnlockGuard::default(), clock, failed: AtomicBool::new(false), writing: AtomicBool::new(false), backing_up: AtomicBool::new(false), auditing: AtomicBool::new(false), switching: AtomicBool::new(false), availability: OnceLock::new(), #[cfg(test)] context_checks: Default::default() })
    }

    fn now(&self) -> Stamp {
        (self.clock)()
    }

    /// Runs `action` on the session with a time read while the session's lock is held. A time
    /// read before the lock can be older than one another thread has already recorded, which the
    /// session would take for a clock moving backwards, and lock.
    fn session_at<T>(&self, action: impl FnOnce(&mut Session, Stamp) -> T) -> T {
        let mut session = self.session.lock().unwrap();
        let now = self.now();
        action(&mut session, now)
    }

    fn storage(&self) -> Arc<Storage> {
        self.storage.read().unwrap().clone()
    }

/// Sets the desktop's check once, before the screen can call anything. Returns false when one was
    /// already set.
    pub fn set_availability(&self, check: Availability) -> bool {
        self.availability.set(check).is_ok()
    }

    /// Called where desktop-main.ts calls assertAvailable, so the refusals come in the same order.
    fn available(&self) -> Result<()> {
        self.availability.get().map_or(Ok(()), |check| check())
    }

    /// Whether a key is in memory, for the desktop's decisions. Expiry is applied first.
    pub fn is_unlocked(&self) -> bool {
        self.session_at(|session, now| session.state(now).is_unlocked)
    }

    /// Whether a switch is still running, so that quitting can give it a moment to stop.
    pub fn is_switching(&self) -> bool {
        self.switching.load(Ordering::SeqCst)
    }

    pub fn is_recovery_required(&self) -> bool {
        matches!(*self.storage(), Storage::RecoveryRequired { .. })
    }

    // ---- The context: the files selected at startup must still be the ones in use.

    /// failVaultContext: from now on every operation fails until the app restarts.
    fn fail(&self) -> VaultError {
        self.failed.store(true, Ordering::SeqCst);
        self.session.lock().unwrap().lock(LockReason::Manual);
        context_failed()
    }

    fn context_is_current(&self) -> files::Checked<bool> {
        #[cfg(test)]
        self.context_checks.fetch_add(1, Ordering::SeqCst);
        match &*self.storage() {
            Storage::Empty { .. } => selection::is_unclaimed(&self.root),
            Storage::V2 { identity, vault_id, key_id, .. } => {
                if files::present(&files::safe_path(&self.root, &[selection::TRANSITION], false, true)?)? {
                    return Ok(false);
                }
                let receipt = selection::read_receipt(&self.root)?;
                let file = files::safe_path(&self.root, &["vaults", vault_id, "vault.sqlite"], false, false)?;
                let found = files::identity(&file)?;
                Ok(selection::read_pointer(&self.root)? == *vault_id && receipt.committed && receipt.vault_id == *vault_id && receipt.key_id == *key_id
                    && (found.volume, found.index) == (identity.volume, identity.index))
            }
            Storage::RecoveryRequired { .. } | Storage::Running { .. } => Ok(false),
        }
    }

    /// assertVaultStorage. While a switch runs there is no vault to fail, so it only waits.
    fn assert_current(&self) -> Result<()> {
        if matches!(*self.storage(), Storage::Running { .. }) {
            return Err(VaultError::conflict(SWITCH_PENDING));
        }
        if self.failed.load(Ordering::SeqCst) || !self.context_is_current().unwrap_or(false) {
            return Err(self.fail());
        }
        Ok(())
    }

    /// assertVaultMaintenanceReady
    fn assert_maintenance_ready(&self) -> Result<()> {
        if self.switching.load(Ordering::SeqCst) {
            return Err(VaultError::conflict(SWITCH_PENDING));
        }
        if self.is_recovery_required() { Err(VaultError::new(503, "保管庫の復旧を先に完了してください")) } else { Ok(()) }
    }

    fn is_configured(&self) -> Result<bool> {
        Ok(!matches!(*self.storage(), Storage::Empty { .. }))
    }

    // ---- Status and session.

    /// getVaultStatus
    pub fn status(&self) -> Result<Value> {
        let state = self.session_at(|session, now| session.state(now));
        let maintenance = match &*self.storage() {
            Storage::Empty { .. } | Storage::V2 { .. } => json!({ "state": "ready", "format": "v2" }),
            Storage::RecoveryRequired { operation } => {
                let mut state = json!({ "state": "recovery-required", "format": "unknown", "operation": "recover" });
                if let Some(operation) = operation {
                    state["recoveryOperation"] = json!(operation);
                }
                state
            }
            Storage::Running { format, operation, source_session_id } => json!({ "state": "running", "format": format, "operation": operation, "sourceSessionId": source_session_id }),
        };
        let mut status = json!({ "isConfigured": self.is_configured()?, "sessionId": state.session_id, "isUnlocked": state.is_unlocked, "idleTimeoutMs": IDLE_TIMEOUT.as_millis() as u64 });
        if let Some(reason) = state.lock_reason {
            status["lockReason"] = json!(reason.as_str());
        }
        status["maintenance"] = maintenance;
        if matches!(*self.storage(), Storage::Empty { legacy_found: true }) {
            status["legacyVaultFound"] = json!(true);
        }
        Ok(status)
    }

    /// Destroys an expired key even when the screen sends nothing. The desktop calls it every second.
    pub fn expire(&self) {
        self.session_at(|session, now| session.expire(now));
    }

    /// A lock the app decided on, such as closing the window. It also cancels an unlock in progress,
    /// because the session id changes even when the vault is already locked.
    pub fn lock_for(&self, reason: LockReason) {
        self.session.lock().unwrap().lock(reason);
    }

    fn require_generation(&self, expected: &str) -> Result<()> {
        self.session_at(|session, now| session.require_generation(expected, now))
    }

    fn require_unlocked(&self, expected: Option<&str>) -> Result<String> {
        self.session_at(|session, now| session.require_unlocked(expected, now))
    }

    fn key(&self, session: &str) -> Result<Secret> {
        self.session_at(|current, now| current.key(session, now))
    }

    fn install_key(&self, key: Secret) {
        self.session_at(|session, now| session.unlock(key, now));
    }

    /// requireUnlockedVault in entry-service.ts.
    fn require_unlocked_vault(&self, expected: Option<&str>) -> Result<String> {
        let session = self.require_unlocked(expected)?;
        self.assert_current()?;
        Ok(session)
    }

    /// handleControl in desktop-main.ts: the request must come from the current session.
    fn control<T>(&self, session_id: Option<&Value>, action: impl FnOnce() -> Result<T>) -> Result<T> {
        self.available()?;
        let expected = parse_session_id(session_id)?;
        self.require_generation(&expected)?;
        action()
    }

    /// handleSession in desktop-main.ts: the desktop's check runs inside withVaultSession, before
    /// and after the action.
    fn with_session<T>(&self, session_id: Option<&Value>, action: impl FnOnce(&str) -> Result<T>) -> Result<T> {
        self.within_session(session_id, |session| {
            self.available()?;
            let result = action(session)?;
            self.available()?;
            Ok(result)
        })
    }

    /// withVaultSession: the vault is unlocked by this session before and after the action.
    fn within_session<T>(&self, session_id: Option<&Value>, action: impl FnOnce(&str) -> Result<T>) -> Result<T> {
        let expected = parse_session_id(session_id)?;
        let session = self.require_unlocked(Some(&expected))?;
        let result = action(&session)?;
        self.require_unlocked(Some(&session))?;
        Ok(result)
    }

    /// The clipboard:writeText handler. `copy` writes the text and must call `current` before and
    /// after writing; it fails when the screen lock or a change of session arrived in between.
    pub fn copy_text(&self, session_id: Option<&Value>, value: Option<&Value>, copy: impl FnOnce(&str, &dyn Fn() -> Result<()>) -> Result<()>) -> Result<Value> {
        self.within_session(session_id, |session| {
            self.available()?;
            let text = input::parse_clipboard_text(value)?;
            copy(text, &|| {
                self.available()?;
                self.require_unlocked(Some(session)).map(|_| ())
            })?;
            Ok(Value::Null)
        })
    }

    /// recordVaultActivity
    pub fn record_activity(&self, session_id: Option<&Value>) -> Result<Value> {
        self.available()?;
        let expected = parse_session_id(session_id)?;
        self.session_at(|session, now| session.record_activity(&expected, now))?;
        self.status()
    }

    /// lockVaultForSession
    pub fn lock(&self, session_id: Option<&Value>) -> Result<Value> {
        let expected = parse_session_id(session_id)?;
        self.require_generation(&expected)?;
        self.lock_for(LockReason::Manual);
        self.status()
    }

    // ---- Setup, unlock and reset.

    /// setupVault: creates the first vault, a v2 vault selected by its pointer files, and unlocks
    /// it. A lock during the key derivation stops it before anything is written; a lock after
    /// that leaves the new vault selected and locked.
    pub fn setup(&self, session_id: Option<&Value>, payload: Option<&Value>) -> Result<Value> {
        self.control(session_id, || {
            self.assert_maintenance_ready()?;
            self.assert_current()?;
            if self.is_configured()? {
                return Err(VaultError::conflict("保管庫はすでに設定済みです"));
            }
            let password = Zeroizing::new(input::parse_master_password(payload, true)?);
            let intent = self.session_at(|session, now| session.id(now));
            self.guard.run(|| self.now().monotonic, || {
                let current = || -> Result<()> {
                    self.require_generation(&intent)?;
                    self.assert_current()
                };
                let created = maintenance::create(&self.root, &password, &|| current().map_err(maintenance::Stop::Error));
                let (_, root) = match created {
                    Ok(created) => created,
                    Err(maintenance::Stop::Error(error)) => return Err(error),
                    Err(_) => {
                        // A selection that was only partly written is found again here.
                        *self.storage.write().unwrap() = Arc::new(open_storage(&self.root).unwrap_or_else(|_| recovery_required(&self.root)));
                        return Err(VaultError::new(500, "保管庫を作成できませんでした"));
                    }
                };
                let opened = open_storage(&self.root)?;
                let ready = matches!(opened, Storage::V2 { .. });
                *self.storage.write().unwrap() = Arc::new(opened);
                if !ready {
                    return Err(self.fail());
                }
                self.require_generation(&intent)?;
                self.install_key(root);
                self.status()
            })
        })
    }

    /// unlockVault
    pub fn unlock(&self, session_id: Option<&Value>, payload: Option<&Value>) -> Result<Value> {
        self.control(session_id, || {
            self.assert_maintenance_ready()?;
            self.assert_current()?;
            let store = self.v2().ok_or_else(|| VaultError::bad_request("保管庫はまだ設定されていません"))?;
            self.unlock_v2(&store, payload)?;
            self.adopt_icon_file(&store);
            self.status()
        })
    }

    /// unlockV2Vault: no key is installed until every current entry authenticates and validates.
    fn unlock_v2(&self, store: &Mutex<V2Store>, payload: Option<&Value>) -> Result<()> {
        let password = Zeroizing::new(input::parse_master_password(payload, false)?);
        let intent = self.session_at(|session, now| session.id(now));
        let (slot, vault_id, key_id) = {
            let store = store.lock().unwrap();
            (store.password_slot().to_string(), store.vault_id().to_string(), store.key_id().to_string())
        };
        self.guard.run(|| self.now().monotonic, || {
            let settle = || -> Result<()> {
                self.require_generation(&intent)?;
                self.assert_current()
            };
            let root = match crypto::unwrap_v2_root(&slot, password.as_bytes(), &vault_id, &key_id, 1) {
                Ok(root) => root,
                Err(error) => {
                    settle()?;
                    return Err(if error == CryptoError::Authentication { VaultError::new(401, error::WRONG_PASSWORD) } else { self.fail() });
                }
            };
            settle()?;
            let verified = {
                let store = store.lock().unwrap();
                store.entries().and_then(|entries| {
                    entries.iter().try_for_each(|(id, _)| match store.read(&root, id)? {
                        Some(_) => Ok(()),
                        None => Err(StoreError::Conflict),
                    })
                })
            };
            settle()?;
            match verified {
                Ok(()) => {}
                Err(StoreError::Conflict) => return Err(not_found()),
                Err(_) => return Err(self.fail()),
            }
            self.install_key(root);
            Ok(())
        })
    }

    // ---- List icons. Each entry carries its own (format 4).

    /// Icons from releases up to v1.0.1 sat in a file beside the vault (icons.rs). The first unlock
    /// moves them into their entries and removes the file. The entries then need format 4, which
    /// those releases refuse, so a copy of the vault as it was is kept first as `before-v4.sqlite`
    /// beside it. Icons are a convenience: a failure leaves the file for the next unlock and the
    /// list without them, and says nothing.
    fn adopt_icon_file(&self, store: &Mutex<V2Store>) {
        let Storage::V2 { vault_id, .. } = &*self.storage() else { return };
        let Ok(session) = self.require_unlocked(None) else { return };
        let Ok(key) = self.key(&session) else { return };
        let found = icons::read(&self.root, &key, &icons::scope(vault_id));
        if !found.is_empty() {
            // An earlier copy is the older one and stays.
            if store.lock().unwrap().copy_beside(BEFORE_V4).is_err() {
                return;
            }
            let adopted = self.v2_mutation(store, |store, root, active| {
                for (id, icon) in &found {
                    let Some((mut entry, revision)) = store.read(root, id)? else { continue };
                    if entry.get("icon").is_some() {
                        continue;
                    }
                    entry["icon"] = icon.clone();
                    Self::write_v2(store, root, &entry, id, revision + 1, active)?;
                }
                Ok(())
            });
            if adopted.is_err() {
                return;
            }
        }
        icons::remove(&self.root);
    }

    /// Sets the icon of one entry, or removes it with null, and returns the entry as the list shows
    /// it. The entry changes revision but not its update date, since its content stays the same.
    pub fn set_entry_icon(&self, session_id: Option<&Value>, id: Option<&Value>, icon: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| {
            let id = input::parse_entry_id(id)?;
            let icon = match icon {
                None | Some(Value::Null) => None,
                Some(value) => Some(icons::parse_icon(value)?),
            };
            let store = self.store()?;
            self.v2_mutation(&store, |store, root, active| {
                let (mut entry, revision) = Self::read_v2(store, root, &id)?;
                let object = entry.as_object_mut().ok_or_else(invalid_entry)?;
                match icon {
                    Some(icon) => object.insert("icon".into(), icon),
                    None => object.remove("icon"),
                };
                Self::write_v2(store, root, &entry, &id, revision + 1, active)?;
                Ok(v2_summary(&entry))
            })
        })
    }

    // ---- Entries.

    /// readOperation in v2-vault-service.ts. A lock or switch reports itself even when the action
    /// failed for another reason first.
    ///
    /// A write is refused while another one runs, before it waits for the store, so that no
    /// request waits in memory with its secrets.
    ///
    /// Every step checks the session. A write also checks the vault's files at every step, since
    /// nothing may be written after a switch. A read of many entries would spend most of its time
    /// on those checks, so between its first and last step it looks at the files only now and then;
    /// the last check still comes before anything is returned.
    fn v2_operation<T>(&self, store: &Mutex<V2Store>, write: bool, action: impl FnOnce(&mut V2Store, &[u8], &dyn Fn() -> Result<()>) -> std::result::Result<T, Failure>) -> Result<T> {
        let session = self.require_unlocked(None)?;
        self.assert_current()?;
        let active = || -> Result<()> {
            self.require_unlocked(Some(&session))?;
            self.assert_current()
        };
        let checked = std::cell::Cell::new(Instant::now());
        let reading = || -> Result<()> {
            self.require_unlocked(Some(&session))?;
            if checked.get().elapsed() >= READ_CONTEXT_INTERVAL {
                self.assert_current()?;
                checked.set(Instant::now());
            }
            Ok(())
        };
        let key = self.key(&session)?;
        let result = if !write {
            action(&mut store.lock().unwrap(), &key, &reading)
        } else if let Some(_writing) = active().ok().and_then(|()| Busy::claim(&self.writing)) {
            action(&mut store.lock().unwrap(), &key, &active)
        } else {
            Err(StoreError::Conflict.into())
        };
        active()?;
        result.map_err(|failure| match failure {
            Failure::User(error) => error,
            Failure::Store(StoreError::Conflict) => VaultError::conflict(error::WRITE_CONFLICT),
            Failure::Store(StoreError::KeyLimit) => VaultError::conflict(error::KEY_LIMIT),
            Failure::Store(StoreError::EntryLimit) => VaultError::too_large(error::ENTRY_LIMIT),
            Failure::Store(StoreError::Cancelled) => changed(),
            Failure::Store(StoreError::Invalid) => self.fail(),
        })
    }

    /// mutation in v2-vault-service.ts.
    fn v2_mutation<T>(&self, store: &Mutex<V2Store>, action: impl FnOnce(&mut V2Store, &[u8], &dyn Fn() -> Result<()>) -> std::result::Result<T, Failure>) -> Result<T> {
        self.v2_operation(store, true, action)
    }

    fn v2(&self) -> Option<Arc<Mutex<V2Store>>> {
        match &*self.storage() {
            Storage::V2 { store, .. } => Some(store.clone()),
            _ => None,
        }
    }

    /// The open vault for an operation of an unlocked session. Only a v2 vault can be unlocked,
    /// so without one the session is locked or the vault is switching.
    fn store(&self) -> Result<Arc<Mutex<V2Store>>> {
        self.require_unlocked(None)?;
        self.assert_current()?;
        self.v2().ok_or_else(|| self.fail())
    }

    fn read_v2(store: &V2Store, root: &[u8], id: &str) -> std::result::Result<(Value, u64), Failure> {
        store.read(root, id)?.ok_or_else(|| not_found().into())
    }

    fn write_v2(store: &mut V2Store, root: &[u8], entry: &Value, id: &str, revision: u64, active: &dyn Fn() -> Result<()>) -> std::result::Result<(), Failure> {
        input::validate_stored_entry(entry, id).map_err(|_| invalid_entry())?;
        Ok(store.write(root, entry, id, revision, &|| active().map_err(|_| StoreError::Cancelled))?)
    }

    /// listEntries. A list never carries secrets.
    pub fn list_entries(&self, session_id: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| self.entry_list())
    }

    /// listEntries without the session wrapper, which the backup also uses.
    fn entry_list(&self) -> Result<Value> {
        let store = self.store()?;
        self.v2_operation(&store, false, |store, root, active| {
            let mut items = Vec::new();
            for (id, _) in store.entries()? {
                active()?;
                items.push(v2_summary(&Self::read_v2(store, root, &id)?.0));
            }
            list_order(&mut items);
            Ok(json!({ "items": items }))
        })
    }

    /// Every entry of a v2 vault in list order, read and opened once in one operation. The backup
    /// and the audit need them all, and one operation per entry would check the vault's files and
    /// open each entry again every time.
    fn v2_entries(&self, store: &Mutex<V2Store>) -> Result<Vec<Value>> {
        self.v2_operation(store, false, |store, root, active| {
            let mut entries = Vec::new();
            for (id, _) in store.entries()? {
                active()?;
                entries.push(Self::read_v2(store, root, &id)?.0);
            }
            list_order(&mut entries);
            Ok(entries)
        })
    }

    /// getEntryById
    pub fn get_entry(&self, session_id: Option<&Value>, id: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| self.entry(id))
    }

    /// getEntryById without the session wrapper, which the backup also uses.
    fn entry(&self, id: Option<&Value>) -> Result<Value> {
        let store = self.store()?;
        self.v2_operation(&store, false, |store, root, _| Ok(Self::read_v2(store, root, &input::parse_entry_id(id)?)?.0))
    }

    /// createEntry
    pub fn create_entry(&self, session_id: Option<&Value>, payload: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| {
            let store = self.store()?;
            let fields = input::parse_vault_entry(payload)?;
            self.v2_mutation(&store, |store, root, active| {
                if store.entries()?.len() >= MAX_ENTRIES {
                    return Err(VaultError::too_large(error::ENTRY_LIMIT).into());
                }
                let now = now_iso();
                let id = Uuid::new_v4().to_string();
                let changed = fields.get("type").is_none().then(|| json!(now));
                let entry = v2_entry(&id, &fields, &json!(now), &now, changed);
                Self::write_v2(store, root, &entry, &id, 1, active)?;
                Ok(entry)
            })
        })
    }

    /// updateEntry. The password change date moves only when the password changes.
    pub fn update_entry(&self, session_id: Option<&Value>, id: Option<&Value>, payload: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| {
            let store = self.store()?;
            let id = input::parse_entry_id(id)?;
            let fields = input::parse_vault_entry(payload)?;
            self.v2_mutation(&store, |store, root, active| {
                let (existing, revision) = Self::read_v2(store, root, &id)?;
                let now = not_before(&existing["updatedAt"]);
                let kind = |value: &Value| value["type"].as_str().unwrap_or("login").to_string();
                if kind(&existing) != kind(&fields) {
                    return Err(VaultError::bad_request("保存済みの項目の種類は変更できません").into());
                }
                let changed = fields.get("type").is_none().then(|| if existing["password"] == fields["password"] { existing["passwordChangedAt"].clone() } else { json!(now) });
                let mut entry = v2_entry(&id, &fields, &existing["createdAt"], &now, changed);
                if let Some(icon) = existing.get("icon") {
                    entry["icon"] = icon.clone();
                }
                Self::write_v2(store, root, &entry, &id, revision + 1, active)?;
                Ok(entry)
            })
        })
    }

    /// deleteEntry. The entry keeps its id and revision as a tombstone.
    pub fn delete_entry(&self, session_id: Option<&Value>, id: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| {
            let store = self.store()?;
            // The app's delete runs as a read whose store refuses it during a write.
            self.v2_operation(&store, true, |store, root, active| {
                let id = input::parse_entry_id(id)?;
                let (_, revision) = Self::read_v2(store, root, &id)?;
                active()?;
                store.delete(&id, revision, &|| active().map_err(|_| StoreError::Cancelled))?;
                Ok(json!({ "success": true }))
            })
        })
    }

    /// setEntriesGroup. Each entry has its own envelope, so an unknown id fails before any write,
    /// and a later failure keeps the entries already rewritten.
    pub fn set_entries_group(&self, session_id: Option<&Value>, payload: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| {
            let store = self.store()?;
            let (ids, group) = input::parse_group_payload(payload)?;
            let group = json!(group);
            self.v2_mutation(&store, |store, root, active| {
                for id in &ids {
                    store.revision(id)?.ok_or_else(not_found)?;
                }
                let mut updated = 0;
                for id in &ids {
                    let (mut entry, revision) = Self::read_v2(store, root, id)?;
                    if entry["group"] == group {
                        continue;
                    }
                    entry["group"] = group.clone();
                    entry["updatedAt"] = json!(not_before(&entry["updatedAt"]));
                    Self::write_v2(store, root, &entry, id, revision + 1, active)?;
                    updated += 1;
                }
                Ok(json!({ "updatedCount": updated }))
            })
        })
    }

    /// generatePassword
    pub fn generate_password(&self, session_id: Option<&Value>, options: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| password::generate_password(options))
    }

    // ---- Backups.

    /// withBackupKey in backup-service.ts: one backup at a time, and the vault must still be
    /// unlocked by the same session once the slow key derivation is done.
    fn with_backup_key<T>(&self, passphrase: &str, salt: &[u8], action: impl FnOnce(&Secret) -> Result<T>) -> Result<T> {
        self.require_unlocked_vault(None)?;
        let _busy = Busy::claim(&self.backing_up).ok_or_else(|| VaultError::conflict("バックアップ処理の完了を待ってください"))?;
        let session = self.require_unlocked(None)?;
        let key = crypto::derive_strong_key(passphrase.as_bytes(), salt).map_err(|_| VaultError::new(500, KDF_FAILED))?;
        self.require_unlocked_vault(None)?;
        self.require_unlocked(Some(&session))?;
        let result = action(&key)?;
        self.require_unlocked_vault(Some(&session))?;
        Ok(result)
    }

    /// exportBackup: every entry, sealed with a key from the passphrase, as a `.cvault` file the
    /// screen saves.
    pub fn export_backup(&self, session_id: Option<&Value>, payload: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| {
            self.require_unlocked_vault(None)?;
            let (passphrase, _) = input::parse_backup_payload(payload, false)?;
            let passphrase = Zeroizing::new(passphrase);
            let salt = random_bytes::<16>()?;
            self.with_backup_key(&passphrase, salt.as_ref(), |key| {
                let store = self.store()?;
                let entries = self.v2_entries(&store)?;
                if entries.len() > MAX_ENTRIES {
                    return Err(VaultError::bad_request("バックアップは10000件まで対応しています"));
                }
                let content = backup::encode(entries, key, salt.as_ref(), random_bytes::<12>()?.as_ref())?;
                Ok(json!({ "fileName": backup::file_name(&now_iso()), "content": content }))
            })
        })
    }

    /// restoreBackup: only into an empty vault, keeping each entry's id and dates. Every backup
    /// version, also one an earlier release wrote, comes into the current format.
    pub fn restore_backup(&self, session_id: Option<&Value>, payload: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| {
            self.require_unlocked_vault(None)?;
            let (passphrase, content) = input::parse_backup_payload(payload, true)?;
            let passphrase = Zeroizing::new(passphrase);
            if self.entry_list()?["items"].as_array().is_some_and(|items| !items.is_empty()) {
                return Err(VaultError::conflict(EMPTY_ONLY));
            }
            let envelope = backup::parse(&content.unwrap_or_default())?;
            self.with_backup_key(&passphrase, &envelope.salt, |key| {
                let entries = backup::decode(&envelope, key)?;
                self.restore_entries(&entries)
            })
        })
    }

    /// restoreEntriesIntoEmptyVault
    fn restore_entries(&self, entries: &[Value]) -> Result<Value> {
        let store = self.store()?;
        for entry in entries {
            input::validate_stored_entry(entry, entry["id"].as_str().unwrap_or_default()).map_err(|_| invalid_entry())?;
        }
        let count = self.v2_mutation(&store, |store, root, active| Ok(store.restore(root, entries, &|| active().map_err(|_| StoreError::Cancelled))?))?;
        Ok(json!({ "restoredCount": count }))
    }

    /// auditVault in audit-service.ts: the logins are scored in this process, and the result holds
    /// no secrets. The vault must stay with the same session while the audit runs.
    pub fn audit_vault(&self, session_id: Option<&Value>) -> Result<Value> {
        self.with_session(session_id, |_| {
            self.require_unlocked_vault(None)?;
            let _busy = Busy::claim(&self.auditing).ok_or_else(|| VaultError::conflict("監査の完了を待ってください"))?;
            let session = self.require_unlocked(None)?;
            let now = Utc::now().timestamp_millis();
            let rows = self.audit_rows()?;
            let result = audit::assess(&rows, now, || {
                if self.require_unlocked_vault(None)? != session {
                    return Err(VaultError::conflict("保管庫の状態が変わりました。もう一度解析してください"));
                }
                Ok(())
            })?;
            self.require_unlocked_vault(Some(&session))?;
            Ok(result)
        })
    }

    /// The logins to audit, in list order. API keys, cards and bank accounts are left out, as
    /// their secrets are not passwords.
    fn audit_rows(&self) -> Result<Vec<audit::Row>> {
        let store = self.store()?;
        let logins = self.v2_entries(&store)?.into_iter().filter(|entry| !matches!(entry["type"].as_str(), Some("apiKey" | "creditCard" | "financial")));
        Ok(logins
            .map(|mut entry| {
                let text = |field: &str| entry[field].as_str().map(str::to_string);
                let (id, service_name, login_id, url, updated_at, password_changed_at) =
                    (text("id"), text("serviceName"), text("loginId"), text("url"), text("updatedAt"), text("passwordChangedAt"));
                let password = match entry["password"].take() {
                    Value::String(password) => Zeroizing::new(password),
                    _ => Zeroizing::new(String::new()),
                };
                audit::Row {
                    id: id.unwrap_or_default(),
                    service_name: service_name.unwrap_or_default(),
                    login_id: login_id.unwrap_or_default(),
                    password,
                    url,
                    updated_at: updated_at.unwrap_or_default(),
                    password_changed_at,
                }
            })
            .collect())
    }
}

fn list_order(items: &mut [Value]) {
    let text = |value: &Value, field: &str| value[field].as_str().unwrap_or_default().to_string();
    items.sort_by(|a, b| text(b, "updatedAt").cmp(&text(a, "updatedAt")).then_with(|| locale_order(&text(a, "id"), &text(b, "id"))));
}

/// String.prototype.localeCompare for entry ids, which hold only ASCII hex digits and dashes. ICU
/// compares letters without case first and then puts lowercase before uppercase, so a restored
/// uppercase id sorts as Node sorts it. Dashes, digits and letters keep their ASCII order.
fn locale_order(left: &str, right: &str) -> std::cmp::Ordering {
    let folded = |text: &str| text.to_ascii_lowercase();
    let case = |text: &str| text.bytes().map(|byte| byte.is_ascii_uppercase()).collect::<Vec<_>>();
    folded(left).cmp(&folded(right)).then_with(|| case(left).cmp(&case(right)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::TemporaryDirectory;
    use crate::v2::tests::{s, v2_directory};
    use std::sync::Arc;
    use std::time::Duration;

    const MASTER: &str = "synthetic-master-password";

    #[test]
    fn ids_sort_as_locale_compare_sorts_them() {
        // The order Node prints for ["AAAAAAAA-…02", "aaaaaaaa-…01", "Aaaaaaaa-…01", "baaaaaaa-…01"].sort(localeCompare)
        let expected = ["aaaaaaaa-0000-4000-8000-000000000001", "Aaaaaaaa-0000-4000-8000-000000000001", "AAAAAAAA-0000-4000-8000-000000000002", "baaaaaaa-0000-4000-8000-000000000001"];
        let mut ids = [expected[2], expected[3], expected[1], expected[0]];
        ids.sort_by(|a, b| locale_order(a, b));
        assert_eq!(ids, expected);
    }


    fn id(status: &Value) -> Value {
        status["sessionId"].clone()
    }

    fn some(value: &Value) -> Option<&Value> {
        Some(value)
    }

    fn password(text: &str) -> Value {
        json!({ "masterPassword": text })
    }

    fn unlocked(vault: &Vault, master: &str) -> Value {
        let status = vault.status().unwrap();
        vault.unlock(some(&id(&status)), some(&password(master))).unwrap()
    }

    /// A vault made by setup in a new directory, unlocked, with its session.
    fn created() -> (TemporaryDirectory, Vault, Value) {
        let directory = TemporaryDirectory::new();
        let vault = Vault::open(&directory.0).unwrap();
        let status = vault.status().unwrap();
        let session = id(&vault.setup(some(&id(&status)), some(&password(MASTER))).unwrap());
        (directory, vault, session)
    }

    fn login() -> Value {
        json!({ "serviceName": " 合成サービス ", "loginId": " synthetic-login ", "password": " synthetic-secret ", "notes": "synthetic-notes", "url": " https://example.test ", "tags": ["a", " b "], "group": " g " })
    }

    /// A clock the test moves by hand.
    fn manual_clock() -> (Arc<Mutex<Duration>>, Clock) {
        let start = Stamp::now();
        let offset = Arc::new(Mutex::new(Duration::ZERO));
        let shared = Arc::clone(&offset);
        let clock: Clock = Box::new(move || {
            let offset = *shared.lock().unwrap();
            Stamp { monotonic: start.monotonic + offset, wall: start.wall + offset }
        });
        (offset, clock)
    }

    #[test]
    fn setup_creates_a_v2_vault_selected_by_its_pointer() {
        let directory = TemporaryDirectory::new();
        let vault = Vault::open(&directory.0).unwrap();
        let first = vault.status().unwrap();
        assert_eq!(first["isConfigured"], false);
        assert_eq!(first["maintenance"], json!({ "state": "ready", "format": "v2" }));
        assert!(first.get("legacyVaultFound").is_none());
        assert_eq!(first["lockReason"], "manual", "opening the storage locks once, as in the app");
        assert_eq!(vault.unlock(some(&id(&first)), some(&password(MASTER))).unwrap_err(), VaultError::bad_request("保管庫はまだ設定されていません"));
        assert_eq!(vault.setup(some(&id(&first)), some(&password("short"))).unwrap_err(), VaultError::bad_request("マスターパスワードは12文字以上で入力してください"));
        assert_eq!(vault.setup(some(&json!("stale")), some(&password(MASTER))).unwrap_err(), changed());
        assert_eq!(vault.setup(None, some(&password(MASTER))).unwrap_err(), VaultError::conflict("保管庫の状態を再取得してください"));
        assert!(!directory.0.join(selection::POINTER).exists(), "a refused setup writes nothing");

        let set = vault.setup(some(&id(&first)), some(&password(MASTER))).unwrap();
        assert_eq!((set["isConfigured"].clone(), set["isUnlocked"].clone()), (json!(true), json!(true)));
        assert_ne!(id(&set), id(&first), "unlocking starts a new session");
        let selected = selection::inspect(&directory.0).unwrap();
        assert!(matches!(selected, Selection::V2 { .. }), "{selected:?}");
        assert!(!directory.0.join(selection::LEGACY_DATABASE).exists(), "no legacy file is made");
        assert_eq!(vault.setup(some(&id(&set)), some(&password(MASTER))).unwrap_err(), VaultError::conflict("保管庫はすでに設定済みです"));
        let created = vault.create_entry(some(&id(&set)), some(&login())).unwrap();

        assert_eq!(vault.lock(some(&id(&first))).unwrap_err(), changed());
        let locked = vault.lock(some(&id(&set))).unwrap();
        assert_eq!((locked["isUnlocked"].clone(), locked["lockReason"].clone()), (json!(false), json!("manual")));
        assert_eq!(vault.unlock(some(&id(&locked)), some(&password("wrong-master-password"))).unwrap_err(), VaultError::new(401, error::WRONG_PASSWORD));
        assert_eq!(vault.unlock(some(&id(&locked)), some(&json!({ "masterPassword": 1 }))).unwrap_err().message, "マスターパスワードは文字列で指定してください");
        drop(vault);
        let reopened = Vault::open(&directory.0).unwrap();
        let again = unlocked(&reopened, MASTER);
        assert_eq!(again["isUnlocked"], true);
        assert!(again.get("lockReason").is_none());
        assert_eq!(reopened.get_entry(some(&id(&again)), some(&created["id"])).unwrap(), created);
    }

    #[test]
    fn a_lock_during_setup_writes_nothing() {
        let directory = TemporaryDirectory::new();
        let vault = Arc::new(Vault::open(&directory.0).unwrap());
        let session = id(&vault.status().unwrap());
        let creating = {
            let vault = Arc::clone(&vault);
            std::thread::spawn(move || vault.setup(Some(&session), Some(&password(MASTER))))
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !vault.guard.is_busy() {
            assert!(std::time::Instant::now() < deadline, "the setup never started");
            std::thread::yield_now();
        }
        vault.lock_for(LockReason::Suspend);
        assert_eq!(creating.join().unwrap().unwrap_err(), changed());
        assert_eq!(vault.status().unwrap()["isConfigured"], false);
        assert!(selection::is_unclaimed(&directory.0).unwrap(), "no state file was written");
    }

    #[test]
    fn a_legacy_file_is_reported_and_left_alone() {
        let directory = TemporaryDirectory::new();
        std::fs::write(directory.0.join(selection::LEGACY_DATABASE), b"synthetic-legacy-bytes").unwrap();
        let vault = Vault::open(&directory.0).unwrap();
        let status = vault.status().unwrap();
        assert_eq!((status["isConfigured"].clone(), status["legacyVaultFound"].clone()), (json!(false), json!(true)));
        let set = vault.setup(some(&id(&status)), some(&password(MASTER))).unwrap();
        assert!(set.get("legacyVaultFound").is_none(), "only an empty directory reports it");
        assert_eq!(std::fs::read(directory.0.join(selection::LEGACY_DATABASE)).unwrap(), b"synthetic-legacy-bytes");
    }

    #[test]
    fn checks_from_several_threads_never_look_like_a_clock_moving_backwards() {
        let (directory, _, v2) = v2_directory();
        let vault = Vault::open(&directory.0).unwrap();
        let session = id(&unlocked(&vault, s(&v2["masterPassword"])));
        // The desktop's watchdog and the commands check the session at the same time.
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..50_000 {
                        vault.expire();
                        let _ = vault.is_unlocked();
                    }
                });
            }
        });
        let status = vault.status().unwrap();
        assert_eq!((status["isUnlocked"].clone(), status.get("lockReason")), (json!(true), None));
        assert_eq!(id(&status), session);
    }


    #[test]
    fn a_switch_waits_for_a_call_that_still_holds_the_closed_vault() {
        let (directory, _, _v2) = v2_directory();
        let vault = Vault::open(&directory.0).unwrap();
        let held = vault.v2().unwrap();
        let file = Arc::downgrade(&held);
        let previous = std::mem::replace(&mut *vault.storage.write().unwrap(), Arc::new(Storage::RecoveryRequired { operation: None }));
        std::thread::scope(|scope| {
            scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                drop(held);
            });
            switch::release(previous);
        });
        assert!(file.upgrade().is_none(), "the file is closed before the switch reads it");
    }

    #[test]
    fn logins_are_created_changed_grouped_and_deleted_like_the_app() {
        let (directory, vault, session) = created();
        let created = vault.create_entry(some(&session), some(&login())).unwrap();
        assert_eq!(created["serviceName"], "合成サービス");
        assert_eq!(created["password"], " synthetic-secret ", "secrets are kept exactly");
        assert_eq!((created["url"].clone(), created["group"].clone(), created["tags"].clone()), (json!("https://example.test"), json!("g"), json!(["a", " b "])));
        assert_eq!(created["passwordChangedAt"], created["createdAt"]);
        let sealed = |vault_files: &std::path::Path| {
            std::fs::read_dir(vault_files.join("vaults")).unwrap().flatten().all(|folder| {
                let bytes = std::fs::read(folder.path().join("vault.sqlite")).unwrap();
                !["synthetic-secret", "synthetic-notes", "synthetic-login", "合成サービス"].iter().any(|text| bytes.windows(text.len()).any(|window| window == text.as_bytes()))
            })
        };
        assert!(sealed(&directory.0), "every field is sealed, also the names");

        let second = vault.create_entry(some(&session), some(&json!({ "serviceName": "second", "loginId": "second-login", "password": "x" }))).unwrap();
        let list = vault.list_entries(some(&session)).unwrap();
        let items = list["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|item| item.get("password").is_none() && item.get("notes").is_none()), "a list never carries secrets");

        let mut changed_login = login();
        changed_login["serviceName"] = json!("変更後");
        changed_login["notes"] = json!("");
        std::thread::sleep(Duration::from_millis(5));
        let updated = vault.update_entry(some(&session), some(&created["id"]), some(&changed_login)).unwrap();
        assert_eq!(updated["passwordChangedAt"], created["passwordChangedAt"], "the same password keeps its change date");
        assert_eq!(updated["notes"], "");
        changed_login["password"] = json!("another-synthetic-secret");
        std::thread::sleep(Duration::from_millis(5));
        let repassworded = vault.update_entry(some(&session), some(&created["id"]), some(&changed_login)).unwrap();
        assert_eq!(repassworded["passwordChangedAt"], repassworded["updatedAt"]);
        assert_eq!(vault.update_entry(some(&session), some(&json!("missing")), some(&login())).unwrap_err(), not_found());
        assert_eq!(vault.get_entry(some(&session), some(&json!(""))).unwrap_err(), VaultError::bad_request("エントリIDの形式が正しくありません"));

        let refused = vault.set_entries_group(some(&session), some(&json!({ "ids": [second["id"], "missing"], "group": "new" }))).unwrap_err();
        assert_eq!(refused, not_found());
        assert_eq!(vault.get_entry(some(&session), some(&second["id"])).unwrap()["group"], Value::Null, "an unknown id fails before any write");
        let grouped = vault.set_entries_group(some(&session), some(&json!({ "ids": [second["id"], created["id"]], "group": "g" }))).unwrap();
        assert_eq!(grouped, json!({ "updatedCount": 1 }), "an entry already in the group is not rewritten");

        assert_eq!(vault.delete_entry(some(&session), some(&created["id"])).unwrap(), json!({ "success": true }));
        assert_eq!(vault.delete_entry(some(&session), some(&created["id"])).unwrap_err(), not_found());
        let password = vault.generate_password(some(&session), None).unwrap();
        assert_eq!(password["password"].as_str().unwrap().len(), 20);
    }

    #[test]
    fn entry_icons_live_in_their_entries_and_raise_the_format() {
        let (_directory, vault, session) = created();
        let first = vault.create_entry(some(&session), some(&login())).unwrap();
        let symbol = json!({ "kind": "symbol", "symbol": "bank", "color": "violet" });
        let set = vault.set_entry_icon(some(&session), some(&first["id"]), some(&symbol)).unwrap();
        assert_eq!((&set["icon"], &set["updatedAt"]), (&symbol, &first["updatedAt"]), "the summary carries the icon and keeps its date");
        assert_eq!(vault.set_entry_icon(some(&session), some(&json!("missing")), some(&symbol)).unwrap_err(), not_found());
        assert_eq!(vault.set_entry_icon(some(&session), some(&first["id"]), some(&json!({ "kind": "symbol" }))).unwrap_err().status, 400);
        let changed = vault.update_entry(some(&session), some(&first["id"]), some(&json!({ "serviceName": "Renamed", "loginId": "user", "password": "synthetic-password", "notes": "", "url": "", "tags": [], "group": null }))).unwrap();
        assert_eq!(changed["icon"], symbol, "a change of the fields keeps the icon");
        assert_eq!(vault.list_entries(some(&session)).unwrap()["items"][0]["icon"], symbol);
        let removed = vault.set_entry_icon(some(&session), some(&first["id"]), None).unwrap();
        assert!(removed.get("icon").is_none(), "null removes the icon");
        let store = vault.v2().unwrap();
        let version: i64 = store.lock().unwrap().connection().pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, 4, "an icon raises the format, and removing it never lowers it");
    }

    #[test]
    fn icons_of_the_old_file_move_into_their_entries_after_a_copy_of_the_vault() {
        let (directory, vault, session) = created();
        let first = vault.create_entry(some(&session), some(&login())).unwrap()["id"].clone();
        let symbol = json!({ "kind": "symbol", "symbol": "bank", "color": "violet" });
        let key = vault.key(s(&session)).unwrap();
        let Storage::V2 { vault_id, .. } = &*vault.storage() else { panic!("a v2 vault") };
        let mut old = Map::new();
        old.insert(s(&first).to_string(), symbol.clone());
        old.insert("deleted-entry".into(), symbol.clone());
        icons::write(&directory.0, &key, &icons::scope(vault_id), &old).unwrap();
        let relocked = id(&vault.lock(some(&session)).unwrap());
        let session = id(&vault.unlock(some(&relocked), some(&password(MASTER))).unwrap());
        assert_eq!(vault.get_entry(some(&session), some(&first)).unwrap()["icon"], symbol);
        assert!(!directory.0.join(icons::FILE).exists(), "the old file is removed");
        let copies: Vec<_> = walk(&directory.0).into_iter().filter(|path| path.ends_with(BEFORE_V4)).collect();
        assert_eq!(copies.len(), 1, "the vault as it was is kept beside it");
        let copy = rusqlite::Connection::open(&copies[0]).unwrap();
        let version: i64 = copy.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, 1, "the copy still opens in older releases");
    }

    fn walk(directory: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(directory).unwrap().flatten().flat_map(|item| if item.path().is_dir() { walk(&item.path()) } else { vec![item.path()] }).collect()
    }

    #[test]
    fn reading_a_whole_v2_vault_does_not_check_its_files_for_every_entry() {
        let (directory, _, v2) = v2_directory();
        let vault = Vault::open(&directory.0).unwrap();
        let session = id(&unlocked(&vault, s(&v2["masterPassword"])));
        for _ in 0..30 {
            vault.create_entry(some(&session), some(&login())).unwrap();
        }
        let checks = |action: &dyn Fn() -> Value| {
            vault.context_checks.store(0, Ordering::SeqCst);
            (action(), vault.context_checks.load(Ordering::SeqCst))
        };
        let (list, listing) = checks(&|| vault.list_entries(some(&session)).unwrap());
        assert_eq!(list["items"].as_array().unwrap().len(), 31);
        let (backup, exporting) = checks(&|| vault.export_backup(some(&session), some(&json!({ "passphrase": "synthetic-backup-passphrase" }))).unwrap());
        let (audit, auditing) = checks(&|| vault.audit_vault(some(&session)).unwrap());
        assert_eq!(audit["total"], 31);
        // One check per entry would be at least 31 each; the scrypt of the backup takes a moment.
        assert!(listing < 10 && exporting < 20 && auditing < 20, "{listing} {exporting} {auditing}");

        // The backup still holds every entry, in list order.
        let envelope = backup::parse(s(&backup["content"])).unwrap();
        let key = crypto::derive_strong_key(b"synthetic-backup-passphrase", &envelope.salt).unwrap();
        let ids = |items: &[Value]| items.iter().map(|item| item["id"].clone()).collect::<Vec<_>>();
        assert_eq!(ids(&backup::decode(&envelope, &key).unwrap()), ids(list["items"].as_array().unwrap()));
    }

    #[test]
    fn v2_entries_keep_their_kind_and_revisions() {
        let (directory, _, v2) = v2_directory();
        let vault = Vault::open(&directory.0).unwrap();
        let first = vault.status().unwrap();
        assert_eq!((first["isConfigured"].clone(), first["maintenance"]["format"].clone()), (json!(true), json!("v2")));
        assert_eq!(vault.setup(some(&id(&first)), some(&password(MASTER))).unwrap_err(), VaultError::conflict("保管庫はすでに設定済みです"));
        assert_eq!(vault.unlock(some(&id(&first)), some(&password("wrong-master-password"))).unwrap_err().status, 401);
        let session = id(&unlocked(&vault, s(&v2["masterPassword"])));
        let expected: Value = serde_json::from_str(s(&v2["entryPlaintext"])).unwrap();
        assert_eq!(vault.get_entry(some(&session), some(&v2["entryId"])).unwrap(), expected);

        let key = json!({ "type": "apiKey", "serviceName": " API ", "apiKey": { "key": " synthetic-token ", "keyId": "", "expiresOn": "" } });
        let created = vault.create_entry(some(&session), some(&key)).unwrap();
        assert_eq!(created["apiKey"], json!({ "key": " synthetic-token ", "keyId": "", "expiresOn": null }));
        assert!(created.get("passwordChangedAt").is_none());
        let keys: Vec<&str> = created.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["id", "serviceName", "notes", "url", "tags", "group", "type", "apiKey", "createdAt", "updatedAt"], "the field order the app writes");
        assert_eq!(vault.update_entry(some(&session), some(&created["id"]), some(&login())).unwrap_err(), VaultError::bad_request("保存済みの項目の種類は変更できません"));

        let list = vault.list_entries(some(&session)).unwrap();
        let summary = list["items"].as_array().unwrap().iter().find(|item| item["id"] == created["id"]).unwrap().clone();
        assert_eq!(summary, json!({ "id": created["id"], "serviceName": "API", "tags": [], "group": null, "updatedAt": created["updatedAt"], "type": "apiKey" }));

        let grouped = vault.set_entries_group(some(&session), some(&json!({ "ids": [created["id"], v2["entryId"]], "group": "g" }))).unwrap();
        assert_eq!(grouped, json!({ "updatedCount": 2 }));
        assert_eq!(vault.set_entries_group(some(&session), some(&json!({ "ids": ["missing"], "group": "g" }))).unwrap_err(), not_found());
        assert_eq!(vault.delete_entry(some(&session), some(&created["id"])).unwrap(), json!({ "success": true }));
        assert_eq!(vault.get_entry(some(&session), some(&created["id"])).unwrap_err(), not_found());

        drop(vault);
        let reopened = Vault::open(&directory.0).unwrap();
        let session = id(&unlocked(&reopened, s(&v2["masterPassword"])));
        assert_eq!(reopened.list_entries(some(&session)).unwrap()["items"].as_array().unwrap().len(), 1, "the changes were saved");
    }

    #[test]
    fn repeated_wrong_passwords_slow_down_unlocking() {
        let (directory, _, v2) = v2_directory();
        let vault = Vault::open(&directory.0).unwrap();
        let session = id(&vault.status().unwrap());
        for _ in 0..5 {
            assert_eq!(vault.unlock(some(&session), some(&password("wrong-master-password"))).unwrap_err().status, 401);
        }
        let refused = vault.unlock(some(&session), some(&password(s(&v2["masterPassword"])))).unwrap_err();
        assert_eq!(refused, VaultError::new(429, "認証の失敗が続いています。1秒後にもう一度お試しください"));
        std::thread::sleep(Duration::from_millis(1050));
        assert!(vault.unlock(some(&session), some(&password(s(&v2["masterPassword"])))).unwrap()["isUnlocked"].as_bool().unwrap());
    }

    #[test]
    fn idle_time_locks_the_vault_and_activity_moves_the_deadline() {
        let (directory, _, v2) = v2_directory();
        let (offset, clock) = manual_clock();
        let vault = Vault::open_with_clock(&directory.0, clock).unwrap();
        let session = id(&unlocked(&vault, s(&v2["masterPassword"])));
        *offset.lock().unwrap() = Duration::from_secs(4 * 60);
        vault.record_activity(some(&session)).unwrap();
        *offset.lock().unwrap() = Duration::from_secs(8 * 60);
        vault.expire();
        assert_eq!(vault.status().unwrap()["isUnlocked"], true);
        *offset.lock().unwrap() = Duration::from_secs(9 * 60);
        vault.expire();
        let status = vault.status().unwrap();
        assert_eq!((status["isUnlocked"].clone(), status["lockReason"].clone(), status["idleTimeoutMs"].clone()), (json!(false), json!("idle"), json!(300000)));
        assert_eq!(vault.list_entries(some(&session)).unwrap_err(), error::locked());
        assert_eq!(vault.record_activity(some(&session)).unwrap_err(), error::locked());
    }

    #[test]
    fn a_lock_during_key_derivation_cancels_the_unlock() {
        let (directory, _, v2) = v2_directory();
        let vault = Arc::new(Vault::open(&directory.0).unwrap());
        let session = id(&vault.status().unwrap());
        let unlocking = {
            let vault = Arc::clone(&vault);
            let master = password(s(&v2["masterPassword"]));
            std::thread::spawn(move || vault.unlock(Some(&session), Some(&master)))
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !vault.guard.is_busy() {
            assert!(std::time::Instant::now() < deadline, "the unlock never started");
            std::thread::yield_now();
        }
        let second = vault.unlock(Some(&id(&vault.status().unwrap())), some(&password(s(&v2["masterPassword"])))).unwrap_err();
        assert_eq!(second, VaultError::conflict("初期設定・解除処理の完了を待ってください"), "a second request is refused, not queued");
        vault.lock_for(LockReason::Suspend);
        assert_eq!(unlocking.join().unwrap().unwrap_err(), changed());
        let status = vault.status().unwrap();
        assert_eq!((status["isUnlocked"].clone(), status["lockReason"].clone()), (json!(false), json!("suspend")));
    }


    #[test]
    fn a_vault_file_changed_underneath_fails_closed_until_restart() {
        let (directory, vault, session) = created();
        std::fs::write(directory.0.join(selection::TRANSITION), "{}").unwrap();
        assert_eq!(vault.list_entries(some(&session)).unwrap_err(), context_failed());
        assert_eq!(vault.list_entries(some(&session)).unwrap_err(), error::locked(), "the failure locked the vault");
        std::fs::remove_file(directory.0.join(selection::TRANSITION)).unwrap();
        let status = vault.status().unwrap();
        assert_eq!((status["isConfigured"].clone(), status["isUnlocked"].clone()), (json!(true), json!(false)));
        assert_eq!(vault.unlock(some(&id(&status)), some(&password(MASTER))).unwrap_err(), context_failed(), "it stays failed");

        let (directory, vault, session) = created();
        let Selection::V2 { database, .. } = selection::inspect(&directory.0).unwrap() else { panic!("a v2 vault") };
        // A second name could change the file unseen. Windows does not let an open SQLite file be renamed or replaced.
        std::fs::hard_link(&database, directory.0.join("second-name.sqlite")).unwrap();
        assert_eq!(vault.create_entry(some(&session), some(&login())).unwrap_err(), context_failed());
        drop(vault);
        std::fs::remove_file(directory.0.join("second-name.sqlite")).unwrap();
        let reopened = Vault::open(&directory.0).unwrap();
        let session = id(&unlocked(&reopened, MASTER));
        assert_eq!(reopened.list_entries(some(&session)).unwrap()["items"], json!([]), "nothing was written");
    }

    #[test]
    fn an_interrupted_switch_opens_locked_and_waits_for_recovery() {
        let (directory, _, v2) = v2_directory();
        std::fs::write(directory.0.join("vault-transition.json"), "{}").unwrap();
        let vault = Vault::open(&directory.0).unwrap();
        assert!(vault.is_recovery_required());
        let status = vault.status().unwrap();
        assert_eq!(status["maintenance"], json!({ "state": "recovery-required", "format": "unknown", "operation": "recover" }));
        assert_eq!(status["isConfigured"], true);
        let refused = VaultError::new(503, "保管庫の復旧を先に完了してください");
        assert_eq!(vault.unlock(some(&id(&status)), some(&password(s(&v2["masterPassword"])))).unwrap_err(), refused);
        assert_eq!(vault.setup(some(&id(&status)), some(&password(MASTER))).unwrap_err(), refused);
        assert_eq!(vault.list_entries(some(&id(&status))).unwrap_err(), error::locked());
    }


    const AWAY: &str = "synthetic-away-message";

    /// A desktop check the test switches on and off, counting how often the core asked.
    fn away_switch(vault: &Vault) -> (Arc<std::sync::atomic::AtomicBool>, Arc<std::sync::atomic::AtomicUsize>) {
        let away = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (flag, count) = (Arc::clone(&away), Arc::clone(&asked));
        assert!(vault.set_availability(Box::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            if flag.load(Ordering::SeqCst) { Err(VaultError::new(423, AWAY)) } else { Ok(()) }
        })));
        assert!(!vault.set_availability(Box::new(|| Ok(()))), "the check is set only once");
        (away, asked)
    }
    #[test]
    fn the_desktop_check_runs_where_the_electron_handlers_call_it() {
        let (directory, _, v2) = v2_directory();
        let vault = Vault::open(&directory.0).unwrap();
        let (away, asked) = away_switch(&vault);
        let session = id(&unlocked(&vault, s(&v2["masterPassword"])));
        assert_eq!(asked.load(Ordering::SeqCst), 1, "unlock asks once, before the generation check");
        assert!(vault.is_unlocked());

        // A session operation asks before and after the action.
        vault.list_entries(some(&session)).unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 3);

        away.store(true, Ordering::SeqCst);
        assert_eq!(vault.list_entries(some(&session)).unwrap_err().message, AWAY);
        assert_eq!(vault.record_activity(some(&session)).unwrap_err().message, AWAY);
        assert_eq!(vault.run_maintenance(some(&session), None).unwrap_err().message, AWAY);
        // withVaultSession checks the session first; handleControl checks the desktop first.
        assert_eq!(vault.list_entries(some(&json!("stale-session"))).unwrap_err().message, error::CHANGED);
        assert_eq!(vault.unlock(some(&json!("stale-session")), some(&password("x"))).unwrap_err().message, AWAY);
        // The status and the lock stay available, as in the Electron app.
        assert_eq!(vault.status().unwrap()["isUnlocked"], true);
        vault.lock(some(&session)).unwrap();
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn copying_checks_the_session_and_the_desktop_around_the_write() {
        let (directory, _, v2) = v2_directory();
        let vault = Vault::open(&directory.0).unwrap();
        let (away, _) = away_switch(&vault);
        let session = id(&unlocked(&vault, s(&v2["masterPassword"])));

        let mut written = None;
        vault
            .copy_text(some(&session), some(&json!("synthetic-copy")), |text, current| {
                current()?;
                written = Some(text.to_string());
                current()
            })
            .unwrap();
        assert_eq!(written.as_deref(), Some("synthetic-copy"));

        let never = |_: &str, _: &dyn Fn() -> Result<()>| -> Result<()> { panic!("nothing may be written") };
        assert_eq!(vault.copy_text(some(&session), Some(&json!(1)), never).unwrap_err().message, "コピーする内容は文字列で指定してください");
        assert_eq!(vault.copy_text(some(&session), None, never).unwrap_err().message, "コピーする内容は文字列で指定してください");
        let large = json!("x".repeat(1024 * 1024 + 1));
        assert_eq!(vault.copy_text(some(&session), Some(&large), never).unwrap_err().status, 413);
        assert_eq!(vault.copy_text(some(&json!("stale-session")), some(&json!("x")), never).unwrap_err().message, error::CHANGED);

        // A lock that arrives during the write fails the copy, so the desktop clears what it wrote.
        let result = vault.copy_text(some(&session), some(&json!("late")), |_, current| {
            current()?;
            vault.lock_for(LockReason::ScreenLock);
            current()
        });
        assert_eq!(result.unwrap_err().message, error::LOCKED);

        let session = id(&unlocked(&vault, s(&v2["masterPassword"])));
        away.store(true, Ordering::SeqCst);
        assert_eq!(vault.copy_text(some(&session), some(&json!("x")), never).unwrap_err().message, AWAY);
    }
}

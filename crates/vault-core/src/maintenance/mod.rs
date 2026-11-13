//! Creating the first vault, and switching the vault to another file: a new master password
//! (rekey), an empty vault (reset), and finishing a switch that stopped part way (recover). It
//! began as apps/api/src/services/vault-maintenance-service.ts and the modules in
//! apps/api/src/migration/. Migrating the legacy format was removed with that format.
//!
//! A switch never changes the file in use. It writes and checks a complete new vault next to it,
//! keeps a copy of the old one with a backup file, and only then moves the pointer files that
//! select the vault. Once a pointer file may have moved, every failure leaves the vault in
//! recovery, where only the same switch, with the same passwords, can finish it.

mod common;
mod recovery_check;
mod replacement;
mod state_files;

use crate::error::{Result, VaultError};
use crate::files::{self, FileCheckFailed};
use crate::input::{self, js_length};
use crate::selection::{self, is_vault_uuid};
use crate::v2::{StoreError, V2Store};
use serde_json::{Map, Value, json};
use std::path::Path;

pub use common::create;
pub use replacement::{Start, replace};

const INVALID_REQUEST: &str = "操作・パスワード・確認入力・バックアップ用パスフレーズを確認してください";
const MIN_NEW_PASSWORD_LENGTH: usize = 12;

/// The outcome codes of the TypeScript migration modules, as far as the screen can tell them
/// apart: translate gives each its message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Invalid,
    Authentication,
    Capacity,
    /// Busy, locked by another program, in use, or cancelled.
    Busy,
    /// Anything else, including a switch that now needs recovery.
    Failed,
}

/// A code, or a message that reaches the screen unchanged.
#[derive(Debug)]
pub enum Stop {
    Code(Code),
    Error(VaultError),
}

pub type Outcome<T> = std::result::Result<T, Stop>;
/// Fails once the switch has been cancelled.
pub type Active<'a> = &'a dyn Fn() -> Outcome<()>;

impl From<Code> for Stop {
    fn from(code: Code) -> Self {
        Self::Code(code)
    }
}

impl From<VaultError> for Stop {
    fn from(error: VaultError) -> Self {
        Self::Error(error)
    }
}

impl From<FileCheckFailed> for Stop {
    fn from(_: FileCheckFailed) -> Self {
        Self::Code(Code::Failed)
    }
}

impl From<std::io::Error> for Stop {
    fn from(_: std::io::Error) -> Self {
        Self::Code(Code::Failed)
    }
}

/// SQLITE_BUSY: another program holds the file.
impl From<rusqlite::Error> for Stop {
    fn from(error: rusqlite::Error) -> Self {
        let busy = matches!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked));
        Self::Code(if busy { Code::Busy } else { Code::Failed })
    }
}

impl From<StoreError> for Stop {
    fn from(error: StoreError) -> Self {
        Self::Code(if error == StoreError::Cancelled { Code::Busy } else { Code::Failed })
    }
}

/// The passwords of one switch.
pub struct Credentials<'a> {
    pub master: &'a str,
    pub new: &'a str,
    pub passphrase: &'a str,
}

pub fn random<const N: usize>() -> Outcome<zeroize::Zeroizing<[u8; N]>> {
    let mut bytes = zeroize::Zeroizing::new([0u8; N]);
    getrandom::fill(bytes.as_mut()).or_else(|_| failed())?;
    Ok(bytes)
}

pub fn failed<T>() -> Outcome<T> {
    Err(Code::Failed.into())
}

/// isDeepStrictEqual for the checks: object keys may come in any order.
pub fn same<T: PartialEq>(actual: &T, expected: &T) -> Outcome<()> {
    if actual == expected { Ok(()) } else { failed() }
}

/// translate in vault-maintenance-service.ts.
pub fn translate(stop: Stop) -> VaultError {
    match stop {
        Stop::Error(error) => error,
        Stop::Code(Code::Authentication) => VaultError::new(401, "パスワードが正しくないか、保管庫の認証に失敗しました"),
        Stop::Code(Code::Invalid) => VaultError::bad_request("入力内容を確認してください"),
        Stop::Code(Code::Capacity) => VaultError::too_large("移行・復旧に対応する容量を超えています"),
        Stop::Code(Code::Busy) => VaultError::conflict("処理が取り消されたか、別の処理が進行中です"),
        Stop::Code(Code::Failed) => VaultError::new(503, "保管庫の検証または切り替えを完了できませんでした。元のファイルを保持し、状態を確認してください"),
    }
}

/// A v2 vault and its key. The slot revision is always 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub vault_id: String,
    pub key_id: String,
}

impl Context {
    /// Two new random ids, which the app requires to differ.
    pub fn fresh() -> Outcome<Self> {
        let context = Self { vault_id: uuid::Uuid::new_v4().to_string(), key_id: uuid::Uuid::new_v4().to_string() };
        if context.vault_id == context.key_id { failed() } else { Ok(context) }
    }

    pub fn json(&self) -> Value {
        json!({ "vaultId": self.vault_id, "keyId": self.key_id, "slotRevision": 1 })
    }

    /// parsePasswordSlotContext, for slot revision 1.
    pub fn parse(value: &Value) -> Outcome<Self> {
        let object = value.as_object().filter(|object| object.len() == 3).ok_or(Code::Failed)?;
        let text = |field: &str| object.get(field).and_then(Value::as_str).filter(|id| is_vault_uuid(id)).map(str::to_string).ok_or(Code::Failed);
        if object.get("slotRevision") != Some(&json!(1)) {
            return failed();
        }
        Ok(Self { vault_id: text("vaultId")?, key_id: text("keyId")? })
    }
}

/// The receipt that names the selected vault, in the order JSON.stringify writes it.
pub fn receipt(context: &Context, count: usize, committed: bool) -> Value {
    json!({ "format": "CIPHER-VAULT-ACTIVATION", "version": 1, "vaultId": context.vault_id, "keyId": context.key_id, "entryCount": count, "state": if committed { "committed" } else { "prepared" } })
}

pub fn pointer(context: &Context) -> Value {
    json!({ "format": "CIPHER-VAULT-ACTIVE", "version": 1, "vaultId": context.vault_id })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Rekey,
    Reset,
    Recover,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rekey => "rekey",
            Self::Reset => "reset",
            Self::Recover => "recover",
        }
    }
}

/// A checked request. The passwords stay in memory only for the switch.
pub struct Request {
    pub operation: Operation,
    pub master_password: zeroize::Zeroizing<String>,
    pub new_master_password: zeroize::Zeroizing<String>,
    pub backup_passphrase: zeroize::Zeroizing<String>,
    pub confirmation: bool,
}

/// parse in vault-maintenance-service.ts. Too large a field keeps its own message; anything else
/// answers with one message, so the screen learns nothing about which field was wrong.
pub fn parse(value: Option<&Value>) -> Result<Request> {
    let invalid = || VaultError::bad_request(INVALID_REQUEST);
    let pass_large = |error: VaultError| if error.status == 413 { error } else { invalid() };
    const FIELDS: [&str; 7] = ["operation", "masterPassword", "newMasterPassword", "confirmNewMasterPassword", "backupPassphrase", "confirmBackupPassphrase", "confirmation"];
    let input: &Map<String, Value> = value.and_then(Value::as_object).ok_or_else(invalid)?;
    if !input.keys().all(|key| FIELDS.contains(&key.as_str())) || !FIELDS[..5].iter().all(|field| input.contains_key(*field)) {
        return Err(invalid());
    }
    let operation = match input["operation"].as_str() {
        Some("rekey") => Operation::Rekey,
        Some("reset") => Operation::Reset,
        Some("recover") => Operation::Recover,
        _ => return Err(invalid()),
    };
    let (Some(master), Some(new)) = (input["masterPassword"].as_str(), input["newMasterPassword"].as_str()) else {
        return Err(invalid());
    };
    let confirmation = input.get("confirmation");
    let reset_confirmed = confirmation.is_some_and(|value| value == "RESET_ALL_DATA");
    let refused = js_length(new) < MIN_NEW_PASSWORD_LENGTH
        || new == master
        || input.get("confirmNewMasterPassword") != Some(&input["newMasterPassword"])
        || (operation != Operation::Recover && input.get("confirmBackupPassphrase") != Some(&input["backupPassphrase"]))
        || (if operation == Operation::Reset { !reset_confirmed } else { operation != Operation::Recover && confirmation.is_some() })
        || (confirmation.is_some() && !reset_confirmed);
    if refused {
        return Err(invalid());
    }
    let master = input::parse_master_password(Some(&json!({ "masterPassword": master })), false).map_err(pass_large)?;
    let new = input::parse_master_password(Some(&json!({ "masterPassword": new })), true).map_err(pass_large)?;
    let (passphrase, _) = input::parse_backup_payload(Some(&json!({ "passphrase": input["backupPassphrase"] })), false).map_err(pass_large)?;
    if input.get("confirmBackupPassphrase").is_some_and(|confirm| confirm != &input["backupPassphrase"]) {
        return Err(invalid());
    }
    Ok(Request {
        operation,
        master_password: zeroize::Zeroizing::new(master),
        new_master_password: zeroize::Zeroizing::new(new),
        backup_passphrase: zeroize::Zeroizing::new(passphrase),
        confirmation: reset_confirmed,
    })
}

/// What a stopped switch was doing, which only says what to verify: recovery still checks both
/// vaults and every file before it selects one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hint {
    pub source: Context,
    pub target: Context,
    pub reset: bool,
}

impl Hint {
    pub fn mode(&self) -> &'static str {
        if self.reset { "reset" } else { "rekey" }
    }
}

/// recovery in vault-maintenance-service.ts: only a rekey or reset leaves a journal that names
/// both vaults. A migration interrupted by an earlier release cannot be finished here.
pub fn recovery_hint(root: &Path) -> Outcome<Hint> {
    if !files::present(&files::safe_path(root, &[selection::TRANSITION], false, true)?)? {
        return failed();
    }
    let transition = replacement::read_transition(root)?;
    Ok(Hint { source: transition.source, target: transition.target, reset: transition.reset })
}

/// A v2 vault of the data directory, opened for reading only.
pub fn open_store(root: &Path, context: &Context) -> Outcome<V2Store> {
    let path = files::safe_path(root, &["vaults", &context.vault_id, "vault.sqlite"], false, false)?;
    V2Store::open_read_only(&path, &context.vault_id, &context.key_id).ok_or(Code::Failed.into())
}

/// inspectVaultSelection, which also opens a selected v2 vault to check it.
pub fn selected(root: &Path) -> Outcome<Option<Context>> {
    match selection::inspect(root)? {
        selection::Selection::Empty { .. } => Ok(None),
        selection::Selection::V2 { vault_id, key_id, .. } => {
            let context = Context { vault_id, key_id };
            open_store(root, &context)?;
            Ok(Some(context))
        }
    }
}

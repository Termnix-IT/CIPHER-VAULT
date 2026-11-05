//! Writes, following apps/api/src/db/v2-store.ts and the entry services. Writing stays off unless
//! the prototype is started in write mode, and real data directories are refused even then.

use super::*;
use crate::entry_input::{self, now_iso};
use rusqlite::{Transaction, TransactionBehavior};

const READ_ONLY: &str = "この試作版は読取専用です";
const CONFLICT: &str = "保管庫の処理が競合しました。もう一度操作してください";
const KEY_LIMIT: &str = "保管庫の鍵更新が必要です";
const ENTRY_LIMIT: &str = "保管庫への新規登録は10000件まで対応しています";
pub(super) const STORAGE_FAILED: &str = "保管庫の保存に失敗しました。アプリを再起動してください";
const UNSUPPORTED: &str = "未対応のDB形式です";
const PROTECTED_PATH: &str = "利用中の保存先には書き込めません。保管庫のコピーを指定してください";

const MAX_ENCRYPTIONS: i64 = 1 << 20;
const MAX_REVISION: u64 = 0xffff_ffff;
const MAX_PLAINTEXT_BYTES: usize = 11 * 1024 * 1024;
const NONCE_ATTEMPTS: usize = 8;
const IV_BYTES: usize = 12;
const LOGIN_SCHEMA_VERSION: i64 = 1;
const ITEM_SCHEMA_VERSION: i64 = 2;
const FINANCIAL_SCHEMA_VERSION: i64 = 3;

// The exact text of V2_TABLES in apps/api/src/db/v2-schema.ts, which is part of the format.
const V2_TABLES: [(&str, &str); 3] = [
    ("vault_header", "CREATE TABLE vault_header (\n  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\n  vault_id TEXT NOT NULL,\n  key_id TEXT NOT NULL UNIQUE,\n  slot_revision INTEGER NOT NULL CHECK (slot_revision BETWEEN 1 AND 4294967295),\n  password_slot TEXT NOT NULL CHECK (length(password_slot) BETWEEN 1 AND 16777216),\n  encryption_count INTEGER NOT NULL CHECK (encryption_count BETWEEN 0 AND 1048576)\n) STRICT"),
    ("vault_entries", "CREATE TABLE vault_entries (\n  entry_id TEXT PRIMARY KEY NOT NULL,\n  revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 4294967295),\n  envelope TEXT CHECK (envelope IS NULL OR length(envelope) BETWEEN 1 AND 16777216)\n) STRICT"),
    ("vault_nonces", "CREATE TABLE vault_nonces (\n  key_id TEXT NOT NULL REFERENCES vault_header(key_id),\n  iv BLOB NOT NULL CHECK (length(iv) = 12),\n  entry_id TEXT NOT NULL,\n  revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 4294967295),\n  PRIMARY KEY (key_id, iv)\n) STRICT"),
];

enum WriteError {
    /// A message for the person, with nothing changed that matters.
    User(String),
    Conflict,
    KeyLimit,
    EntryLimit,
    /// The session or OS state changed. The caller reports the current reason.
    Cancelled,
    /// The storage is not behaving as expected, so no further write should trust it.
    Storage,
}

impl From<rusqlite::Error> for WriteError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

type Active<'a> = &'a dyn Fn() -> Result<(), WriteError>;

/// Lets the UI check prove that a crash at this point leaves a vault the app can still open.
#[cfg(feature = "e2e")]
fn crash_point(name: &str) {
    if std::env::var("CIPHER_VAULT_POC_E2E_CRASH").is_ok_and(|value| value == name) {
        std::process::abort();
    }
}
#[cfg(not(feature = "e2e"))]
fn crash_point(_name: &str) {}

/// Real data must not be reachable by mistake. These are compared as text because the checks are
/// only a safety net for a prototype, and a user's copy elsewhere must stay usable.
fn is_protected_path(path: &str, app_data: Option<&str>) -> bool {
    let path = path.to_lowercase().replace('/', "\\");
    let in_app_data = app_data.is_some_and(|directory| {
        let directory = directory.to_lowercase().replace('/', "\\");
        path.starts_with(&format!("{}\\", directory.trim_end_matches('\\')))
    });
    in_app_data || path.contains("\\apps\\api\\data\\") || path.contains("\\release\\data\\")
}

fn check_protected(path: &Path) -> Result<(), String> {
    let canonical = path.canonicalize().map_err(|_| "DBを開けません")?;
    let app_data = std::env::var_os("APPDATA").and_then(|directory| Path::new(&directory).canonicalize().ok());
    let app_data = app_data.as_ref().map(|directory| directory.to_string_lossy());
    if is_protected_path(&canonical.to_string_lossy(), app_data.as_deref()) { Err(PROTECTED_PATH.into()) } else { Ok(()) }
}

fn fresh_iv() -> Result<[u8; IV_BYTES], WriteError> {
    let mut iv = [0u8; IV_BYTES];
    getrandom::fill(&mut iv).map_err(|_| WriteError::Storage)?;
    Ok(iv)
}

fn inspect_v2_strictly(connection: &Connection, format: &Format) -> Result<(), String> {
    let Format::V2 { vault_id, key_id, slot_revision, slot } = format else {
        return Err(UNSUPPORTED.into());
    };
    let check = || -> rusqlite::Result<bool> {
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        let mut statement = connection.prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT 4")?;
        let objects = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let schema_matches = objects.len() == V2_TABLES.len() && objects.iter().all(|(kind, name, sql)| kind == "table" && V2_TABLES.iter().any(|(table, text)| table == name && text == sql));
        let (count, nonces, foreign_nonces, broken_links, entries): (i64, i64, i64, i64, i64) = connection.query_row(
            "SELECT (SELECT encryption_count FROM vault_header WHERE singleton = 1), (SELECT COUNT(*) FROM vault_nonces),
                    (SELECT COUNT(*) FROM vault_nonces WHERE key_id != ?1), (SELECT COUNT(*) FROM pragma_foreign_key_check),
                    (SELECT COUNT(*) FROM vault_entries WHERE envelope IS NOT NULL)",
            [key_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
        Ok((LOGIN_SCHEMA_VERSION..=FINANCIAL_SCHEMA_VERSION).contains(&version)
            && journal == "delete"
            && schema_matches
            && count == nonces
            && (0..=MAX_ENCRYPTIONS).contains(&count)
            && foreign_nonces == 0
            && broken_links == 0
            && usize::try_from(entries).is_ok_and(|entries| entries <= entry_input::MAX_ENTRIES))
    };
    let slot: Value = serde_json::from_str(slot).map_err(|_| UNSUPPORTED)?;
    let slot_matches = slot["vaultId"] == vault_id.as_str() && slot["keyId"] == key_id.as_str() && slot["slotRevision"] == *slot_revision;
    if slot_matches && check().map_err(|_| UNSUPPORTED)? { Ok(()) } else { Err(UNSUPPORTED.into()) }
}

fn inspect_legacy_strictly(connection: &Connection, format: &Format) -> Result<(), String> {
    let Format::Legacy { has_group: true, has_changed_at: true, .. } = format else {
        return Err("古い形式の列が不足しています。この試作版は書き込み前の移行を行いません".into());
    };
    let check = || -> rusqlite::Result<bool> {
        let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let objects: i64 = connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'", [], |row| row.get(0))?;
        Ok(application_id == 0 && version == 0 && objects == 2)
    };
    if check().map_err(|_| UNSUPPORTED)? { Ok(()) } else { Err(UNSUPPORTED.into()) }
}

fn configure_v2_writer(connection: &Connection) -> rusqlite::Result<bool> {
    connection.pragma_update(None, "synchronous", "EXTRA")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "secure_delete", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let foreign_keys: i64 = connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    Ok(synchronous == 3 && foreign_keys == 1)
}

fn schema_version_for(entry: &Value) -> i64 {
    match entry["type"].as_str() {
        Some("financial") => FINANCIAL_SCHEMA_VERSION,
        Some(_) => ITEM_SCHEMA_VERSION,
        None => LOGIN_SCHEMA_VERSION,
    }
}

/// The marker keeps older apps out, so a later save of a lesser kind must never lower it.
fn raise_schema_version(transaction: &Transaction<'_>, version: i64) -> rusqlite::Result<()> {
    let current: i64 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > current {
        transaction.pragma_update(None, "user_version", version)?;
    }
    Ok(())
}

fn sql_revision(revision: u64) -> Result<i64, WriteError> {
    i64::try_from(revision).map_err(|_| WriteError::Storage)
}

fn can_write_v2(connection: &Connection, entry_id: &str, revision: u64) -> Result<(), WriteError> {
    let current: Option<(i64, bool)> = connection
        .query_row("SELECT revision, envelope IS NULL FROM vault_entries WHERE entry_id = ?1", [entry_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    let expected = match current {
        Some((stored, _)) => u64::try_from(stored).map_err(|_| WriteError::Storage)? + 1,
        None => 1,
    };
    if revision != expected {
        return Err(WriteError::Conflict);
    }
    if revision > MAX_REVISION {
        return Err(WriteError::Storage);
    }
    if current.is_none_or(|(_, deleted)| deleted) {
        let count: i64 = connection.query_row("SELECT COUNT(*) FROM vault_entries WHERE envelope IS NOT NULL", [], |row| row.get(0))?;
        if usize::try_from(count).map_err(|_| WriteError::Storage)? >= entry_input::MAX_ENTRIES {
            return Err(WriteError::EntryLimit);
        }
    }
    Ok(())
}

impl Vault {
    /// Opens read-write only after the same strict checks the app's writer applies.
    pub fn open_writable(path: &Path) -> Result<Self, String> {
        const CANNOT_OPEN: &str = "DBを書き込み用に開けません";
        check_protected(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut connection = Connection::open_with_flags(path, flags).map_err(|_| CANNOT_OPEN)?;
        let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0)).map_err(|_| CANNOT_OPEN)?;
        let is_v2 = application_id == V2_APPLICATION_ID;
        let configured = if is_v2 { configure_v2_writer(&connection) } else { connection.pragma_update(None, "secure_delete", true).map(|()| true) };
        if !configured.map_err(|_| CANNOT_OPEN)? {
            return Err(CANNOT_OPEN.into());
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|_| CANNOT_OPEN)?;
        let format = if is_v2 { inspect_v2(&transaction)? } else { inspect_legacy(&transaction)? };
        if is_v2 { inspect_v2_strictly(&transaction, &format)? } else { inspect_legacy_strictly(&transaction, &format)? }
        transaction.commit().map_err(|_| CANNOT_OPEN)?;
        Ok(Self::assemble(format, connection, true))
    }

    /// Runs one write. `guard` reports whether the OS still allows use, and it is checked again
    /// at every step, so that a lock during a write stops it instead of saving afterwards.
    fn mutation<T>(&self, session_id: &str, guard: &dyn Fn() -> Result<(), String>, action: impl FnOnce(&[u8], Active<'_>) -> Result<T, WriteError>) -> Result<T, String> {
        if !self.writable {
            return Err(READ_ONLY.into());
        }
        self.require_healthy()?;
        let check = || {
            guard()?;
            self.require_unlocked(session_id)
        };
        check()?;
        // Later requests are refused rather than queued with their secrets.
        if self.writing.swap(true, Ordering::SeqCst) {
            return Err(CONFLICT.into());
        }
        let active = || check().map_err(|_| WriteError::Cancelled);
        let key = self.session.lock().unwrap().key.clone();
        let result = match key {
            Some(key) => action(&key, &active),
            None => Err(WriteError::Cancelled),
        };
        self.writing.store(false, Ordering::SeqCst);
        if matches!(result, Err(WriteError::Storage)) {
            self.faulted.store(true, Ordering::SeqCst);
        }
        // A lock reports the lock, even when the write failed for another reason first.
        check()?;
        result.map_err(|error| match error {
            WriteError::User(message) => message,
            WriteError::Conflict => CONFLICT.into(),
            WriteError::KeyLimit => KEY_LIMIT.into(),
            WriteError::EntryLimit => ENTRY_LIMIT.into(),
            WriteError::Cancelled => CHANGED.into(),
            WriteError::Storage => STORAGE_FAILED.into(),
        })
    }

    pub fn create_entry(&self, session_id: &str, input: &Value, guard: &dyn Fn() -> Result<(), String>) -> Result<Value, String> {
        self.mutation(session_id, guard, |key, active| match &self.format {
            Format::Legacy { .. } => self.create_legacy(key, input, active),
            Format::V2 { .. } => self.create_v2(key, input, active),
        })
    }

    pub fn update_entry(&self, session_id: &str, id: &Value, input: &Value, guard: &dyn Fn() -> Result<(), String>) -> Result<Value, String> {
        self.mutation(session_id, guard, |key, active| match &self.format {
            Format::Legacy { .. } => self.update_legacy(key, id, input, active),
            Format::V2 { .. } => self.update_v2(key, id, input, active),
        })
    }

    pub fn delete_entry(&self, session_id: &str, id: &Value, guard: &dyn Fn() -> Result<(), String>) -> Result<Value, String> {
        self.mutation(session_id, guard, |key, active| {
            let id = entry_input::parse_entry_id(id).map_err(WriteError::User)?;
            match &self.format {
                Format::Legacy { .. } => self.delete_legacy(&id, active)?,
                Format::V2 { .. } => self.delete_v2(key, &id, active)?,
            }
            Ok(json!({ "success": true }))
        })
    }

    pub fn set_entries_group(&self, session_id: &str, input: &Value, guard: &dyn Fn() -> Result<(), String>) -> Result<Value, String> {
        self.mutation(session_id, guard, |key, active| {
            let (ids, group) = entry_input::parse_group_payload(input).map_err(WriteError::User)?;
            let updated = match &self.format {
                Format::Legacy { .. } => self.group_legacy(&ids, group.as_deref(), active)?,
                Format::V2 { .. } => self.group_v2(key, &ids, group.as_deref(), active)?,
            };
            Ok(json!({ "updatedCount": updated }))
        })
    }

    fn immediate<T>(&self, active: Active<'_>, action: impl FnOnce(&Transaction<'_>) -> Result<T, WriteError>) -> Result<T, WriteError> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Checked while holding the write lock, so a lock before this point cannot be missed.
        active()?;
        let result = action(&transaction)?;
        active()?;
        crash_point("save");
        transaction.commit()?;
        Ok(result)
    }

    // ---- Legacy format: each secret is sealed on its own, and there is no nonce table.

    fn seal_legacy(key: &[u8], plaintext: &str) -> Result<String, WriteError> {
        crypto::seal_legacy_secret(key, &fresh_iv()?, plaintext.as_bytes()).map_err(|_| WriteError::Storage)
    }

    fn create_legacy(&self, key: &[u8], input: &Value, active: Active<'_>) -> Result<Value, WriteError> {
        entry_input::require_legacy_item(input).map_err(WriteError::User)?;
        let data = entry_input::parse_login(input).map_err(WriteError::User)?;
        let id = Uuid::new_v4().to_string();
        let now = now_iso();
        let password = Self::seal_legacy(key, data["password"].as_str().unwrap_or_default())?;
        let notes = Self::legacy_notes(key, &data)?;
        self.immediate(active, |transaction| {
            let count: i64 = transaction.query_row("SELECT COUNT(*) FROM password_entries", [], |row| row.get(0))?;
            if usize::try_from(count).map_err(|_| WriteError::Storage)? >= entry_input::MAX_ENTRIES {
                return Err(WriteError::EntryLimit);
            }
            transaction.execute(
                "INSERT INTO password_entries (id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at, password_changed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?9)",
                params![id, data["serviceName"].as_str(), data["loginId"].as_str(), password, notes, Self::legacy_url(&data), data["tags"].to_string(), data["group"].as_str(), now],
            )?;
            Ok(())
        })?;
        self.get_legacy(key, &id, true, true).map_err(|_| WriteError::Storage)
    }

    fn legacy_notes(key: &[u8], data: &Value) -> Result<Option<String>, WriteError> {
        match data["notes"].as_str() {
            Some(notes) if !notes.is_empty() => Self::seal_legacy(key, notes).map(Some),
            _ => Ok(None),
        }
    }

    fn legacy_url(data: &Value) -> Option<&str> {
        data["url"].as_str().filter(|url| !url.is_empty())
    }

    fn update_legacy(&self, key: &[u8], id: &Value, input: &Value, active: Active<'_>) -> Result<Value, WriteError> {
        entry_input::require_legacy_item(input).map_err(WriteError::User)?;
        let id = entry_input::parse_entry_id(id).map_err(WriteError::User)?;
        let data = entry_input::parse_login(input).map_err(WriteError::User)?;
        let existing: Option<(String, Option<String>)> = {
            let connection = self.connection.lock().unwrap();
            connection.query_row("SELECT encrypted_password, password_changed_at FROM password_entries WHERE id = ?1", [&id], |row| Ok((row.get(0)?, row.get(1)?))).optional()?
        };
        let (stored_password, changed_at) = existing.ok_or_else(|| WriteError::User(NOT_FOUND.into()))?;
        let new_password = data["password"].as_str().unwrap_or_default();
        let now = now_iso();
        let password_is_same = decrypted_text(key, &stored_password).map_err(|_| WriteError::Storage)?.as_str() == new_password;
        let changed_at = if password_is_same { changed_at } else { Some(now.clone()) };
        let password = Self::seal_legacy(key, new_password)?;
        let notes = Self::legacy_notes(key, &data)?;
        self.immediate(active, |transaction| {
            transaction.execute(
                "UPDATE password_entries SET service_name = ?2, login_id = ?3, encrypted_password = ?4, encrypted_notes = ?5, url = ?6, tags = ?7, group_name = ?8, password_changed_at = ?9, updated_at = ?10 WHERE id = ?1",
                params![id, data["serviceName"].as_str(), data["loginId"].as_str(), password, notes, Self::legacy_url(&data), data["tags"].to_string(), data["group"].as_str(), changed_at, now],
            )?;
            Ok(())
        })?;
        self.get_legacy(key, &id, true, true).map_err(|_| WriteError::Storage)
    }

    fn delete_legacy(&self, id: &str, active: Active<'_>) -> Result<(), WriteError> {
        self.immediate(active, |transaction| {
            if transaction.execute("DELETE FROM password_entries WHERE id = ?1", [id])? == 0 {
                return Err(WriteError::User(NOT_FOUND.into()));
            }
            Ok(())
        })
    }

    /// Plain columns only, so the secrets and their change date stay untouched. One transaction,
    /// so an unknown id rolls back every change.
    fn group_legacy(&self, ids: &[String], group: Option<&str>, active: Active<'_>) -> Result<usize, WriteError> {
        let now = now_iso();
        self.immediate(active, |transaction| {
            let mut updated = 0;
            for id in ids {
                let current: Option<Option<String>> = transaction.query_row("SELECT group_name FROM password_entries WHERE id = ?1", [id], |row| row.get(0)).optional()?;
                let current = current.ok_or_else(|| WriteError::User(NOT_FOUND.into()))?;
                if current.as_deref() != group {
                    transaction.execute("UPDATE password_entries SET group_name = ?2, updated_at = ?3 WHERE id = ?1", params![id, group, now])?;
                    updated += 1;
                }
            }
            Ok(updated)
        })
    }

    // ---- v2 format: nonce first and durably, then seal, then save in a separate transaction.

    fn v2_ids(&self) -> Result<(&str, &str, u64), WriteError> {
        match &self.format {
            Format::V2 { vault_id, key_id, slot_revision, .. } => Ok((vault_id, key_id, *slot_revision)),
            Format::Legacy { .. } => Err(WriteError::Storage),
        }
    }

    fn check_v2_header(&self, connection: &Connection) -> Result<i64, WriteError> {
        let (vault_id, key_id, slot_revision) = self.v2_ids()?;
        let (stored_vault, stored_key, stored_revision, count): (String, String, i64, i64) =
            connection.query_row("SELECT vault_id, key_id, slot_revision, encryption_count FROM vault_header WHERE singleton = 1", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
        let matches = stored_vault == vault_id && stored_key == key_id && u64::try_from(stored_revision).is_ok_and(|revision| revision == slot_revision);
        if matches && (0..=MAX_ENCRYPTIONS).contains(&count) { Ok(count) } else { Err(WriteError::Storage) }
    }

    /// True only once the nonce is committed, even if everything after this fails. A used nonce
    /// is never released, which is why a failed write still consumes one.
    fn reserve_nonce(&self, entry_id: &str, revision: u64, iv: &[u8]) -> Result<bool, WriteError> {
        let (_, key_id, _) = self.v2_ids()?;
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count = self.check_v2_header(&transaction)?;
        can_write_v2(&transaction, entry_id, revision)?;
        let taken = transaction.query_row("SELECT 1 FROM vault_nonces WHERE key_id = ?1 AND iv = ?2", params![key_id, iv], |_| Ok(())).optional()?.is_some();
        if taken {
            return Ok(false);
        }
        if count >= MAX_ENCRYPTIONS {
            return Err(WriteError::KeyLimit);
        }
        transaction.execute("INSERT INTO vault_nonces VALUES (?1, ?2, ?3, ?4)", params![key_id, iv, entry_id, sql_revision(revision)?])?;
        transaction.execute("UPDATE vault_header SET encryption_count = encryption_count + 1 WHERE singleton = 1", [])?;
        transaction.commit()?;
        Ok(true)
    }

    fn write_v2_entry(&self, root: &[u8], entry: &Value, entry_id: &str, revision: u64, active: Active<'_>) -> Result<(), WriteError> {
        let (vault_id, key_id, _) = self.v2_ids()?;
        active()?;
        entry_input::validate_stored_entry(entry, entry_id).map_err(WriteError::User)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(entry).map_err(|_| WriteError::Storage)?);
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(WriteError::User("エントリの形式が正しくありません".into()));
        }
        {
            let connection = self.connection.lock().unwrap();
            can_write_v2(&connection, entry_id, revision)?;
            if self.check_v2_header(&connection)? >= MAX_ENCRYPTIONS {
                return Err(WriteError::KeyLimit);
            }
        }
        let mut reserved = None;
        for _ in 0..NONCE_ATTEMPTS {
            active()?;
            let candidate = fresh_iv()?;
            if self.reserve_nonce(entry_id, revision, &candidate)? {
                reserved = Some(candidate);
                break;
            }
        }
        let iv = reserved.ok_or(WriteError::Storage)?;
        crash_point("reserve");
        active()?;
        let envelope = crypto::seal_v2_entry(root, &iv, &plaintext, vault_id, key_id, entry_id, revision).map_err(|_| WriteError::Storage)?;
        let version = schema_version_for(entry);
        self.immediate(active, |transaction| {
            self.check_v2_header(transaction)?;
            can_write_v2(transaction, entry_id, revision)?;
            let is_reserved = transaction
                .query_row("SELECT 1 FROM vault_nonces WHERE key_id = ?1 AND iv = ?2 AND entry_id = ?3 AND revision = ?4", params![key_id, &iv[..], entry_id, sql_revision(revision)?], |_| Ok(()))
                .optional()?
                .is_some();
            if !is_reserved {
                return Err(WriteError::Storage);
            }
            transaction.execute(
                "INSERT INTO vault_entries (entry_id, revision, envelope) VALUES (?1, ?2, ?3)
                 ON CONFLICT(entry_id) DO UPDATE SET revision = excluded.revision, envelope = excluded.envelope",
                params![entry_id, sql_revision(revision)?, envelope],
            )?;
            // Committed with the first entry of the kind, never before it is authorized.
            raise_schema_version(transaction, version)?;
            Ok(())
        })
    }

    fn stored_v2_revision(&self, id: &str) -> Result<Option<u64>, WriteError> {
        let connection = self.connection.lock().unwrap();
        let revision: Option<i64> = connection.query_row("SELECT revision FROM vault_entries WHERE entry_id = ?1 AND envelope IS NOT NULL", [id], |row| row.get(0)).optional()?;
        revision.map(|revision| u64::try_from(revision).map_err(|_| WriteError::Storage)).transpose()
    }

    /// The revision is read before the entry, so a stale read can only cause a conflict later.
    fn read_v2_for_write(&self, root: &[u8], id: &str) -> Result<(Value, u64), WriteError> {
        let revision = self.stored_v2_revision(id)?.ok_or_else(|| WriteError::User(NOT_FOUND.into()))?;
        let entry = self.read_v2_entry(root, id).map_err(|_| WriteError::Storage)?.ok_or_else(|| WriteError::User(NOT_FOUND.into()))?;
        Ok((entry, revision))
    }

    fn create_v2(&self, root: &[u8], input: &Value, active: Active<'_>) -> Result<Value, WriteError> {
        let mut entry = entry_input::parse_vault_entry(input).map_err(WriteError::User)?;
        let id = Uuid::new_v4().to_string();
        let now = now_iso();
        entry["id"] = json!(id);
        entry["createdAt"] = json!(now);
        entry["updatedAt"] = json!(now);
        if entry.get("type").is_none() {
            entry["passwordChangedAt"] = json!(now);
        }
        self.write_v2_entry(root, &entry, &id, 1, active)?;
        Ok(entry)
    }

    fn update_v2(&self, root: &[u8], id: &Value, input: &Value, active: Active<'_>) -> Result<Value, WriteError> {
        let id = entry_input::parse_entry_id(id).map_err(WriteError::User)?;
        let mut entry = entry_input::parse_vault_entry(input).map_err(WriteError::User)?;
        let (existing, revision) = self.read_v2_for_write(root, &id)?;
        let kind_of = |value: &Value| value["type"].as_str().unwrap_or("login").to_string();
        if kind_of(&existing) != kind_of(&entry) {
            return Err(WriteError::User("保存済みの項目の種類は変更できません".into()));
        }
        // ISO text in this one form sorts by time, and an entry never moves back in time.
        let now = now_iso().max(existing["updatedAt"].as_str().unwrap_or_default().to_string());
        entry["id"] = json!(id);
        entry["createdAt"] = existing["createdAt"].clone();
        entry["updatedAt"] = json!(now);
        if entry.get("type").is_none() {
            entry["passwordChangedAt"] = if existing["password"] == entry["password"] { existing["passwordChangedAt"].clone() } else { json!(now) };
        }
        self.write_v2_entry(root, &entry, &id, revision + 1, active)?;
        Ok(entry)
    }

    /// Removes the ciphertext and keeps the id and revision as a tombstone. Nonces stay used.
    fn delete_v2(&self, root: &[u8], id: &str, active: Active<'_>) -> Result<(), WriteError> {
        let (_, revision) = self.read_v2_for_write(root, id)?;
        self.immediate(active, |transaction| {
            let current: Option<(i64, bool)> = transaction.query_row("SELECT revision, envelope IS NULL FROM vault_entries WHERE entry_id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
            if !current.is_some_and(|(stored, deleted)| !deleted && u64::try_from(stored).is_ok_and(|stored| stored == revision)) {
                return Err(WriteError::Conflict);
            }
            transaction.execute("UPDATE vault_entries SET envelope = NULL WHERE entry_id = ?1", [id])?;
            Ok(())
        })
    }

    /// Each entry has its own envelope, so a later failure keeps the entries already rewritten.
    /// An unknown id fails before any write.
    fn group_v2(&self, root: &[u8], ids: &[String], group: Option<&str>, active: Active<'_>) -> Result<usize, WriteError> {
        for id in ids {
            self.stored_v2_revision(id)?.ok_or_else(|| WriteError::User(NOT_FOUND.into()))?;
        }
        let mut updated = 0;
        for id in ids {
            let (mut entry, revision) = self.read_v2_for_write(root, id)?;
            if entry["group"].as_str() == group {
                continue;
            }
            entry["group"] = json!(group);
            entry["updatedAt"] = json!(now_iso().max(entry["updatedAt"].as_str().unwrap_or_default().to_string()));
            self.write_v2_entry(root, &entry, id, revision + 1, active)?;
            updated += 1;
        }
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{TemporaryDatabase, fixture, legacy_database, s};
    use super::*;
    use std::cell::Cell;

    fn available() -> Result<(), String> {
        Ok(())
    }

    fn v2_database() -> (TemporaryDatabase, Value) {
        let v2 = fixture()["draftV2"].clone();
        let database = TemporaryDatabase::new();
        let connection = Connection::open(&database.0).unwrap();
        connection.pragma_update(None, "application_id", V2_APPLICATION_ID).unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        for (_, sql) in V2_TABLES {
            connection.execute_batch(sql).unwrap();
        }
        let slot = json!({ "cryptoVersion": 2, "cipher": "aes-256-gcm", "vaultId": v2["vaultId"], "keyId": v2["keyId"], "slotId": "password", "slotRevision": v2["slotRevision"],
            "kdf": { "profile": v2["profile"], "salt": v2["salt"] }, "iv": v2["wrapIv"], "tag": v2["wrapTag"], "data": v2["wrappedRoot"] }).to_string();
        let envelope = json!({ "cryptoVersion": 2, "cipher": "aes-256-gcm", "vaultId": v2["vaultId"], "keyId": v2["keyId"], "entryId": v2["entryId"], "revision": v2["revision"],
            "iv": v2["entryIv"], "tag": v2["entryTag"], "data": v2["entryData"] }).to_string();
        connection.execute("INSERT INTO vault_header VALUES (1, ?1, ?2, ?3, ?4, 1)", params![s(&v2["vaultId"]), s(&v2["keyId"]), v2["slotRevision"].as_i64(), slot]).unwrap();
        connection.execute("INSERT INTO vault_entries VALUES (?1, ?2, ?3)", params![s(&v2["entryId"]), v2["revision"].as_i64(), envelope]).unwrap();
        let iv = crypto::decode_base64(s(&v2["entryIv"]), Some(12)).unwrap();
        connection.execute("INSERT INTO vault_nonces VALUES (?1, ?2, ?3, ?4)", params![s(&v2["keyId"]), iv, s(&v2["entryId"]), v2["revision"].as_i64()]).unwrap();
        (database, v2)
    }

    fn unlocked_v2() -> (TemporaryDatabase, Value, Vault, String) {
        let (database, v2) = v2_database();
        let vault = Vault::open_writable(&database.0).unwrap();
        let id = vault.status().session_id;
        let session = vault.unlock(&id, s(&v2["masterPassword"]).as_bytes()).unwrap().session_id;
        (database, v2, vault, session)
    }

    fn unlocked_legacy() -> (TemporaryDatabase, Value, Vault, String) {
        let (database, legacy) = legacy_database(true, true);
        let vault = Vault::open_writable(&database.0).unwrap();
        let id = vault.status().session_id;
        let session = vault.unlock(&id, s(&legacy["password"]).as_bytes()).unwrap().session_id;
        (database, legacy, vault, session)
    }

    fn login() -> Value {
        json!({ "serviceName": "合成サービス", "loginId": "synthetic-login", "password": "synthetic-secret-value", "notes": "synthetic-notes-value", "tags": ["a"], "group": "g" })
    }

    fn counts(vault: &Vault) -> (i64, i64) {
        let connection = vault.connection.lock().unwrap();
        let header = connection.query_row("SELECT encryption_count FROM vault_header", [], |row| row.get(0)).unwrap();
        let nonces = connection.query_row("SELECT COUNT(*) FROM vault_nonces", [], |row| row.get(0)).unwrap();
        (header, nonces)
    }

    fn user_version(vault: &Vault) -> i64 {
        vault.connection.lock().unwrap().pragma_query_value(None, "user_version", |row| row.get(0)).unwrap()
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle.as_bytes())
    }

    #[test]
    fn v2_create_update_delete_keeps_revisions_nonces_and_a_tombstone() {
        let (database, _, vault, session) = unlocked_v2();
        let created = vault.create_entry(&session, &login(), &available).unwrap();
        let id = created["id"].as_str().unwrap().to_string();
        assert_eq!(created["passwordChangedAt"], created["createdAt"]);
        assert_eq!(vault.get_entry(&session, &id).unwrap(), created);
        assert_eq!(vault.stored_v2_revision(&id).ok().flatten(), Some(1));
        assert_eq!(counts(&vault), (2, 2));

        let mut changed = login();
        changed["serviceName"] = json!("変更後");
        let updated = vault.update_entry(&session, &json!(id), &changed, &available).unwrap();
        assert_eq!(updated["createdAt"], created["createdAt"]);
        assert_eq!(updated["passwordChangedAt"], created["passwordChangedAt"], "the same password keeps its change date");
        assert_eq!(vault.stored_v2_revision(&id).ok().flatten(), Some(2));
        assert_eq!(counts(&vault), (3, 3));

        changed["password"] = json!("another-synthetic-secret");
        let repassworded = vault.update_entry(&session, &json!(id), &changed, &available).unwrap();
        assert_eq!(repassworded["passwordChangedAt"], repassworded["updatedAt"]);

        assert_eq!(vault.delete_entry(&session, &json!(id), &available).unwrap(), json!({ "success": true }));
        assert_eq!(vault.get_entry(&session, &id).unwrap_err(), NOT_FOUND);
        assert_eq!(vault.delete_entry(&session, &json!(id), &available).unwrap_err(), NOT_FOUND);
        let tombstone: (i64, Option<String>) = vault.connection.lock().unwrap()
            .query_row("SELECT revision, envelope FROM vault_entries WHERE entry_id = ?1", [&id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!(tombstone, (3, None), "the id and revision stay, the ciphertext goes");
        assert_eq!(counts(&vault), (4, 4), "deleting releases no nonce");
        drop(vault);

        // Reopening runs the strict checks over everything written above.
        let reopened = Vault::open_writable(&database.0).unwrap();
        assert_eq!(reopened.status().maintenance.format, "v2");
    }

    #[test]
    fn nonces_are_never_reused_even_when_offered_twice() {
        let (_database, _, vault, _) = unlocked_v2();
        let iv = [7u8; IV_BYTES];
        assert!(matches!(vault.reserve_nonce("22222222-2222-4222-8222-222222222222", 1, &iv), Ok(true)));
        assert!(matches!(vault.reserve_nonce("33333333-3333-4333-8333-333333333333", 1, &iv), Ok(false)));
        assert_eq!(counts(&vault), (2, 2), "a collision consumes nothing");
    }

    #[test]
    fn a_stale_revision_conflicts_without_consuming_a_nonce() {
        let (_database, v2, vault, session) = unlocked_v2();
        let key = vault.session.lock().unwrap().key.clone().unwrap();
        let active = || -> Result<(), WriteError> { Ok(()) };
        let (entry, revision) = vault.read_v2_for_write(&key, s(&v2["entryId"])).ok().unwrap();
        let result = vault.write_v2_entry(&key, &entry, s(&v2["entryId"]), revision, &active);
        assert!(matches!(result, Err(WriteError::Conflict)));
        assert_eq!(counts(&vault), (1, 1));
        assert!(vault.get_entry(&session, s(&v2["entryId"])).is_ok());
    }

    #[test]
    fn a_lock_during_a_write_saves_nothing_and_keeps_the_used_nonce() {
        let (_database, v2, vault, session) = unlocked_v2();
        let before = vault.get_entry(&session, s(&v2["entryId"])).unwrap();
        let mut changed = login();
        changed["serviceName"] = json!("保存されない");
        // Every later check fails, which covers a lock arriving at each step up to the commit.
        for allowed_checks in 1..=5 {
            let calls = Cell::new(0);
            let guard = || {
                calls.set(calls.get() + 1);
                if calls.get() <= allowed_checks { Ok(()) } else { Err("画面ロック中".to_string()) }
            };
            let (nonces_before, _) = counts(&vault);
            match vault.update_entry(&session, &json!(s(&v2["entryId"])), &changed, &guard) {
                Ok(_) => panic!("a write finished with the OS away at check {allowed_checks}"),
                Err(message) => assert_eq!(message, "画面ロック中"),
            }
            assert_eq!(vault.get_entry(&session, s(&v2["entryId"])).unwrap(), before, "the entry is unchanged at check {allowed_checks}");
            let (nonces_after, table) = counts(&vault);
            assert_eq!(nonces_after, table);
            assert!(nonces_after - nonces_before <= 1);
        }
        assert!(!vault.faulted.load(Ordering::SeqCst), "a cancelled write is not a storage failure");
    }

    #[test]
    fn a_failure_after_the_reservation_leaves_a_vault_that_reopens_and_keeps_working() {
        let (database, v2, vault, session) = unlocked_v2();
        vault.reserve_nonce(&Uuid::new_v4().to_string(), 1, &[9u8; IV_BYTES]).ok().unwrap();
        assert_eq!(counts(&vault), (2, 2));
        drop(vault);
        let reopened = Vault::open_writable(&database.0).unwrap();
        let id = reopened.status().session_id;
        let new_session = reopened.unlock(&id, s(&v2["masterPassword"]).as_bytes()).unwrap().session_id;
        assert_ne!(new_session, session);
        reopened.create_entry(&new_session, &login(), &available).unwrap();
        assert_eq!(counts(&reopened), (3, 3));
    }

    #[test]
    fn the_key_and_entry_limits_stop_new_encryption_but_not_reading() {
        let (_database, v2, vault, session) = unlocked_v2();
        vault.connection.lock().unwrap().execute("UPDATE vault_header SET encryption_count = ?1", [MAX_ENCRYPTIONS]).unwrap();
        assert_eq!(vault.create_entry(&session, &login(), &available).unwrap_err(), KEY_LIMIT);
        assert!(vault.get_entry(&session, s(&v2["entryId"])).is_ok());
        assert!(!vault.faulted.load(Ordering::SeqCst));

        let (_database, _, vault, session) = unlocked_v2();
        {
            let mut connection = vault.connection.lock().unwrap();
            let transaction = connection.transaction().unwrap();
            for number in 0..entry_input::MAX_ENTRIES {
                transaction.execute("INSERT INTO vault_entries VALUES (?1, 1, 'x')", [format!("filler-{number}")]).unwrap();
            }
            transaction.commit().unwrap();
        }
        assert_eq!(vault.create_entry(&session, &login(), &available).unwrap_err(), ENTRY_LIMIT);
        assert_eq!(counts(&vault), (1, 1), "refused before using a nonce");
    }

    #[test]
    fn saving_a_kind_raises_the_schema_marker_and_never_lowers_it() {
        let (_database, _, vault, session) = unlocked_v2();
        assert_eq!(user_version(&vault), 1);
        vault.create_entry(&session, &json!({ "type": "apiKey", "serviceName": "合成", "apiKey": { "key": "synthetic" } }), &available).unwrap();
        assert_eq!(user_version(&vault), 2);
        vault.create_entry(&session, &json!({ "type": "financial", "serviceName": "合成", "financial": { "loginId": "x", "loginPassword": "synthetic" } }), &available).unwrap();
        assert_eq!(user_version(&vault), 3);
        vault.create_entry(&session, &login(), &available).unwrap();
        assert_eq!(user_version(&vault), 3);
    }

    #[test]
    fn a_rejected_input_uses_no_nonce_and_kinds_cannot_change() {
        let (_database, v2, vault, session) = unlocked_v2();
        let missing_password = json!({ "serviceName": "x", "loginId": "y", "password": "" });
        assert_eq!(vault.create_entry(&session, &missing_password, &available).unwrap_err(), "パスワードは必須です");
        let api_key = json!({ "type": "apiKey", "serviceName": "x", "apiKey": { "key": "synthetic" } });
        assert_eq!(vault.update_entry(&session, &json!(s(&v2["entryId"])), &api_key, &available).unwrap_err(), "保存済みの項目の種類は変更できません");
        assert_eq!(vault.update_entry(&session, &json!("missing"), &login(), &available).unwrap_err(), NOT_FOUND);
        assert_eq!(vault.update_entry(&session, &json!(""), &login(), &available).unwrap_err(), "エントリIDの形式が正しくありません");
        assert_eq!(counts(&vault), (1, 1));
    }

    #[test]
    fn v2_keeps_every_field_out_of_the_file_in_plain_text() {
        let (database, _, vault, session) = unlocked_v2();
        vault.create_entry(&session, &login(), &available).unwrap();
        drop(vault);
        let bytes = std::fs::read(&database.0).unwrap();
        for value in ["合成サービス", "synthetic-login", "synthetic-secret-value", "synthetic-notes-value"] {
            assert!(!contains(&bytes, value), "{value} reached the file");
        }
    }

    #[test]
    fn a_deleted_secret_is_overwritten_in_the_file() {
        let (database, _, vault, session) = unlocked_legacy();
        let created = vault.create_entry(&session, &json!({ "serviceName": "消える合成名", "loginId": "x", "password": "synthetic" }), &available).unwrap();
        vault.delete_entry(&session, &created["id"], &available).unwrap();
        drop(vault);
        assert!(!contains(&std::fs::read(&database.0).unwrap(), "消える合成名"), "secure_delete is on");
    }

    #[test]
    fn group_changes_touch_only_what_changed_and_an_unknown_id_changes_nothing() {
        let (_database, _, vault, session) = unlocked_v2();
        let first = vault.create_entry(&session, &login(), &available).unwrap();
        let second = vault.create_entry(&session, &login(), &available).unwrap();
        let ids = json!([first["id"], second["id"], first["id"]]);
        assert_eq!(vault.set_entries_group(&session, &json!({ "ids": ids, "group": " 新 " }), &available).unwrap()["updatedCount"], 2, "duplicates count once");
        assert_eq!(vault.set_entries_group(&session, &json!({ "ids": ids, "group": "新" }), &available).unwrap()["updatedCount"], 0);
        let (before, _) = counts(&vault);
        assert_eq!(vault.set_entries_group(&session, &json!({ "ids": [first["id"], "missing"], "group": "別" }), &available).unwrap_err(), NOT_FOUND);
        assert_eq!(counts(&vault).0, before);
        assert_eq!(vault.get_entry(&session, first["id"].as_str().unwrap()).unwrap()["group"], "新");
        assert_eq!(vault.set_entries_group(&session, &json!({ "ids": [first["id"]], "group": null }), &available).unwrap()["updatedCount"], 1);
        assert_eq!(vault.get_entry(&session, first["id"].as_str().unwrap()).unwrap()["group"], Value::Null);

        let (_database, _, vault, session) = unlocked_legacy();
        let first = vault.create_entry(&session, &login(), &available).unwrap();
        assert_eq!(vault.set_entries_group(&session, &json!({ "ids": [first["id"], "missing"], "group": "別" }), &available).unwrap_err(), NOT_FOUND);
        assert_eq!(vault.get_entry(&session, first["id"].as_str().unwrap()).unwrap()["group"], "g", "one transaction rolls back the whole change");
    }

    #[test]
    fn legacy_writes_keep_the_old_columns_and_stay_logins_only() {
        let (database, legacy, vault, session) = unlocked_legacy();
        let created = vault.create_entry(&session, &login(), &available).unwrap();
        let id = created["id"].as_str().unwrap();
        assert_eq!(created["password"], "synthetic-secret-value");
        assert_eq!(created["notes"], "synthetic-notes-value");
        assert_eq!(created["group"], "g");
        assert_eq!(created["passwordChangedAt"], created["createdAt"]);

        let mut no_extras = json!({ "serviceName": "x", "loginId": "y", "password": "synthetic-secret-value" });
        let updated = vault.update_entry(&session, &json!(id), &no_extras, &available).unwrap();
        assert_eq!(updated["passwordChangedAt"], created["passwordChangedAt"]);
        assert_eq!(updated["createdAt"], created["createdAt"]);
        assert_eq!(updated["notes"], "");
        assert_eq!(updated["group"], Value::Null);
        let stored: (Option<String>, Option<String>) = vault.connection.lock().unwrap()
            .query_row("SELECT encrypted_notes, url FROM password_entries WHERE id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!(stored, (None, None), "empty values are stored as NULL, like the app");
        no_extras["password"] = json!("another-synthetic-secret");
        let changed = vault.update_entry(&session, &json!(id), &no_extras, &available).unwrap();
        assert_eq!(changed["passwordChangedAt"], changed["updatedAt"]);

        let api_key = json!({ "type": "apiKey", "serviceName": "x", "apiKey": { "key": "synthetic" } });
        assert!(vault.create_entry(&session, &api_key, &available).unwrap_err().contains("新しい形式への移行"));
        let typed_login = json!({ "type": "login", "serviceName": "x", "loginId": "y", "password": "z" });
        assert_eq!(vault.create_entry(&session, &typed_login, &available).unwrap_err(), "未対応の入力項目があります");
        vault.delete_entry(&session, &json!(id), &available).unwrap();
        assert_eq!(vault.delete_entry(&session, &json!(id), &available).unwrap_err(), NOT_FOUND);
        for expected in legacy["entries"].as_array().unwrap() {
            assert_eq!(vault.get_entry(&session, s(&expected["id"])).unwrap(), *expected, "other entries still read");
        }
        drop(vault);
        let bytes = std::fs::read(&database.0).unwrap();
        assert!(!contains(&bytes, "another-synthetic-secret"));
    }

    #[test]
    fn writes_need_write_mode_an_unlocked_current_session_and_the_os_present() {
        let (database, legacy) = legacy_database(true, true);
        let before = std::fs::read(&database.0).unwrap();
        let read_only = Vault::open(&database.0).unwrap();
        let id = read_only.status().session_id;
        let session = read_only.unlock(&id, s(&legacy["password"]).as_bytes()).unwrap().session_id;
        assert_eq!(read_only.create_entry(&session, &login(), &available).unwrap_err(), READ_ONLY);
        assert_eq!(read_only.delete_entry(&session, &json!(s(&legacy["entries"][0]["id"])), &available).unwrap_err(), READ_ONLY);
        drop(read_only);
        assert_eq!(std::fs::read(&database.0).unwrap(), before);

        let (_database, _, vault, session) = unlocked_legacy();
        let away = || Err("画面ロック中".to_string());
        assert_eq!(vault.create_entry(&session, &login(), &away).unwrap_err(), "画面ロック中");
        assert_eq!(vault.create_entry("stale", &login(), &available).unwrap_err(), CHANGED);
        vault.lock_for("suspend");
        assert_eq!(vault.create_entry(&session, &login(), &available).unwrap_err(), LOCKED);
    }

    #[test]
    fn a_second_write_during_a_write_is_refused() {
        let (_database, _, vault, session) = unlocked_legacy();
        vault.writing.store(true, Ordering::SeqCst);
        assert_eq!(vault.create_entry(&session, &login(), &available).unwrap_err(), CONFLICT);
    }

    #[test]
    fn a_storage_failure_stops_all_use_until_a_restart() {
        let (_database, _, vault, session) = unlocked_v2();
        vault.connection.lock().unwrap().execute_batch("DROP TABLE vault_nonces").unwrap();
        assert_eq!(vault.create_entry(&session, &login(), &available).unwrap_err(), STORAGE_FAILED);
        assert_eq!(vault.create_entry(&session, &login(), &available).unwrap_err(), STORAGE_FAILED);
        assert_eq!(vault.list_entries(&session).unwrap_err(), STORAGE_FAILED);
    }

    #[test]
    fn write_mode_refuses_anything_but_the_exact_expected_database() {
        let tamper = |sql: &str| {
            let (database, _) = v2_database();
            Connection::open(&database.0).unwrap().execute_batch(sql).unwrap();
            let error = Vault::open_writable(&database.0).err().expect("a tampered database opened for writing");
            assert_eq!(error, UNSUPPORTED, "{sql}");
        };
        tamper("UPDATE vault_header SET encryption_count = 5");
        tamper("CREATE TABLE extra (id INTEGER)");
        tamper("PRAGMA journal_mode = WAL");
        tamper("PRAGMA user_version = 9");
        tamper("DROP TABLE vault_nonces; CREATE TABLE vault_nonces (key_id TEXT, iv BLOB, entry_id TEXT, revision INTEGER)");

        let (database, _) = legacy_database(true, false);
        assert!(Vault::open_writable(&database.0).err().unwrap().contains("移行"), "columns are not added silently");
        let (database, _) = legacy_database(true, true);
        Connection::open(&database.0).unwrap().execute_batch("PRAGMA user_version = 1").unwrap();
        assert_eq!(Vault::open_writable(&database.0).err().unwrap(), UNSUPPORTED);
    }

    #[test]
    fn real_data_locations_are_refused_and_a_copy_elsewhere_is_not() {
        let app_data = Some(r"C:\Users\someone\AppData\Roaming");
        for path in [r"C:\Users\someone\AppData\Roaming\CIPHER VAULT\data\password-manager.db", r"c:\users\someone\appdata\roaming\password-manager\data\x.db",
            r"D:\work\repo\apps\api\data\password-manager.db", "D:/work/repo/release/data/password-manager.db"] {
            assert!(is_protected_path(path, app_data), "{path}");
        }
        for path in [r"C:\Users\someone\AppData\Local\Temp\sample\vault.db", r"C:\Users\someone\AppData\RoamingCopy\vault.db", r"D:\copies\vault.db"] {
            assert!(!is_protected_path(path, app_data), "{path}");
        }
        assert!(!is_protected_path(r"D:\copies\vault.db", None));
    }
}

//! Read-only vault access for the prototype, mirroring apps/api/src/services for these paths only.
//! It never writes, so a legacy raw verifier stays as it is instead of being upgraded on unlock.

use cipher_vault_crypto_compat::{self as crypto, CryptoError, Secret};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;
use zeroize::Zeroizing;

const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const V2_APPLICATION_ID: i64 = 0x4356_3200;
const MAX_PASSWORD_BYTES: usize = 1024 * 1024;
const MAX_ENTRY_ID_BYTES: usize = 128;

const LOCKED: &str = "保管庫はロックされています";
const CHANGED: &str = "保管庫の状態が変わりました。もう一度操作してください";
const WRONG_PASSWORD: &str = "マスターパスワードが正しくありません";
const NOT_FOUND: &str = "エントリが見つかりません";
const BROKEN: &str = "保管庫の検証に失敗しました";

#[derive(Clone, Copy)]
struct Stamp {
    monotonic: Instant,
    wall: SystemTime,
}

impl Stamp {
    fn now() -> Self {
        Self { monotonic: Instant::now(), wall: SystemTime::now() }
    }
}

struct Session {
    key: Option<Secret>,
    id: String,
    lock_reason: Option<&'static str>,
    activity: Stamp,
    observed: Stamp,
}

impl Session {
    fn new() -> Self {
        let now = Stamp::now();
        Self { key: None, id: Uuid::new_v4().to_string(), lock_reason: None, activity: now, observed: now }
    }

    /// Replacing the key drops the old one, and `Zeroizing` clears it.
    fn set_key(&mut self, key: Secret, now: Stamp) {
        self.key = Some(key);
        self.id = Uuid::new_v4().to_string();
        self.lock_reason = None;
        self.activity = now;
        self.observed = now;
    }

    fn lock(&mut self, reason: &'static str) {
        self.key = None;
        self.id = Uuid::new_v4().to_string();
        self.lock_reason = Some(reason);
    }

    fn expire(&mut self, now: Stamp) {
        if self.key.is_none() {
            return;
        }
        // A wall clock moving backwards could otherwise extend the deadline.
        let Ok(wall_elapsed) = now.wall.duration_since(self.activity.wall) else {
            self.lock("clock-change");
            return;
        };
        if now.wall < self.observed.wall {
            self.lock("clock-change");
            return;
        }
        self.observed = now;
        // Wall time covers suspend, when the monotonic clock may pause.
        if now.monotonic.duration_since(self.activity.monotonic).max(wall_elapsed) >= IDLE_TIMEOUT {
            self.lock("idle");
        }
    }
}

enum Format {
    Legacy { salt: String, verifier: String, raw_verifier: bool, has_group: bool, has_changed_at: bool },
    V2 { vault_id: String, key_id: String, slot_revision: u64, slot: String },
}

#[derive(Debug, Serialize)]
pub struct Maintenance {
    state: &'static str,
    format: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    is_configured: bool,
    session_id: String,
    is_unlocked: bool,
    idle_timeout_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    lock_reason: Option<&'static str>,
    maintenance: Maintenance,
}

pub struct Vault {
    format: Format,
    connection: Mutex<Connection>,
    session: Mutex<Session>,
    unlocking: AtomicBool,
}

fn storage_error<E>(_: E) -> String {
    // Native error text can contain paths, so it stays out of the UI.
    BROKEN.to_string()
}

fn column_names(connection: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    connection
        .prepare("SELECT name FROM pragma_table_info(?1)")?
        .query_map([table], |row| row.get(0))?
        .collect()
}

fn inspect_legacy(connection: &Connection) -> Result<Format, String> {
    const UNSUPPORTED: &str = "未対応のDB形式です";
    const REQUIRED: [&str; 9] = ["id", "service_name", "login_id", "encrypted_password", "encrypted_notes", "url", "tags", "created_at", "updated_at"];
    let columns = column_names(connection, "password_entries").map_err(|_| UNSUPPORTED)?;
    if !REQUIRED.iter().all(|name| columns.iter().any(|column| column == name)) {
        return Err(UNSUPPORTED.into());
    }
    let (salt, verifier, kdf_params): (String, String, String) = connection
        .query_row("SELECT password_salt, password_verifier, kdf_params FROM vault_metadata WHERE id = 1", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .optional()
        .map_err(|_| UNSUPPORTED)?
        .ok_or("保管庫が設定されていないDBです。この試作版は初期設定を行いません")?;
    let params: Value = serde_json::from_str(&kdf_params).map_err(|_| UNSUPPORTED)?;
    let verifier_algorithm = params.get("verifierAlgorithm");
    if params["algorithm"] != "scrypt" || params["keyLength"] != 32 || verifier_algorithm.is_some_and(|value| value != "hmac-sha256-v1") {
        return Err(UNSUPPORTED.into());
    }
    Ok(Format::Legacy {
        salt,
        verifier,
        raw_verifier: verifier_algorithm.is_none(),
        has_group: columns.iter().any(|column| column == "group_name"),
        has_changed_at: columns.iter().any(|column| column == "password_changed_at"),
    })
}

/// Checks the header only. The app also compares the exact DDL and nonce counts.
fn inspect_v2(connection: &Connection) -> Result<Format, String> {
    let header: (String, String, i64, String) = connection
        .query_row("SELECT vault_id, key_id, slot_revision, password_slot FROM vault_header WHERE singleton = 1", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(|_| "未対応のDB形式です")?;
    let slot_revision = u64::try_from(header.2).map_err(|_| "未対応のDB形式です")?;
    Ok(Format::V2 { vault_id: header.0, key_id: header.1, slot_revision, slot: header.3 })
}

fn text_list(tags: &str) -> Value {
    let parsed: Value = serde_json::from_str(tags).unwrap_or(Value::Null);
    let strings = parsed.as_array().map(|items| items.iter().filter(|item| item.is_string()).cloned().collect());
    Value::Array(strings.unwrap_or_default())
}

fn decrypted_text(key: &[u8], payload: &str) -> Result<Zeroizing<String>, String> {
    let bytes = crypto::open_legacy_secret(key, payload).map_err(storage_error)?;
    // Matches Buffer.toString("utf8"), which also replaces invalid sequences.
    Ok(Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned()))
}

fn entry_summary(entry: &Value) -> Value {
    let mut summary = json!({ "id": entry["id"], "serviceName": entry["serviceName"], "tags": entry["tags"], "group": entry["group"], "updatedAt": entry["updatedAt"] });
    match entry["type"].as_str() {
        Some(kind @ ("apiKey" | "financial")) => summary["type"] = json!(kind),
        Some("creditCard") => {
            let number: Vec<char> = entry["card"]["number"].as_str().unwrap_or_default().chars().collect();
            let last4: String = number[number.len().saturating_sub(4)..].iter().collect();
            summary["type"] = json!("creditCard");
            summary["cardLast4"] = json!(last4);
        }
        _ => summary["loginId"] = entry["loginId"].clone(),
    }
    summary
}

impl Vault {
    pub fn open(path: &Path) -> Result<Self, String> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(path, flags).map_err(|_| "DBを読取専用で開けません")?;
        connection.pragma_update(None, "query_only", true).map_err(|_| "DBを読取専用で開けません")?;
        let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0)).map_err(|_| "DBを読み取れません")?;
        let format = if application_id == V2_APPLICATION_ID { inspect_v2(&connection)? } else { inspect_legacy(&connection)? };
        Ok(Self { format, connection: Mutex::new(connection), session: Mutex::new(Session::new()), unlocking: AtomicBool::new(false) })
    }

    pub fn status(&self) -> VaultStatus {
        let mut session = self.session.lock().unwrap();
        session.expire(Stamp::now());
        VaultStatus {
            is_configured: true,
            session_id: session.id.clone(),
            is_unlocked: session.key.is_some(),
            idle_timeout_ms: IDLE_TIMEOUT.as_millis() as u64,
            lock_reason: session.lock_reason,
            maintenance: Maintenance { state: "ready", format: if matches!(self.format, Format::V2 { .. }) { "v2" } else { "legacy" } },
        }
    }

    fn require_generation(&self, session_id: &str) -> Result<(), String> {
        let mut session = self.session.lock().unwrap();
        session.expire(Stamp::now());
        if session.id == session_id { Ok(()) } else { Err(CHANGED.into()) }
    }

    /// Runs `action` with the key, then rechecks that the session is still the same one.
    fn with_key<T>(&self, session_id: &str, action: impl FnOnce(&[u8]) -> Result<T, String>) -> Result<T, String> {
        let key = {
            let mut session = self.session.lock().unwrap();
            session.expire(Stamp::now());
            if session.id != session_id {
                return Err(if session.key.is_some() { CHANGED } else { LOCKED }.into());
            }
            session.key.clone().ok_or(LOCKED)?
        };
        let result = action(&key)?;
        self.require_generation(session_id)?;
        Ok(result)
    }

    pub fn unlock(&self, session_id: &str, password: &[u8]) -> Result<VaultStatus, String> {
        if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
            return Err("マスターパスワードの形式が正しくありません".into());
        }
        self.require_generation(session_id)?;
        // One KDF at a time, and later requests are refused rather than queued with their passwords.
        if self.unlocking.swap(true, Ordering::SeqCst) {
            return Err("解除処理を実行中です。しばらく待ってから操作してください".into());
        }
        let derived = self.derive_session_key(password);
        self.unlocking.store(false, Ordering::SeqCst);
        let key = derived?;
        let mut session = self.session.lock().unwrap();
        // A lock during the KDF changed the generation, so the new key is dropped.
        if session.id != session_id {
            return Err(CHANGED.into());
        }
        session.set_key(key, Stamp::now());
        drop(session);
        Ok(self.status())
    }

    fn derive_session_key(&self, password: &[u8]) -> Result<Secret, String> {
        match &self.format {
            Format::Legacy { salt, verifier, raw_verifier, .. } => {
                let key = crypto::derive_legacy_key(password, salt).map_err(storage_error)?;
                if crypto::verify_legacy_key(&key, verifier, *raw_verifier) { Ok(key) } else { Err(WRONG_PASSWORD.into()) }
            }
            Format::V2 { vault_id, key_id, slot_revision, slot } => {
                let root = crypto::unwrap_v2_root(slot, password, vault_id, key_id, *slot_revision).map_err(|error| match error {
                    CryptoError::Authentication => WRONG_PASSWORD.to_string(),
                    _ => BROKEN.to_string(),
                })?;
                // Like the app: no key is installed until every current entry authenticates.
                self.read_v2_entries(&root)?;
                Ok(root)
            }
        }
    }

    pub fn lock(&self, session_id: &str) -> Result<VaultStatus, String> {
        self.require_generation(session_id)?;
        self.session.lock().unwrap().lock("manual");
        Ok(self.status())
    }

    pub fn record_activity(&self, session_id: &str) -> Result<VaultStatus, String> {
        {
            let mut session = self.session.lock().unwrap();
            // Check expiry first: late traffic must not revive an expired key.
            session.expire(Stamp::now());
            if session.key.is_none() {
                return Err(LOCKED.into());
            }
            if session.id != session_id {
                return Err(CHANGED.into());
            }
            let now = Stamp::now();
            session.activity = now;
            session.observed = now;
        }
        Ok(self.status())
    }

    pub fn list_entries(&self, session_id: &str) -> Result<Value, String> {
        self.with_key(session_id, |key| {
            let items = match &self.format {
                Format::Legacy { has_group, .. } => self.list_legacy(*has_group)?,
                Format::V2 { .. } => {
                    let mut items: Vec<Value> = self.read_v2_entries(key)?.iter().map(entry_summary).collect();
                    items.sort_by(|a, b| {
                        let field = |value: &'_ Value, name: &str| value[name].as_str().unwrap_or_default().to_string();
                        field(b, "updatedAt").cmp(&field(a, "updatedAt")).then_with(|| field(a, "id").cmp(&field(b, "id")))
                    });
                    items
                }
            };
            Ok(json!({ "items": items }))
        })
    }

    pub fn get_entry(&self, session_id: &str, id: &str) -> Result<Value, String> {
        if id.is_empty() || id.len() > MAX_ENTRY_ID_BYTES {
            return Err(NOT_FOUND.into());
        }
        self.with_key(session_id, |key| match &self.format {
            Format::Legacy { has_group, has_changed_at, .. } => self.get_legacy(key, id, *has_group, *has_changed_at),
            Format::V2 { .. } => self.read_v2_entry(key, id)?.ok_or_else(|| NOT_FOUND.to_string()),
        })
    }

    fn list_legacy(&self, has_group: bool) -> Result<Vec<Value>, String> {
        let group = if has_group { "group_name" } else { "NULL" };
        let connection = self.connection.lock().unwrap();
        let sql = format!("SELECT id, service_name, login_id, tags, {group}, updated_at FROM password_entries ORDER BY updated_at DESC");
        let mut statement = connection.prepare(&sql).map_err(storage_error)?;
        let rows = statement.query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?, "serviceName": row.get::<_, String>(1)?, "loginId": row.get::<_, String>(2)?,
                "tags": text_list(&row.get::<_, String>(3)?), "group": row.get::<_, Option<String>>(4)?, "updatedAt": row.get::<_, String>(5)?
            }))
        });
        rows.map_err(storage_error)?.collect::<rusqlite::Result<_>>().map_err(storage_error)
    }

    fn get_legacy(&self, key: &[u8], id: &str, has_group: bool, has_changed_at: bool) -> Result<Value, String> {
        let group = if has_group { "group_name" } else { "NULL" };
        let changed_at = if has_changed_at { "password_changed_at" } else { "NULL" };
        let sql = format!(
            "SELECT id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, {group}, created_at, updated_at, {changed_at} FROM password_entries WHERE id = ?1"
        );
        let connection = self.connection.lock().unwrap();
        type Row = (String, String, String, String, Option<String>, Option<String>, String, Option<String>, String, String, Option<String>);
        let row: Row = connection
            .query_row(&sql, [id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?))
            })
            .optional()
            .map_err(storage_error)?
            .ok_or(NOT_FOUND)?;
        drop(connection);
        let password = decrypted_text(key, &row.3)?;
        let notes = match row.4.as_deref() {
            Some(payload) if !payload.is_empty() => decrypted_text(key, payload)?,
            _ => Zeroizing::new(String::new()),
        };
        Ok(json!({
            "id": row.0, "serviceName": row.1, "loginId": row.2, "tags": text_list(&row.6), "group": row.7, "updatedAt": row.9,
            "password": *password, "notes": *notes, "url": row.5.unwrap_or_default(), "createdAt": row.8, "passwordChangedAt": row.10
        }))
    }

    fn read_v2_entries(&self, root: &[u8]) -> Result<Vec<Value>, String> {
        let ids: Vec<String> = {
            let connection = self.connection.lock().unwrap();
            let mut statement = connection.prepare("SELECT entry_id FROM vault_entries WHERE envelope IS NOT NULL ORDER BY entry_id").map_err(storage_error)?;
            let rows = statement.query_map([], |row| row.get(0)).map_err(storage_error)?;
            rows.collect::<rusqlite::Result<_>>().map_err(storage_error)?
        };
        ids.iter().map(|id| self.read_v2_entry(root, id)?.ok_or_else(|| BROKEN.to_string())).collect()
    }

    fn read_v2_entry(&self, root: &[u8], id: &str) -> Result<Option<Value>, String> {
        let Format::V2 { vault_id, key_id, .. } = &self.format else {
            return Err(BROKEN.into());
        };
        let connection = self.connection.lock().unwrap();
        let row: Option<(i64, Option<String>)> = connection
            .query_row("SELECT revision, envelope FROM vault_entries WHERE entry_id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
            .map_err(storage_error)?;
        let Some((revision, Some(envelope))) = row else {
            return Ok(None);
        };
        // An envelope whose nonce was never reserved for this revision did not come from the writer.
        let parsed: Value = serde_json::from_str(&envelope).map_err(storage_error)?;
        let iv = crypto::decode_base64(parsed["iv"].as_str().unwrap_or_default(), Some(12)).map_err(storage_error)?;
        let reserved = connection
            .query_row("SELECT 1 FROM vault_nonces WHERE key_id = ?1 AND iv = ?2 AND entry_id = ?3 AND revision = ?4", params![key_id, iv, id, revision], |_| Ok(()))
            .optional()
            .map_err(storage_error)?;
        drop(connection);
        reserved.ok_or(BROKEN)?;
        let revision = u64::try_from(revision).map_err(storage_error)?;
        let plaintext = crypto::open_v2_entry(root, &envelope, vault_id, key_id, id, revision).map_err(storage_error)?;
        serde_json::from_slice(&plaintext).map(Some).map_err(storage_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SCHEMA: &str = include_str!("../../../apps/api/src/db/schema.sql");
    const FIXTURE: &str = include_str!("../../../tests/fixtures/crypto-compatibility.json");

    struct TemporaryDatabase(PathBuf);

    impl TemporaryDatabase {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!("cipher-vault-tauri-poc-{}", Uuid::new_v4()));
            std::fs::create_dir(&directory).unwrap();
            Self(directory.join("vault.db"))
        }
    }

    impl Drop for TemporaryDatabase {
        fn drop(&mut self) {
            let directory = self.0.parent().unwrap();
            assert!(directory.file_name().unwrap().to_string_lossy().starts_with("cipher-vault-tauri-poc-"));
            let _ = std::fs::remove_dir_all(directory);
        }
    }

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn s(value: &Value) -> &str {
        value.as_str().unwrap()
    }

    fn legacy_database(hmac_verifier: bool, modern_columns: bool) -> (TemporaryDatabase, Value) {
        let fixture = fixture();
        let legacy = fixture["legacy"].clone();
        let database = TemporaryDatabase::new();
        let connection = Connection::open(&database.0).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        if !modern_columns {
            connection.execute_batch("ALTER TABLE password_entries DROP COLUMN group_name; ALTER TABLE password_entries DROP COLUMN password_changed_at;").unwrap();
        }
        let metadata = &legacy["metadata"];
        let (verifier, params) = if hmac_verifier {
            (s(&legacy["verifier"]), r#"{"algorithm":"scrypt","keyLength":32,"verifierAlgorithm":"hmac-sha256-v1"}"#)
        } else {
            (s(&metadata["passwordVerifier"]), s(&metadata["kdfParams"]))
        };
        connection
            .execute("INSERT INTO vault_metadata VALUES (1, ?1, ?2, ?3, ?4, ?5)", params![s(&metadata["passwordSalt"]), verifier, params, s(&metadata["createdAt"]), s(&metadata["updatedAt"])])
            .unwrap();
        for row in legacy["rows"].as_array().unwrap() {
            let values = [("id", row["id"].clone()), ("service_name", row["service_name"].clone()), ("login_id", row["login_id"].clone()),
                ("encrypted_password", row["encrypted_password"].clone()), ("encrypted_notes", row["encrypted_notes"].clone()), ("url", row["url"].clone()),
                ("tags", row["tags"].clone()), ("created_at", row["created_at"].clone()), ("updated_at", row["updated_at"].clone()),
                ("group_name", row["group_name"].clone()), ("password_changed_at", row["password_changed_at"].clone())];
            let values: Vec<_> = values.iter().filter(|(name, _)| modern_columns || !matches!(*name, "group_name" | "password_changed_at")).collect();
            let names: Vec<&str> = values.iter().map(|(name, _)| *name).collect();
            let marks = vec!["?"; values.len()].join(",");
            let parameters = rusqlite::params_from_iter(values.iter().map(|(_, value)| value.as_str().map(str::to_string)));
            connection.execute(&format!("INSERT INTO password_entries ({}) VALUES ({marks})", names.join(",")), parameters).unwrap();
        }
        (database, legacy)
    }

    fn v2_database() -> (TemporaryDatabase, Value) {
        let fixture = fixture();
        let v2 = fixture["draftV2"].clone();
        let database = TemporaryDatabase::new();
        let connection = Connection::open(&database.0).unwrap();
        connection
            .execute_batch(&format!(
                "PRAGMA application_id = {V2_APPLICATION_ID};
                 CREATE TABLE vault_header (singleton INTEGER PRIMARY KEY, vault_id TEXT, key_id TEXT, slot_revision INTEGER, password_slot TEXT, encryption_count INTEGER);
                 CREATE TABLE vault_entries (entry_id TEXT PRIMARY KEY, revision INTEGER, envelope TEXT);
                 CREATE TABLE vault_nonces (key_id TEXT, iv BLOB, entry_id TEXT, revision INTEGER);"
            ))
            .unwrap();
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

    #[test]
    fn legacy_unlock_list_and_read_match_the_fixture_without_changing_the_file() {
        for hmac_verifier in [false, true] {
            let (database, legacy) = legacy_database(hmac_verifier, true);
            let before = std::fs::read(&database.0).unwrap();
            let vault = Vault::open(&database.0).unwrap();
            let id = vault.status().session_id;
            assert_eq!(vault.unlock(&id, b"fixture-wrong-master-password").unwrap_err(), WRONG_PASSWORD);
            assert!(!vault.status().is_unlocked);
            let status = vault.unlock(&id, s(&legacy["password"]).as_bytes()).unwrap();
            assert!(status.is_unlocked);
            assert_ne!(status.session_id, id, "unlocking starts a new session");

            let list = vault.list_entries(&status.session_id).unwrap();
            let items = list["items"].as_array().unwrap();
            assert_eq!(items.len(), 2);
            assert_eq!(items[0]["id"], legacy["entries"][1]["id"], "newest first");
            assert!(items.iter().all(|item| item.get("password").is_none()), "a list never carries secrets");
            for expected in legacy["entries"].as_array().unwrap() {
                assert_eq!(vault.get_entry(&status.session_id, s(&expected["id"])).unwrap(), *expected);
            }
            assert_eq!(vault.get_entry(&status.session_id, "missing").unwrap_err(), NOT_FOUND);
            drop(vault);
            assert_eq!(std::fs::read(&database.0).unwrap(), before);
        }
    }

    #[test]
    fn databases_from_before_the_optional_columns_still_read() {
        let (database, legacy) = legacy_database(false, false);
        let vault = Vault::open(&database.0).unwrap();
        let id = vault.status().session_id;
        let session = vault.unlock(&id, s(&legacy["password"]).as_bytes()).unwrap().session_id;
        let entry = vault.get_entry(&session, s(&legacy["entries"][0]["id"])).unwrap();
        assert_eq!(entry["password"], legacy["entries"][0]["password"]);
        assert_eq!(entry["group"], Value::Null);
        assert_eq!(entry["passwordChangedAt"], Value::Null);
    }

    #[test]
    fn v2_unlock_list_and_read_match_the_fixture() {
        let (database, v2) = v2_database();
        let vault = Vault::open(&database.0).unwrap();
        let id = vault.status().session_id;
        assert_eq!(vault.unlock(&id, b"wrong-password").unwrap_err(), WRONG_PASSWORD);
        let session = vault.unlock(&id, s(&v2["masterPassword"]).as_bytes()).unwrap().session_id;
        let expected: Value = serde_json::from_str(s(&v2["entryPlaintext"])).unwrap();
        assert_eq!(vault.get_entry(&session, s(&v2["entryId"])).unwrap(), expected);
        let list = vault.list_entries(&session).unwrap();
        assert_eq!(list["items"][0]["loginId"], expected["loginId"]);
        assert!(list["items"][0].get("password").is_none());
    }

    #[test]
    fn v2_refuses_to_unlock_when_an_entry_has_no_reserved_nonce() {
        let (database, v2) = v2_database();
        Connection::open(&database.0).unwrap().execute("DELETE FROM vault_nonces", []).unwrap();
        let vault = Vault::open(&database.0).unwrap();
        let id = vault.status().session_id;
        assert_eq!(vault.unlock(&id, s(&v2["masterPassword"]).as_bytes()).unwrap_err(), BROKEN);
        assert!(!vault.status().is_unlocked);
    }

    #[test]
    fn old_sessions_and_locked_vaults_cannot_read() {
        let (database, legacy) = legacy_database(true, true);
        let vault = Vault::open(&database.0).unwrap();
        let first = vault.status().session_id;
        assert_eq!(vault.list_entries(&first).unwrap_err(), LOCKED);
        let session = vault.unlock(&first, s(&legacy["password"]).as_bytes()).unwrap().session_id;
        assert_eq!(vault.list_entries(&first).unwrap_err(), CHANGED);
        assert_eq!(vault.record_activity(&first).unwrap_err(), CHANGED);
        assert_eq!(vault.lock(&first).unwrap_err(), CHANGED);
        let locked = vault.lock(&session).unwrap();
        assert!(!locked.is_unlocked);
        assert_eq!(locked.lock_reason, Some("manual"));
        // Like VaultSession.requireUnlocked, "locked" takes priority over a stale session id.
        assert_eq!(vault.list_entries(&session).unwrap_err(), LOCKED);
        assert_eq!(vault.record_activity(&locked.session_id).unwrap_err(), LOCKED);
    }

    #[test]
    fn writes_are_impossible_through_the_connection() {
        let (database, _) = legacy_database(true, true);
        let vault = Vault::open(&database.0).unwrap();
        let connection = vault.connection.lock().unwrap();
        assert!(connection.execute("DELETE FROM password_entries", []).is_err());
    }

    #[test]
    fn idle_time_and_clock_changes_destroy_the_key() {
        let start = Stamp::now();
        let unlocked = || {
            let mut session = Session::new();
            session.set_key(Zeroizing::new(vec![1; 32]), start);
            session
        };
        let mut session = unlocked();
        session.expire(Stamp { monotonic: start.monotonic + IDLE_TIMEOUT - Duration::from_secs(1), wall: start.wall + Duration::from_secs(1) });
        assert!(session.key.is_some());
        session.expire(Stamp { monotonic: start.monotonic + IDLE_TIMEOUT, wall: start.wall + IDLE_TIMEOUT });
        assert!(session.key.is_none());
        assert_eq!(session.lock_reason, Some("idle"));

        // A suspended machine: the monotonic clock paused while the wall clock moved on.
        let mut session = unlocked();
        session.expire(Stamp { monotonic: start.monotonic + Duration::from_secs(1), wall: start.wall + IDLE_TIMEOUT });
        assert_eq!(session.lock_reason, Some("idle"));

        let mut session = unlocked();
        session.expire(Stamp { monotonic: start.monotonic + Duration::from_secs(1), wall: start.wall - Duration::from_secs(1) });
        assert_eq!(session.lock_reason, Some("clock-change"));
        assert!(session.key.is_none());
    }
}

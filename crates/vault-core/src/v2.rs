//! The v2 SQLite file, following apps/api/src/db/v2-schema.ts and v2-store.ts. Each entry is its
//! own envelope. A nonce is reserved durably before it is used and never released, so a key never
//! encrypts twice with one nonce, even after a crash between reserving and saving.

use crate::crypto;
use crate::input::{self, MAX_ENTRIES};
use crate::selection::is_vault_uuid;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Map, Value};
use std::path::Path;

pub const APPLICATION_ID: i64 = 0x4356_3200;
const LOGIN_SCHEMA_VERSION: i64 = 1;
const ITEM_SCHEMA_VERSION: i64 = 2;
const FINANCIAL_SCHEMA_VERSION: i64 = 3;
const MAX_ENCRYPTIONS: i64 = 1 << 20;
const MAX_REVISION: u64 = 0xffff_ffff;
const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize = 11 * 1024 * 1024;
const MAX_ID_BYTES: usize = 128;
const NONCE_ATTEMPTS: usize = 8;
const IV_BYTES: usize = 12;
const SLOT_REVISION: u64 = 1;

// The exact text of V2_TABLES in apps/api/src/db/v2-schema.ts, which is part of the format.
const TABLES: [(&str, &str); 3] = [
    ("vault_header", "CREATE TABLE vault_header (\n  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\n  vault_id TEXT NOT NULL,\n  key_id TEXT NOT NULL UNIQUE,\n  slot_revision INTEGER NOT NULL CHECK (slot_revision BETWEEN 1 AND 4294967295),\n  password_slot TEXT NOT NULL CHECK (length(password_slot) BETWEEN 1 AND 16777216),\n  encryption_count INTEGER NOT NULL CHECK (encryption_count BETWEEN 0 AND 1048576)\n) STRICT"),
    ("vault_entries", "CREATE TABLE vault_entries (\n  entry_id TEXT PRIMARY KEY NOT NULL,\n  revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 4294967295),\n  envelope TEXT CHECK (envelope IS NULL OR length(envelope) BETWEEN 1 AND 16777216)\n) STRICT"),
    ("vault_nonces", "CREATE TABLE vault_nonces (\n  key_id TEXT NOT NULL REFERENCES vault_header(key_id),\n  iv BLOB NOT NULL CHECK (length(iv) = 12),\n  entry_id TEXT NOT NULL,\n  revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 4294967295),\n  PRIMARY KEY (key_id, iv)\n) STRICT"),
];

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    Conflict,
    KeyLimit,
    EntryLimit,
    /// The session or storage changed during the operation. The caller reports the current reason.
    Cancelled,
    /// The file is not what the writer left, so nothing more should trust it.
    Invalid,
}

impl From<rusqlite::Error> for StoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Invalid
    }
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;
pub type Active<'a> = &'a dyn Fn() -> StoreResult<()>;

fn require(condition: bool) -> StoreResult<()> {
    if condition { Ok(()) } else { Err(StoreError::Invalid) }
}

/// decodeBase64 with the app's limits: canonical text only.
fn base64_bytes(value: &Value, max: usize, exact: Option<usize>) -> StoreResult<Vec<u8>> {
    let text = value.as_str().ok_or(StoreError::Invalid)?;
    require(text.len() <= 4 * max.div_ceil(3) && text.len() % 4 == 0)?;
    let bytes = crypto::decode_base64(text, exact).map_err(|_| StoreError::Invalid)?;
    require(bytes.len() <= max)?;
    Ok(bytes)
}

fn exact<'a>(value: &'a Value, fields: &[&str]) -> StoreResult<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(StoreError::Invalid)?;
    require(object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field)))?;
    Ok(object)
}

fn revision_of(value: &Value) -> StoreResult<u64> {
    value.as_u64().filter(|revision| (1..=MAX_REVISION).contains(revision)).ok_or(StoreError::Invalid)
}

fn valid_entry_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID_BYTES && !id.contains('\0')
}

/// parsePasswordSlotEnvelope, returning its vault, key and slot revision.
fn slot_context(slot: &str) -> StoreResult<(String, String, u64)> {
    require(slot.len() <= MAX_ENVELOPE_BYTES)?;
    let value: Value = serde_json::from_str(slot).map_err(|_| StoreError::Invalid)?;
    let envelope = exact(&value, &["cryptoVersion", "cipher", "vaultId", "keyId", "slotId", "slotRevision", "kdf", "iv", "tag", "data"])?;
    require(envelope["cryptoVersion"] == 2 && envelope["cipher"] == "aes-256-gcm" && envelope["slotId"] == "password")?;
    let (vault_id, key_id) = (envelope["vaultId"].as_str().unwrap_or_default(), envelope["keyId"].as_str().unwrap_or_default());
    require(is_vault_uuid(vault_id) && is_vault_uuid(key_id))?;
    let kdf = exact(&envelope["kdf"], &["profile", "salt"])?;
    require(kdf["profile"] == "scrypt-n17-r8-p1-k32")?;
    base64_bytes(&kdf["salt"], 16, Some(16))?;
    base64_bytes(&envelope["iv"], 12, Some(12))?;
    base64_bytes(&envelope["tag"], 16, Some(16))?;
    base64_bytes(&envelope["data"], 32, Some(32))?;
    Ok((vault_id.into(), key_id.into(), revision_of(&envelope["slotRevision"])?))
}

fn schema_version_for(entry: &Value) -> i64 {
    match entry["type"].as_str() {
        Some("financial") => FINANCIAL_SCHEMA_VERSION,
        Some(_) => ITEM_SCHEMA_VERSION,
        None => LOGIN_SCHEMA_VERSION,
    }
}

fn sql_revision(revision: u64) -> StoreResult<i64> {
    i64::try_from(revision).map_err(|_| StoreError::Invalid)
}

fn fresh_iv() -> StoreResult<[u8; IV_BYTES]> {
    let mut iv = [0u8; IV_BYTES];
    getrandom::fill(&mut iv).map_err(|_| StoreError::Invalid)?;
    Ok(iv)
}

pub struct V2Store {
    connection: Connection,
    vault_id: String,
    key_id: String,
    slot: String,
}

impl V2Store {
    /// openV2Store in writer mode: the strict checks run once more under the write lock, after the
    /// writer's settings are confirmed. None means the file is not a v2 vault this app wrote.
    pub fn open(path: &Path, vault_id: &str, key_id: &str) -> Option<Self> {
        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX).ok()?;
        let configured = (|| -> rusqlite::Result<bool> {
            connection.pragma_update(None, "synchronous", "EXTRA")?;
            connection.pragma_update(None, "foreign_keys", true)?;
            connection.pragma_update(None, "secure_delete", true)?;
            connection.pragma_update(None, "trusted_schema", false)?;
            let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
            let foreign_keys: i64 = connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
            Ok(synchronous == 3 && foreign_keys == 1)
        })();
        if !configured.ok()? {
            return None;
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).ok()?;
        let slot = inspect(&transaction, vault_id, key_id).ok()?;
        transaction.commit().ok()?;
        Some(Self { connection, vault_id: vault_id.into(), key_id: key_id.into(), slot })
    }

    pub fn password_slot(&self) -> &str {
        &self.slot
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// readHeader: the encryption count, after confirming the header still names this vault.
    fn header(&self, connection: &Connection) -> StoreResult<i64> {
        header(connection, &self.vault_id, &self.key_id).map(|(count, _)| count)
    }

    /// listEntryContexts: the ids and revisions of the entries that are not deleted.
    pub fn entries(&self) -> StoreResult<Vec<(String, u64)>> {
        let mut statement = self.connection.prepare("SELECT entry_id, revision FROM vault_entries WHERE envelope IS NOT NULL ORDER BY entry_id LIMIT ?1")?;
        let rows = statement.query_map([MAX_ENTRIES as i64 + 1], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        require(rows.len() <= MAX_ENTRIES)?;
        rows.into_iter()
            .map(|(id, revision)| {
                require(valid_entry_id(&id))?;
                Ok((id, revision_of(&Value::from(revision))?))
            })
            .collect()
    }

    /// The stored revision of a current entry.
    pub fn revision(&self, id: &str) -> StoreResult<Option<u64>> {
        let revision: Option<i64> = self.connection.query_row("SELECT revision FROM vault_entries WHERE entry_id = ?1 AND envelope IS NOT NULL", [id], |row| row.get(0)).optional()?;
        revision.map(|revision| revision_of(&Value::from(revision))).transpose()
    }

    /// readEntry and openEntry: the entry and its revision, or None when it does not exist or was
    /// deleted. An envelope whose nonce was never reserved for its revision did not come from the
    /// writer, so it is refused even if it authenticates.
    pub fn read(&self, root: &[u8], id: &str) -> StoreResult<Option<(Value, u64)>> {
        let row: Option<(i64, Option<String>)> = self.connection.query_row("SELECT revision, envelope FROM vault_entries WHERE entry_id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
        let Some((revision, Some(envelope))) = row else {
            return Ok(None);
        };
        let revision = revision_of(&Value::from(revision))?;
        require(envelope.len() <= MAX_ENVELOPE_BYTES)?;
        let parsed: Value = serde_json::from_str(&envelope).map_err(|_| StoreError::Invalid)?;
        let fields = exact(&parsed, &["cryptoVersion", "cipher", "vaultId", "keyId", "entryId", "revision", "iv", "tag", "data"])?;
        require(fields["cryptoVersion"] == 2 && fields["cipher"] == "aes-256-gcm")?;
        require(fields["vaultId"] == self.vault_id.as_str() && fields["keyId"] == self.key_id.as_str() && fields["entryId"] == id && revision_of(&fields["revision"])? == revision)?;
        let iv = base64_bytes(&fields["iv"], 12, Some(12))?;
        base64_bytes(&fields["tag"], 16, Some(16))?;
        require(!base64_bytes(&fields["data"], MAX_PLAINTEXT_BYTES, None)?.is_empty())?;
        let reserved = self
            .connection
            .query_row("SELECT 1 FROM vault_nonces WHERE key_id = ?1 AND iv = ?2 AND entry_id = ?3 AND revision = ?4", params![self.key_id, iv, id, sql_revision(revision)?], |_| Ok(()))
            .optional()?;
        require(reserved.is_some())?;
        let plaintext = crypto::open_v2_entry(root, &envelope, &self.vault_id, &self.key_id, id, revision).map_err(|_| StoreError::Invalid)?;
        let entry: Value = serde_json::from_slice(&plaintext).map_err(|_| StoreError::Invalid)?;
        input::validate_stored_entry(&entry, id).map_err(|_| StoreError::Invalid)?;
        Ok(Some((entry, revision)))
    }

    /// The revision a write must carry, and room for a new entry.
    fn can_write(connection: &Connection, id: &str, revision: u64) -> StoreResult<()> {
        let current: Option<(i64, bool)> = connection.query_row("SELECT revision, envelope IS NULL FROM vault_entries WHERE entry_id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
        let expected = match current {
            Some((stored, _)) => revision_of(&Value::from(stored))? + 1,
            None => 1,
        };
        if revision != expected {
            return Err(StoreError::Conflict);
        }
        require(revision <= MAX_REVISION)?;
        if current.is_none_or(|(_, deleted)| deleted) {
            let count: i64 = connection.query_row("SELECT COUNT(*) FROM vault_entries WHERE envelope IS NOT NULL", [], |row| row.get(0))?;
            if count >= MAX_ENTRIES as i64 {
                return Err(StoreError::EntryLimit);
            }
        }
        Ok(())
    }

    /// True once the nonce is committed. A used nonce is never released, which is why a failed
    /// write still consumes one.
    fn reserve(&mut self, id: &str, revision: u64, iv: &[u8]) -> StoreResult<bool> {
        let (vault_id, key_id) = (self.vault_id.clone(), self.key_id.clone());
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (count, _) = header(&transaction, &vault_id, &key_id)?;
        Self::can_write(&transaction, id, revision)?;
        if transaction.query_row("SELECT 1 FROM vault_nonces WHERE key_id = ?1 AND iv = ?2", params![key_id, iv], |_| Ok(())).optional()?.is_some() {
            return Ok(false);
        }
        if count >= MAX_ENCRYPTIONS {
            return Err(StoreError::KeyLimit);
        }
        transaction.execute("INSERT INTO vault_nonces VALUES (?1, ?2, ?3, ?4)", params![key_id, iv, id, sql_revision(revision)?])?;
        transaction.execute("UPDATE vault_header SET encryption_count = encryption_count + 1 WHERE singleton = 1", [])?;
        transaction.commit()?;
        Ok(true)
    }

    fn immediate<T>(&mut self, active: Active<'_>, action: impl FnOnce(&Transaction<'_>) -> StoreResult<T>) -> StoreResult<T> {
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Checked while holding the write lock, so a lock or switch before this point cannot be missed.
        active()?;
        let result = action(&transaction)?;
        active()?;
        transaction.commit()?;
        Ok(result)
    }

    /// writeEntry: validate, reserve a nonce, seal, then save with the same checks once more.
    pub fn write(&mut self, root: &[u8], entry: &Value, id: &str, revision: u64, active: Active<'_>) -> StoreResult<()> {
        active()?;
        require(valid_entry_id(id))?;
        Self::can_write(&self.connection, id, revision)?;
        if self.header(&self.connection)? >= MAX_ENCRYPTIONS {
            return Err(StoreError::KeyLimit);
        }
        input::validate_stored_entry(entry, id).map_err(|_| StoreError::Invalid)?;
        let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(entry).map_err(|_| StoreError::Invalid)?);
        require(plaintext.len() <= MAX_PLAINTEXT_BYTES)?;
        let mut reserved = None;
        for _ in 0..NONCE_ATTEMPTS {
            active()?;
            let candidate = fresh_iv()?;
            if self.reserve(id, revision, &candidate)? {
                reserved = Some(candidate);
                break;
            }
        }
        let iv = reserved.ok_or(StoreError::Invalid)?;
        active()?;
        let envelope = crypto::seal_v2_entry(root, &iv, &plaintext, &self.vault_id, &self.key_id, id, revision).map_err(|_| StoreError::Invalid)?;
        let (vault_id, key_id) = (self.vault_id.clone(), self.key_id.clone());
        let version = schema_version_for(entry);
        self.immediate(active, |transaction| {
            header(transaction, &vault_id, &key_id)?;
            Self::can_write(transaction, id, revision)?;
            let is_reserved = transaction
                .query_row("SELECT 1 FROM vault_nonces WHERE key_id = ?1 AND iv = ?2 AND entry_id = ?3 AND revision = ?4", params![key_id, &iv[..], id, sql_revision(revision)?], |_| Ok(()))
                .optional()?
                .is_some();
            require(is_reserved)?;
            transaction.execute(
                "INSERT INTO vault_entries (entry_id, revision, envelope) VALUES (?1, ?2, ?3)
                 ON CONFLICT(entry_id) DO UPDATE SET revision = excluded.revision, envelope = excluded.envelope",
                params![id, sql_revision(revision)?, envelope],
            )?;
            // The marker keeps older apps out, so it is raised with the first entry of a kind and never lowered.
            let current: i64 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
            if version > current {
                transaction.pragma_update(None, "user_version", version)?;
            }
            Ok(())
        })
    }

    /// deleteEntry: removes the ciphertext and keeps the id and revision as a tombstone, so the
    /// revision never repeats. Its nonces stay used.
    pub fn delete(&mut self, id: &str, revision: u64, active: Active<'_>) -> StoreResult<()> {
        active()?;
        self.immediate(active, |transaction| {
            let current: Option<(i64, bool)> = transaction.query_row("SELECT revision, envelope IS NULL FROM vault_entries WHERE entry_id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
            if !current.is_some_and(|(stored, deleted)| !deleted && u64::try_from(stored).is_ok_and(|stored| stored == revision)) {
                return Err(StoreError::Conflict);
            }
            transaction.execute("UPDATE vault_entries SET envelope = NULL WHERE entry_id = ?1", [id])?;
            Ok(())
        })
    }

    #[cfg(test)]
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }
}

/// readHeader: one row naming this vault, its key and slot, with a count in range.
fn header(connection: &Connection, vault_id: &str, key_id: &str) -> StoreResult<(i64, String)> {
    let mut statement = connection.prepare("SELECT singleton, vault_id, key_id, slot_revision, password_slot, encryption_count FROM vault_header LIMIT 2")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let [(singleton, stored_vault, stored_key, slot_revision, slot, count)] = rows.as_slice() else {
        return Err(StoreError::Invalid);
    };
    require(*singleton == 1 && stored_vault == vault_id && stored_key == key_id && *slot_revision == SLOT_REVISION as i64 && is_vault_uuid(vault_id) && is_vault_uuid(key_id))?;
    let (slot_vault, slot_key, revision) = slot_context(slot)?;
    require(slot_vault == vault_id && slot_key == key_id && revision == SLOT_REVISION && (0..=MAX_ENCRYPTIONS).contains(count))?;
    Ok((*count, slot.clone()))
}

/// inspectV2Database: the marker, version, journal mode, exact DDL, header and nonce accounting.
/// Returns the password slot.
pub fn inspect(connection: &Connection, vault_id: &str, key_id: &str) -> StoreResult<String> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    require(application_id == APPLICATION_ID && (LOGIN_SCHEMA_VERSION..=FINANCIAL_SCHEMA_VERSION).contains(&version) && journal == "delete")?;
    let mut statement = connection.prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT 4")?;
    let objects = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    require(objects.len() == TABLES.len() && objects.iter().all(|(kind, name, sql)| kind == "table" && TABLES.iter().any(|(table, text)| table == name && sql.as_deref() == Some(*text))))?;
    let (count, slot) = header(connection, vault_id, key_id)?;
    let (nonces, foreign, broken, entries): (i64, i64, i64, i64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM vault_nonces), (SELECT COUNT(*) FROM vault_nonces WHERE key_id != ?1),
                (SELECT COUNT(*) FROM pragma_foreign_key_check), (SELECT COUNT(*) FROM vault_entries WHERE envelope IS NOT NULL)",
        [key_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    require(nonces == count && foreign == 0 && broken == 0 && entries <= MAX_ENTRIES as i64)?;
    Ok(slot)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::files::tests::TemporaryDirectory;
    use serde_json::json;
    use std::path::PathBuf;

    const FIXTURE: &str = include_str!("../../../tests/fixtures/crypto-compatibility.json");

    pub fn fixture() -> Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    pub fn s(value: &Value) -> &str {
        value.as_str().unwrap()
    }

    /// The fixture's v2 vault laid out as the app's activation leaves it.
    pub fn v2_directory() -> (TemporaryDirectory, PathBuf, Value) {
        let v2 = fixture()["draftV2"].clone();
        let directory = TemporaryDirectory::new();
        let vault_directory = directory.0.join("vaults").join(s(&v2["vaultId"]));
        std::fs::create_dir_all(&vault_directory).unwrap();
        let path = vault_directory.join("vault.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection.pragma_update(None, "application_id", APPLICATION_ID).unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        for (_, sql) in TABLES {
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
        drop(connection);
        let receipt = format!(r#"{{"format":"CIPHER-VAULT-ACTIVATION","version":1,"vaultId":"{}","keyId":"{}","entryCount":1,"state":"committed"}}"#, s(&v2["vaultId"]), s(&v2["keyId"]));
        std::fs::write(directory.0.join("vault-activation.json"), receipt).unwrap();
        std::fs::write(directory.0.join("vault-current.json"), format!(r#"{{"format":"CIPHER-VAULT-ACTIVE","version":1,"vaultId":"{}"}}"#, s(&v2["vaultId"]))).unwrap();
        (directory, path, v2)
    }

    fn root(v2: &Value) -> crypto::Secret {
        crypto::unwrap_v2_root(&json!({ "cryptoVersion": 2, "cipher": "aes-256-gcm", "vaultId": v2["vaultId"], "keyId": v2["keyId"], "slotId": "password", "slotRevision": v2["slotRevision"],
            "kdf": { "profile": v2["profile"], "salt": v2["salt"] }, "iv": v2["wrapIv"], "tag": v2["wrapTag"], "data": v2["wrappedRoot"] }).to_string(), s(&v2["masterPassword"]).as_bytes(), s(&v2["vaultId"]), s(&v2["keyId"]), 1).unwrap()
    }

    fn available() -> StoreResult<()> {
        Ok(())
    }

    fn entry(id: &str) -> Value {
        json!({ "id": id, "serviceName": "s", "loginId": "i", "password": "p", "notes": "", "url": "", "tags": [], "group": null,
            "createdAt": "2029-01-01T00:00:00.000Z", "updatedAt": "2029-01-01T00:00:00.000Z", "passwordChangedAt": "2029-01-01T00:00:00.000Z" })
    }

    #[test]
    fn the_fixture_reads_and_writes_keep_revisions_nonces_and_tombstones() {
        let (_directory, path, v2) = v2_directory();
        let mut store = V2Store::open(&path, s(&v2["vaultId"]), s(&v2["keyId"])).unwrap();
        let root = root(&v2);
        let expected: Value = serde_json::from_str(s(&v2["entryPlaintext"])).unwrap();
        assert_eq!(store.read(&root, s(&v2["entryId"])).unwrap(), Some((expected, 1)));
        let id = "33333333-3333-4333-8333-333333333333";
        store.write(&root, &entry(id), id, 1, &available).unwrap();
        assert_eq!(store.write(&root, &entry(id), id, 1, &available), Err(StoreError::Conflict), "a stale revision");
        store.write(&root, &entry(id), id, 2, &available).unwrap();
        assert_eq!(store.read(&root, id).unwrap().unwrap().1, 2);
        let count = |store: &V2Store, sql: &str| store.connection().query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap();
        assert_eq!((count(&store, "SELECT encryption_count FROM vault_header"), count(&store, "SELECT COUNT(*) FROM vault_nonces")), (3, 3));
        assert_eq!(store.delete(id, 1, &available), Err(StoreError::Conflict));
        store.delete(id, 2, &available).unwrap();
        assert_eq!(store.read(&root, id).unwrap(), None);
        assert_eq!(store.entries().unwrap(), vec![(s(&v2["entryId"]).to_string(), 1)]);
        store.write(&root, &entry(id), id, 3, &available).unwrap();
        assert_eq!(store.revision(id).unwrap(), Some(3), "a tombstone keeps the revision going");
        assert_eq!(count(&store, "PRAGMA user_version"), 1);
        let mut key = entry(id);
        for field in ["loginId", "password", "passwordChangedAt"] {
            key.as_object_mut().unwrap().remove(field);
        }
        key["type"] = json!("apiKey");
        key["apiKey"] = json!({ "key": "k", "keyId": "", "expiresOn": null });
        store.write(&root, &key, id, 4, &available).unwrap();
        assert_eq!(count(&store, "PRAGMA user_version"), 2, "the first item raises the marker");
        store.write(&root, &entry(id), id, 5, &available).unwrap();
        assert_eq!(count(&store, "PRAGMA user_version"), 2, "and a later login never lowers it");
    }

    #[test]
    fn a_cancelled_write_still_uses_its_nonce_but_saves_nothing() {
        let (_directory, path, v2) = v2_directory();
        let mut store = V2Store::open(&path, s(&v2["vaultId"]), s(&v2["keyId"])).unwrap();
        let root = root(&v2);
        let id = "33333333-3333-4333-8333-333333333333";
        let calls = std::cell::Cell::new(0);
        let cancel_late = || {
            calls.set(calls.get() + 1);
            if calls.get() > 3 { Err(StoreError::Cancelled) } else { Ok(()) }
        };
        assert_eq!(store.write(&root, &entry(id), id, 1, &cancel_late), Err(StoreError::Cancelled));
        assert_eq!(store.read(&root, id).unwrap(), None);
        let nonces: i64 = store.connection().query_row("SELECT COUNT(*) FROM vault_nonces", [], |row| row.get(0)).unwrap();
        assert_eq!(nonces, 2);
        drop(store);
        assert!(V2Store::open(&path, s(&v2["vaultId"]), s(&v2["keyId"])).is_some(), "the counts still agree");
    }

    #[test]
    fn files_that_differ_from_what_the_writer_leaves_are_refused() {
        let changes = [
            "PRAGMA user_version = 4",
            "PRAGMA journal_mode = WAL",
            "CREATE INDEX extra ON vault_entries (revision)",
            "UPDATE vault_header SET encryption_count = 2",
            "DELETE FROM vault_nonces",
            "INSERT INTO vault_header VALUES (2, 'a', 'b', 1, 'x', 0)",
        ];
        for change in changes {
            let (_directory, path, v2) = v2_directory();
            let connection = Connection::open(&path).unwrap();
            let _ = connection.execute_batch(&format!("PRAGMA ignore_check_constraints = ON; {change};"));
            drop(connection);
            assert!(V2Store::open(&path, s(&v2["vaultId"]), s(&v2["keyId"])).is_none(), "{change}");
        }
        let (_directory, path, v2) = v2_directory();
        assert!(V2Store::open(&path, s(&v2["keyId"]), s(&v2["keyId"])).is_none(), "another vault id");
    }

    #[test]
    fn an_envelope_without_its_reserved_nonce_is_refused() {
        let (_directory, path, v2) = v2_directory();
        let store = V2Store::open(&path, s(&v2["vaultId"]), s(&v2["keyId"])).unwrap();
        // Keep the counts consistent so only the missing reservation differs.
        store.connection().execute_batch("UPDATE vault_nonces SET revision = 2").unwrap();
        assert_eq!(store.read(&root(&v2), s(&v2["entryId"])), Err(StoreError::Invalid));
    }
}

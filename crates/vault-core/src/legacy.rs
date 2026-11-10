//! The legacy SQLite file, following apps/api/src/db/database.ts, database-format.ts,
//! services/vault-store.ts and the legacy half of services/entry-service.ts. The format is
//! unchanged: secrets are sealed one by one, and the names, IDs, URLs, tags and groups stay plain.

use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use std::fs;
use std::io;
use std::path::Path;

/// VaultStorageError in apps/api/src/db/database-format.ts. Shown when the vault cannot be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    UnsupportedFormat,
    InvalidDatabase,
    OpenFailed,
}

impl StorageError {
    pub fn message(self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "未対応の保管庫保存形式です。原本を保持して対応する版で確認してください",
            Self::InvalidDatabase => "保管庫の保存形式を読み取れません。原本を保持して復旧を確認してください",
            Self::OpenFailed => "保管庫の保存先を開けません。アクセス権・使用状況・復旧の必要性を確認してください",
        }
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt | ErrorCode::Unknown) => Self::InvalidDatabase,
            _ => Self::OpenFailed,
        }
    }
}

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS vault_metadata (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  password_salt TEXT NOT NULL,
  password_verifier TEXT NOT NULL,
  kdf_params TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS password_entries (
  id TEXT PRIMARY KEY,
  service_name TEXT NOT NULL,
  login_id TEXT NOT NULL,
  encrypted_password TEXT NOT NULL,
  encrypted_notes TEXT,
  url TEXT,
  tags TEXT NOT NULL,
  group_name TEXT,
  password_changed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
";

// (name, declared type, not null, primary key)
const METADATA_COLUMNS: [(&str, &str, i64, i64); 6] = [
    ("id", "INTEGER", 0, 1), ("password_salt", "TEXT", 1, 0), ("password_verifier", "TEXT", 1, 0),
    ("kdf_params", "TEXT", 1, 0), ("created_at", "TEXT", 1, 0), ("updated_at", "TEXT", 1, 0),
];
const ENTRY_COLUMNS: [(&str, &str, i64, i64); 11] = [
    ("id", "TEXT", 0, 1), ("service_name", "TEXT", 1, 0), ("login_id", "TEXT", 1, 0),
    ("encrypted_password", "TEXT", 1, 0), ("encrypted_notes", "TEXT", 0, 0), ("url", "TEXT", 0, 0),
    ("tags", "TEXT", 1, 0), ("group_name", "TEXT", 0, 0), ("password_changed_at", "TEXT", 0, 0),
    ("created_at", "TEXT", 1, 0), ("updated_at", "TEXT", 1, 0),
];
const OPTIONAL_ENTRY_COLUMNS: [&str; 2] = ["group_name", "password_changed_at"];

/// Checks the exact columns, so that a file another program shaped differently is never written.
/// Returns whether optional columns are missing.
fn check_columns(connection: &Connection, table: &str, expected: &[(&str, &str, i64, i64)], optional: &[&str]) -> Result<bool, StorageError> {
    // Table names are fixed constants, never file-provided SQL.
    let mut statement = connection.prepare(&format!("SELECT name, type, \"notnull\", pk, hidden, dflt_value IS NULL FROM pragma_table_xinfo('{table}')"))?;
    let columns = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, bool>(5)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has = |name: &str| columns.iter().any(|column| column.0 == name);
    if expected.iter().any(|(name, ..)| !optional.contains(name) && !has(name)) {
        return Err(StorageError::UnsupportedFormat);
    }
    for (name, kind, not_null, primary, hidden, no_default) in &columns {
        let spec = expected.iter().find(|(expected, ..)| expected == name);
        if !spec.is_some_and(|(_, expected_kind, expected_not_null, expected_primary)| kind == expected_kind && not_null == expected_not_null && primary == expected_primary) || *hidden != 0 || !no_default {
            return Err(StorageError::UnsupportedFormat);
        }
    }
    let foreign_keys: i64 = connection.query_row(&format!("SELECT COUNT(*) FROM pragma_foreign_key_list('{table}')"), [], |row| row.get(0))?;
    if foreign_keys != 0 {
        return Err(StorageError::UnsupportedFormat);
    }
    Ok(optional.iter().any(|name| !has(name)))
}

/// inspectDatabase: an empty file or exactly the two legacy tables. Returns whether the schema
/// still needs creating or its optional columns adding.
pub fn inspect(connection: &Connection) -> Result<bool, StorageError> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != 0 || user_version != 0 {
        return Err(StorageError::UnsupportedFormat);
    }
    let mut statement = connection.prepare("SELECT type, name FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT 3")?;
    let objects = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    if objects.is_empty() {
        return Ok(true);
    }
    let has = |name: &str| objects.iter().any(|(_, object)| object == name);
    if objects.len() != 2 || objects.iter().any(|(kind, _)| kind != "table") || !has("vault_metadata") || !has("password_entries") {
        return Err(StorageError::UnsupportedFormat);
    }
    let unusual: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_list WHERE schema = 'main' AND name IN ('vault_metadata', 'password_entries') AND (type != 'table' OR wr != 0 OR strict != 0)",
        [],
        |row| row.get(0),
    )?;
    if unusual != 0 {
        return Err(StorageError::UnsupportedFormat);
    }
    check_columns(connection, "vault_metadata", &METADATA_COLUMNS, &[])?;
    check_columns(connection, "password_entries", &ENTRY_COLUMNS, &OPTIONAL_ENTRY_COLUMNS)
}

pub(crate) fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(SCHEMA)?;
    let mut statement = connection.prepare("SELECT name FROM pragma_table_info('password_entries')")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    for column in OPTIONAL_ENTRY_COLUMNS {
        if !columns.iter().any(|name| name == column) {
            connection.execute_batch(&format!("ALTER TABLE password_entries ADD COLUMN {column} TEXT"))?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Metadata {
    pub salt: String,
    pub verifier: String,
    pub kdf_params: String,
    pub created_at: String,
}

pub struct EntryRow {
    pub id: String,
    pub service_name: String,
    pub login_id: String,
    pub encrypted_password: String,
    pub encrypted_notes: Option<String>,
    pub url: Option<String>,
    pub tags: String,
    pub group: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub password_changed_at: Option<String>,
}

/// The stored fields of a login, already normalized and sealed.
pub struct SealedLogin<'a> {
    pub service_name: &'a str,
    pub login_id: &'a str,
    pub password: &'a str,
    pub notes: Option<&'a str>,
    pub url: Option<&'a str>,
    pub tags: &'a str,
    pub group: Option<&'a str>,
}

/// parseTags: anything but an array of strings reads as no tags.
pub fn parse_tags(tags: &str) -> Value {
    let parsed: Value = serde_json::from_str(tags).unwrap_or(Value::Null);
    Value::Array(parsed.as_array().map(|items| items.iter().filter(|item| item.is_string()).cloned().collect()).unwrap_or_default())
}

pub fn summary(row: &EntryRow) -> Value {
    json!({ "id": row.id, "serviceName": row.service_name, "loginId": row.login_id, "tags": parse_tags(&row.tags), "group": row.group, "updatedAt": row.updated_at })
}

const ENTRY_SELECT: &str = "SELECT id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at, password_changed_at FROM password_entries";

fn entry_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRow> {
    Ok(EntryRow {
        id: row.get(0)?,
        service_name: row.get(1)?,
        login_id: row.get(2)?,
        encrypted_password: row.get(3)?,
        encrypted_notes: row.get(4)?,
        url: row.get(5)?,
        tags: row.get(6)?,
        group: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        password_changed_at: row.get(10)?,
    })
}

pub struct LegacyDatabase {
    connection: Connection,
}

impl LegacyDatabase {
    /// openDatabase: a missing file is created without ever replacing one that appeared meanwhile,
    /// and the schema is checked, created or extended in one transaction that holds the write lock.
    /// `namespace_is_clear` runs once the lock is held.
    pub fn open(path: &Path, namespace_is_clear: &dyn Fn() -> bool) -> Result<Self, StorageError> {
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(StorageError::OpenFailed),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|_| StorageError::OpenFailed)?;
            }
            Err(_) => return Err(StorageError::OpenFailed),
        }
        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        // Deleted secrets are overwritten in the file rather than left in free pages.
        connection.pragma_update(None, "secure_delete", true)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !namespace_is_clear() {
            return Err(StorageError::OpenFailed);
        }
        if inspect(&transaction)? {
            initialize(&transaction)?;
        }
        transaction.commit()?;
        Ok(Self { connection })
    }

    pub fn metadata(&self) -> rusqlite::Result<Option<Metadata>> {
        self.connection
            .query_row("SELECT password_salt, password_verifier, kdf_params, created_at FROM vault_metadata WHERE id = 1", [], |row| {
                Ok(Metadata { salt: row.get(0)?, verifier: row.get(1)?, kdf_params: row.get(2)?, created_at: row.get(3)? })
            })
            .optional()
    }

    /// Runs `action` in a transaction that holds the write lock. `check` runs once the lock is
    /// held and again before the commit, so that nothing is written after a lock or a switch.
    pub fn write<T, E: From<rusqlite::Error>>(&mut self, check: &dyn Fn() -> Result<(), E>, action: impl FnOnce(&Transaction<'_>) -> Result<T, E>) -> Result<T, E> {
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check()?;
        let result = action(&transaction)?;
        check()?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn list(&self) -> rusqlite::Result<Vec<EntryRow>> {
        let mut statement = self.connection.prepare(&format!("{ENTRY_SELECT} ORDER BY updated_at DESC"))?;
        statement.query_map([], entry_row)?.collect()
    }

    /// Every entry in table order, as a SELECT without ORDER BY returns them in the app.
    pub fn all(&self) -> rusqlite::Result<Vec<EntryRow>> {
        let mut statement = self.connection.prepare(ENTRY_SELECT)?;
        statement.query_map([], entry_row)?.collect()
    }

    pub fn get(&self, id: &str) -> rusqlite::Result<Option<EntryRow>> {
        self.connection.query_row(&format!("{ENTRY_SELECT} WHERE id = ?1"), [id], entry_row).optional()
    }

    #[cfg(test)]
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }
}

pub fn save_metadata(transaction: &Transaction<'_>, salt: &str, verifier: &str, kdf_params: &str, created_at: &str, updated_at: &str) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO vault_metadata (id, password_salt, password_verifier, kdf_params, created_at, updated_at) VALUES (1, ?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET password_salt = excluded.password_salt, password_verifier = excluded.password_verifier,
           kdf_params = excluded.kdf_params, updated_at = excluded.updated_at",
        params![salt, verifier, kdf_params, created_at, updated_at],
    )?;
    Ok(())
}

pub fn reset(transaction: &Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute("DELETE FROM password_entries", [])?;
    transaction.execute("DELETE FROM vault_metadata", [])?;
    Ok(())
}

pub fn count(transaction: &Transaction<'_>) -> rusqlite::Result<i64> {
    transaction.query_row("SELECT COUNT(*) FROM password_entries", [], |row| row.get(0))
}

pub fn insert(transaction: &Transaction<'_>, id: &str, login: &SealedLogin<'_>, now: &str) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO password_entries (id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at, password_changed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?9)",
        params![id, login.service_name, login.login_id, login.password, login.notes, login.url, login.tags, login.group, now],
    )?;
    Ok(())
}

/// restoreLegacyEntries: a login from a backup keeps its id and dates.
pub fn insert_restored(transaction: &Transaction<'_>, id: &str, login: &SealedLogin<'_>, created_at: &str, updated_at: &str, changed_at: Option<&str>) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO password_entries (id, service_name, login_id, encrypted_password, encrypted_notes, url, tags, group_name, created_at, updated_at, password_changed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![id, login.service_name, login.login_id, login.password, login.notes, login.url, login.tags, login.group, created_at, updated_at, changed_at],
    )?;
    Ok(())
}

pub fn update(transaction: &Transaction<'_>, id: &str, login: &SealedLogin<'_>, changed_at: Option<&str>, now: &str) -> rusqlite::Result<usize> {
    transaction.execute(
        "UPDATE password_entries SET service_name = ?2, login_id = ?3, encrypted_password = ?4, encrypted_notes = ?5, url = ?6, tags = ?7, group_name = ?8,
           password_changed_at = ?9, updated_at = ?10 WHERE id = ?1",
        params![id, login.service_name, login.login_id, login.password, login.notes, login.url, login.tags, login.group, changed_at, now],
    )
}

pub fn delete(transaction: &Transaction<'_>, id: &str) -> rusqlite::Result<usize> {
    transaction.execute("DELETE FROM password_entries WHERE id = ?1", [id])
}

/// The group of an entry, or None when there is no such entry.
pub fn group_of(transaction: &Transaction<'_>, id: &str) -> rusqlite::Result<Option<Option<String>>> {
    transaction.query_row("SELECT group_name FROM password_entries WHERE id = ?1", [id], |row| row.get(0)).optional()
}

/// Only plain columns change, so the secrets and their change date stay untouched. The entry
/// never moves before its own dates, which sort as text in the one form the app writes.
pub fn set_group(transaction: &Transaction<'_>, id: &str, group: Option<&str>, now: &str) -> rusqlite::Result<()> {
    transaction.execute(
        "UPDATE password_entries SET group_name = ?2, updated_at = max(?3, updated_at, created_at, coalesce(password_changed_at, '')) WHERE id = ?1",
        params![id, group, now],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::TemporaryDirectory;

    fn open(directory: &TemporaryDirectory) -> Result<LegacyDatabase, StorageError> {
        LegacyDatabase::open(&directory.0.join("password-manager.db"), &|| true)
    }

    #[test]
    fn a_new_file_gets_the_current_schema_and_reopens_unchanged() {
        let directory = TemporaryDirectory::new();
        let database = open(&directory).unwrap();
        assert_eq!(inspect(database.connection()), Ok(false));
        let secure_delete: i64 = database.connection().pragma_query_value(None, "secure_delete", |row| row.get(0)).unwrap();
        assert_eq!(secure_delete, 1);
        drop(database);
        let before = fs::read(directory.0.join("password-manager.db")).unwrap();
        drop(open(&directory).unwrap());
        assert_eq!(fs::read(directory.0.join("password-manager.db")).unwrap(), before);
    }

    #[test]
    fn missing_optional_columns_are_added() {
        let directory = TemporaryDirectory::new();
        let connection = Connection::open(directory.0.join("password-manager.db")).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection.execute_batch("ALTER TABLE password_entries DROP COLUMN group_name; ALTER TABLE password_entries DROP COLUMN password_changed_at;").unwrap();
        assert_eq!(inspect(&connection), Ok(true));
        drop(connection);
        let database = open(&directory).unwrap();
        assert_eq!(inspect(database.connection()), Ok(false));
    }

    #[test]
    fn files_shaped_by_something_else_are_refused_without_change() {
        let shapes = [
            "PRAGMA user_version = 1;",
            "PRAGMA application_id = 7;",
            "CREATE TABLE other (x);",
            "CREATE INDEX extra ON password_entries (service_name);",
            "ALTER TABLE password_entries ADD COLUMN extra TEXT;",
            "CREATE TRIGGER t AFTER INSERT ON password_entries BEGIN SELECT 1; END;",
        ];
        for shape in shapes {
            let directory = TemporaryDirectory::new();
            let connection = Connection::open(directory.0.join("password-manager.db")).unwrap();
            connection.execute_batch(SCHEMA).unwrap();
            connection.execute_batch(shape).unwrap();
            drop(connection);
            let before = fs::read(directory.0.join("password-manager.db")).unwrap();
            assert_eq!(open(&directory).err(), Some(StorageError::UnsupportedFormat), "{shape}");
            assert_eq!(fs::read(directory.0.join("password-manager.db")).unwrap(), before, "{shape}");
        }
        let directory = TemporaryDirectory::new();
        fs::write(directory.0.join("password-manager.db"), b"not a database, only text that is long enough to fill a header....................................").unwrap();
        assert_eq!(open(&directory).err(), Some(StorageError::InvalidDatabase));
    }

    #[test]
    fn a_switch_announced_before_the_lock_keeps_the_file_closed() {
        let directory = TemporaryDirectory::new();
        assert_eq!(LegacyDatabase::open(&directory.0.join("password-manager.db"), &|| false).err(), Some(StorageError::OpenFailed));
    }

    #[test]
    fn tags_that_are_not_a_list_of_text_read_as_none() {
        assert_eq!(parse_tags(r#"["a",1,"b"]"#), json!(["a", "b"]));
        assert_eq!(parse_tags("{}"), json!([]));
        assert_eq!(parse_tags("not json"), json!([]));
    }
}

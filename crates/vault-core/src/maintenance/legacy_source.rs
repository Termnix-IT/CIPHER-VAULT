//! Reading a legacy vault for migration, following apps/api/src/migration/legacy-reader.ts. Unlike
//! the everyday reader it trusts nothing in the file: every text must be valid UTF-8, every date
//! must be in the app's own form, and the sizes stay within what a backup can hold.

use super::{Active, Code, Outcome, failed};
use crate::crypto;
use crate::input::{self, BACKUP_FILE_BYTES, BACKUP_PLAINTEXT_BYTES, MAX_ENTRIES};
use crate::legacy;
use crate::backup;
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OpenFlags, Row};
use serde_json::{Map, Value, json};
use std::path::Path;
use zeroize::Zeroizing;

pub const RAW_BYTES: i64 = 32 * 1024 * 1024;
const FIELDS: [&str; 11] = ["id", "service_name", "login_id", "encrypted_password", "encrypted_notes", "url", "tags", "group_name", "password_changed_at", "created_at", "updated_at"];
const OPTIONAL: [&str; 2] = ["group_name", "password_changed_at"];
const METADATA_FIELDS: [&str; 5] = ["password_salt", "password_verifier", "kdf_params", "created_at", "updated_at"];
/// Byte length of `{"version":1,"entries":[]}`, where every entry's JSON is added.
const EMPTY_BACKUP_BYTES: usize = 26;

pub struct Inspection {
    pub count: i64,
    pub missing: Vec<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub salt: String,
    pub verifier: String,
    pub raw_verifier: bool,
}

/// A read-only connection that never waits for another writer.
pub fn open(path: &Path) -> Outcome<Connection> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    connection.busy_timeout(std::time::Duration::ZERO)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(connection)
}

/// inspectLegacySource: the legacy tables in UTF-8, within the entry count and size limits.
pub fn inspect(connection: &Connection) -> Outcome<Inspection> {
    let checked = (|| -> Option<Inspection> {
        legacy::inspect(connection).ok()?;
        let tables: i64 = connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'", [], |row| row.get(0)).ok()?;
        let encoding: String = connection.pragma_query_value(None, "encoding", |row| row.get(0)).ok()?;
        if tables == 0 || encoding != "UTF-8" {
            return None;
        }
        let mut statement = connection.prepare("SELECT name FROM pragma_table_info('password_entries')").ok()?;
        let columns: Vec<String> = statement.query_map([], |row| row.get(0)).ok()?.collect::<rusqlite::Result<_>>().ok()?;
        let missing = OPTIONAL.into_iter().filter(|name| !columns.iter().any(|column| column == name)).collect();
        let count = connection.query_row("SELECT COUNT(*) FROM password_entries", [], |row| row.get(0)).ok()?;
        Some(Inspection { count, missing })
    })();
    let inspection = checked.ok_or(Code::Failed)?;
    if inspection.count > MAX_ENTRIES as i64 {
        return Err(Code::Capacity.into());
    }
    let sum = FIELDS.iter().filter(|name| !inspection.missing.contains(name)).map(|name| format!("coalesce(length(CAST({name} AS BLOB)), 0)")).collect::<Vec<_>>().join(" + ");
    let bytes: i64 = connection.query_row(&format!("SELECT coalesce(sum({sum}), 0) FROM password_entries"), [], |row| row.get(0)).or_else(|_| failed())?;
    if bytes > RAW_BYTES {
        return Err(Code::Capacity.into());
    }
    Ok(inspection)
}

/// `CAST(x AS BLOB)` and `typeof(x)` for each column, so that the text is decoded here, strictly.
fn projection(names: &[&str], missing: &[&str]) -> String {
    names
        .iter()
        .flat_map(|name| {
            let expression = if missing.contains(name) { "NULL" } else { name };
            [format!("CAST({expression} AS BLOB)"), format!("typeof({expression})")]
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The text of the column at `index` in a projection, or None for a NULL that may be one.
fn text(row: &Row<'_>, index: usize, nullable: bool) -> Option<Option<String>> {
    let kind: String = row.get(index * 2 + 1).ok()?;
    if kind == "null" && nullable {
        return Some(None);
    }
    if kind != "text" {
        return None;
    }
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(row.get(index * 2).ok()?);
    // TextDecoder with fatal set: invalid UTF-8 is refused, never replaced.
    std::str::from_utf8(&bytes).ok().map(|text| Some(text.to_string()))
}

fn required(row: &Row<'_>, index: usize) -> Option<String> {
    text(row, index, false)?
}

/// A date in the one form `toISOString` writes.
fn canonical_date(text: &str) -> bool {
    DateTime::parse_from_rfc3339(text).is_ok_and(|parsed| parsed.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::Millis, true) == text)
}

/// readLegacyMetadata: one row with a 16-byte salt, a 32-byte verifier, scrypt parameters and dates.
pub fn metadata(connection: &Connection) -> Outcome<Metadata> {
    let read = || -> Option<Metadata> {
        let sum = METADATA_FIELDS.iter().map(|name| format!("coalesce(length(CAST({name} AS BLOB)), 0)")).collect::<Vec<_>>().join(" + ");
        let large: Option<i64> = connection.query_row(&format!("SELECT 1 FROM vault_metadata WHERE {sum} > 8192 LIMIT 1"), [], |row| row.get(0)).ok();
        if large.is_some() {
            return None;
        }
        let mut statement = connection.prepare(&format!("SELECT id, {} FROM vault_metadata LIMIT 2", projection(&METADATA_FIELDS, &[]))).ok()?;
        let mut rows = statement.query([]).ok()?;
        let row = rows.next().ok()??;
        // The id column comes first, so the projection's columns start at 1.
        let id: SqlValue = row.get(0).ok()?;
        let field = |index: usize| -> Option<String> {
            let kind: String = row.get(index * 2 + 2).ok()?;
            if kind != "text" {
                return None;
            }
            let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(row.get(index * 2 + 1).ok()?);
            std::str::from_utf8(&bytes).ok().map(str::to_string)
        };
        let (salt, verifier, params, created, updated) = (field(0)?, field(1)?, field(2)?, field(3)?, field(4)?);
        if id != SqlValue::Integer(1) || rows.next().ok()?.is_some() {
            return None;
        }
        crypto::decode_base64(&salt, Some(16)).ok()?;
        crypto::decode_base64(&verifier, Some(32)).ok()?;
        let params: Value = serde_json::from_str(&params).ok()?;
        let params = params.as_object()?;
        let allowed = ["algorithm", "keyLength", "verifierAlgorithm"];
        if !params.keys().all(|key| allowed.contains(&key.as_str())) || params.get("algorithm")? != "scrypt" || params.get("keyLength")?.as_f64()? != 32.0 {
            return None;
        }
        let verifier_algorithm = params.get("verifierAlgorithm");
        if verifier_algorithm.is_some_and(|algorithm| algorithm != "hmac-sha256-v1") {
            return None;
        }
        if !canonical_date(&created) || !canonical_date(&updated) || created > updated {
            return None;
        }
        Some(Metadata { salt, verifier, raw_verifier: verifier_algorithm.is_none() })
    };
    read().ok_or_else(|| Code::Failed.into())
}

/// Every row of vault_metadata as the app compares them, to prove a copy kept them unchanged.
pub fn metadata_rows(connection: &Connection) -> Outcome<Vec<Vec<SqlValue>>> {
    let mut statement = connection.prepare("SELECT * FROM vault_metadata")?;
    let width = statement.column_count();
    let rows = statement.query_map([], |row| (0..width).map(|index| row.get::<_, SqlValue>(index)).collect::<rusqlite::Result<Vec<_>>>())?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// A sealed secret: canonical Base64 of at least the IV and tag, decrypted and valid UTF-8.
fn secret(key: &[u8], encoded: &str) -> Option<String> {
    let bytes = crypto::decode_base64(encoded, None).ok()?;
    if bytes.len() > BACKUP_FILE_BYTES || bytes.len() < 28 {
        return None;
    }
    let plaintext = crypto::open_legacy_secret(key, encoded).ok()?;
    std::str::from_utf8(&plaintext).ok().map(str::to_string)
}

/// readLegacyEntries: every entry in id order, as the login objects a v1 backup holds. Returns
/// them with the plaintext size a backup of them takes.
pub fn entries(connection: &Connection, key: &[u8], active: Active<'_>) -> Outcome<(Vec<Value>, usize)> {
    let inspection = inspect(connection)?;
    let mut statement = connection.prepare(&format!("SELECT {} FROM password_entries ORDER BY id", projection(&FIELDS, &inspection.missing)))?;
    let mut rows = statement.query([])?;
    let mut entries = Vec::new();
    let mut size = EMPTY_BACKUP_BYTES;
    while let Some(row) = rows.next()? {
        active()?;
        let read = || -> Option<Value> {
            let mut entry = Map::new();
            entry.insert("id".into(), json!(required(row, 0)?));
            entry.insert("serviceName".into(), json!(required(row, 1)?));
            entry.insert("loginId".into(), json!(required(row, 2)?));
            entry.insert("password".into(), json!(secret(key, &required(row, 3)?)?));
            let notes = match text(row, 4, true)? {
                None => String::new(),
                Some(sealed) => secret(key, &sealed)?,
            };
            entry.insert("notes".into(), json!(notes));
            entry.insert("url".into(), json!(text(row, 5, true)?.unwrap_or_default()));
            entry.insert("tags".into(), serde_json::from_str(&required(row, 6)?).ok()?);
            entry.insert("group".into(), json!(text(row, 7, true)?));
            entry.insert("createdAt".into(), json!(required(row, 9)?));
            entry.insert("updatedAt".into(), json!(required(row, 10)?));
            entry.insert("passwordChangedAt".into(), json!(text(row, 8, true)?));
            Some(Value::Object(entry))
        };
        let entry = read().ok_or(Code::Failed)?;
        let serialized = Zeroizing::new(entry.to_string());
        let next = size + serialized.len() + usize::from(!entries.is_empty());
        if next > BACKUP_PLAINTEXT_BYTES {
            return Err(Code::Capacity.into());
        }
        input::validate_stored_entry(&entry, entry["id"].as_str().unwrap_or_default()).or_else(|_| failed())?;
        size = next;
        entries.push(entry);
    }
    if !backup::validate_entries(&entries, false) {
        return failed();
    }
    Ok((entries, size))
}

//! `.cvault` backup files, following apps/api/src/crypto/backup-v1.ts and vault-backup.ts. A
//! file names its version, which is the lowest one that can hold its entries, so an older app
//! reports an unsupported file instead of a wrong passphrase. The messages are the app's own: a
//! file that cannot be parsed is "unsupported or damaged", and anything that fails after the key
//! is derived is "wrong passphrase or damaged", so the two cases never reveal more than that.

// The names in a file's header are the ones its AAD is built from.
use crate::crypto::{self, BACKUP_KDF as KDF, CIPHER, Secret};
use crate::error::{Result, VaultError};
use crate::input::{self, BACKUP_FILE_BYTES, BACKUP_PLAINTEXT_BYTES, MAX_ENTRIES};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use zeroize::Zeroizing;

const UNSUPPORTED: &str = "未対応または破損したバックアップファイルです";
const WRONG_PASSPHRASE: &str = "パスフレーズが違うか、バックアップファイルが破損しています";
const LOGIN_FIELDS: [&str; 11] = ["id", "serviceName", "loginId", "password", "notes", "url", "tags", "group", "createdAt", "updatedAt", "passwordChangedAt"];

pub struct Envelope {
    pub version: u64,
    pub salt: Vec<u8>,
    iv: Vec<u8>,
    tag: Vec<u8>,
    data: Vec<u8>,
}

/// JavaScript compares numbers by value, so a version written as 1.0 is still version 1.
fn version_of(value: Option<&Value>) -> Option<u64> {
    let number = value?.as_f64()?;
    [1, 2, 3].into_iter().find(|version| *version as f64 == number)
}

/// parseRecord: an object whose keys are all among `fields`. Missing fields fail the later checks.
fn record<'a>(value: &'a Value, fields: &[&str]) -> Option<&'a Map<String, Value>> {
    value.as_object().filter(|object| object.keys().all(|key| fields.contains(&key.as_str())))
}

fn base64_field(envelope: &Map<String, Value>, field: &str, length: Option<usize>) -> Option<Vec<u8>> {
    let text = envelope.get(field)?.as_str().filter(|text| text.len() <= BACKUP_FILE_BYTES)?;
    let bytes = STANDARD.decode(text).ok()?;
    length.is_none_or(|length| bytes.len() == length).then_some(bytes)
}

/// parseVaultBackup
pub fn parse(content: &str) -> Result<Envelope> {
    let parse = || -> Option<Envelope> {
        if content.len() > BACKUP_FILE_BYTES {
            return None;
        }
        let value: Value = serde_json::from_str(content).ok()?;
        let version = version_of(value.get("version"))?;
        let envelope = record(&value, &["format", "version", "kdf", "cipher", "salt", "iv", "tag", "data"])?;
        if envelope.get("format")? != "CIPHER-VAULT" || envelope.get("kdf")? != KDF || envelope.get("cipher")? != CIPHER {
            return None;
        }
        let parsed = Envelope {
            version,
            salt: base64_field(envelope, "salt", Some(16))?,
            iv: base64_field(envelope, "iv", Some(12))?,
            tag: base64_field(envelope, "tag", Some(16))?,
            data: base64_field(envelope, "data", None)?,
        };
        (parsed.data.len() <= BACKUP_PLAINTEXT_BYTES).then_some(parsed)
    };
    parse().ok_or_else(|| VaultError::bad_request(UNSUPPORTED))
}

/// validateBackupEntries for one login: all eleven fields, an id of 36 hex digits and dashes,
/// and the checks a stored login passes.
fn valid_login(entry: &Value) -> Option<String> {
    let object = record(entry, &LOGIN_FIELDS)?;
    let id = object.get("id")?.as_str().filter(|id| input::is_entry_uuid(id))?;
    input::validate_stored_entry(entry, id).ok()?;
    Some(id.to_string())
}

/// validateBackupEntries (version 1, logins only) and validateVaultEntries (later versions).
fn validate(entries: &Value, typed: bool) -> Option<()> {
    validate_list(entries.as_array()?, typed)
}

/// validateBackupEntries or, when `typed`, validateVaultEntries.
pub fn validate_entries(entries: &[Value], typed: bool) -> bool {
    validate_list(entries, typed).is_some()
}

fn validate_list(entries: &[Value], typed: bool) -> Option<()> {
    if entries.len() > MAX_ENTRIES {
        return None;
    }
    let mut ids = HashSet::new();
    for entry in entries {
        let id = match entry.get("type") {
            Some(_) if typed => {
                let id = entry["id"].as_str()?;
                input::validate_stored_entry(entry, id).ok()?;
                id.to_string()
            }
            _ => valid_login(entry)?,
        };
        if !ids.insert(id) {
            return None;
        }
    }
    Some(())
}

/// decodeVaultBackup: the entries of an authentic file, after the same checks as the app.
pub fn decode(envelope: &Envelope, key: &[u8]) -> Result<Vec<Value>> {
    let decode = || -> Option<Vec<Value>> {
        let plaintext = crypto::open(key, &envelope.iv, &envelope.tag, &envelope.data, &crypto::backup_aad(envelope.version)).ok()?;
        // Buffer.toString("utf8") replaces invalid sequences rather than failing.
        let text = Zeroizing::new(String::from_utf8_lossy(&plaintext).into_owned());
        let mut payload: Value = serde_json::from_str(&text).ok()?;
        let decoded = record(&payload, &["version", "entries"])?;
        if version_of(decoded.get("version"))? != envelope.version {
            return None;
        }
        validate(decoded.get("entries")?, envelope.version != 1)?;
        match payload.get_mut("entries")?.take() {
            Value::Array(entries) => Some(entries),
            _ => None,
        }
    };
    decode().ok_or_else(|| VaultError::bad_request(WRONG_PASSPHRASE))
}

/// encodeVaultBackup: the lowest version that can hold the entries.
pub fn encode(entries: Vec<Value>, key: &Secret, salt: &[u8], iv: &[u8]) -> Result<String> {
    let entries = Value::Array(entries);
    if validate(&entries, true).is_none() {
        return Err(VaultError::bad_request("バックアップの項目が正しくありません"));
    }
    let kinds: Vec<&str> = entries.as_array().into_iter().flatten().filter_map(|entry| entry["type"].as_str()).collect();
    let version = if kinds.contains(&"financial") {
        3
    } else if kinds.iter().any(|kind| matches!(*kind, "apiKey" | "creditCard")) {
        2
    } else {
        1
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&json!({ "version": version, "entries": entries })).map_err(|_| VaultError::bad_request("バックアップの項目が正しくありません"))?);
    if plaintext.len() > BACKUP_PLAINTEXT_BYTES {
        return Err(VaultError::bad_request("バックアップ可能な容量を超えています（内容は11 MiBまで）"));
    }
    let (ciphertext, tag) = crypto::seal_backup(key, iv, &plaintext, version).map_err(|_| VaultError::new(500, "バックアップを暗号化できませんでした"))?;
    Ok(json!({
        "format": "CIPHER-VAULT", "version": version, "kdf": KDF, "cipher": CIPHER, "salt": STANDARD.encode(salt),
        "iv": STANDARD.encode(iv), "tag": STANDARD.encode(tag), "data": STANDARD.encode(ciphertext)
    })
    .to_string())
}

/// `CIPHER-VAULT-${new Date().toISOString().replace(/[:.]/g, "-")}.cvault`
pub fn file_name(now: &str) -> String {
    format!("CIPHER-VAULT-{}.cvault", now.replace([':', '.'], "-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(id: &str) -> Value {
        json!({ "id": id, "serviceName": "Backup", "loginId": "user", "password": "synthetic-backup-entry", "notes": "", "url": "", "tags": [], "group": null,
            "createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-02T00:00:00.000Z", "passwordChangedAt": null })
    }

    fn key() -> Secret {
        crypto::derive_strong_key(b"synthetic-backup-passphrase", &[7; 16]).unwrap()
    }

    #[test]
    fn a_file_round_trips_and_names_the_lowest_version() {
        let key = key();
        let first = login("11111111-1111-4111-8111-111111111111");
        let card = json!({ "id": "22222222-2222-4222-8222-222222222222", "type": "creditCard", "serviceName": "Card", "notes": "", "url": "", "tags": [], "group": null,
            "card": { "number": "4111111111111111", "cardholder": "", "expiryMonth": null, "securityCode": "" }, "createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-01T00:00:00.000Z" });
        for (entries, version) in [(vec![first.clone()], 1), (vec![first.clone(), card], 2)] {
            let content = encode(entries.clone(), &key, &[7; 16], &[9; 12]).unwrap();
            let envelope = parse(&content).unwrap();
            assert_eq!(envelope.version, version);
            assert_eq!(decode(&envelope, &key).unwrap(), entries);
            // The same bytes open with the format code shared with the fixed vectors.
            assert!(crypto::open_backup(&content, b"synthetic-backup-passphrase").is_ok());
        }
        assert_eq!(file_name("2026-11-06T01:02:03.456Z"), "CIPHER-VAULT-2026-11-06T01-02-03-456Z.cvault");
    }

    #[test]
    fn damaged_files_and_wrong_keys_get_the_app_messages() {
        let key = key();
        let content = encode(vec![login("11111111-1111-4111-8111-111111111111")], &key, &[7; 16], &[9; 12]).unwrap();
        for damaged in ["", "[]", "{\"version\":4}", &content.replace("CIPHER-VAULT", "OTHER"), &content.replace("\"cipher\"", "\"extra\":1,\"cipher\"")] {
            assert_eq!(parse(damaged).err(), Some(VaultError::bad_request(UNSUPPORTED)), "{damaged}");
        }
        let wrong = crypto::derive_strong_key(b"synthetic-other-passphrase", &[7; 16]).unwrap();
        assert_eq!(decode(&parse(&content).unwrap(), &wrong).err(), Some(VaultError::bad_request(WRONG_PASSPHRASE)));
    }

    #[test]
    fn entries_are_checked_as_the_app_checks_them() {
        let id = "11111111-1111-4111-8111-111111111111";
        assert!(validate(&json!([login(id)]), false).is_some());
        assert!(validate(&json!([login(id), login(id)]), true).is_none(), "duplicate ids");
        assert!(validate(&json!([login("not-a-uuid-not-a-uuid-not-a-uuid-xxx")]), true).is_none());
        let mut typed = login(id);
        typed["type"] = json!("apiKey");
        assert!(validate(&json!([typed]), false).is_none(), "version 1 holds logins only");
        let mut missing = login(id);
        missing.as_object_mut().unwrap().remove("passwordChangedAt");
        assert!(validate(&json!([missing]), true).is_none());
    }
}

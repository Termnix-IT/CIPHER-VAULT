//! Which vault the data directory holds, following inspectVaultSelection, readReceipt and
//! readPointer in apps/api/src/migration/active-pointer.ts. Without a pointer or receipt no vault
//! has been created yet; with both, and a committed receipt naming the same vault, it is that v2
//! vault. A file of the legacy format, which this release no longer opens, is only reported.
//! Anything else, including an interrupted switch, needs recovery and is never guessed at.

use crate::files::{Checked, FileCheckFailed, bounded_read, present, safe_path};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const LEGACY_DATABASE: &str = "password-manager.db";
pub const RECEIPT: &str = "vault-activation.json";
pub const POINTER: &str = "vault-current.json";
pub const TRANSITION: &str = "vault-transition.json";
const STATE_FILE_BYTES: u64 = 512;
const MAX_RECEIPT_ENTRIES: u64 = 10000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    /// No vault yet. `legacy_found` tells that a legacy file is there, which only an earlier
    /// release can open and back up.
    Empty { legacy_found: bool },
    V2 { database: PathBuf, vault_id: String, key_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub vault_id: String,
    pub key_id: String,
    pub entry_count: u64,
    pub committed: bool,
}

/// The lowercase version 4 UUIDs the app writes.
pub fn is_vault_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    let hex = |byte: &u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte);
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| if matches!(index, 8 | 13 | 18 | 23) { *byte == b'-' } else { hex(byte) })
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// The app accepts a state file only in the exact form JSON.stringify wrote it. Every writer
/// uses one key order, so the file must equal that form rebuilt from its own values.
fn state_file(path: &Path, fields: &[&str]) -> Checked<Value> {
    let bytes = bounded_read(path, STATE_FILE_BYTES)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| FileCheckFailed)?;
    let object = value.as_object().ok_or(FileCheckFailed)?;
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(FileCheckFailed);
    }
    let rebuilt: Vec<String> = fields.iter().map(|field| format!("{}:{}", Value::from(*field), object[*field])).collect();
    if bytes != format!("{{{}}}", rebuilt.join(",")).into_bytes() {
        return Err(FileCheckFailed);
    }
    Ok(value)
}

pub fn read_receipt(root: &Path) -> Checked<Receipt> {
    let value = state_file(&safe_path(root, &[RECEIPT], false, false)?, &["format", "version", "vaultId", "keyId", "entryCount", "state"])?;
    let text = |field: &str| value[field].as_str().ok_or(FileCheckFailed);
    let entry_count = value["entryCount"].as_u64().filter(|count| *count <= MAX_RECEIPT_ENTRIES).ok_or(FileCheckFailed)?;
    let committed = match text("state")? {
        "committed" => true,
        "prepared" => false,
        _ => return Err(FileCheckFailed),
    };
    let (vault_id, key_id) = (text("vaultId")?, text("keyId")?);
    if text("format")? != "CIPHER-VAULT-ACTIVATION" || value["version"] != 1 || !is_vault_uuid(vault_id) || !is_vault_uuid(key_id) {
        return Err(FileCheckFailed);
    }
    Ok(Receipt { vault_id: vault_id.into(), key_id: key_id.into(), entry_count, committed })
}

pub fn read_pointer(root: &Path) -> Checked<String> {
    let value = state_file(&safe_path(root, &[POINTER], false, false)?, &["format", "version", "vaultId"])?;
    let vault_id = value["vaultId"].as_str().filter(|id| is_vault_uuid(id)).ok_or(FileCheckFailed)?;
    if value["format"] != "CIPHER-VAULT-ACTIVE" || value["version"] != 1 {
        return Err(FileCheckFailed);
    }
    Ok(vault_id.into())
}

/// The v2 database's own checks run when it is opened, and their failure also needs recovery.
pub fn inspect(root: &Path) -> Checked<Selection> {
    let marker = safe_path(root, &[RECEIPT], false, true)?;
    let pointer = safe_path(root, &[POINTER], false, true)?;
    if present(&safe_path(root, &[TRANSITION], false, true)?)? {
        return Err(FileCheckFailed);
    }
    let (has_marker, has_pointer) = (present(&marker)?, present(&pointer)?);
    if !has_marker && !has_pointer {
        return Ok(Selection::Empty { legacy_found: present(&safe_path(root, &[LEGACY_DATABASE], false, true)?)? });
    }
    if !has_marker || !has_pointer {
        return Err(FileCheckFailed);
    }
    let receipt = read_receipt(root)?;
    if !receipt.committed || read_pointer(root)? != receipt.vault_id {
        return Err(FileCheckFailed);
    }
    let database = safe_path(root, &["vaults", &receipt.vault_id, "vault.sqlite"], false, false)?;
    Ok(Selection::V2 { database, vault_id: receipt.vault_id, key_id: receipt.key_id })
}

/// No vault is selected while none of the state files is there.
pub fn is_unclaimed(root: &Path) -> Checked<bool> {
    for name in [POINTER, RECEIPT, TRANSITION] {
        if present(&safe_path(root, &[name], false, true)?)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::TemporaryDirectory;
    use std::fs;

    const VAULT: &str = "11111111-1111-4111-8111-111111111111";
    const KEY: &str = "22222222-2222-4222-8222-222222222222";

    fn receipt(state: &str) -> String {
        format!(r#"{{"format":"CIPHER-VAULT-ACTIVATION","version":1,"vaultId":"{VAULT}","keyId":"{KEY}","entryCount":2,"state":"{state}"}}"#)
    }

    fn pointer(vault: &str) -> String {
        format!(r#"{{"format":"CIPHER-VAULT-ACTIVE","version":1,"vaultId":"{vault}"}}"#)
    }

    fn v2_root() -> TemporaryDirectory {
        let root = TemporaryDirectory::new();
        fs::create_dir_all(root.0.join("vaults").join(VAULT)).unwrap();
        fs::write(root.0.join("vaults").join(VAULT).join("vault.sqlite"), b"").unwrap();
        fs::write(root.0.join(RECEIPT), receipt("committed")).unwrap();
        fs::write(root.0.join(POINTER), pointer(VAULT)).unwrap();
        root
    }

    #[test]
    fn an_empty_directory_has_no_vault_and_tells_of_a_legacy_file() {
        let root = TemporaryDirectory::new();
        assert_eq!(inspect(&root.0).unwrap(), Selection::Empty { legacy_found: false });
        assert!(is_unclaimed(&root.0).unwrap());
        fs::write(root.0.join(LEGACY_DATABASE), b"").unwrap();
        assert_eq!(inspect(&root.0).unwrap(), Selection::Empty { legacy_found: true });
    }

    #[test]
    fn a_committed_receipt_and_matching_pointer_select_the_v2_vault() {
        let root = v2_root();
        let expected = Selection::V2 { database: root.0.join("vaults").join(VAULT).join("vault.sqlite"), vault_id: VAULT.into(), key_id: KEY.into() };
        assert_eq!(inspect(&root.0).unwrap(), expected);
        assert!(!is_unclaimed(&root.0).unwrap());
    }

    #[test]
    fn anything_unfinished_or_unusual_needs_recovery() {
        type Change = fn(&Path);
        let cases: [(&str, Change); 8] = [
            ("a pending transition", |root| fs::write(root.join(TRANSITION), "{}").unwrap()),
            ("a prepared receipt", |root| fs::write(root.join(RECEIPT), receipt("prepared")).unwrap()),
            ("a pointer to another vault", |root| fs::write(root.join(POINTER), pointer(KEY)).unwrap()),
            ("a receipt without a pointer", |root| fs::remove_file(root.join(POINTER)).unwrap()),
            ("a pointer without a receipt", |root| fs::remove_file(root.join(RECEIPT)).unwrap()),
            ("a reformatted receipt", |root| fs::write(root.join(RECEIPT), receipt("committed").replace(",", ", ")).unwrap()),
            ("a reordered pointer", |root| fs::write(root.join(POINTER), format!(r#"{{"version":1,"format":"CIPHER-VAULT-ACTIVE","vaultId":"{VAULT}"}}"#)).unwrap()),
            ("a missing database", |root| fs::remove_file(root.join("vaults").join(VAULT).join("vault.sqlite")).unwrap()),
        ];
        for (name, change) in cases {
            let root = v2_root();
            change(&root.0);
            assert!(inspect(&root.0).is_err(), "{name}");
        }
    }

    #[test]
    fn ids_are_lowercase_version_4_uuids() {
        assert!(is_vault_uuid(VAULT));
        for refused in ["11111111-1111-1111-8111-111111111111", "11111111-1111-4111-7111-111111111111", "AAAAAAAA-1111-4111-8111-111111111111", "11111111111141118111111111111111"] {
            assert!(!is_vault_uuid(refused), "{refused}");
        }
    }
}

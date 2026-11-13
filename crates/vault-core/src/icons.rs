//! List icons (a letter, a preset symbol or a small image). Since format 4 each entry carries its
//! own icon inside its encrypted record, and this module checks one from the screen.
//!
//! Releases up to v1.0.1 kept the icons in a file of their own beside the vault, encrypted under a
//! key derived from the vault key. The first unlock moves them into their entries (vault.rs), and
//! this module reads that file and removes it. A missing, damaged or foreign file reads as no icons.

use crate::crypto::{self, CryptoError, Secret};
use crate::error::{Result, VaultError};
use crate::files::{bounded_read, present, safe_path};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value};
#[cfg(test)]
use serde_json::json;
use std::fs;
use std::path::Path;

pub const FILE: &str = "entry-icons.json";
const TEMPORARY: &str = "entry-icons.json.tmp";
const FORMAT: &str = "CIPHER-VAULT-ENTRY-ICONS";
const INFO: &str = "CIPHER-VAULT/entry-icons/v1";
/// The screen redraws every picture as a 64 px PNG, which stays well below this.
pub const MAX_IMAGE_BYTES: usize = 32 * 1024;
#[cfg(test)]
const MAX_PLAIN_BYTES: usize = 8 * 1024 * 1024;
/// Base64 of the largest plaintext, with room for the fields around it.
const MAX_FILE_BYTES: u64 = 12 * 1024 * 1024;
const IMAGE_PREFIX: &str = "data:image/png;base64,";
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const ID_BYTES: usize = 128;

/// Whose key the file is under: the vault by its id.
pub fn scope(vault_id: &str) -> String {
    format!("v2:{vault_id}")
}

/// A key for this file only, so it never equals the key of an entry or a password slot.
fn key(vault_key: &[u8], scope: &str) -> std::result::Result<Secret, CryptoError> {
    crypto::derive_purpose_key(vault_key, format!("{FORMAT}\0{scope}").as_bytes(), INFO)
}

fn aad(scope: &str) -> Vec<u8> {
    format!("{FORMAT}\0v1\0{scope}").into_bytes()
}

/// Preset colors and symbols are named by the screen. The core checks only their form, and the
/// screen shows its default for a name it does not know.
fn is_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_entry_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= ID_BYTES && !value.contains('\0')
}

/// One icon from the screen. Like entries, an icon with an unknown field is refused.
pub fn parse_icon(value: &Value) -> Result<Value> {
    let invalid = || VaultError::bad_request("アイコンの形式が正しくありません");
    let object = value.as_object().ok_or_else(invalid)?;
    let text = |field: &str| object.get(field).and_then(Value::as_str);
    let fields: &[&str] = match text("kind") {
        Some("letter") => &["kind", "color"],
        Some("symbol") => &["kind", "symbol", "color"],
        Some("image") => &["kind", "image"],
        _ => return Err(invalid()),
    };
    if object.len() != fields.len() || !fields.iter().all(|field| text(field).is_some()) {
        return Err(invalid());
    }
    match text("image") {
        None => {
            if !fields.iter().skip(1).all(|field| text(field).is_some_and(is_name)) {
                return Err(invalid());
            }
        }
        Some(image) => {
            let data = image.strip_prefix(IMAGE_PREFIX).ok_or_else(invalid)?;
            let too_large = || VaultError::too_large("画像は32KB以内にしてください");
            if data.len() > MAX_IMAGE_BYTES.div_ceil(3) * 4 {
                return Err(too_large());
            }
            let bytes = STANDARD.decode(data).map_err(|_| invalid())?;
            if bytes.len() > MAX_IMAGE_BYTES {
                return Err(too_large());
            }
            if !bytes.starts_with(PNG_SIGNATURE) {
                return Err(invalid());
            }
        }
    }
    Ok(value.clone())
}

/// The icons in the file by entry id. Anything that cannot be read under this key reads as none,
/// and an icon that no longer passes the checks is left out.
pub fn read(root: &Path, vault_key: &[u8], scope: &str) -> Map<String, Value> {
    try_read(root, vault_key, scope).unwrap_or_default()
}

fn try_read(root: &Path, vault_key: &[u8], scope: &str) -> Option<Map<String, Value>> {
    let path = safe_path(root, &[FILE], false, true).ok()?;
    if !present(&path).ok()? {
        return None;
    }
    let file: Value = serde_json::from_slice(&bounded_read(&path, MAX_FILE_BYTES).ok()?).ok()?;
    if file["format"] != FORMAT || file["version"] != 1 || file["scope"] != scope {
        return None;
    }
    let field = |name: &str| file[name].as_str().and_then(|value| crypto::decode_base64(value, None).ok());
    let key = key(vault_key, scope).ok()?;
    let plain = crypto::open(&key, &field("iv")?, &field("tag")?, &field("data")?, &aad(scope)).ok()?;
    let icons: Value = serde_json::from_slice(&plain).ok()?;
    Some(icons.as_object()?.iter().filter(|(id, icon)| is_entry_id(id) && parse_icon(icon).is_ok()).map(|(id, icon)| (id.clone(), icon.clone())).collect())
}

/// Replaces the file with these icons, as releases up to v1.0.1 did. Only the tests write it now.
#[cfg(test)]
pub fn write(root: &Path, vault_key: &[u8], scope: &str, icons: &Map<String, Value>) -> Result<()> {
    use std::io::Write;
    use zeroize::Zeroizing;
    let failed = || VaultError::new(500, "アイコンを保存できませんでした");
    let plain = Zeroizing::new(serde_json::to_vec(icons).map_err(|_| failed())?);
    if plain.len() > MAX_PLAIN_BYTES {
        return Err(VaultError::too_large("画像のアイコンが多すぎます。いくつかを文字やシンボルに戻してください"));
    }
    let key = key(vault_key, scope).map_err(|_| failed())?;
    let (iv, tag, data) = crypto::seal_with_random_iv(&key, &plain, &aad(scope)).map_err(|_| failed())?;
    let text = json!({ "format": FORMAT, "version": 1, "scope": scope, "iv": STANDARD.encode(iv), "tag": STANDARD.encode(tag), "data": STANDARD.encode(data) }).to_string();
    let temporary = safe_path(root, &[TEMPORARY], false, true).map_err(|_| failed())?;
    let target = safe_path(root, &[FILE], false, true).map_err(|_| failed())?;
    let written = (|| -> std::io::Result<()> {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(failed());
    }
    Ok(())
}

/// Removes the file once its icons are in their entries.
pub fn remove(root: &Path) {
    for name in [FILE, TEMPORARY] {
        if let Ok(path) = safe_path(root, &[name], false, true) {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::TemporaryDirectory;

    const KEY: [u8; 32] = [7; 32];

    fn png(extra: usize) -> String {
        format!("{IMAGE_PREFIX}{}", STANDARD.encode([PNG_SIGNATURE, &vec![0u8; extra]].concat()))
    }

    fn icons() -> Map<String, Value> {
        let mut icons = Map::new();
        icons.insert("a".into(), json!({ "kind": "symbol", "symbol": "bank", "color": "violet" }));
        icons.insert("b".into(), json!({ "kind": "image", "image": png(16) }));
        icons
    }

    #[test]
    fn icons_round_trip_under_their_own_key_and_scope() {
        let root = TemporaryDirectory::new();
        assert!(read(&root.0, &KEY, "legacy").is_empty(), "no file reads as no icons");
        write(&root.0, &KEY, "legacy", &icons()).unwrap();
        assert_eq!(read(&root.0, &KEY, "legacy"), icons());
        let stored = fs::read_to_string(root.0.join(FILE)).unwrap();
        assert!(!stored.contains("bank") && !stored.contains("violet"), "the icons are sealed");
        assert!(read(&root.0, &[8; 32], "legacy").is_empty(), "another key, as after a new master password, reads as none");
        assert!(read(&root.0, &KEY, &scope("11111111-1111-4111-8111-111111111111")).is_empty(), "another vault reads as none");
        fs::write(root.0.join(FILE), stored.replace("\"data\":\"", "\"data\":\"AA")).unwrap();
        assert!(read(&root.0, &KEY, "legacy").is_empty(), "altered data reads as none");
        remove(&root.0);
        assert!(!root.0.join(FILE).exists());
    }

    #[test]
    fn only_known_icon_shapes_and_small_png_images_are_accepted() {
        assert!(parse_icon(&json!({ "kind": "letter", "color": "teal" })).is_ok());
        assert!(parse_icon(&json!({ "kind": "symbol", "symbol": "credit-card", "color": "red" })).is_ok());
        assert!(parse_icon(&json!({ "kind": "image", "image": png(MAX_IMAGE_BYTES - PNG_SIGNATURE.len()) })).is_ok());
        for refused in [
            json!(null),
            json!({ "kind": "letter" }),
            json!({ "kind": "letter", "color": "teal", "extra": 1 }),
            json!({ "kind": "symbol", "symbol": "Bank", "color": "teal" }),
            json!({ "kind": "symbol", "symbol": "a/b", "color": "teal" }),
            json!({ "kind": "letter", "color": "x".repeat(33) }),
            json!({ "kind": "image", "image": "data:image/svg+xml;base64,PHN2Zz4=" }),
            json!({ "kind": "image", "image": format!("{IMAGE_PREFIX}{}", STANDARD.encode(b"GIF89a")) }),
            json!({ "kind": "image", "image": format!("{IMAGE_PREFIX}not base64") }),
            json!({ "kind": "video" }),
        ] {
            assert_eq!(parse_icon(&refused).unwrap_err().status, 400, "{refused}");
        }
        assert_eq!(parse_icon(&json!({ "kind": "image", "image": png(MAX_IMAGE_BYTES) })).unwrap_err().status, 413);
    }
}

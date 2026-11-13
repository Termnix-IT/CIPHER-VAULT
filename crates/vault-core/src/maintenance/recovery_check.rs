//! Proves that a backup file can bring the entries back, following backup-recovery.ts and
//! typed-backup-recovery.ts: the file is opened with its own passphrase, restored into a separate
//! vault under another key, read back, and compared with what it should hold.

use super::{Active, Code, Context, Outcome, failed, random, same};
use crate::backup;
use crate::crypto;
use crate::v2::{StoreError, V2Store};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use zeroize::Zeroizing;

const TYPED_PREFIX: &str = "cipher-vault-typed-recovery-";

fn decoded(content: &str, passphrase: &[u8], active: Active<'_>) -> Outcome<(u64, Vec<Value>)> {
    active()?;
    let envelope = backup::parse(content).or_else(|_| failed())?;
    let key = crypto::derive_strong_key(passphrase, &envelope.salt).or_else(|_| failed())?;
    active()?;
    let entries = backup::decode(&envelope, &key).or_else(|_| failed())?;
    Ok((envelope.version, entries))
}

/// verifyBackupRecovery: every version is restored into a temporary v2 vault.
pub fn verify(content: &str, passphrase: &[u8], active: Active<'_>) -> Outcome<Vec<Value>> {
    let (_, entries) = decoded(content, passphrase, active)?;
    verify_in_v2(entries, active)
}

/// The scratch folder of a typed check, removed again whatever happens.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let name = self.0.file_name().map(|name| name.to_string_lossy().starts_with(TYPED_PREFIX)).unwrap_or(false);
        if name && !self.0.is_symlink() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// The entries restored through the real v2 restore into a temporary vault, reopened and read.
fn verify_in_v2(entries: Vec<Value>, active: Active<'_>) -> Outcome<Vec<Value>> {
    let root = random::<32>()?;
    let password = Zeroizing::new(STANDARD.encode(random::<32>()?.as_ref()));
    let context = Context::fresh()?;
    let slot = crypto::wrap_v2_root(root.as_ref(), password.as_bytes(), &context.vault_id, &context.key_id, 1, random::<16>()?.as_ref(), random::<12>()?.as_ref()).or_else(|_| failed())?;
    active()?;
    let temporary = crate::files::data_root(&std::env::temp_dir())?;
    let scratch = Scratch(temporary.join(format!("{TYPED_PREFIX}{}", uuid::Uuid::new_v4())));
    super::state_files::create_directory(&scratch.0)?;
    let file = scratch.0.join("vault.sqlite");
    let mut store = V2Store::create(&file, &slot, &context.vault_id, &context.key_id)?;
    store.restore(root.as_ref(), &entries, &|| active().map_err(|_| StoreError::Cancelled))?;
    drop(store);
    active()?;
    let store = V2Store::open_read_only(&file, &context.vault_id, &context.key_id).ok_or(Code::Failed)?;
    let reopened = crypto::unwrap_v2_root(store.password_slot(), password.as_bytes(), &context.vault_id, &context.key_id, 1).or_else(|_| failed())?;
    same(&reopened.as_slice(), &root.as_slice())?;
    let mut restored = Vec::new();
    for (id, _) in store.entries()? {
        active()?;
        restored.push(store.read(&reopened, &id)?.ok_or(Code::Failed)?.0);
    }
    drop(store);
    if !backup::validate_entries(&restored) {
        return failed();
    }
    let by_id = |values: &[Value]| values.iter().map(|entry| (entry["id"].as_str().unwrap_or_default().to_string(), entry.clone())).collect::<BTreeMap<_, _>>();
    same(&by_id(&restored), &by_id(&entries))?;
    Ok(entries)
}

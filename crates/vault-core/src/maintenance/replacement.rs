//! Replacing a v2 vault with a new one, following v2-replacement.ts, v2-replacement-state.ts and
//! v2-replacement-verification.ts. A rekey copies every entry under a new root key and password;
//! a reset starts empty. The old vault stays as it is, with a copy, its backup and its pointer
//! files beside the new one. A journal names both vaults and the hashes of every file before the
//! pointer moves, so an interrupted switch can only be finished, after all of it checks again.

use super::migration::{copy_database, encode_backup, locker, refuses, same_receipt};
use super::recovery_check;
use super::state_files::{self, Retained};
use super::{Active, Code, Context, Credentials, Outcome, Stop, failed, open_store, pointer, random, receipt, same};
use crate::crypto::{self, CryptoError};
use crate::error::VaultError;
use crate::files;
use crate::input::{BACKUP_FILE_BYTES, BACKUP_PLAINTEXT_BYTES, MAX_ENTRIES};
use crate::selection;
use crate::v2::{StoreError, V2Store};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

pub const SNAPSHOT_BYTES: i64 = 512 * 1024 * 1024;
const MAX_USES: u64 = 1 << 20;
const HASHES: [&str; 7] = ["source", "snapshot", "backup", "sourcePointer", "sourceReceipt", "target", "targetBackup"];
const EMPTY_BACKUP_BYTES: usize = 26;

/// Runs an unwrap of the old password under the unlock guard, which slows down repeated failures.
pub type Guard<'a> = &'a dyn Fn(&dyn Fn() -> crate::error::Result<crypto::Secret>) -> crate::error::Result<crypto::Secret>;

/// The journal of a replacement, vault-transition.json.
#[derive(Clone, Debug, PartialEq)]
pub struct Transition {
    pub reset: bool,
    pub source: Context,
    pub target: Context,
    pub source_count: u64,
    pub target_count: u64,
    pub source_uses: u64,
    pub hashes: Map<String, Value>,
}

impl Transition {
    /// The form JSON.stringify writes, which is also the only form the reader accepts.
    fn json(&self) -> Value {
        json!({ "format": "CIPHER-VAULT-TRANSITION", "version": 1, "mode": if self.reset { "reset" } else { "rekey" }, "source": self.source.json(), "target": self.target.json(),
            "sourceCount": self.source_count, "targetCount": self.target_count, "sourceUses": self.source_uses, "hashes": Value::Object(self.hashes.clone()) })
    }
}

/// readTransition: the exact bytes JSON.stringify wrote, two distinct vaults, and counts and
/// hashes in range.
pub fn read_transition(root: &Path) -> Outcome<Transition> {
    let read = || -> Option<Transition> {
        let bytes = files::bounded_read(&files::safe_path(root, &[selection::TRANSITION], false, false).ok()?, 4096).ok()?;
        let value: Value = serde_json::from_slice(&bytes).ok()?;
        if value.to_string().into_bytes() != bytes {
            return None;
        }
        let object = value.as_object()?;
        let fields = ["format", "version", "mode", "source", "target", "sourceCount", "targetCount", "sourceUses", "hashes"];
        if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
            return None;
        }
        let (source, target) = (Context::parse(&object["source"]).ok()?, Context::parse(&object["target"]).ok()?);
        let reset = match object["mode"].as_str()? {
            "reset" => true,
            "rekey" => false,
            _ => return None,
        };
        let (source_count, target_count, source_uses) = (object["sourceCount"].as_u64()?, object["targetCount"].as_u64()?, object["sourceUses"].as_u64()?);
        let ids = [&source.vault_id, &source.key_id];
        if object["format"] != "CIPHER-VAULT-TRANSITION" || object["version"] != 1 || target.vault_id == target.key_id || ids.contains(&&target.vault_id) || ids.contains(&&target.key_id)
            || source_count > MAX_ENTRIES as u64 || target_count != if reset { 0 } else { source_count } || source_uses < source_count || source_uses > MAX_USES
        {
            return None;
        }
        let hashes = object["hashes"].as_object()?;
        let hex = |text: &str| text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if hashes.len() != HASHES.len() || !HASHES.iter().all(|name| hashes.get(*name).and_then(Value::as_str).is_some_and(hex)) {
            return None;
        }
        Some(Transition { reset, source, target, source_count, target_count, source_uses, hashes: hashes.clone() })
    };
    read().ok_or_else(|| Code::Failed.into())
}

/// replacementFiles, in `vaults/<target vault id>/`.
struct Files {
    directory: PathBuf,
    database: PathBuf,
    snapshot: PathBuf,
    backup: PathBuf,
    source_pointer: PathBuf,
    source_receipt: PathBuf,
    target_backup: PathBuf,
    archive: PathBuf,
}

impl Files {
    fn of(root: &Path, target: &Context) -> Outcome<Self> {
        let path = |name: &str| files::safe_path(root, &["vaults", &target.vault_id, name], false, true);
        Ok(Self {
            directory: files::safe_path(root, &["vaults", &target.vault_id], true, false)?,
            database: path("vault.sqlite")?,
            snapshot: path("source.sqlite")?,
            backup: path("source.cvault")?,
            source_pointer: path("source-pointer.json")?,
            source_receipt: path("source-receipt.json")?,
            target_backup: path("target.cvault")?,
            archive: path("replacement.json")?,
        })
    }
}

/// readV2Entries: every entry of an opened store, within the size a backup holds. `fresh` asks
/// for revision 1 throughout, and `old_root` must not open any of them.
fn read_entries(store: &V2Store, root: &[u8], active: Active<'_>, fresh: bool, old_root: Option<&[u8]>) -> Outcome<Vec<Value>> {
    let mut entries = Vec::new();
    let mut size = EMPTY_BACKUP_BYTES;
    for (id, revision) in store.entries()? {
        active()?;
        if fresh {
            same(&revision, &1)?;
        }
        let entry = store.read(root, &id)?.ok_or(Code::Failed)?.0;
        size += serde_json::to_vec(&entry).map_err(|_| Stop::Code(Code::Failed))?.len() + usize::from(!entries.is_empty());
        if size > BACKUP_PLAINTEXT_BYTES {
            return Err(Code::Capacity.into());
        }
        entries.push(entry);
        if let Some(old_root) = old_root {
            let envelope = store.envelope(&id)?.ok_or(Code::Failed)?;
            if crypto::open_v2_entry(old_root, &envelope, store.vault_id(), store.key_id(), &id, revision) != Err(CryptoError::Authentication) {
                return failed();
            }
        }
    }
    if !crate::backup::validate_entries(&entries, true) {
        return failed();
    }
    Ok(entries)
}

fn verify_backup(file: &Path, passphrase: &str, expected: &[Value], active: Active<'_>) -> Outcome<()> {
    let entries = recovery_check::verify(&state_files::load_backup(file)?, passphrase.as_bytes(), active, true)?;
    active()?;
    same(&entries.as_slice(), &expected)
}

fn export_backup(file: &Path, entries: &[Value], passphrase: &str, active: Active<'_>) -> Outcome<()> {
    state_files::save(file, encode_backup(entries, passphrase)?.as_bytes())?;
    verify_backup(file, passphrase, entries, active)
}

/// verifySnapshot: the copy opens with the old password to the same key, count and entries.
fn verify_snapshot(file: &Path, context: &Context, password: &str, root: &[u8], entries: &[Value], uses: i64, active: Active<'_>) -> Outcome<()> {
    let store = V2Store::open_read_only(file, &context.vault_id, &context.key_id).ok_or(Code::Failed)?;
    let key = crypto::unwrap_v2_root(store.password_slot(), password.as_bytes(), &context.vault_id, &context.key_id, 1).or_else(|_| failed())?;
    active()?;
    same(&key.as_slice(), &root)?;
    same(&store.encryption_count()?, &uses)?;
    same(&read_entries(&store, &key, active, false, None)?.as_slice(), &entries)
}

fn fingerprints(root: &Path, source: &Context, target: &Context, active: Active<'_>, retained: &mut Retained) -> Outcome<Map<String, Value>> {
    let files = Files::of(root, target)?;
    let source_path = files::safe_path(root, &["vaults", &source.vault_id, "vault.sqlite"], false, false)?;
    let backup = BACKUP_FILE_BYTES as u64;
    let list: [(&Path, u64); 7] = [
        (&source_path, SNAPSHOT_BYTES as u64), (&files.snapshot, SNAPSHOT_BYTES as u64), (&files.backup, backup), (&files.source_pointer, 512),
        (&files.source_receipt, 512), (&files.database, SNAPSHOT_BYTES as u64), (&files.target_backup, backup),
    ];
    let mut hashes = Map::new();
    for (name, (path, maximum)) in HASHES.iter().zip(list) {
        hashes.insert((*name).into(), state_files::hash_file(path, maximum, active, retained)?.into());
    }
    Ok(hashes)
}

/// preserveGlobals: copies of the pointer files before recovery replaces them, refusing ones
/// that validly select some unrelated vault.
fn preserve_globals(root: &Path, directory: &Path, source: &Context, target: &Context, active: Active<'_>) -> Outcome<()> {
    use base64::Engine;
    for name in [selection::POINTER, selection::RECEIPT] {
        let file = files::safe_path(root, &[name], false, true)?;
        if !files::present(&file)? {
            continue;
        }
        let bytes = files::bounded_read(&file, 512)?;
        let known = |vault: &str, key: Option<&str>| [source, target].iter().any(|context| context.vault_id == vault && key.is_none_or(|key| context.key_id == key));
        if name == selection::POINTER {
            if let Ok(id) = selection::read_pointer(root)
                && !known(&id, None)
            {
                return failed();
            }
        } else if let Ok(receipt) = selection::read_receipt(root)
            && !known(&receipt.vault_id, Some(&receipt.key_id))
        {
            return failed();
        }
        active()?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        state_files::save(&directory.join(format!("preserved-{name}-{}", uuid::Uuid::new_v4())), encoded.as_bytes())?;
    }
    state_files::sync_directory(directory)?;
    Ok(())
}

/// What a replacement starts from: a fresh one, or the journal of an interrupted one.
pub enum Start {
    Replace { source: Context, reset: bool },
    Recover { source: Context, target: Context, reset: bool },
}

/// replaceV2Vault and recoverV2Replacement. `owner_key` is the key of the session that asked,
/// which the old password must reproduce. `authenticate` runs the unwrap under the unlock guard.
pub fn replace(root: &Path, start: Start, credentials: &Credentials<'_>, owner_key: &[u8], authenticate: Guard<'_>, active: Active<'_>) -> Outcome<()> {
    let mut retained = Retained::default();
    let mut publishing = matches!(start, Start::Recover { .. });
    let result = replace_checked(root, start, credentials, owner_key, authenticate, active, &mut retained, &mut publishing);
    drop(retained);
    result.map_err(|stop| {
        let pending = publishing || files::safe_path(root, &[selection::TRANSITION], false, true).and_then(|path| files::present(&path)).unwrap_or(true);
        match stop {
            _ if pending => Code::Failed.into(),
            Stop::Error(error) if error.status == 401 => Code::Authentication.into(),
            Stop::Error(error) if error.status == 409 || error.status == 429 => Code::Busy.into(),
            Stop::Error(_) => Code::Failed.into(),
            other => other,
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn replace_checked(
    root: &Path, start: Start, credentials: &Credentials<'_>, owner_key: &[u8], authenticate: Guard<'_>,
    active: Active<'_>, retained: &mut Retained, publishing: &mut bool,
) -> Outcome<()> {
    active()?;
    let (source, mut target, reset, mut transition) = match start {
        Start::Replace { source, reset } => (source, None, reset, None),
        Start::Recover { source, target, reset } => {
            let transition = read_transition(root)?;
            same(&(&transition.source, &transition.target, transition.reset), &(&source, &target, reset))?;
            (source, Some(target), reset, Some(transition))
        }
    };
    let read_global = |name: &str| files::bounded_read(&files::safe_path(root, &[name], false, false)?, 512);
    let mut saved_globals: Option<(Vec<u8>, Vec<u8>)> = None;
    let selected_source = |globals: &Option<(Vec<u8>, Vec<u8>)>| -> Outcome<()> {
        same(&super::selected(root)?, &Some(source.clone()))?;
        if let Some((pointer_bytes, receipt_bytes)) = globals {
            same(&read_global(selection::POINTER)?, pointer_bytes)?;
            same(&read_global(selection::RECEIPT)?, receipt_bytes)?;
        }
        Ok(())
    };
    if transition.is_none() {
        selected_source(&None)?;
        saved_globals = Some((read_global(selection::POINTER)?, read_global(selection::RECEIPT)?));
        selected_source(&saved_globals)?;
    }
    let source_path = files::safe_path(root, &["vaults", &source.vault_id, "vault.sqlite"], false, false)?;
    let source_store = open_store(root, &source)?;
    let source_locker = locker(&source_path)?;
    source_locker.execute_batch("BEGIN IMMEDIATE")?;
    active()?;
    if transition.is_none() {
        selected_source(&saved_globals)?;
    }
    let page_size: i64 = source_locker.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let page_count: i64 = source_locker.pragma_query_value(None, "page_count", |row| row.get(0))?;
    if page_size * page_count > SNAPSHOT_BYTES {
        return Err(Code::Capacity.into());
    }
    let wrong = || VaultError::new(401, "保管庫の認証に失敗しました");
    let source_key = authenticate(&|| {
        let key = match crypto::unwrap_v2_root(source_store.password_slot(), credentials.master.as_bytes(), &source.vault_id, &source.key_id, 1) {
            Ok(key) => key,
            Err(CryptoError::Authentication) => return Err(wrong()),
            Err(_) => return Err(VaultError::new(503, "")),
        };
        if active().is_err() {
            return Err(VaultError::conflict(""));
        }
        if key.as_slice() != owner_key { Err(wrong()) } else { Ok(key) }
    })?;
    active()?;
    let original = read_entries(&source_store, &source_key, active, false, None)?;
    let source_uses = source_store.encryption_count()?;
    match &transition {
        Some(transition) => {
            same(&(original.len() as u64), &transition.source_count)?;
            same(&(source_uses as u64), &transition.source_uses)?;
        }
        None => {
            let fresh = Context::fresh()?;
            let ids = [&source.vault_id, &source.key_id];
            if ids.contains(&&fresh.vault_id) || ids.contains(&&fresh.key_id) {
                return failed();
            }
            target = Some(fresh);
        }
    }
    let target = target.ok_or(Code::Failed)?;
    let mut target_key = None;
    let files = match &transition {
        Some(_) => Files::of(root, &target)?,
        None => {
            state_files::create_directory(&files::safe_path(root, &["vaults"], true, false)?.join(&target.vault_id))?;
            Files::of(root, &target)?
        }
    };
    if let Some(transition) = &transition {
        same(&fingerprints(root, &source, &target, active, retained)?, &transition.hashes)?;
        verify_backup(&files.backup, credentials.passphrase, &original, active)?;
        verify_snapshot(&files.snapshot, &source, credentials.master, &source_key, &original, source_uses, active)?;
        let saved_pointer: Value = serde_json::from_slice(&files::bounded_read(&files.source_pointer, 512)?).or_else(|_| failed())?;
        let saved_receipt: Value = serde_json::from_slice(&files::bounded_read(&files.source_receipt, 512)?).or_else(|_| failed())?;
        same(&saved_pointer, &pointer(&source))?;
        let count = saved_receipt["entryCount"].as_u64().filter(|count| *count <= MAX_ENTRIES as u64).ok_or(Code::Failed)?;
        same(&saved_receipt, &receipt(&source, count as usize, true))?;
    } else {
        let (pointer_bytes, receipt_bytes) = saved_globals.as_ref().ok_or(Code::Failed)?;
        state_files::save(&files.source_pointer, pointer_bytes)?;
        state_files::save(&files.source_receipt, receipt_bytes)?;
        export_backup(&files.backup, &original, credentials.passphrase, active)?;
        active()?;
        // The copy is read through its own read-only connection, never through the locker.
        let snapshot_reader = super::legacy_source::open(&source_path)?;
        copy_database(&snapshot_reader, &files.snapshot, page_size, SNAPSHOT_BYTES, active)?;
        drop(snapshot_reader);
        state_files::sync_file(&files.snapshot)?;
        verify_snapshot(&files.snapshot, &source, credentials.master, &source_key, &original, source_uses, active)?;
        active()?;
        let key = random::<32>()?;
        if key.as_slice() == source_key.as_slice() {
            return failed();
        }
        let slot = crypto::wrap_v2_root(key.as_ref(), credentials.new.as_bytes(), &target.vault_id, &target.key_id, 1, random::<16>()?.as_ref(), random::<12>()?.as_ref()).or_else(|_| failed())?;
        active()?;
        let mut store = V2Store::create(&files.database, &slot, &target.vault_id, &target.key_id)?;
        if !reset {
            for entry in &original {
                active()?;
                store.write(key.as_ref(), entry, entry["id"].as_str().unwrap_or_default(), 1, &|| active().map_err(|_| StoreError::Cancelled))?;
            }
        }
        drop(store);
        state_files::sync_file(&files.database)?;
        target_key = Some(key);
    }

    // The target's write lock is taken after it exists, and both locks are held to the end.
    V2Store::open_read_only(&files.database, &target.vault_id, &target.key_id).ok_or(Code::Failed)?;
    let target_locker = locker(&files.database)?;
    target_locker.execute_batch("BEGIN IMMEDIATE")?;
    let target_store = V2Store::open_read_only(&files.database, &target.vault_id, &target.key_id).ok_or(Code::Failed)?;
    let reopened = crypto::unwrap_v2_root(target_store.password_slot(), credentials.new.as_bytes(), &target.vault_id, &target.key_id, 1).map_err(|error| {
        Stop::Code(if error == CryptoError::Authentication { Code::Authentication } else { Code::Failed })
    })?;
    active()?;
    if let Some(key) = &target_key {
        same(&reopened.as_slice(), &key.as_slice())?;
    }
    if reopened.as_slice() == source_key.as_slice() {
        return failed();
    }
    refuses(target_store.password_slot(), credentials.master, &target)?;
    active()?;
    let actual = read_entries(&target_store, &reopened, active, true, Some(&source_key))?;
    same(&actual, &if reset { Vec::new() } else { original.clone() })?;
    same(&target_store.encryption_count()?, &(actual.len() as i64))?;
    drop(target_store);

    let transition = match transition.take() {
        Some(transition) => {
            verify_backup(&files.target_backup, credentials.passphrase, &actual, active)?;
            same(&fingerprints(root, &source, &target, active, retained)?, &transition.hashes)?;
            same(&read_transition(root)?, &transition)?;
            preserve_globals(root, &files.directory, &source, &target, active)?;
            transition
        }
        None => {
            export_backup(&files.target_backup, &actual, credentials.passphrase, active)?;
            active()?;
            let files = Files::of(root, &target)?;
            let transition = Transition {
                reset,
                source: source.clone(),
                target: target.clone(),
                source_count: original.len() as u64,
                target_count: actual.len() as u64,
                source_uses: source_uses as u64,
                hashes: fingerprints(root, &source, &target, active, retained)?,
            };
            for file in [&files.database, &files.snapshot, &files.backup, &files.source_pointer, &files.source_receipt, &files.target_backup] {
                active()?;
                let synced = state_files::sync_file(file)?;
                if file == &files.database {
                    retained.keep(synced);
                }
            }
            state_files::sync_directory(&files.directory)?;
            state_files::sync_directory(files.directory.parent().ok_or(Code::Failed)?)?;
            state_files::sync_directory(root)?;
            active()?;
            selected_source(&saved_globals)?;
            state_files::write_state(root, selection::TRANSITION, &transition.json(), &|| {
                active()?;
                selected_source(&saved_globals)
            }, true)?;
            *publishing = true;
            transition
        }
    };
    let check_pending = || -> Outcome<()> {
        active()?;
        Files::of(root, &target)?;
        same(&read_transition(root)?, &transition)
    };
    check_pending()?;
    state_files::write_state(root, selection::RECEIPT, &receipt(&target, actual.len(), false), &check_pending, false)?;
    state_files::write_state(root, selection::POINTER, &pointer(&target), &check_pending, false)?;
    state_files::write_state(root, selection::RECEIPT, &receipt(&target, actual.len(), true), &check_pending, false)?;
    check_pending()?;
    same(&selection::read_pointer(root)?, &target.vault_id)?;
    same_receipt(root, &receipt(&target, actual.len(), true))?;
    let files = Files::of(root, &target)?;
    if files::present(&files.archive)? {
        return failed();
    }
    std::fs::rename(files::safe_path(root, &[selection::TRANSITION], false, false)?, &files.archive)?;
    state_files::sync_file(&files.archive)?;
    state_files::sync_directory(&files.directory)?;
    state_files::sync_directory(root)?;
    drop(target_locker);
    drop(source_locker);
    drop(source_store);
    Ok(())
}

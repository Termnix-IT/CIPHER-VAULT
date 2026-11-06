//! Migrating a legacy vault to v2, following staging.ts, activation.ts and publishPointer in
//! active-pointer.ts. Staging writes a complete v2 vault in its own folder under `vaults`, with a
//! copy of the legacy file and backups of both, and checks all of it. Activation checks it all
//! again while holding both files' write locks, then writes the receipt and the pointer that
//! select it. Recovery repeats activation for a receipt that is already there.

use super::legacy_source::{self, Inspection, Metadata};
use super::recovery_check;
use super::state_files::{self, Retained};
use super::{Active, Code, Context, Credentials, Outcome, Stop, failed, pointer, random, receipt, same};
use crate::backup;
use crate::crypto::{self, CryptoError};
use crate::files;
use crate::selection::{self, Selection};
use crate::v2::{StoreError, V2Store};
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub const SNAPSHOT_MAX_BYTES: i64 = 64 * 1024 * 1024;

/// The files of a staged vault, in `vaults/<vault id>/`.
pub struct Staged {
    pub directory: PathBuf,
    pub snapshot: PathBuf,
    pub backup: PathBuf,
    pub database: PathBuf,
    pub export: PathBuf,
}

const STAGED: [&str; 4] = ["legacy.sqlite", "legacy.cvault", "vault.sqlite", "v2-export.cvault"];

impl Staged {
    fn at(directory: PathBuf) -> Self {
        let [snapshot, backup, database, export] = STAGED.map(|name| directory.join(name));
        Self { directory, snapshot, backup, database, export }
    }

    /// stagedFiles: every file must already be there, as a plain file.
    fn existing(root: &Path, context: &Context) -> Outcome<Self> {
        let directory = files::safe_path(root, &["vaults", &context.vault_id], true, false)?;
        for name in STAGED {
            files::safe_path(root, &["vaults", &context.vault_id, name], false, false)?;
        }
        Ok(Self::at(directory))
    }
}

/// A private writer that takes the write lock and never writes: other programs cannot change the
/// file while the switch reads it. It is opened after a read-only connection, and closed before
/// it, so that closing it never checkpoints a write-ahead log of the source.
pub fn locker(path: &Path) -> Outcome<Connection> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    connection.busy_timeout(Duration::ZERO)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(connection)
}

fn lock_legacy(path: &Path) -> Outcome<Connection> {
    let connection = locker(path)?;
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if mode != "delete" && mode != "wal" {
        return failed();
    }
    connection.execute_batch("BEGIN IMMEDIATE")?;
    Ok(connection)
}

fn snapshot_capacity(connection: &Connection) -> Outcome<i64> {
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let page_count: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    if page_size * page_count > SNAPSHOT_MAX_BYTES { Err(Code::Capacity.into()) } else { Ok(page_size) }
}

/// The SQLite backup API from a read-only connection into a reserved file, within `maximum` bytes.
pub fn copy_database(reader: &Connection, destination: &Path, page_size: i64, maximum: i64, active: Active<'_>) -> Outcome<()> {
    state_files::reserve(destination)?;
    let mut copy = Connection::open_with_flags(destination, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    {
        let backup = Backup::new(reader, &mut copy)?;
        loop {
            active()?;
            let step = backup.step(100)?;
            if i64::from(backup.progress().pagecount) * page_size > maximum {
                return Err(Code::Capacity.into());
            }
            match step {
                StepResult::Done => break,
                StepResult::More => {}
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
    drop(copy);
    active()
}

fn legacy_key(master: &str, metadata: &Metadata) -> Outcome<crypto::Secret> {
    let key = crypto::derive_legacy_key(master.as_bytes(), &metadata.salt).or_else(|_| failed())?;
    if crypto::verify_legacy_key(&key, &metadata.verifier, metadata.raw_verifier) { Ok(key) } else { Err(Code::Authentication.into()) }
}

/// A `.cvault` file of the entries, sealed under a new salt, which only the passphrase opens.
pub fn encode_backup(entries: &[Value], passphrase: &str) -> Outcome<String> {
    let salt = random::<16>()?;
    let key = crypto::derive_strong_key(passphrase.as_bytes(), salt.as_ref()).or_else(|_| failed())?;
    backup::encode(entries.to_vec(), &key, salt.as_ref(), random::<12>()?.as_ref()).or_else(|_| failed())
}

/// A password that must not open the slot: only an authentication failure counts.
pub fn refuses(slot: &str, password: &str, context: &Context) -> Outcome<()> {
    match crypto::unwrap_v2_root(slot, password.as_bytes(), &context.vault_id, &context.key_id, 1) {
        Err(CryptoError::Authentication) => Ok(()),
        _ => failed(),
    }
}

/// The entries of a reopened v2 vault, each at revision 1, which the legacy key cannot open.
fn reopened_entries(store: &V2Store, root: &[u8], old_key: &[u8], context: &Context, active: Active<'_>) -> Outcome<Vec<Value>> {
    let mut entries = Vec::new();
    for (id, revision) in store.entries()? {
        active()?;
        same(&revision, &1)?;
        entries.push(store.read(root, &id)?.ok_or(Code::Failed)?.0);
        let envelope = store.envelope(&id)?.ok_or(Code::Failed)?;
        if crypto::open_v2_entry(old_key, &envelope, &context.vault_id, &context.key_id, &id, 1) != Err(CryptoError::Authentication) {
            return failed();
        }
    }
    Ok(entries)
}

/// stageLegacyVault. Nothing that selects a vault is written, so a failure here leaves the legacy
/// vault in use; the staged folder is kept for inspection.
pub fn stage(root: &Path, credentials: &Credentials<'_>, active: Active<'_>) -> Outcome<Context> {
    active()?;
    let source = files::safe_path(root, &[selection::LEGACY_DATABASE], false, false)?;
    let vaults = files::safe_path(root, &["vaults"], true, true)?;
    if !files::present(&vaults)? {
        state_files::create_directory(&vaults)?;
    }
    let vaults = files::safe_path(root, &["vaults"], true, false)?;
    // Unknown formats are refused before any writable connection, and checked again under the lock.
    let reader = legacy_source::open(&source)?;
    legacy_source::inspect(&reader)?;
    legacy_source::metadata(&reader)?;
    snapshot_capacity(&reader)?;
    let locker = lock_legacy(&source)?;
    let inspection: Inspection = legacy_source::inspect(&locker)?;
    let metadata = legacy_source::metadata(&locker)?;
    let page_size = snapshot_capacity(&locker)?;
    let metadata_rows = legacy_source::metadata_rows(&locker)?;

    // verifyLegacyMigrationSource: the password opens the vault, and a backup of it restores.
    let old_key = legacy_key(credentials.master, &metadata)?;
    active()?;
    let (entries, _) = legacy_source::entries(&reader, &old_key, active)?;
    let content = Zeroizing::new(encode_backup(&entries, credentials.passphrase)?);
    active()?;

    let context = Context::fresh()?;
    let directory = vaults.join(&context.vault_id);
    state_files::create_directory(&directory)?;
    let staged = Staged::at(directory);
    state_files::save(&staged.backup, content.as_bytes())?;
    let expected = recovery_check::verify(&state_files::load_backup(&staged.backup)?, credentials.passphrase.as_bytes(), active, false)?;
    same(&expected, &entries)?;
    same(&(expected.len() as i64), &inspection.count)?;

    // A copy of the legacy file that stands alone even when the source uses a write-ahead log.
    copy_database(&reader, &staged.snapshot, page_size, SNAPSHOT_MAX_BYTES, active)?;
    {
        let snapshot = Connection::open(&staged.snapshot)?;
        let mode: String = snapshot.pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))?;
        same(&mode.as_str(), &"delete")?;
    }
    state_files::sync_file(&staged.snapshot)?;
    let snapshot = legacy_source::open(&staged.snapshot)?;
    let check: String = snapshot.pragma_query_value(None, "quick_check", |row| row.get(0))?;
    same(&check.as_str(), &"ok")?;
    same(&legacy_source::inspect(&snapshot)?.missing, &inspection.missing)?;
    same(&legacy_source::metadata_rows(&snapshot)?, &metadata_rows)?;
    let saved = legacy_source::metadata(&snapshot)?;
    same(&saved, &metadata)?;
    let snapshot_key = legacy_key(credentials.master, &saved).map_err(|_| Stop::Code(Code::Failed))?;
    active()?;
    same(&legacy_source::entries(&snapshot, &snapshot_key, active)?.0, &expected)?;
    drop(snapshot);

    // The new vault: a new random root key, sealed by the new password.
    let root_key = random::<32>()?;
    if root_key.as_slice() == old_key.as_slice() {
        return failed();
    }
    let slot = crypto::wrap_v2_root(root_key.as_ref(), credentials.new.as_bytes(), &context.vault_id, &context.key_id, 1, random::<16>()?.as_ref(), random::<12>()?.as_ref())
        .or_else(|_| failed())?;
    active()?;
    let mut store = V2Store::create(&staged.database, &slot, &context.vault_id, &context.key_id)?;
    for entry in &expected {
        active()?;
        let id = entry["id"].as_str().unwrap_or_default();
        store.write(root_key.as_ref(), entry, id, 1, &|| active().map_err(|_| StoreError::Cancelled))?;
    }
    same(&store.encryption_count()?, &(expected.len() as i64))?;
    drop(store);
    state_files::sync_file(&staged.database)?;
    active()?;

    let store = V2Store::open_read_only(&staged.database, &context.vault_id, &context.key_id).ok_or(Code::Failed)?;
    let reopened = crypto::unwrap_v2_root(store.password_slot(), credentials.new.as_bytes(), &context.vault_id, &context.key_id, 1).or_else(|_| failed())?;
    same(&reopened.as_slice(), &root_key.as_slice())?;
    refuses(store.password_slot(), credentials.master, &context)?;
    active()?;
    let actual = reopened_entries(&store, &reopened, &old_key, &context, active)?;
    same(&actual, &expected)?;
    drop(store);

    state_files::save(&staged.export, encode_backup(&actual, credentials.passphrase)?.as_bytes())?;
    let recovered = recovery_check::verify(&state_files::load_backup(&staged.export)?, credentials.passphrase.as_bytes(), active, false)?;
    same(&recovered, &expected)?;
    drop(locker);
    drop(reader);
    Ok(context)
}

/// activateStagedVault and recoverVaultActivation. `owner_key` is the key the legacy session
/// unlocked with, which the master password must reproduce.
pub fn activate(root: &Path, context: &Context, credentials: &Credentials<'_>, owner_key: &[u8], recovery: bool, active: Active<'_>) -> Outcome<()> {
    let mut retained = Retained::default();
    let result = activate_checked(root, context, credentials, owner_key, recovery, active, &mut retained);
    drop(retained);
    result.map_err(|stop| {
        // Any receipt means the pointer may have moved: only an explicit recovery may continue.
        let observed = files::safe_path(root, &[selection::RECEIPT], false, true).and_then(|marker| files::present(&marker)).unwrap_or(true);
        match stop {
            _ if observed => Code::Failed.into(),
            Stop::Code(Code::Capacity | Code::Invalid) => Code::Failed.into(),
            other => other,
        }
    })
}

fn check_state(root: &Path, context: &Context, recovery: bool) -> Outcome<()> {
    if !recovery {
        return match selection::inspect(root) {
            Ok(Selection::Legacy { .. }) => Ok(()),
            _ => failed(),
        };
    }
    let receipt = selection::read_receipt(root)?;
    same(&(receipt.vault_id.as_str(), receipt.key_id.as_str()), &(context.vault_id.as_str(), context.key_id.as_str()))?;
    let pointer = files::safe_path(root, &[selection::POINTER], false, true)?;
    if files::present(&pointer)? {
        // Explicit recovery may replace a malformed pointer, which it preserves first.
        if let Ok(target) = selection::read_pointer(root)
            && target != context.vault_id
        {
            return failed();
        }
    }
    Ok(())
}

fn activate_checked(root: &Path, context: &Context, credentials: &Credentials<'_>, owner_key: &[u8], recovery: bool, active: Active<'_>, retained: &mut Retained) -> Outcome<()> {
    active()?;
    check_state(root, context, recovery)?;
    let staged = Staged::existing(root, context)?;
    let source_path = files::safe_path(root, &[selection::LEGACY_DATABASE], false, false)?;
    let source = legacy_source::open(&source_path)?;
    legacy_source::inspect(&source)?;
    legacy_source::metadata(&source)?;
    let locker = lock_legacy(&source_path)?;
    active()?;
    check_state(root, context, recovery)?;
    V2Store::open_read_only(&staged.database, &context.vault_id, &context.key_id).ok_or(Code::Failed)?;
    let target_locker = super::migration::locker(&staged.database)?;
    target_locker.execute_batch("BEGIN IMMEDIATE")?;
    let store = V2Store::open_read_only(&staged.database, &context.vault_id, &context.key_id).ok_or(Code::Failed)?;
    let metadata = legacy_source::metadata(&locker)?;
    legacy_source::inspect(&locker)?;
    let old_key = legacy_key(credentials.master, &metadata)?;
    active()?;
    if old_key.as_slice() != owner_key {
        return Err(Code::Authentication.into());
    }
    let (original, _) = legacy_source::entries(&source, &old_key, active)?;
    active()?;
    let expected = recovery_check::verify(&state_files::load_backup(&staged.backup)?, credentials.passphrase.as_bytes(), active, false)?;
    same(&expected, &original)?;
    let snapshot = legacy_source::open(&staged.snapshot)?;
    let check: String = snapshot.pragma_query_value(None, "quick_check", |row| row.get(0))?;
    same(&check.as_str(), &"ok")?;
    same(&legacy_source::inspect(&snapshot)?.missing, &legacy_source::inspect(&source)?.missing)?;
    same(&legacy_source::metadata_rows(&snapshot)?, &legacy_source::metadata_rows(&source)?)?;
    same(&legacy_source::entries(&snapshot, &old_key, active)?.0, &expected)?;
    drop(snapshot);

    let root_key = crypto::unwrap_v2_root(store.password_slot(), credentials.new.as_bytes(), &context.vault_id, &context.key_id, 1).map_err(|error| {
        Stop::Code(if error == CryptoError::Authentication { Code::Authentication } else { Code::Failed })
    })?;
    active()?;
    if root_key.as_slice() == old_key.as_slice() {
        return failed();
    }
    refuses(store.password_slot(), credentials.master, context)?;
    active()?;
    same(&store.encryption_count()?, &(expected.len() as i64))?;
    let actual = reopened_entries(&store, &root_key, &old_key, context, active)?;
    same(&actual, &expected)?;
    drop(store);
    let exported = recovery_check::verify(&state_files::load_backup(&staged.export)?, credentials.passphrase.as_bytes(), active, false)?;
    same(&exported, &expected)?;

    check_state(root, context, recovery)?;
    let staged = Staged::existing(root, context)?;
    let committed = if recovery { selection::read_receipt(root)?.committed } else { false };
    let expected_receipt = receipt(context, expected.len(), committed);
    if recovery {
        same_receipt(root, &expected_receipt)?;
    }
    publish(root, context, &staged, &expected_receipt, recovery, active, retained)?;
    active()?;
    drop(target_locker);
    drop(locker);
    drop(source);
    Ok(())
}

/// The receipt on disk, read back through the strict reader, equals `expected`.
pub fn same_receipt(root: &Path, expected: &Value) -> Outcome<()> {
    let found = selection::read_receipt(root)?;
    let committed = expected["state"] == "committed";
    let matches = expected["vaultId"] == found.vault_id.as_str() && expected["keyId"] == found.key_id.as_str() && expected["entryCount"] == found.entry_count && committed == found.committed;
    if matches { Ok(()) } else { failed() }
}

/// publishPointer: sync every staged file, then the prepared receipt, the pointer and the
/// committed receipt, each written whole and renamed into place.
fn publish(root: &Path, context: &Context, staged: &Staged, prepared: &Value, recovery: bool, active: Active<'_>, retained: &mut Retained) -> Outcome<()> {
    for file in [&staged.backup, &staged.snapshot, &staged.database, &staged.export] {
        active()?;
        let synced = state_files::sync_file(file)?;
        if file == &staged.database {
            retained.keep(synced);
        }
    }
    state_files::sync_directory(&staged.directory)?;
    state_files::sync_directory(staged.directory.parent().ok_or(Code::Failed)?)?;
    state_files::sync_directory(root)?;
    active()?;
    let marker = files::safe_path(root, &[selection::RECEIPT], false, !recovery)?;
    let pointer_file = files::safe_path(root, &[selection::POINTER], false, true)?;
    if !recovery {
        if files::present(&marker)? || files::present(&pointer_file)? {
            return failed();
        }
        let pending = state_files::temporary(root, "vault-activation", prepared.to_string().as_bytes())?;
        active()?;
        if files::present(&marker)? || files::present(&pointer_file)? {
            return failed();
        }
        std::fs::rename(&pending, &marker)?;
        state_files::sync_file(&marker)?;
        state_files::sync_directory(root)?;
    } else {
        same_receipt(root, prepared)?;
        if files::present(&pointer_file)? {
            // Even malformed pointer bytes are kept before they are replaced.
            let previous = files::bounded_read(&pointer_file, 512)?;
            state_files::temporary(root, "vault-current-preserved", &previous)?;
        }
    }
    active()?;
    let pending = state_files::temporary(root, "vault-current", pointer(context).to_string().as_bytes())?;
    active()?;
    Staged::existing(root, context)?;
    same_receipt(root, prepared)?;
    files::safe_path(root, &[selection::POINTER], false, true)?;
    std::fs::rename(&pending, &pointer_file)?;
    state_files::sync_file(&pointer_file)?;
    state_files::sync_directory(root)?;
    same(&selection::read_pointer(root)?, &context.vault_id)?;
    let mut committed = prepared.clone();
    committed["state"] = "committed".into();
    let acknowledgment = state_files::temporary(root, "vault-activation", committed.to_string().as_bytes())?;
    active()?;
    std::fs::rename(&acknowledgment, &marker)?;
    state_files::sync_file(&marker)?;
    state_files::sync_directory(root)?;
    same_receipt(root, &committed)
}

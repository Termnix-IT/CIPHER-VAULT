//! Helpers the switches share: the read-only and locking connections, the copy of a database,
//! a sealed backup file, and the checks of a password slot and of the receipt.

use super::state_files;
use super::{Active, Code, Context, Outcome, failed, pointer, random, receipt};
use crate::backup;
use crate::crypto::{self, CryptoError};
use crate::files;
use crate::selection;
use crate::v2::V2Store;
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

/// A read-only connection that never waits for another writer.
pub fn open(path: &Path) -> Outcome<Connection> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    connection.busy_timeout(std::time::Duration::ZERO)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(connection)
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

pub fn same_receipt(root: &Path, expected: &Value) -> Outcome<()> {
    let found = selection::read_receipt(root)?;
    let committed = expected["state"] == "committed";
    let matches = expected["vaultId"] == found.vault_id.as_str() && expected["keyId"] == found.key_id.as_str() && expected["entryCount"] == found.entry_count && committed == found.committed;
    if matches { Ok(()) } else { failed() }
}

/// The first vault of an empty data directory: a new v2 vault written and synced in its own
/// folder, then selected the way a switch publishes one, with the prepared receipt, the pointer
/// and the committed receipt. The vault is opened again and must give back its root key before
/// that key is returned. Nothing is selected when any state file is already there, and nothing
/// is written once `active` fails after the slow key derivation.
pub fn create(root: &Path, master: &str, active: Active<'_>) -> Outcome<(Context, crypto::Secret)> {
    let unclaimed = || -> Outcome<()> {
        for name in [selection::RECEIPT, selection::POINTER, selection::TRANSITION] {
            if files::present(&files::safe_path(root, &[name], false, true)?)? {
                return failed();
            }
        }
        Ok(())
    };
    unclaimed()?;
    let context = Context::fresh()?;
    let key = random::<32>()?;
    let slot = crypto::wrap_v2_root(key.as_ref(), master.as_bytes(), &context.vault_id, &context.key_id, 1, random::<16>()?.as_ref(), random::<12>()?.as_ref()).or_else(|_| failed())?;
    active()?;
    unclaimed()?;
    let vaults = files::safe_path(root, &["vaults"], true, true)?;
    if !files::present(&vaults)? {
        state_files::create_directory(&vaults)?;
    }
    let directory = files::safe_path(root, &["vaults"], true, false)?.join(&context.vault_id);
    state_files::create_directory(&directory)?;
    let database = directory.join("vault.sqlite");
    drop(V2Store::create(&database, &slot, &context.vault_id, &context.key_id)?);
    state_files::sync_file(&database)?;
    state_files::sync_directory(&directory)?;
    state_files::sync_directory(&vaults)?;
    let opened = V2Store::open_read_only(&database, &context.vault_id, &context.key_id).ok_or(Code::Failed)?;
    let reopened = crypto::unwrap_v2_root(opened.password_slot(), master.as_bytes(), &context.vault_id, &context.key_id, 1).or_else(|_| failed())?;
    super::same(&reopened.as_slice(), &key.as_slice())?;
    super::same(&opened.entries()?.len(), &0)?;
    drop(opened);

    // From the first state file on, the selection is finished whatever happens to the session.
    active()?;
    unclaimed()?;
    let finish: Active<'_> = &|| Ok(());
    state_files::write_state(root, selection::RECEIPT, &receipt(&context, 0, false), finish, true)?;
    state_files::write_state(root, selection::POINTER, &pointer(&context), finish, true)?;
    super::same(&selection::read_pointer(root)?, &context.vault_id)?;
    state_files::write_state(root, selection::RECEIPT, &receipt(&context, 0, true), finish, false)?;
    same_receipt(root, &receipt(&context, 0, true))?;
    Ok((context, reopened))
}

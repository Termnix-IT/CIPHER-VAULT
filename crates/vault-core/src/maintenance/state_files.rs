//! Durable file steps of a switch, following staging-files.ts, active-pointer.ts and
//! v2-replacement-state.ts: files are written whole and synced before a rename puts them in
//! place, and a new file never replaces an existing one unless the step says so.

use super::{Active, Code, Outcome, failed};
use crate::files;
use crate::input::BACKUP_FILE_BYTES;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Files opened to sync a database are kept open until every SQLite connection to it closes. On
/// POSIX systems closing any descriptor of a file releases the process's SQLite locks on it.
#[derive(Default)]
pub struct Retained(Vec<File>);

impl Retained {
    pub fn keep(&mut self, file: File) {
        self.0.push(file);
    }
}

fn create_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// syncFile. Returns the open file for a caller that must keep it.
pub fn sync_file(path: &Path) -> Outcome<File> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    file.sync_all()?;
    Ok(file)
}

/// syncDirectory. Windows cannot sync a directory, so it reports that nothing was synced, as the
/// app does, rather than claiming durability.
pub fn sync_directory(directory: &Path) -> Outcome<bool> {
    if cfg!(windows) {
        let _ = directory;
        return Ok(false);
    }
    File::open(directory)?.sync_all()?;
    Ok(true)
}

/// createStageDirectory and createReplacementDirectory: a new, private directory.
pub fn create_directory(path: &Path) -> Outcome<()> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)?;
    Ok(())
}

/// reserveSnapshot: the name is taken before the copy is written into it.
pub fn reserve(path: &Path) -> Outcome<()> {
    create_new(path)?;
    Ok(())
}

/// saveBackup: a new file, written and synced.
pub fn save(path: &Path, content: &[u8]) -> Outcome<()> {
    let mut file = create_new(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

/// loadBackup and the bounded reads of a backup: a plain UTF-8 file of at most 16 MiB.
pub fn load_backup(path: &Path) -> Outcome<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return failed();
    }
    if metadata.len() > BACKUP_FILE_BYTES as u64 {
        return Err(Code::Capacity.into());
    }
    let bytes = files::bounded_read(path, BACKUP_FILE_BYTES as u64)?;
    String::from_utf8(bytes).or_else(|_| failed())
}

/// temporary: a hidden file next to its destination, written and synced. An interrupted one is
/// left in place.
pub fn temporary(root: &Path, label: &str, bytes: &[u8]) -> Outcome<PathBuf> {
    let path = root.join(format!(".{label}.{}.tmp", uuid::Uuid::new_v4()));
    save(&path, bytes)?;
    Ok(path)
}

/// writeState: a state file replaced in one rename, after `active` confirms the switch still
/// stands. `exclusive` refuses a file that is already there.
pub fn write_state(root: &Path, name: &str, value: &Value, active: Active<'_>, exclusive: bool) -> Outcome<()> {
    let destination = files::safe_path(root, &[name], false, true)?;
    let pending = temporary(root, name, value.to_string().as_bytes())?;
    active()?;
    files::safe_path(root, &[name], false, true)?;
    if exclusive && files::present(&destination)? {
        return failed();
    }
    fs::rename(&pending, &destination)?;
    sync_file(&destination)?;
    sync_directory(root)?;
    Ok(())
}

/// hashFile: SHA-256 of a plain file of at most `maximum` bytes, as lowercase hex.
pub fn hash_file(path: &Path, maximum: u64, active: Active<'_>, retained: &mut Retained) -> Outcome<String> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if !file.metadata()?.is_file() || files::identity(path)?.links != 1 || size > maximum {
        return Err(Code::Capacity.into());
    }
    let mut hash = Sha256::new();
    let mut chunk = zeroize::Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut offset = 0;
    while offset < size {
        active()?;
        let count = file.read(&mut chunk[..])?;
        if count == 0 {
            return failed();
        }
        hash.update(&chunk[..count]);
        offset += count as u64;
    }
    if file.metadata()?.len() != size || offset != size {
        return failed();
    }
    active()?;
    retained.keep(file);
    Ok(hex::encode(hash.finalize()))
}

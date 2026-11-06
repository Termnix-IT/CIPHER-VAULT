//! Path checks for the data directory, following dataRoot, safePath, present and boundedRead in
//! apps/api/src/migration/active-pointer.ts. Every component must be a plain file or directory on
//! the data directory's volume: links, junctions, other volumes and hard-linked files are refused,
//! so a vault file cannot be swapped for one somewhere else.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// A check failed. The callers report it as a vault that needs recovery or a failed context,
/// so the reason stays internal.
#[derive(Debug)]
pub struct FileCheckFailed;

pub type Checked<T> = std::result::Result<T, FileCheckFailed>;

impl From<io::Error> for FileCheckFailed {
    fn from(_: io::Error) -> Self {
        Self
    }
}

/// The volume and file index identify a file across renames; the link count catches hard links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume: u64,
    pub index: u64,
    pub links: u64,
}

#[cfg(windows)]
pub fn identity(path: &Path) -> io::Result<FileIdentity> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, GetFileInformationByHandle};
    // No access rights are needed to read the identity, and the link itself is opened, never its target.
    let file = fs::OpenOptions::new().access_mode(0).custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0).open(path)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle stays open for the call, and the structure is the size the call expects.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }.map_err(|error| io::Error::other(error.message()))?;
    Ok(FileIdentity {
        volume: u64::from(information.dwVolumeSerialNumber),
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        links: u64::from(information.nNumberOfLinks),
    })
}

#[cfg(unix)]
pub fn identity(path: &Path) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    Ok(FileIdentity { volume: metadata.dev(), index: metadata.ino(), links: metadata.nlink() })
}

/// Windows' verbatim prefix, which `canonicalize` adds, is removed for drive paths: SQLite and
/// the checks below then see the same form the TypeScript services use.
fn plain(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    // Windows compares names without case; the canonical form carries the stored case.
    if cfg!(windows) { left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase() } else { left == right }
}

/// dataRoot: the real path of an existing directory.
pub fn data_root(directory: &Path) -> Checked<PathBuf> {
    let root = plain(fs::canonicalize(directory)?);
    if fs::symlink_metadata(&root)?.is_dir() { Ok(root) } else { Err(FileCheckFailed) }
}

fn valid_component(part: &str) -> bool {
    !part.is_empty() && part != "." && part != ".." && !part.contains(['\\', '/', ':', '\0'])
}

/// safePath. `directory` asks for a directory at the end, and `missing` accepts a last component
/// that does not exist yet.
pub fn safe_path(root: &Path, components: &[&str], directory: bool, missing: bool) -> Checked<PathBuf> {
    let volume = identity(root)?.volume;
    let mut current = root.to_path_buf();
    for (index, part) in components.iter().enumerate() {
        if !valid_component(part) {
            return Err(FileCheckFailed);
        }
        current.push(part);
        let last = index == components.len() - 1;
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if last && missing && error.kind() == io::ErrorKind::NotFound => return Ok(current),
            Err(error) => return Err(error.into()),
        };
        let found = identity(&current)?;
        let real = plain(fs::canonicalize(&current)?);
        let kind_matches = if last && !directory { metadata.is_file() && found.links == 1 } else { metadata.is_dir() };
        if metadata.file_type().is_symlink() || found.volume != volume || !same_path(&current, &real) || !kind_matches {
            return Err(FileCheckFailed);
        }
    }
    Ok(current)
}

/// present: whether anything, even a broken link, exists at the path.
pub fn present(path: &Path) -> Checked<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// boundedRead: a plain file of at most `max` bytes, read whole.
pub fn bounded_read(path: &Path, max: u64) -> Checked<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || identity(path)?.links != 1 || metadata.len() > max {
        return Err(FileCheckFailed);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref().take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() { Err(FileCheckFailed) } else { Ok(bytes) }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A directory under the system temp directory, removed when dropped.
    pub struct TemporaryDirectory(pub PathBuf);

    impl TemporaryDirectory {
        pub fn new() -> Self {
            let directory = std::env::temp_dir().join(format!("cipher-vault-core-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&directory).unwrap();
            Self(data_root(&directory).unwrap())
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            assert!(self.0.file_name().unwrap().to_string_lossy().starts_with("cipher-vault-core-test-"));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn plain_files_and_directories_pass_and_missing_ones_only_when_allowed() {
        let root = TemporaryDirectory::new();
        fs::create_dir(root.0.join("vaults")).unwrap();
        fs::write(root.0.join("vaults").join("file"), b"x").unwrap();
        assert_eq!(safe_path(&root.0, &["vaults", "file"], false, false).unwrap(), root.0.join("vaults").join("file"));
        assert!(safe_path(&root.0, &["vaults"], true, false).is_ok());
        assert!(safe_path(&root.0, &["vaults"], false, false).is_err(), "a directory is not a file");
        assert!(safe_path(&root.0, &["vaults", "missing"], false, true).is_ok());
        assert!(safe_path(&root.0, &["vaults", "missing"], false, false).is_err());
        assert!(safe_path(&root.0, &["missing", "file"], false, true).is_err(), "only the last part may be missing");
        for part in ["", ".", "..", "a/b", "a\\b", "c:", "a\0"] {
            assert!(safe_path(&root.0, &[part], false, true).is_err(), "{part:?}");
        }
    }

    #[test]
    fn hard_links_and_other_names_for_a_file_are_refused() {
        let root = TemporaryDirectory::new();
        fs::write(root.0.join("file"), b"x").unwrap();
        fs::hard_link(root.0.join("file"), root.0.join("link")).unwrap();
        assert!(safe_path(&root.0, &["file"], false, false).is_err(), "a second name could change it unseen");
        assert!(bounded_read(&root.0.join("file"), 10).is_err());
        fs::remove_file(root.0.join("link")).unwrap();
        assert_eq!(bounded_read(&root.0.join("file"), 10).unwrap(), b"x");
        assert!(bounded_read(&root.0.join("file"), 0).is_err(), "over the limit");
        if cfg!(windows) {
            let upper = PathBuf::from(root.0.to_string_lossy().to_uppercase());
            assert!(same_path(&upper, &root.0), "Windows names ignore case");
        }
    }

    #[cfg(windows)]
    #[test]
    fn junctions_are_refused() {
        let root = TemporaryDirectory::new();
        fs::create_dir(root.0.join("target")).unwrap();
        let status = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(root.0.join("junction")).arg(root.0.join("target")).output().unwrap();
        assert!(status.status.success(), "{status:?}");
        assert!(safe_path(&root.0, &["junction"], true, false).is_err());
        assert!(present(&root.0.join("junction")).unwrap());
    }
}

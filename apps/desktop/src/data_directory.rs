//! Where the app keeps its vault: `%APPDATA%\<product name>\data`, the folder the Electron app
//! uses, so the vault stays where it is when this app replaces it. CIPHER_VAULT_DATA_DIR names
//! another existing folder instead, for trying the app with test data.
//!
//! The e2e build exists for automated checks and never opens the real vault. Without the variable
//! it only uses the folder of a test product name, and the variable may not name a folder where the
//! app or the development tools keep real data.

use std::path::{Path, PathBuf};

pub const VARIABLE: &str = "CIPHER_VAULT_DATA_DIR";
/// The released product. Its folder under %APPDATA% holds the user's vault.
pub const RELEASED_PRODUCT: &str = "CIPHER VAULT";

pub struct Location {
    pub path: PathBuf,
    /// The folder the Electron app of this product opens, however it was chosen.
    pub shared_with_electron: bool,
}

/// Lower-cased with one trailing separator, so a folder never matches a longer name.
fn comparable(path: &str) -> String {
    format!("{}\\", path.to_lowercase().replace('/', "\\").trim_end_matches('\\'))
}

/// Whether `path` is `folder` or inside it, ignoring case as Windows does.
fn is_within(path: &str, folder: &str) -> bool {
    comparable(path).starts_with(&comparable(folder))
}

/// The Electron app keeps its vault under %APPDATA%, and the Web/API builds under these folders.
fn is_protected(path: &str, app_data: Option<&str>) -> bool {
    let path = comparable(path);
    app_data.is_some_and(|directory| is_within(&path, directory)) || path.contains("\\apps\\api\\data\\") || path.contains("\\release\\data\\")
}

/// %APPDATA% resolved through links, as the folders checked against it are.
fn resolved_app_data(app_data: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    app_data.map(Path::new).filter(|directory| directory.is_absolute()).and_then(|directory| directory.canonicalize().ok())
}

fn from_variable(value: &std::ffi::OsStr, app_data: Option<&std::ffi::OsStr>) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(format!("{VARIABLE} must be an absolute path."));
    }
    // canonicalize resolves links and junctions, so the check sees the folder actually used.
    let resolved = path.canonicalize().ok().filter(|resolved| resolved.is_dir()).ok_or_else(|| format!("{VARIABLE} must name an existing folder."))?;
    if cfg!(feature = "e2e") {
        // Without %APPDATA% the check could not see the real vault, so the e2e build stops.
        let app_data = resolved_app_data(app_data).ok_or_else(|| format!("APPDATA must name an existing folder before {VARIABLE} is checked."))?;
        if is_protected(&resolved.to_string_lossy(), Some(&app_data.to_string_lossy())) {
            return Err(format!("{VARIABLE} names a folder that holds real vault data. Use a separate test folder."));
        }
    }
    Ok(resolved)
}

/// The product's folder, created on first use as the Electron app does.
fn product_folder(product_name: &str, app_data: Option<&std::ffi::OsStr>) -> Result<PathBuf, String> {
    if cfg!(feature = "e2e") && product_name.eq_ignore_ascii_case(RELEASED_PRODUCT) {
        return Err(format!("The e2e build never opens the vault of {RELEASED_PRODUCT}. Set {VARIABLE} to a test folder, or build it under a test product name."));
    }
    let app_data = app_data.map(Path::new).filter(|directory| directory.is_absolute()).ok_or("APPDATA does not name an absolute folder.")?;
    let path = app_data.join(product_name).join("data");
    std::fs::create_dir_all(&path).map_err(|_| "The vault folder could not be created.".to_string())?;
    let resolved = path.canonicalize().map_err(|_| "The vault folder could not be opened.".to_string())?;
    if cfg!(feature = "e2e") {
        // A test product's folder may still lead to the real one through a link.
        let real = resolved_app_data(Some(app_data.as_os_str())).map(|directory| directory.join(RELEASED_PRODUCT));
        if real.is_some_and(|real| is_within(&resolved.to_string_lossy(), &real.to_string_lossy())) {
            return Err(format!("The vault folder of this test product leads to the vault of {RELEASED_PRODUCT}."));
        }
    }
    Ok(resolved)
}

fn resolve_with(product_name: &str, variable: Option<&std::ffi::OsStr>, app_data: Option<&std::ffi::OsStr>) -> Result<Location, String> {
    let Some(value) = variable else {
        return Ok(Location { path: product_folder(product_name, app_data)?, shared_with_electron: true });
    };
    let path = from_variable(value, app_data)?;
    // The variable may name the product's own folder, which the Electron app opens as well.
    let electron = app_data.map(Path::new).and_then(|directory| directory.join(product_name).join("data").canonicalize().ok());
    let shared_with_electron = electron.is_some_and(|electron| comparable(&electron.to_string_lossy()) == comparable(&path.to_string_lossy()));
    Ok(Location { path, shared_with_electron })
}

pub fn resolve(product_name: &str) -> Result<Location, String> {
    resolve_with(product_name, std::env::var_os(VARIABLE).as_deref(), std::env::var_os("APPDATA").as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_folders_holding_real_data_are_refused() {
        let app_data = Some(r"\\?\C:\Users\someone\AppData\Roaming");
        for refused in [
            r"\\?\C:\Users\someone\AppData\Roaming\CIPHER VAULT\data",
            r"\\?\c:\users\SOMEONE\appdata\roaming",
            r"\\?\C:\work\CIPHER-VAULT\apps\api\data",
            r"\\?\C:\work\CIPHER-VAULT\release\data\nested",
        ] {
            assert!(is_protected(refused, app_data), "{refused}");
        }
        for allowed in [r"\\?\C:\Users\someone\AppData\Local\Temp\cipher-vault-e2e-data-1", r"\\?\C:\Users\someone\AppData\RoamingOther", r"\\?\C:\work\release\database"] {
            assert!(!is_protected(allowed, app_data), "{allowed}");
        }
    }

    #[test]
    fn the_product_folder_is_the_one_the_electron_app_uses() {
        let root = std::env::temp_dir().join(format!("cipher-vault-roaming-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let product = "CIPHER VAULT Folder Test";
        let path = product_folder(product, Some(root.as_os_str())).unwrap();
        assert_eq!(path, root.join(product).join("data").canonicalize().unwrap());
        assert!(path.is_dir(), "created on first use");
        assert_eq!(product_folder(product, Some(root.as_os_str())).unwrap(), path, "and reused");
        assert!(product_folder(product, Some(std::ffi::OsStr::new("relative"))).is_err());
        assert!(product_folder(product, None).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_the_e2e_build_refuses_the_released_product() {
        let root = std::env::temp_dir().join(format!("cipher-vault-roaming-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let result = product_folder(RELEASED_PRODUCT, Some(root.as_os_str()));
        assert_eq!(result.is_err(), cfg!(feature = "e2e"));
        assert_eq!(product_folder("cipher vault", Some(root.as_os_str())).is_err(), cfg!(feature = "e2e"), "case is ignored");
        assert_eq!(root.join(RELEASED_PRODUCT).exists(), !cfg!(feature = "e2e"), "a refused folder is never created");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn naming_the_product_folder_still_counts_as_the_shared_one() {
        let root = std::env::temp_dir().join(format!("cipher-vault-roaming-{}", uuid::Uuid::new_v4()));
        let product = "CIPHER VAULT Shared Test";
        let own = root.join(product).join("data");
        std::fs::create_dir_all(&own).unwrap();
        let shared = |folder: &Path| resolve_with(product, Some(folder.as_os_str()), Some(root.as_os_str())).map(|location| location.shared_with_electron);
        // The e2e build refuses every folder under %APPDATA%, so only the other build gets here.
        if !cfg!(feature = "e2e") {
            assert_eq!(shared(&own), Ok(true));
            let differently_written = PathBuf::from(own.to_string_lossy().to_uppercase());
            assert_eq!(shared(&differently_written), Ok(true));
        }
        assert_eq!(resolve_with(product, None, Some(root.as_os_str())).map(|location| location.shared_with_electron), Ok(true));
        let outside = std::env::temp_dir().join(format!("cipher-vault-other-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&outside).unwrap();
        assert_eq!(shared(&outside), Ok(false));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}

//! Where this build keeps its vault. Until the Rust app replaces the Electron app, it must never
//! open the vault in use, so it has no default location: the folder comes from
//! CIPHER_VAULT_DATA_DIR, must already exist, and may not be one of the places the app or the
//! development tools keep real data.

use std::path::{Path, PathBuf};

pub const VARIABLE: &str = "CIPHER_VAULT_DATA_DIR";

/// The Electron app keeps its vault under %APPDATA%, and the Web/API builds under these folders.
fn is_protected(path: &str, app_data: Option<&str>) -> bool {
    let normalize = |text: &str| format!("{}\\", text.to_lowercase().replace('/', "\\").trim_end_matches('\\'));
    let path = normalize(path);
    let in_app_data = app_data.is_some_and(|directory| path.starts_with(&normalize(directory)));
    in_app_data || path.contains("\\apps\\api\\data\\") || path.contains("\\release\\data\\")
}

pub fn from_environment() -> Result<PathBuf, String> {
    let Some(value) = std::env::var_os(VARIABLE) else {
        return Err(format!("Set {VARIABLE} to an existing test folder. This build has no default vault location yet."));
    };
    let path = Path::new(&value);
    if !path.is_absolute() {
        return Err(format!("{VARIABLE} must be an absolute path."));
    }
    // canonicalize resolves links and junctions, so the check sees the folder actually used.
    let resolved = path.canonicalize().ok().filter(|resolved| resolved.is_dir()).ok_or_else(|| format!("{VARIABLE} must name an existing folder."))?;
    let app_data = std::env::var_os("APPDATA").and_then(|directory| Path::new(&directory).canonicalize().ok());
    if is_protected(&resolved.to_string_lossy(), app_data.as_deref().map(|directory| directory.to_string_lossy()).as_deref()) {
        return Err(format!("{VARIABLE} names a folder that holds real vault data. Use a separate test folder."));
    }
    Ok(resolved)
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
}

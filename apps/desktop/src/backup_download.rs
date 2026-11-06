//! Saving a backup. The screen hands the encrypted `.cvault` text to a Blob link, as it does in the
//! Electron app, where Chromium asks where to save it. WebView2 would save without asking, so the
//! window asks here instead. Only a Blob made by the bundled screen may be saved; any other
//! download is refused, so the window never fetches a file from elsewhere.

use crate::is_application_url;
use std::path::{Path, PathBuf};
use tauri::webview::DownloadEvent;
use tauri::{Runtime, Url, Webview};

/// A `blob:` URL whose origin is the bundled screen, such as `blob:http://tauri.localhost/<uuid>`.
pub fn is_screen_blob(url: &Url) -> bool {
    url.scheme() == "blob" && Url::parse(url.path()).is_ok_and(|inner| is_application_url(&inner))
}

/// The name WebView2 suggests, which is the `download` attribute the screen set.
fn suggested_name(destination: &Path) -> String {
    destination.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| "CIPHER-VAULT.cvault".to_string())
}

/// Returns whether the download goes ahead, after setting where it is saved.
pub fn handle<R: Runtime>(webview: Webview<R>, event: DownloadEvent<'_>) -> bool {
    match event {
        DownloadEvent::Requested { url, destination } => {
            if !is_screen_blob(&url) {
                crate::trace("download-refused");
                return false;
            }
            match choose(&webview, destination) {
                Some(path) => {
                    *destination = path;
                    true
                }
                None => false,
            }
        }
        DownloadEvent::Finished { success, .. } => {
            crate::trace(&format!("download-finished {success}"));
            true
        }
        _ => false,
    }
}

/// The save dialog, owned by the window so it stays in front of it. Cancel stops the download.
#[cfg(not(feature = "e2e"))]
fn choose<R: Runtime>(webview: &Webview<R>, destination: &Path) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new()
        .set_title("バックアップの保存先")
        .set_file_name(suggested_name(destination))
        .add_filter("CIPHER VAULT バックアップ", &["cvault"]);
    if let Some(folder) = destination.parent().filter(|folder| folder.is_dir()) {
        dialog = dialog.set_directory(folder);
    }
    let window = webview.window();
    dialog.set_parent(&window).save_file().filter(|path| path.is_absolute())
}

/// The automated checks cannot answer a dialog, so they name a folder to save into.
#[cfg(feature = "e2e")]
fn choose<R: Runtime>(_webview: &Webview<R>, destination: &Path) -> Option<PathBuf> {
    let folder = std::env::var_os("CIPHER_VAULT_E2E_DOWNLOADS").map(PathBuf::from).filter(|path| path.is_absolute())?;
    Some(folder.join(suggested_name(destination)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_blobs_of_the_bundled_screen_may_be_saved() {
        for allowed in ["blob:http://tauri.localhost/0f8fad5b-d9cb-469f-a165-70867728950e", "blob:tauri://localhost/0f8fad5b-d9cb-469f-a165-70867728950e"] {
            assert!(is_screen_blob(&Url::parse(allowed).unwrap()), "{allowed}");
        }
        for refused in [
            "http://tauri.localhost/index.html",
            "https://example.test/file.cvault",
            "blob:https://example.test/0f8fad5b-d9cb-469f-a165-70867728950e",
            "blob:http://tauri.localhost.example.test/0f8fad5b",
            "blob:null/0f8fad5b-d9cb-469f-a165-70867728950e",
            "data:application/octet-stream,x",
            "file:///C:/backup.cvault",
        ] {
            assert!(!is_screen_blob(&Url::parse(refused).unwrap()), "{refused}");
        }
    }

    #[test]
    fn the_suggested_name_is_kept() {
        assert_eq!(suggested_name(Path::new("C:/Users/test/Downloads/CIPHER-VAULT-2026-11-06T01-02-03-456Z.cvault")), "CIPHER-VAULT-2026-11-06T01-02-03-456Z.cvault");
    }
}

//! Read-only Tauri prototype. It opens only the file named by CIPHER_VAULT_POC_DB and
//! has no default location, so it cannot reach a real vault by accident.

mod vault;

use std::sync::Arc;
use tauri::webview::NewWindowResponse;
use tauri::{State, Url, WebviewUrl, WebviewWindowBuilder};
use vault::{Vault, VaultStatus};
use zeroize::Zeroizing;

const DATABASE_VARIABLE: &str = "CIPHER_VAULT_POC_DB";

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnlockPayload {
    master_password: Zeroizing<String>,
}

type SharedVault = Arc<Vault>;

#[tauri::command]
fn vault_status(vault: State<'_, SharedVault>) -> VaultStatus {
    vault.status()
}

#[tauri::command]
async fn vault_unlock(vault: State<'_, SharedVault>, session_id: String, payload: UnlockPayload) -> Result<VaultStatus, String> {
    let vault = Arc::clone(&vault);
    // scrypt takes hundreds of milliseconds, so it must not run on the UI thread.
    tauri::async_runtime::spawn_blocking(move || vault.unlock(&session_id, payload.master_password.as_bytes()))
        .await
        .map_err(|_| "保管庫を開けませんでした".to_string())?
}

#[tauri::command]
fn vault_lock(vault: State<'_, SharedVault>, session_id: String) -> Result<VaultStatus, String> {
    vault.lock(&session_id)
}

#[tauri::command]
fn vault_activity(vault: State<'_, SharedVault>, session_id: String) -> Result<VaultStatus, String> {
    vault.record_activity(&session_id)
}

#[tauri::command]
fn entries_list(vault: State<'_, SharedVault>, session_id: String) -> Result<serde_json::Value, String> {
    vault.list_entries(&session_id)
}

#[tauri::command]
fn entries_get(vault: State<'_, SharedVault>, session_id: String, id: String) -> Result<serde_json::Value, String> {
    vault.get_entry(&session_id, &id)
}

fn is_application_url(url: &Url) -> bool {
    matches!((url.scheme(), url.host_str()), ("http", Some("tauri.localhost")) | ("tauri", Some("localhost")))
}

fn main() {
    let Some(path) = std::env::var_os(DATABASE_VARIABLE) else {
        eprintln!("Set {DATABASE_VARIABLE} to a COPY of a vault database. This prototype has no default location.");
        std::process::exit(2);
    };
    let vault = match Vault::open(std::path::Path::new(&path)) {
        Ok(vault) => Arc::new(vault),
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    tauri::Builder::default()
        .manage(vault)
        .invoke_handler(tauri::generate_handler![vault_status, vault_unlock, vault_lock, vault_activity, entries_list, entries_get])
        .setup(|app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("CIPHER VAULT (Tauri PoC / read-only)")
                .inner_size(880.0, 780.0)
                .min_inner_size(780.0, 680.0)
                .initialization_script(include_str!("desktop-api.js"))
                .on_navigation(is_application_url)
                .on_new_window(|_url, _features| NewWindowResponse::Deny)
                .disable_drag_drop_handler()
                .incognito(true)
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the prototype window failed to start");
}

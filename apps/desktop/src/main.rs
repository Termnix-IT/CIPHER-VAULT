//! CIPHER VAULT on Tauri. It shows the existing React screen from `apps/web` and replaces
//! `apps/electron` and the Node services step by step. The vault commands run the Rust core in
//! `crates/vault-core`; maintenance, backup, audit, the clipboard and updates are not ported yet.
//!
//! The `e2e` feature exists for automated checks only. It keeps the WebView2 debugging port
//! available and reports events on stdout. Never distribute it.

#![cfg_attr(not(feature = "e2e"), windows_subsystem = "windows")]

mod data_directory;
#[cfg_attr(feature = "e2e", allow(dead_code))]
mod webview_hardening;

use cipher_vault_core::{LockReason, Vault};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tauri::webview::NewWindowResponse;
use tauri::{Manager, State, Url, WebviewUrl, WebviewWindowBuilder, WindowEvent};

type Shared = Arc<Vault>;

/// How often the idle limit is checked. The screen asks for the status every second as well.
const EXPIRY_INTERVAL: Duration = Duration::from_secs(1);

/// Reports events to the automated checks. Prints nothing in a normal build.
fn trace(_event: &str) {
    #[cfg(feature = "e2e")]
    {
        use std::io::Write;
        let mut output = std::io::stdout();
        let _ = writeln!(output, "e2e-event {_event}");
        let _ = output.flush();
    }
}

/// Runs a vault call off the async runtime, since unlocking derives a key for about a second. The
/// screen sees only the message, as the Electron preload passes it on.
async fn run(vault: State<'_, Shared>, action: impl FnOnce(&Vault) -> cipher_vault_core::error::Result<Value> + Send + 'static) -> Result<Value, String> {
    let vault = Arc::clone(&vault);
    tauri::async_runtime::spawn_blocking(move || action(&vault))
        .await
        .map_err(|_| "処理に失敗しました".to_string())?
        .map_err(|error| error.message)
}

// The arguments follow the Electron preload. They stay JSON values that the core checks itself, so
// a missing or malformed argument gets the same answer as in the Electron app.
#[tauri::command]
async fn vault_status(vault: State<'_, Shared>) -> Result<Value, String> {
    run(vault, |vault| vault.status()).await
}

#[tauri::command]
async fn vault_activity(vault: State<'_, Shared>, session_id: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.record_activity(session_id.as_ref())).await
}

#[tauri::command]
async fn vault_setup(vault: State<'_, Shared>, session_id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.setup(session_id.as_ref(), payload.as_ref())).await
}

#[tauri::command]
async fn vault_unlock(vault: State<'_, Shared>, session_id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.unlock(session_id.as_ref(), payload.as_ref())).await
}

#[tauri::command]
async fn vault_lock(vault: State<'_, Shared>, session_id: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.lock(session_id.as_ref())).await
}

#[tauri::command]
async fn vault_reset(vault: State<'_, Shared>, session_id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.reset(session_id.as_ref(), payload.as_ref())).await
}

#[tauri::command]
async fn entries_list(vault: State<'_, Shared>, session_id: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.list_entries(session_id.as_ref())).await
}

#[tauri::command]
async fn entries_get(vault: State<'_, Shared>, session_id: Option<Value>, id: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.get_entry(session_id.as_ref(), id.as_ref())).await
}

#[tauri::command]
async fn entries_create(vault: State<'_, Shared>, session_id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.create_entry(session_id.as_ref(), payload.as_ref())).await
}

#[tauri::command]
async fn entries_update(vault: State<'_, Shared>, session_id: Option<Value>, id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.update_entry(session_id.as_ref(), id.as_ref(), payload.as_ref())).await
}

#[tauri::command]
async fn entries_delete(vault: State<'_, Shared>, session_id: Option<Value>, id: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.delete_entry(session_id.as_ref(), id.as_ref())).await
}

#[tauri::command]
async fn entries_set_group(vault: State<'_, Shared>, session_id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.set_entries_group(session_id.as_ref(), payload.as_ref())).await
}

#[tauri::command]
async fn password_generate(vault: State<'_, Shared>, session_id: Option<Value>, options: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.generate_password(session_id.as_ref(), options.as_ref())).await
}

/// The bundled screen only. Tauri serves it as http://tauri.localhost on Windows.
fn is_application_url(url: &Url) -> bool {
    matches!((url.scheme(), url.host_str()), ("http", Some("tauri.localhost")) | ("tauri", Some("localhost")))
}

/// The automated checks reach the page through WebView2's debugging port. The arguments are set
/// here rather than through WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, which WebView2 does not apply
/// on every machine (it was ignored on the CI runner). WebView2 requires a separate profile for
/// different browser arguments, so the check passes a temporary one.
#[cfg(feature = "e2e")]
fn with_debugging_port<'a, R: tauri::Runtime, M: tauri::Manager<R>>(builder: WebviewWindowBuilder<'a, R, M>) -> WebviewWindowBuilder<'a, R, M> {
    let port = std::env::var("CIPHER_VAULT_E2E_DEBUG_PORT").ok().and_then(|value| value.parse::<u16>().ok());
    let profile = std::env::var_os("CIPHER_VAULT_E2E_PROFILE").map(std::path::PathBuf::from).filter(|path| path.is_absolute());
    let (Some(port), Some(profile)) = (port, profile) else {
        fail_startup("Set CIPHER_VAULT_E2E_DEBUG_PORT and an absolute CIPHER_VAULT_E2E_PROFILE for the e2e build.");
    };
    // wry's own defaults are replaced by these, so they are repeated.
    builder.data_directory(profile).additional_browser_args(&format!(
        "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --remote-debugging-port={port} --remote-allow-origins=*"
    ))
}

fn fail_startup(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2);
}

fn main() {
    #[cfg(not(feature = "e2e"))]
    {
        // SAFETY: no other thread exists yet.
        unsafe { webview_hardening::remove_webview2_overrides() };
        if webview_hardening::webview2_policy_override_exists() {
            fail_startup("A WebView2 policy overrides this application's browser settings, so it will not start.");
        }
    }

    let directory = data_directory::from_environment().unwrap_or_else(|message| fail_startup(&message));
    let vault: Shared = Arc::new(Vault::open(&directory).unwrap_or_else(|error| fail_startup(&error.message)));
    let ticker = Arc::clone(&vault);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(EXPIRY_INTERVAL);
            ticker.expire();
        }
    });

    tauri::Builder::default()
        .manage(vault)
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_activity,
            vault_setup,
            vault_unlock,
            vault_lock,
            vault_reset,
            entries_list,
            entries_get,
            entries_create,
            entries_update,
            entries_delete,
            entries_set_group,
            password_generate
        ])
        .setup(|app| {
            let builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("CIPHER VAULT")
                .inner_size(880.0, 780.0)
                .min_inner_size(780.0, 680.0)
                .initialization_script(include_str!("desktop-api.js"))
                .on_navigation(is_application_url)
                .on_new_window(|_url, _features| NewWindowResponse::Deny)
                .disable_drag_drop_handler();
            #[cfg(feature = "e2e")]
            let builder = with_debugging_port(builder);
            let window = builder.build()?;
            let vault = Arc::clone(app.state::<Shared>().inner());
            let closed = Arc::clone(&vault);
            // The Electron app locks when its window closes; the process may outlive the window.
            window.on_window_event(move |event| {
                if matches!(event, WindowEvent::Destroyed) {
                    closed.lock_for(LockReason::WindowClosed);
                }
            });
            window.with_webview(move |webview| {
                let gone = move || {
                    vault.lock_for(LockReason::RendererGone);
                    trace("renderer-gone");
                };
                match webview_hardening::apply_settings(&webview, gone) {
                    Ok(settings) => trace(&format!("webview-settings {settings}")),
                    // These settings protect secrets, so the window must not stay open without them.
                    Err(_) => fail_startup("The WebView2 security settings could not be applied."),
                }
            })?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the window failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_bundled_screen_is_an_application_url() {
        for allowed in ["http://tauri.localhost/index.html", "http://tauri.localhost/assets/a.js#x", "tauri://localhost/index.html"] {
            assert!(is_application_url(&Url::parse(allowed).unwrap()), "{allowed}");
        }
        for refused in [
            "https://tauri.localhost/",
            "http://tauri.localhost.example.test/",
            "http://ipc.localhost/vault_status",
            "https://example.test/",
            "file:///C:/index.html",
            "data:text/html,x",
        ] {
            assert!(!is_application_url(&Url::parse(refused).unwrap()), "{refused}");
        }
    }
}

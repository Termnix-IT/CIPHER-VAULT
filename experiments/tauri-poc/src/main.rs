//! Read-only Tauri prototype. It opens only the file named by CIPHER_VAULT_POC_DB and
//! has no default location, so it cannot reach a real vault by accident.
//!
//! The `e2e` feature exists for automated UI checks only. It keeps the debugging port available,
//! replaces the clipboard with a fake one and reports events on stdout. Never distribute it.

mod clipboard;
mod clock;
mod os_events;
mod vault;
#[cfg_attr(feature = "e2e", allow(dead_code))]
mod webview_hardening;
// Left out of the E2E build, so that build cannot reach the real clipboard at all.
#[cfg(not(feature = "e2e"))]
mod windows_clipboard;

use clipboard::ExpiringClipboard;
use os_events::{OsEvent, PowerGuard};
use std::sync::Arc;
use std::time::Duration;
use tauri::webview::NewWindowResponse;
use tauri::{Manager, RunEvent, State, Url, WebviewUrl, WebviewWindowBuilder};
use vault::{Vault, VaultStatus};
use zeroize::Zeroizing;

const DATABASE_VARIABLE: &str = "CIPHER_VAULT_POC_DB";
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;
const WATCHDOG_INTERVAL: Duration = Duration::from_millis(500);

/// Reports events to the E2E check. Prints nothing in a normal build.
pub fn trace(_event: &str) {
    #[cfg(feature = "e2e")]
    {
        use std::io::Write;
        let mut output = std::io::stdout();
        let _ = writeln!(output, "e2e-event {_event}");
        let _ = output.flush();
    }
}

struct Core {
    vault: Vault,
    clipboard: ExpiringClipboard,
    power: PowerGuard,
}

impl Core {
    /// Lock first: the key must be gone even if the clipboard is busy.
    fn lock_and_clear(&self, reason: &'static str) {
        self.vault.lock_for(reason);
        trace(&format!("vault-locked {reason}"));
        self.clipboard.clear_owned();
    }

    fn handle_os_event(&self, event: OsEvent) {
        self.power.observe(event);
        self.lock_and_clear(event.lock_reason());
    }

    fn assert_available(&self) -> Result<(), String> {
        let result = self.power.check(os_events::session_is_locked());
        // A lock found here had no notification, so nothing has locked the vault yet. Only the key
        // is destroyed here: a copy in progress calls this while holding the clipboard lease, so
        // clearing is left to that copy's failure path and to the watchdog.
        if result.is_err() && self.vault.status().is_unlocked() {
            self.vault.lock_for("screen-lock");
            trace("vault-locked screen-lock");
        }
        result.map_err(str::to_string)
    }

    /// The key lives here even if the page hangs, so expiry cannot depend on the page polling.
    fn watch(&self) {
        if self.vault.status().is_unlocked() {
            self.clipboard.tick();
        } else {
            self.clipboard.clear_owned();
        }
    }
}

type SharedCore = Arc<Core>;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnlockPayload {
    master_password: Zeroizing<String>,
}

#[tauri::command]
fn vault_status(core: State<'_, SharedCore>) -> VaultStatus {
    core.vault.status()
}

#[tauri::command]
async fn vault_unlock(core: State<'_, SharedCore>, session_id: String, payload: UnlockPayload) -> Result<VaultStatus, String> {
    core.assert_available()?;
    let core = Arc::clone(&core);
    // scrypt takes hundreds of milliseconds, so it must not run on the UI thread.
    tauri::async_runtime::spawn_blocking(move || core.vault.unlock(&session_id, payload.master_password.as_bytes()))
        .await
        .map_err(|_| "保管庫を開けませんでした".to_string())?
}

#[tauri::command]
fn vault_lock(core: State<'_, SharedCore>, session_id: String) -> Result<VaultStatus, String> {
    let status = core.vault.lock(&session_id)?;
    trace("vault-locked manual");
    core.clipboard.clear_owned();
    Ok(status)
}

#[tauri::command]
fn vault_activity(core: State<'_, SharedCore>, session_id: String) -> Result<VaultStatus, String> {
    core.assert_available()?;
    core.vault.record_activity(&session_id)
}

#[tauri::command]
fn entries_list(core: State<'_, SharedCore>, session_id: String) -> Result<serde_json::Value, String> {
    core.assert_available()?;
    core.vault.list_entries(&session_id)
}

#[tauri::command]
fn entries_get(core: State<'_, SharedCore>, session_id: String, id: String) -> Result<serde_json::Value, String> {
    core.assert_available()?;
    core.vault.get_entry(&session_id, &id)
}

#[tauri::command]
async fn clipboard_write(core: State<'_, SharedCore>, session_id: String, value: Zeroizing<String>) -> Result<(), String> {
    if value.len() > MAX_CLIPBOARD_BYTES {
        return Err("コピーする内容が大きすぎます".into());
    }
    let core = Arc::clone(&core);
    // Waiting for a busy clipboard must not freeze the window.
    tauri::async_runtime::spawn_blocking(move || {
        core.clipboard.copy(&value, || {
            core.assert_available()?;
            core.vault.require_unlocked(&session_id)
        })
    })
    .await
    .map_err(|_| "クリップボードへコピーできませんでした".to_string())?
}

fn is_application_url(url: &Url) -> bool {
    matches!((url.scheme(), url.host_str()), ("http", Some("tauri.localhost")) | ("tauri", Some("localhost")))
}

fn clipboard_port() -> Box<dyn clipboard::ClipboardPort> {
    #[cfg(feature = "e2e")]
    return Box::new(clipboard::fake::FakeClipboard::default());
    #[cfg(not(feature = "e2e"))]
    return Box::new(windows_clipboard::WindowsClipboard);
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

    let Some(path) = std::env::var_os(DATABASE_VARIABLE) else {
        fail_startup(&format!("Set {DATABASE_VARIABLE} to a COPY of a vault database. This prototype has no default location."));
    };
    let vault = Vault::open(std::path::Path::new(&path)).unwrap_or_else(|message| fail_startup(&message));
    let core: SharedCore = Arc::new(Core { vault, clipboard: ExpiringClipboard::new(clipboard_port()), power: PowerGuard::default() });

    let listener = Arc::clone(&core);
    match os_events::start(Box::new(move |event| listener.handle_os_event(event))) {
        Ok(window) => trace(&format!("os-window {window}")),
        // Running without these notifications would silently lose a protection.
        Err(message) => fail_startup(&message),
    }
    let watchdog = Arc::clone(&core);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(WATCHDOG_INTERVAL);
            watchdog.watch();
        }
    });

    let app = tauri::Builder::default()
        .manage(Arc::clone(&core))
        .invoke_handler(tauri::generate_handler![vault_status, vault_unlock, vault_lock, vault_activity, entries_list, entries_get, clipboard_write])
        .setup(|app| {
            let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("CIPHER VAULT (Tauri PoC / read-only)")
                .inner_size(880.0, 780.0)
                .min_inner_size(780.0, 680.0)
                .initialization_script(include_str!("desktop-api.js"))
                .on_navigation(is_application_url)
                .on_new_window(|_url, _features| NewWindowResponse::Deny)
                .disable_drag_drop_handler()
                .incognito(true)
                .build()?;
            let core = Arc::clone(app.state::<SharedCore>().inner());
            window.with_webview(move |webview| {
                let failed = Arc::clone(&core);
                match webview_hardening::apply_settings(&webview, move || failed.lock_and_clear("renderer-gone")) {
                    Ok(settings) => trace(&format!("webview-settings {settings}")),
                    // These settings protect secrets, so the window must not stay open without them.
                    Err(_) => fail_startup("The WebView2 security settings could not be applied."),
                }
            })?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("the prototype window failed to start");

    app.run(move |_app, event| {
        if let RunEvent::Exit = event {
            core.lock_and_clear("window-closed");
            trace("exit-complete");
        }
    });
}

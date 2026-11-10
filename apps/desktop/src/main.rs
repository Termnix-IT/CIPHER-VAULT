//! CIPHER VAULT on Tauri. It shows the React screen from `apps/web`, and the vault commands run
//! the Rust core in `crates/vault-core`. It replaced the Electron app (removed after v0.9.0; the
//! TypeScript files the comments name are in `apps/electron` at the git tag v0.9.0). The desktop
//! adds what the Electron main process did: the expiring clipboard, locking on screen lock and
//! sleep, one app per vault folder and manual updates.
//!
//! The `e2e` feature exists for automated checks only. It keeps the WebView2 debugging port
//! available, replaces the clipboard with a fake one and reports events on stdout. Never distribute it.

#![cfg_attr(not(feature = "e2e"), windows_subsystem = "windows")]

mod backup_download;
mod clipboard;
mod data_directory;
mod electron_guard;
mod os_events;
mod single_instance;
mod updates;
#[cfg_attr(feature = "e2e", allow(dead_code))]
mod webview_hardening;
// Left out of the e2e build, so that build cannot reach the real clipboard at all.
#[cfg(not(feature = "e2e"))]
mod windows_clipboard;

use cipher_vault_core::error::VaultError;
use cipher_vault_core::{LockReason, Vault};
use clipboard::ExpiringClipboard;
use os_events::{OsEvent, PowerGuard};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tauri::webview::NewWindowResponse;
use tauri::{AppHandle, Manager, RunEvent, State, Url, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use updates::Updates;
use zeroize::Zeroize;

type Shared = Arc<Vault>;
type SharedDesktop = Arc<Desktop>;

/// How often the idle limit and the copy deadline are checked, even when the screen hangs.
const WATCHDOG_INTERVAL: Duration = Duration::from_millis(500);
/// How long quitting waits for a switch to stop, as the Electron app waits before it exits.
const QUIT_WAIT: Duration = Duration::from_millis(1500);
const QUITTING: &str = "アプリを終了しています";

/// What the Electron main process kept around the services: the clipboard, the OS state and quitting.
struct Desktop {
    vault: Shared,
    clipboard: ExpiringClipboard,
    power: PowerGuard,
    quitting: AtomicBool,
}

impl Desktop {
    /// Lock first: the key must be gone even if the clipboard is busy. The report comes before the
    /// lock, so the watchdog's clearing can never be reported ahead of it.
    fn lock_and_clear(&self, reason: LockReason) {
        trace(&format!("vault-locked {}", reason.as_str()));
        self.vault.lock_for(reason);
        self.clipboard.clear_owned();
    }

    fn handle_os_event(&self, event: OsEvent) {
        self.power.observe(event);
        self.lock_and_clear(event.lock_reason());
    }

    /// assertAvailable in desktop-main.ts. The core calls it where the Electron handlers did.
    fn assert_available(&self) -> cipher_vault_core::error::Result<()> {
        if self.quitting.load(Ordering::SeqCst) {
            return Err(VaultError::new(503, QUITTING));
        }
        let result = self.power.check(os_events::session_is_locked());
        // A lock found here had no notification, so nothing has locked the vault yet. Only the key
        // is destroyed here: a copy in progress calls this while holding the clipboard lease, so
        // clearing is left to that copy's failure path and to the watchdog.
        if result.is_err() && self.vault.is_unlocked() {
            self.vault.lock_for(LockReason::ScreenLock);
            trace("vault-locked screen-lock");
        }
        result.map_err(|message| VaultError::new(423, message))
    }

    /// The key and the copy expire here even if the page hangs, so expiry never depends on polling.
    /// Any lock, however it happened, clears this app's copy, as onVaultState does in Electron.
    fn watch(&self) {
        self.vault.expire();
        if self.vault.is_unlocked() {
            self.clipboard.tick();
        } else {
            self.clipboard.clear_owned();
        }
    }

    fn quit(&self) {
        self.quitting.store(true, Ordering::SeqCst);
        self.lock_and_clear(LockReason::WindowClosed);
        // The lock cancels a switch at its next check; it then reopens the vault before it returns.
        let deadline = Instant::now() + QUIT_WAIT;
        while self.vault.is_switching() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        trace("exit-complete");
    }
}

/// Reports events to the automated checks. Prints nothing in a normal build.
pub(crate) fn trace(_event: &str) {
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
async fn vault_lock(vault: State<'_, Shared>, desktop: State<'_, SharedDesktop>, session_id: Option<Value>) -> Result<Value, String> {
    let desktop = Arc::clone(&desktop);
    run(vault, move |vault| {
        trace("vault-locked manual");
        let status = vault.lock(session_id.as_ref())?;
        desktop.clipboard.clear_owned();
        Ok(status)
    })
    .await
}

/// clipboard:writeText. The text is wiped from this copy of the request once it is written.
#[tauri::command]
async fn clipboard_write(vault: State<'_, Shared>, desktop: State<'_, SharedDesktop>, session_id: Option<Value>, mut value: Option<Value>) -> Result<Value, String> {
    let desktop = Arc::clone(&desktop);
    run(vault, move |vault| {
        let result = vault.copy_text(session_id.as_ref(), value.as_ref(), |text, current| {
            desktop.clipboard.copy(text, || current().map_err(|error| error.message)).map_err(|message| VaultError::new(500, message))
        });
        if let Some(Value::String(text)) = &mut value {
            text.zeroize();
        }
        result
    })
    .await
}

/// Migration, rekey, reset to an empty v2 vault, and recovery of a switch that stopped.
#[tauri::command]
async fn vault_maintenance(vault: State<'_, Shared>, session_id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.run_maintenance(session_id.as_ref(), payload.as_ref())).await
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

#[tauri::command]
async fn backup_export(vault: State<'_, Shared>, session_id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.export_backup(session_id.as_ref(), payload.as_ref())).await
}

#[tauri::command]
async fn backup_restore(vault: State<'_, Shared>, session_id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.restore_backup(session_id.as_ref(), payload.as_ref())).await
}

#[tauri::command]
async fn vault_audit(vault: State<'_, Shared>, session_id: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.audit_vault(session_id.as_ref())).await
}

#[tauri::command]
fn update_state(updates: State<'_, Updates>) -> Value {
    updates.state()
}

#[tauri::command]
async fn update_check(app: AppHandle, updates: State<'_, Updates>, desktop: State<'_, SharedDesktop>) -> Result<(), String> {
    updates.check(&app, Arc::clone(&desktop)).await;
    Ok(())
}

#[tauri::command]
async fn update_download(updates: State<'_, Updates>) -> Result<(), String> {
    updates.download().await;
    Ok(())
}

#[tauri::command]
async fn update_install(app: AppHandle, updates: State<'_, Updates>, desktop: State<'_, SharedDesktop>, has_unsaved_changes: Option<Value>) -> Result<Option<bool>, String> {
    let desktop = Arc::clone(&desktop);
    updates.install(&app, &desktop, has_unsaved_changes).await
}

#[tauri::command]
fn update_open_releases() -> Result<(), String> {
    updates::open_release_page()
}

/// The bundled screen only. Tauri serves it as http://tauri.localhost on Windows.
pub(crate) fn is_application_url(url: &Url) -> bool {
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

/// The installer restarts the app after an update with this process's arguments but not its
/// environment, so the update check passes the e2e build's settings as arguments as well.
#[cfg(feature = "e2e")]
fn apply_e2e_arguments() {
    const NAMES: [&str; 5] = ["CIPHER_VAULT_DATA_DIR", "CIPHER_VAULT_E2E_DEBUG_PORT", "CIPHER_VAULT_E2E_PROFILE", "CIPHER_VAULT_E2E_DOWNLOADS", "CIPHER_VAULT_E2E_UPDATE_ANSWER"];
    for argument in std::env::args().skip(1) {
        if let Some((name, value)) = argument.strip_prefix("--e2e-env=").and_then(|setting| setting.split_once('='))
            && NAMES.contains(&name)
        {
            // SAFETY: no other thread exists yet.
            unsafe { std::env::set_var(name, value) };
        }
    }
}

/// The released build has no console, so the reason is shown in a dialog as well.
fn fail_startup(message: &str) -> ! {
    eprintln!("{message}");
    #[cfg(not(feature = "e2e"))]
    {
        let _ = rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title(data_directory::RELEASED_PRODUCT)
            .set_description(message)
            .set_buttons(rfd::MessageButtons::Ok)
            .show();
    }
    std::process::exit(2);
}

fn clipboard_port() -> Box<dyn clipboard::ClipboardPort> {
    #[cfg(feature = "e2e")]
    return Box::new(clipboard::fake::FakeClipboard::default());
    #[cfg(not(feature = "e2e"))]
    return Box::new(windows_clipboard::WindowsClipboard);
}

fn main() {
    #[cfg(feature = "e2e")]
    apply_e2e_arguments();
    #[cfg(not(feature = "e2e"))]
    {
        // SAFETY: no other thread exists yet.
        unsafe { webview_hardening::remove_webview2_overrides() };
        if webview_hardening::webview2_policy_override_exists() {
            fail_startup("A WebView2 policy overrides this application's browser settings, so it will not start.");
        }
    }

    let context = tauri::generate_context!();
    let product_name = context.config().product_name.clone().unwrap_or_else(|| data_directory::RELEASED_PRODUCT.to_string());
    let location = data_directory::resolve(&product_name).unwrap_or_else(|message| fail_startup(&message));
    if location.shared_with_electron && electron_guard::electron_is_running(&product_name) {
        trace("electron-running");
        fail_startup(&electron_guard::message(&product_name));
    }
    let directory = location.path;
    // Before the vault opens, so a second copy never touches it.
    let _instance = match single_instance::claim(&directory) {
        Ok(Some(instance)) => instance,
        Ok(None) => {
            trace("already-running");
            std::process::exit(0);
        }
        Err(message) => fail_startup(&message),
    };
    let vault: Shared = Arc::new(Vault::open(&directory).unwrap_or_else(|error| fail_startup(&error.message)));
    let desktop: SharedDesktop = Arc::new(Desktop { vault: Arc::clone(&vault), clipboard: ExpiringClipboard::new(clipboard_port()), power: PowerGuard::default(), quitting: AtomicBool::new(false) });
    // The vault keeps only a weak link back, so the two do not keep each other alive.
    let checker = Arc::downgrade(&desktop);
    vault.set_availability(Box::new(move || checker.upgrade().map_or(Ok(()), |desktop| desktop.assert_available())));

    let listener = Arc::clone(&desktop);
    match os_events::start(Box::new(move |event| listener.handle_os_event(event))) {
        Ok(window) => trace(&format!("os-window {window}")),
        // Running without these notifications would silently lose a protection.
        Err(message) => fail_startup(&message),
    }
    let watchdog = Arc::clone(&desktop);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(WATCHDOG_INTERVAL);
            watchdog.watch();
        }
    });

    let app = tauri::Builder::default()
        .manage(vault)
        .manage(Arc::clone(&desktop))
        // Its commands for the screen are granted to no window; see updates.rs.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_activity,
            vault_setup,
            vault_unlock,
            vault_lock,
            vault_reset,
            vault_maintenance,
            entries_list,
            entries_get,
            entries_create,
            entries_update,
            entries_delete,
            entries_set_group,
            password_generate,
            backup_export,
            backup_restore,
            vault_audit,
            clipboard_write,
            update_state,
            update_check,
            update_download,
            update_install,
            update_open_releases
        ])
        .setup(|app| {
            let supported = updates::supported(app.handle());
            trace(&format!("update-support {supported}"));
            app.manage(Updates::new(app.package_info().version.to_string(), supported));
            let builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title(single_instance::WINDOW_TITLE)
                .inner_size(880.0, 780.0)
                .min_inner_size(780.0, 680.0)
                // The screen draws the title bar: the menus with the window buttons, as the Electron app had.
                .decorations(false)
                .shadow(true)
                .initialization_script(include_str!("desktop-api.js"))
                .on_navigation(is_application_url)
                .on_new_window(|_url, _features| NewWindowResponse::Deny)
                .on_download(backup_download::handle)
                .disable_drag_drop_handler();
            #[cfg(feature = "e2e")]
            let builder = with_debugging_port(builder);
            let window = builder.build()?;
            let desktop = Arc::clone(app.state::<SharedDesktop>().inner());
            let closed = Arc::clone(&desktop);
            // The Electron app locks when its window closes; the process may outlive the window.
            window.on_window_event(move |event| {
                if matches!(event, WindowEvent::Destroyed) {
                    closed.lock_and_clear(LockReason::WindowClosed);
                }
            });
            window.with_webview(move |webview| {
                let gone = move || {
                    desktop.lock_and_clear(LockReason::RendererGone);
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
        .build(context)
        .unwrap_or_else(|_| fail_startup("The window failed to start."));

    app.run(move |_app, event| {
        if let RunEvent::Exit = event {
            desktop.quit();
        }
    });
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

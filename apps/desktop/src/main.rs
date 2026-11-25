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
mod external_url;
mod global_hotkey;
mod os_events;
mod single_instance;
mod updates;
#[cfg_attr(feature = "e2e", allow(dead_code))]
mod webview_hardening;
mod window_prefs;
// Left out of the e2e build, so that build cannot reach the real clipboard at all.
#[cfg(not(feature = "e2e"))]
mod windows_clipboard;

use cipher_vault_core::error::VaultError;
use cipher_vault_core::{LockReason, Vault};
use clipboard::ExpiringClipboard;
use global_hotkey::{Hotkey, HotkeyError, HotkeyListener};
use os_events::{OsEvent, PowerGuard};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tauri::webview::NewWindowResponse;
use tauri::{AppHandle, LogicalSize, Manager, PhysicalPosition, RunEvent, State, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent};
use updates::Updates;
use window_prefs::{CompactBounds, WindowPrefs};
use zeroize::Zeroize;

type Shared = Arc<Vault>;
type SharedDesktop = Arc<Desktop>;
type WindowSettings = Arc<Mutex<WindowPreferences>>;

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
async fn entry_icon_set(vault: State<'_, Shared>, session_id: Option<Value>, id: Option<Value>, icon: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.set_entry_icon(session_id.as_ref(), id.as_ref(), icon.as_ref())).await
}

/// The auto-lock time the user chose. The core keeps it beside the vault and applies it at once.
#[tauri::command]
async fn settings_auto_lock_set(vault: State<'_, Shared>, session_id: Option<Value>, payload: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.set_auto_lock(session_id.as_ref(), payload.as_ref())).await
}

struct WindowPreferences {
    directory: PathBuf,
    prefs: WindowPrefs,
    listener: Option<HotkeyListener>,
    registration_error: Option<&'static str>,
}

impl WindowPreferences {
    fn start(directory: PathBuf, app: &AppHandle) -> Self {
        let prefs = WindowPrefs::load(&directory);
        let app = app.clone();
        let listener = HotkeyListener::start(Box::new(move || queue_summon(&app))).ok();
        let registration_error = match (&listener, prefs.global_shortcut) {
            (Some(listener), Some(hotkey)) => listener.set(Some(hotkey)).err(),
            (None, _) => Some(HotkeyError::Failed),
            _ => None,
        }.map(|error| error.message());
        Self { directory, prefs, listener, registration_error }
    }

    fn shortcut_status(&self) -> Value {
        let shortcut = self.prefs.global_shortcut;
        let registered = self.listener.as_ref().zip(shortcut).is_some_and(|(listener, hotkey)| listener.registered(hotkey));
        let error = self.registration_error.or_else(|| (shortcut.is_some() && !registered).then(|| HotkeyError::Failed.message()));
        json!({
            "shortcut": shortcut.map(|hotkey| hotkey.to_string()),
            "summonCompact": self.prefs.summon_compact,
            "registered": registered,
            "error": error,
        })
    }

    fn set_shortcut(&mut self, shortcut: Option<Hotkey>, summon_compact: bool) -> Result<Value, String> {
        if let Some(listener) = &self.listener {
            listener.set(shortcut).map_err(|error| error.message())?;
            self.registration_error = None;
        } else if shortcut.is_some() {
            return Err(HotkeyError::Failed.message().into());
        }
        let previous = (self.prefs.global_shortcut, self.prefs.summon_compact);
        self.prefs.global_shortcut = shortcut;
        self.prefs.summon_compact = summon_compact;
        if let Err(error) = self.prefs.save(&self.directory) {
            // Not saved, so the key that was in use comes back; the status then reads what is registered.
            (self.prefs.global_shortcut, self.prefs.summon_compact) = previous;
            if let Some(Err(restore)) = self.listener.as_ref().map(|listener| listener.set(previous.0)) {
                self.registration_error = Some(restore.message());
            }
            return Err(error);
        }
        Ok(self.shortcut_status())
    }
}

#[tauri::command]
fn settings_global_shortcut_get(settings: State<'_, WindowSettings>) -> Result<Value, String> {
    let settings = settings.lock().map_err(|_| HotkeyError::Failed.message())?;
    Ok(settings.shortcut_status())
}

#[tauri::command]
async fn settings_global_shortcut_set(
    vault: State<'_, Shared>, settings: State<'_, WindowSettings>, session_id: Option<Value>, payload: Option<Value>,
) -> Result<Value, String> {
    let settings = Arc::clone(&settings);
    run(vault, move |vault| {
        let mut settings = settings.lock().map_err(|_| VaultError::new(500, window_prefs::SAVE_FAILED))?;
        vault.require_session(session_id.as_ref())?;
        let payload = payload.as_ref().ok_or_else(|| VaultError::bad_request("呼び出しキーの設定が正しくありません"))?;
        let shortcut = match payload.get("shortcut") {
            Some(Value::Null) => None,
            Some(Value::String(text)) => Some(Hotkey::parse(text).map_err(VaultError::bad_request)?),
            _ => return Err(VaultError::bad_request(global_hotkey::INVALID_SHORTCUT)),
        };
        let summon_compact = payload.get("summonCompact").and_then(Value::as_bool)
            .ok_or_else(|| VaultError::bad_request("呼び出しキーの設定が正しくありません"))?;
        settings.set_shortcut(shortcut, summon_compact).map_err(|message| VaultError::new(500, message))
    }).await
}

#[tauri::command]
async fn entry_favorite_set(vault: State<'_, Shared>, session_id: Option<Value>, id: Option<Value>, favorite: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.set_entry_favorite(session_id.as_ref(), id.as_ref(), favorite.as_ref())).await
}

/// Records that the user copied from or opened an entry, for the list of recently used entries.
#[tauri::command]
async fn entry_use_record(vault: State<'_, Shared>, session_id: Option<Value>, id: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| vault.record_entry_use(session_id.as_ref(), id.as_ref())).await
}

/// Opens the URL stored in an entry. The screen names only the entry, so it cannot have any other
/// address opened, and only web addresses are handed to the browser (external_url.rs).
#[tauri::command]
async fn entry_url_open(vault: State<'_, Shared>, session_id: Option<Value>, id: Option<Value>) -> Result<Value, String> {
    run(vault, move |vault| {
        vault.open_entry_url(session_id.as_ref(), id.as_ref(), |text, current| {
            let url = external_url::launchable(text).ok_or_else(|| VaultError::bad_request(external_url::REFUSED))?;
            current()?;
            external_url::open(&url).map_err(|message| VaultError::new(500, message))
        })
    })
    .await
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
async fn update_install(updates: State<'_, Updates>, desktop: State<'_, SharedDesktop>, has_unsaved_changes: Option<Value>) -> Result<Option<bool>, String> {
    let desktop = Arc::clone(&desktop);
    updates.install(&desktop, has_unsaved_changes).await
}

#[tauri::command]
fn update_open_releases() -> Result<(), String> {
    updates::open_release_page()
}

/// The compact layout's size in logical pixels: one column for finding an entry and copying from it.
/// The reasons are in docs/設計.md (コンパクト表示).
const COMPACT_WIDTH: f64 = 400.0;
const COMPACT_HEIGHT: (f64, f64) = (480.0, 720.0);
const COMPACT_MIN: (f64, f64) = (360.0, 400.0);
const COMPACT_MAX: (f64, f64) = (520.0, 4000.0);
const WINDOW_FAILED: &str = "ウィンドウの大きさを変えられませんでした";

/// The size the window had before the compact layout, to return to it. None while not compact.
#[derive(Default)]
struct WindowLayout {
    normal: Mutex<Option<NormalWindow>>,
}

#[derive(Clone, Copy)]
struct NormalWindow {
    width: f64,
    height: f64,
    maximized: bool,
}

/// The first compact size keeps the normal height within the original range.
fn compact_size(height: Option<f64>) -> (f64, f64) {
    (COMPACT_WIDTH, height.unwrap_or(640.0).clamp(COMPACT_HEIGHT.0, COMPACT_HEIGHT.1))
}

#[derive(Clone, Copy)]
struct WorkArea {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    scale: f64,
}

impl From<tauri::Monitor> for WorkArea {
    fn from(monitor: tauri::Monitor) -> Self {
        let area = monitor.work_area();
        Self { x: area.position.x, y: area.position.y, width: area.size.width, height: area.size.height, scale: monitor.scale_factor() }
    }
}

impl WorkArea {
    fn contains_center(self, bounds: CompactBounds, frame: (f64, f64)) -> bool {
        let x = f64::from(bounds.x) + (bounds.width + frame.0) * self.scale / 2.0 - f64::from(self.x);
        let y = f64::from(bounds.y) + (bounds.height + frame.1) * self.scale / 2.0 - f64::from(self.y);
        (0.0..f64::from(self.width)).contains(&x) && (0.0..f64::from(self.height)).contains(&y)
    }

    fn move_inside(self, mut bounds: CompactBounds, frame: (f64, f64)) -> CompactBounds {
        let dx = (f64::from(self.width) - ((bounds.width + frame.0) * self.scale).round()).max(0.0);
        let dy = (f64::from(self.height) - ((bounds.height + frame.1) * self.scale).round()).max(0.0);
        bounds.x = f64::from(bounds.x).clamp(f64::from(self.x), f64::from(self.x) + dx) as i32;
        bounds.y = f64::from(bounds.y).clamp(f64::from(self.y), f64::from(self.y) + dy) as i32;
        bounds
    }
}

/// A saved window returns to a connected monitor even after a DPI or work area change.
fn compact_placement(
    saved: Option<CompactBounds>, fallback: CompactBounds, frame: (f64, f64), monitors: &[WorkArea], current: Option<WorkArea>,
) -> CompactBounds {
    if let Some(mut bounds) = saved
        && let Some(area) = monitors.iter().find(|area| area.contains_center(bounds, frame))
    {
        let max_width = (f64::from(area.width) / area.scale - frame.0).clamp(COMPACT_MIN.0, COMPACT_MAX.0);
        let max_height = (f64::from(area.height) / area.scale - frame.1).clamp(COMPACT_MIN.1, COMPACT_MAX.1);
        bounds.width = bounds.width.clamp(COMPACT_MIN.0, max_width);
        bounds.height = bounds.height.clamp(COMPACT_MIN.1, max_height);
        return area.move_inside(bounds, frame);
    }
    current.map_or(fallback, |area| area.move_inside(fallback, frame))
}

fn current_compact_bounds(window: &WebviewWindow) -> Option<CompactBounds> {
    let position = window.outer_position().ok()?;
    let size = window.inner_size().ok()?.to_logical::<f64>(window.scale_factor().ok()?);
    (size.width > 0.0 && size.height > 0.0).then_some(CompactBounds {
        x: position.x, y: position.y, width: size.width, height: size.height,
    })
}

fn save_compact_bounds(settings: &WindowSettings, bounds: Option<CompactBounds>) {
    if let Some(bounds) = bounds
        && let Ok(mut settings) = settings.lock()
    {
        settings.prefs.compact_bounds = Some(bounds);
        let _ = settings.prefs.save(&settings.directory);
    }
}

/// Switches the window between the normal and the compact layout. The screen can choose only
/// between the two, never a size or a place of its own.
#[tauri::command]
fn window_set_compact(
    window: WebviewWindow, layout: State<'_, WindowLayout>, settings: State<'_, WindowSettings>, compact: Option<Value>,
) -> Result<(), String> {
    let compact = compact.as_ref().and_then(Value::as_bool).ok_or("表示の指定が正しくありません")?;
    let failed = |_| WINDOW_FAILED.to_string();
    let mut normal = layout.normal.lock().map_err(|_| WINDOW_FAILED)?;
    if compact {
        if normal.is_none() {
            let maximized = window.is_maximized().map_err(failed)?;
            let size = window.inner_size().map_err(failed)?.to_logical::<f64>(window.scale_factor().map_err(failed)?);
            // A maximized window has no size of its own to come back to, so it returns maximized.
            let (width, height) = if maximized { WINDOW_DEFAULT } else { (size.width, size.height) };
            let previous = NormalWindow { width, height, maximized };
            if maximized {
                window.unmaximize().map_err(failed)?;
            }
            let position = window.outer_position().map_err(failed)?;
            let (width, height) = compact_size((!maximized).then_some(size.height));
            let fallback = CompactBounds { x: position.x, y: position.y, width, height };
            let frame = window.outer_size().ok().zip(window.inner_size().ok()).zip(window.scale_factor().ok()).map_or((0.0, 0.0), |((outer, inner), scale)| {
                let extra_width = outer.width.saturating_sub(inner.width);
                let extra_height = outer.height.saturating_sub(inner.height);
                (f64::from(extra_width) / scale, f64::from(extra_height) / scale)
            });
            let saved = settings.lock().ok().and_then(|settings| settings.prefs.compact_bounds);
            let monitors = window.available_monitors().unwrap_or_default().into_iter().map(WorkArea::from).collect::<Vec<_>>();
            let current = window.current_monitor().ok().flatten().map(WorkArea::from);
            let bounds = compact_placement(saved, fallback, frame, &monitors, current);
            window.set_min_size(Some(LogicalSize::new(COMPACT_MIN.0, COMPACT_MIN.1))).map_err(failed)?;
            window.set_max_size(Some(LogicalSize::new(COMPACT_MAX.0, COMPACT_MAX.1))).map_err(failed)?;
            if (bounds.x, bounds.y) != (position.x, position.y) {
                window.set_position(PhysicalPosition::new(bounds.x, bounds.y)).map_err(failed)?;
            }
            window.set_size(LogicalSize::new(bounds.width, bounds.height)).map_err(failed)?;
            // A maximized narrow column would lose its point, so the compact window cannot be maximized.
            window.set_maximizable(false).map_err(failed)?;
            // Kept only once the window is compact, so a failed change can be asked for again.
            *normal = Some(previous);
        }
    } else if let Some(previous) = *normal {
        let bounds = current_compact_bounds(&window);
        window.set_max_size(None::<LogicalSize<f64>>).map_err(failed)?;
        window.set_maximizable(true).map_err(failed)?;
        if window.is_maximized().map_err(failed)? {
            window.unmaximize().map_err(failed)?;
        }
        // The size first, so the larger minimum never resizes the window on its own.
        window.set_size(LogicalSize::new(previous.width.max(WINDOW_MIN.0), previous.height.max(WINDOW_MIN.1))).map_err(failed)?;
        window.set_min_size(Some(LogicalSize::new(WINDOW_MIN.0, WINDOW_MIN.1))).map_err(failed)?;
        if previous.maximized {
            window.maximize().map_err(failed)?;
        }
        // Forgotten only once the window is back, so a failed change can be asked for again.
        *normal = None;
        save_compact_bounds(&settings, bounds);
    }
    Ok(())
}

fn summon(window: &WebviewWindow, compact: bool) {
    if matches!(window.is_visible(), Ok(true)) && matches!(window.is_minimized(), Ok(false)) && matches!(window.is_focused(), Ok(true)) {
        let _ = window.minimize();
        trace("summon-hidden");
    } else {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.eval(format!("window.dispatchEvent(new CustomEvent('cipher-vault-summon', {{ detail: {{ compact: {compact} }} }}))"));
        trace("summoned");
    }
}

fn queue_summon(app: &AppHandle) {
    let main = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(window) = main.get_webview_window("main") {
            let settings = main.state::<WindowSettings>();
            let compact = settings.lock().map_or(true, |settings| settings.prefs.summon_compact);
            summon(&window, compact);
        }
    });
}

/// Lets the shell check request a press without reserving a real key.
#[cfg(feature = "e2e")]
fn watch_summon_file(app: &AppHandle) {
    let marker = std::env::var_os("CIPHER_VAULT_E2E_SUMMON_FILE").map(PathBuf::from).filter(|path| path.is_absolute());
    if let Some(marker) = marker {
        let app = app.clone();
        std::thread::spawn(move || {
            while !app.state::<SharedDesktop>().quitting.load(Ordering::SeqCst) {
                if std::fs::remove_file(&marker).is_ok() {
                    queue_summon(&app);
                }
                std::thread::sleep(WATCHDOG_INTERVAL);
            }
        });
    }
}

/// Keeps the window above other windows, or stops doing so. It is not saved: each start is normal.
#[tauri::command]
fn window_set_always_on_top(window: WebviewWindow, on_top: Option<Value>) -> Result<(), String> {
    let on_top = on_top.as_ref().and_then(Value::as_bool).ok_or("表示の指定が正しくありません")?;
    window.set_always_on_top(on_top).map_err(|_| "最前面の表示を切り替えられませんでした".to_string())?;
    trace(&format!("always-on-top {}", window.is_always_on_top().unwrap_or(!on_top)));
    Ok(())
}

/// The window's size in logical pixels; the reasons are in docs/設計.md (ウィンドウの大きさ).
/// The minimum leaves the detail pane 440px beside the list at its default 280px.
const WINDOW_DEFAULT: (f64, f64) = (960.0, 680.0);
const WINDOW_MIN: (f64, f64) = (720.0, 560.0);

/// The first size: the default, made smaller to fit a work area (the screen less the taskbar) that
/// cannot hold it, but never under the minimum. There is no maximum, so maximizing and snapping fill the screen.
fn initial_window_size(work_area: Option<(f64, f64)>) -> (f64, f64) {
    let (width, height) = work_area.unwrap_or(WINDOW_DEFAULT);
    (WINDOW_DEFAULT.0.min(width).max(WINDOW_MIN.0), WINDOW_DEFAULT.1.min(height).max(WINDOW_MIN.1))
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
    const NAMES: [&str; 5] = ["CIPHER_VAULT_DATA_DIR", "CIPHER_VAULT_E2E_DEBUG_PORT", "CIPHER_VAULT_E2E_PROFILE", "CIPHER_VAULT_E2E_DOWNLOADS", "CIPHER_VAULT_E2E_SUMMON_FILE"];
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
        .manage(WindowLayout::default())
        // Its commands for the screen are granted to no window; see updates.rs.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_activity,
            vault_setup,
            vault_unlock,
            vault_lock,
            vault_maintenance,
            entries_list,
            entries_get,
            entries_create,
            entries_update,
            entries_delete,
            entries_set_group,
            entry_icon_set,
            entry_favorite_set,
            entry_use_record,
            entry_url_open,
            settings_auto_lock_set,
            settings_global_shortcut_get,
            settings_global_shortcut_set,
            password_generate,
            backup_export,
            backup_restore,
            vault_audit,
            clipboard_write,
            update_state,
            update_check,
            update_download,
            update_install,
            update_open_releases,
            window_set_compact,
            window_set_always_on_top
        ])
        .setup(move |app| {
            let supported = updates::supported(app.handle());
            trace(&format!("update-support {supported}"));
            app.manage(Updates::new(app.package_info().version.to_string(), supported));
            let work_area = app.primary_monitor().ok().flatten().map(|monitor| {
                let area = monitor.work_area().size.to_logical::<f64>(monitor.scale_factor());
                (area.width, area.height)
            });
            let (width, height) = initial_window_size(work_area);
            let builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title(single_instance::WINDOW_TITLE)
                .inner_size(width, height)
                .min_inner_size(WINDOW_MIN.0, WINDOW_MIN.1)
                .center()
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
            app.manage(Arc::new(Mutex::new(WindowPreferences::start(directory, app.handle()))));
            #[cfg(feature = "e2e")]
            watch_summon_file(app.handle());
            let desktop = Arc::clone(app.state::<SharedDesktop>().inner());
            let closed = Arc::clone(&desktop);
            let closing = window.clone();
            // The Electron app locks when its window closes; the process may outlive the window.
            window.on_window_event(move |event| {
                match event {
                    WindowEvent::CloseRequested { .. } if closing.state::<WindowLayout>().normal.lock().is_ok_and(|normal| normal.is_some()) => {
                        save_compact_bounds(&closing.state::<WindowSettings>(), current_compact_bounds(&closing));
                    }
                    WindowEvent::Destroyed => closed.lock_and_clear(LockReason::WindowClosed),
                    _ => {}
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

    app.run(move |app, event| {
        if let RunEvent::Exit = event {
            let listener = app.state::<WindowSettings>().lock().ok().and_then(|mut settings| settings.listener.take());
            drop(listener);
            desktop.quit();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_window_fits_the_work_area_down_to_the_minimum() {
        assert_eq!(initial_window_size(None), (960.0, 680.0));
        assert_eq!(initial_window_size(Some((1920.0, 1032.0))), (960.0, 680.0));
        // 1366x768 at 100% and at 125%, and 1920x1080 at 150%, each less the 48px taskbar.
        assert_eq!(initial_window_size(Some((1366.0, 720.0))), (960.0, 680.0));
        assert_eq!(initial_window_size(Some((1092.8, 566.4))), (960.0, 566.4));
        assert_eq!(initial_window_size(Some((1280.0, 672.0))), (960.0, 672.0));
        assert_eq!(initial_window_size(Some((640.0, 400.0))), (720.0, 560.0));
    }

    #[test]
    fn the_compact_window_keeps_its_height_within_range() {
        assert_eq!(compact_size(None), (400.0, 640.0));
        assert_eq!(compact_size(Some(680.0)), (400.0, 680.0));
        assert_eq!(compact_size(Some(1032.0)), (400.0, 720.0));
        assert_eq!(compact_size(Some(300.0)), (400.0, 480.0));
        assert!(COMPACT_MIN.0 <= COMPACT_WIDTH && COMPACT_MIN.1 <= COMPACT_HEIGHT.0);
    }

    #[test]
    fn a_disconnected_compact_monitor_uses_the_current_work_area() {
        let primary = WorkArea { x: 0, y: 40, width: 1280, height: 860, scale: 1.0 };
        let fallback = CompactBounds { x: 1100, y: -20, width: 400.0, height: 640.0 };
        let saved = CompactBounds { x: -1400, y: 100, ..fallback };
        let expected = CompactBounds { x: 870, y: 40, ..fallback };
        assert_eq!(compact_placement(Some(saved), fallback, (10.0, 10.0), &[primary], Some(primary)), expected);
        assert_eq!(compact_placement(None, fallback, (10.0, 10.0), &[primary], None), fallback);
    }

    #[test]
    fn compact_bounds_restore_on_a_scaled_monitor_with_negative_coordinates() {
        let primary = WorkArea { x: 0, y: 0, width: 1920, height: 1040, scale: 1.0 };
        let secondary = WorkArea { x: -1500, y: -200, width: 1500, height: 1050, scale: 1.5 };
        let monitors = [primary, secondary];
        let fallback = CompactBounds { x: 70, y: 80, width: 400.0, height: 640.0 };
        let saved = CompactBounds { x: -1200, y: -170, width: 590.0, height: 900.0 };
        let expected = CompactBounds { x: -1200, y: -200, width: 520.0, height: 690.0 };
        assert_eq!(compact_placement(Some(saved), fallback, (10.0, 10.0), &monitors, Some(primary)), expected);
        let small = CompactBounds { width: 50.0, height: 40.0, ..saved };
        let minimum = CompactBounds { width: 360.0, height: 400.0, ..small };
        assert_eq!(compact_placement(Some(small), fallback, (0.0, 0.0), &monitors, Some(primary)), minimum);
        let fitting = CompactBounds { width: 430.0, height: 610.0, ..saved };
        assert_eq!(compact_placement(Some(fitting), fallback, (0.0, 0.0), &monitors, Some(primary)), fitting);
        let off_secondary = CompactBounds { x: -250, width: 400.0, ..fitting };
        assert_eq!(compact_placement(Some(off_secondary), fallback, (0.0, 0.0), &monitors, Some(primary)), fallback);
    }

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

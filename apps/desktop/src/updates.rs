//! Manual updates, as `apps/electron/src/manual-updater.ts` and `update-service.ts` do them. The
//! user checks, downloads and installs; nothing runs at start or on exit. The vault locks before
//! the installer starts.
//!
//! Only the setup build updates itself, and only with a public key to check the download against.
//! The portable exe and builds without a key point to the releases page instead. The updater's own
//! commands for the screen are registered by the plugin but granted to no window, so the screen
//! reaches the updater only through the commands here.

use crate::SharedDesktop;
use cipher_vault_core::LockReason;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use tauri::utils::config::BundleType;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_updater::{Update, UpdaterExt};

pub const RELEASE_PAGE: &str = "https://github.com/Termnix-IT/CIPHER-VAULT/releases/latest";
const FAILED: &str = "更新処理に失敗しました。通信環境と公開済みの更新ファイルを確認して、再試行してください。";
const INVALID_REQUEST: &str = "Invalid update request";
/// The screen shows at most this many UTF-16 units of the notes, as the Electron app does.
const NOTES_LIMIT: usize = 20000;
const DISCARD: &str = "破棄して更新";
const BACK_TO_EDITING: &str = "編集に戻る";

#[derive(Clone, Default)]
struct State {
    status: &'static str,
    latest_version: Option<String>,
    release_notes: Option<String>,
    progress: Option<f64>,
    message: Option<&'static str>,
}

pub struct Updates {
    current_version: String,
    state: Mutex<State>,
    busy: AtomicBool,
    found: Mutex<Option<Update>>,
    package: Mutex<Option<Vec<u8>>>,
}

/// Clears the busy flag however the step ends.
struct Busy<'a>(&'a AtomicBool);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Whether this copy may update itself: the setup build, with a key to check downloads against.
pub fn supported<R: Runtime>(app: &AppHandle<R>) -> bool {
    let has_key = app.config().plugins.0.get("updater").and_then(|updater| updater.get("pubkey")).and_then(Value::as_str).is_some_and(|key| !key.trim().is_empty());
    has_key && tauri::utils::platform::bundle_type() == Some(BundleType::Nsis)
}

/// JavaScript's `slice(0, limit)` counts UTF-16 units. A pair is never split here.
fn truncate_notes(notes: &str) -> String {
    let mut units = 0;
    let end = notes
        .char_indices()
        .find(|(_, character)| {
            units += character.len_utf16();
            units > NOTES_LIMIT
        })
        .map_or(notes.len(), |(index, _)| index);
    notes[..end].to_string()
}

impl Updates {
    pub fn new(current_version: String, supported: bool) -> Self {
        let state = State { status: if supported { "idle" } else { "unsupported" }, ..State::default() };
        Self { current_version, state: Mutex::new(state), busy: AtomicBool::new(false), found: Mutex::new(None), package: Mutex::new(None) }
    }

    /// AppUpdateState in packages/shared/src/types.ts. Absent fields are left out, as in Electron.
    pub fn state(&self) -> Value {
        let state = locked(&self.state).clone();
        let mut value = json!({ "status": state.status, "currentVersion": self.current_version });
        let fields = [
            ("latestVersion", state.latest_version.map(Value::from)),
            ("releaseNotes", state.release_notes.map(Value::from)),
            ("progress", state.progress.map(Value::from)),
            ("message", state.message.map(Value::from)),
        ];
        for (name, field) in fields {
            if let Some(field) = field {
                value[name] = field;
            }
        }
        value
    }

    /// Every change clears the message unless it sets one, as ManualUpdater.set does.
    fn set(&self, change: impl FnOnce(&mut State)) {
        let mut state = locked(&self.state);
        state.message = None;
        change(&mut state);
    }

    /// The screen gets only the fixed message. The e2e build also reports the cause.
    fn fail(&self, cause: &str) {
        #[cfg(feature = "e2e")]
        crate::trace(&format!("update-failed {cause}"));
        #[cfg(not(feature = "e2e"))]
        let _ = cause;
        self.set(|state| {
            state.status = "error";
            state.message = Some(FAILED);
        });
    }

    /// None while another step runs or when the current status does not allow this one.
    fn begin(&self, allowed: &[&str]) -> Option<Busy<'_>> {
        let state = locked(&self.state);
        if !allowed.contains(&state.status) || self.busy.swap(true, Ordering::SeqCst) {
            return None;
        }
        Some(Busy(&self.busy))
    }

    pub async fn check<R: Runtime>(&self, app: &AppHandle<R>, desktop: SharedDesktop) {
        let Some(_busy) = self.begin(&["idle", "current", "available", "error"]) else {
            return;
        };
        self.set(|state| {
            *state = State { status: "checking", ..State::default() };
        });
        locked(&self.found).take();
        locked(&self.package).take();
        let handle = app.clone();
        // The installer exits the process directly, so the app's own exit steps run here first.
        let updater = app
            .updater_builder()
            .on_before_exit(move || {
                desktop.quit();
                handle.cleanup_before_exit();
            })
            .build();
        let updater = match updater {
            Ok(updater) => updater,
            Err(error) => return self.fail(&error.to_string()),
        };
        match updater.check().await {
            Ok(Some(update)) => {
                let (version, notes) = (update.version.clone(), update.body.as_deref().map(truncate_notes));
                *locked(&self.found) = Some(update);
                self.set(|state| {
                    state.status = "available";
                    state.latest_version = Some(version);
                    state.release_notes = notes;
                });
            }
            Ok(None) => self.set(|state| state.status = "current"),
            Err(error) => self.fail(&error.to_string()),
        }
    }

    pub async fn download(&self) {
        let Some(_busy) = self.begin(&["available"]) else {
            return;
        };
        let Some(update) = locked(&self.found).clone() else {
            return self.fail("no update was found");
        };
        self.set(|state| {
            state.status = "downloading";
            state.progress = Some(0.0);
        });
        let mut received = 0u64;
        let progress = |chunk: usize, total: Option<u64>| {
            received += chunk as u64;
            if let Some(total) = total.filter(|total| *total > 0) {
                let percent = (received as f64 * 100.0 / total as f64).clamp(0.0, 100.0);
                self.set(|state| state.progress = Some(percent));
            }
        };
        // The plugin checks the signature before it returns the bytes.
        match update.download(progress, || ()).await {
            Ok(bytes) => {
                *locked(&self.package) = Some(bytes);
                self.set(|state| {
                    state.status = "downloaded";
                    state.progress = Some(100.0);
                });
            }
            Err(error) => self.fail(&error.to_string()),
        }
    }

    /// Some(false) when the user went back to editing; None when the step does not apply.
    pub async fn install<R: Runtime>(&self, app: &AppHandle<R>, desktop: &SharedDesktop, has_unsaved_changes: Option<Value>) -> Result<Option<bool>, String> {
        let Some(Value::Bool(has_unsaved_changes)) = has_unsaved_changes else {
            return Err(INVALID_REQUEST.to_string());
        };
        let Some(_busy) = self.begin(&["downloaded"]) else {
            return Ok(None);
        };
        let Some(window) = app.get_webview_window("main") else {
            return Ok(Some(false));
        };
        if has_unsaved_changes && !confirm_discard(window).await {
            return Ok(Some(false));
        }
        desktop.lock_and_clear(LockReason::Update);
        let (update, package) = (locked(&self.found).clone(), locked(&self.package).take());
        let (Some(update), Some(package)) = (update, package) else {
            self.fail("nothing was downloaded");
            return Ok(None);
        };
        self.set(|state| state.status = "installing");
        // On success this starts the installer and exits; the installer restarts the app.
        let failure = match tauri::async_runtime::spawn_blocking(move || update.install(package)).await {
            Ok(Ok(())) => return Ok(None),
            Ok(Err(error)) => error.to_string(),
            Err(error) => error.to_string(),
        };
        self.fail(&failure);
        // The exit steps run just before the installer starts, so a failure to start it leaves an
        // app that refuses every vault operation. Tauri must not be used after its cleanup either,
        // so the app ends here; the vault is already locked.
        if desktop.quitting.load(Ordering::SeqCst) {
            std::process::exit(1);
        }
        Ok(None)
    }
}

/// The question the Electron app asks, with going back to editing as the default and on Esc.
#[cfg(not(feature = "e2e"))]
async fn confirm_discard<R: Runtime>(window: tauri::WebviewWindow<R>) -> bool {
    let (sender, receiver) = std::sync::mpsc::channel();
    let owner = window.clone();
    // The dialog belongs to the window's thread, so it stays modal to the window.
    let asked = window.run_on_main_thread(move || {
        let answer = rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Warning)
            .set_title("未保存の編集があります")
            .set_description("編集内容を破棄して更新しますか？\n\n保存する場合は「編集に戻る」を選び、保存後にもう一度更新してください。")
            .set_buttons(rfd::MessageButtons::OkCancelCustom(BACK_TO_EDITING.to_string(), DISCARD.to_string()))
            .set_parent(&owner)
            .show();
        let _ = sender.send(answer == rfd::MessageDialogResult::Custom(DISCARD.to_string()));
    });
    if asked.is_err() {
        return false;
    }
    tauri::async_runtime::spawn_blocking(move || receiver.recv().unwrap_or(false)).await.unwrap_or(false)
}

/// The automated checks cannot answer a dialog, so they say beforehand which button is chosen.
#[cfg(feature = "e2e")]
async fn confirm_discard<R: Runtime>(_window: tauri::WebviewWindow<R>) -> bool {
    crate::trace("update-dialog");
    let _ = (BACK_TO_EDITING, DISCARD);
    std::env::var("CIPHER_VAULT_E2E_UPDATE_ANSWER").is_ok_and(|answer| answer == "discard")
}

/// shell.openExternal in Electron: the default browser opens the fixed releases page.
#[cfg(not(feature = "e2e"))]
pub fn open_release_page() -> Result<(), String> {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{HSTRING, w};
    let result = unsafe { ShellExecuteW(None, w!("open"), &HSTRING::from(RELEASE_PAGE), None, None, SW_SHOWNORMAL) };
    // ShellExecuteW reports success with a value above 32.
    if result.0 as isize > 32 { Ok(()) } else { Err("ダウンロードページを開けませんでした".to_string()) }
}

/// The automated checks never open a browser.
#[cfg(feature = "e2e")]
pub fn open_release_page() -> Result<(), String> {
    crate::trace(&format!("release-page {RELEASE_PAGE}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_are_cut_where_the_electron_app_cuts_them() {
        assert_eq!(truncate_notes("短い"), "短い");
        let long = "あ".repeat(NOTES_LIMIT + 5);
        assert_eq!(truncate_notes(&long).chars().count(), NOTES_LIMIT);
        // A character outside the BMP counts twice and is never split.
        let pairs = format!("{}{}", "a".repeat(NOTES_LIMIT - 1), "😀");
        assert_eq!(truncate_notes(&pairs), "a".repeat(NOTES_LIMIT - 1));
    }

    #[test]
    fn the_state_has_only_the_fields_that_are_set() {
        let updates = Updates::new("1.2.3".to_string(), false);
        assert_eq!(updates.state(), json!({ "status": "unsupported", "currentVersion": "1.2.3" }));
        let updates = Updates::new("1.2.3".to_string(), true);
        updates.fail("synthetic");
        assert_eq!(updates.state(), json!({ "status": "error", "currentVersion": "1.2.3", "message": FAILED }));
        updates.set(|state| state.status = "checking");
        assert_eq!(updates.state(), json!({ "status": "checking", "currentVersion": "1.2.3" }), "a change clears the message");
    }

    #[test]
    fn each_step_starts_only_from_the_states_the_electron_app_allows() {
        let unsupported = Updates::new("1.0.0".to_string(), false);
        assert!(unsupported.begin(&["idle", "current", "available", "error"]).is_none());
        let updates = Updates::new("1.0.0".to_string(), true);
        let first = updates.begin(&["idle"]);
        assert!(first.is_some());
        assert!(updates.begin(&["idle"]).is_none(), "one step at a time");
        drop(first);
        assert!(updates.begin(&["idle"]).is_some());
        assert!(updates.begin(&["downloaded"]).is_none());
    }
}

//! Closes the routes that let another program reconfigure WebView2, and matches the Electron
//! policy of denying every renderer permission. This raises the bar only: a program running as
//! the same user can still attack the process in other ways.

use tauri::webview::PlatformWebview;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    COREWEBVIEW2_PERMISSION_STATE_DENY, ICoreWebView2Settings3, ICoreWebView2Settings4,
};
use webview2_com::{PermissionRequestedEventHandler, ProcessFailedEventHandler};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_ANY, RegGetValueW};
use windows::core::{BOOL, HSTRING, Interface, PCWSTR};

const POLICY_ROOT: &str = r"Software\Policies\Microsoft\Edge\WebView2";
const CONTROLLED_POLICIES: [&str; 4] = ["AdditionalBrowserArguments", "BrowserExecutableFolder", "ReleaseChannelPreference", "UserDataFolder"];
const CONTROLLED_VARIABLES: [&str; 6] = [
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
    "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
    "WEBVIEW2_USER_DATA_FOLDER",
    "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
    "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
];

/// Must run before any other thread starts, because it changes the process environment.
pub unsafe fn remove_webview2_overrides() {
    for name in CONTROLLED_VARIABLES {
        unsafe { std::env::remove_var(name) };
    }
}

fn value_exists(hive: HKEY, key: &str, value: &str) -> bool {
    let (key, value) = (HSTRING::from(key), HSTRING::from(value));
    let status = unsafe { RegGetValueW(hive, PCWSTR(key.as_ptr()), PCWSTR(value.as_ptr()), RRF_RT_ANY, None, None, None) };
    status == ERROR_SUCCESS
}

fn override_exists_under(hive: HKEY, root: &str, executable: &str) -> bool {
    CONTROLLED_POLICIES.iter().any(|policy| {
        let key = format!(r"{root}\{policy}");
        value_exists(hive, &key, executable) || value_exists(hive, &key, "*")
    })
}

/// A policy cannot be removed from here, so the app refuses to start under one.
pub fn webview2_policy_override_exists() -> bool {
    let executable = std::env::current_exe().ok().and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned())).unwrap_or_default();
    [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE].into_iter().any(|hive| override_exists_under(hive, POLICY_ROOT, &executable))
}

/// Applies the settings and returns them as read back from WebView2, so a check can confirm them.
pub fn apply_settings(webview: &PlatformWebview, on_process_failed: impl Fn() + 'static) -> windows::core::Result<String> {
    unsafe {
        let core = webview.controller().CoreWebView2()?;
        let settings = core.Settings()?;
        settings.SetAreDefaultContextMenusEnabled(false)?;
        settings.SetIsStatusBarEnabled(false)?;
        settings.SetAreHostObjectsAllowed(false)?;
        let settings3: ICoreWebView2Settings3 = settings.cast()?;
        settings3.SetAreBrowserAcceleratorKeysEnabled(false)?;
        let settings4: ICoreWebView2Settings4 = settings.cast()?;
        settings4.SetIsGeneralAutofillEnabled(false)?;
        settings4.SetIsPasswordAutosaveEnabled(false)?;
        // The E2E build reaches the page through the debugging protocol.
        #[cfg(not(feature = "e2e"))]
        settings.SetAreDevToolsEnabled(false)?;

        let mut token = 0;
        let deny_permissions = PermissionRequestedEventHandler::create(Box::new(|_, arguments| {
            if let Some(arguments) = arguments {
                arguments.SetState(COREWEBVIEW2_PERMISSION_STATE_DENY)?;
            }
            Ok(())
        }));
        core.add_PermissionRequested(&deny_permissions, &mut token)?;
        let process_failed = ProcessFailedEventHandler::create(Box::new(move |_, _| {
            on_process_failed();
            Ok(())
        }));
        core.add_ProcessFailed(&process_failed, &mut token)?;

        let (mut autofill, mut autosave, mut accelerators) = (BOOL(1), BOOL(1), BOOL(1));
        settings4.IsGeneralAutofillEnabled(&mut autofill)?;
        settings4.IsPasswordAutosaveEnabled(&mut autosave)?;
        settings3.AreBrowserAcceleratorKeysEnabled(&mut accelerators)?;
        Ok(format!("autofill={} autosave={} accelerators={}", autofill.as_bool(), autosave.as_bool(), accelerators.as_bool()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW};

    struct TemporaryPolicy(String);

    impl TemporaryPolicy {
        fn new() -> Self {
            Self(format!(r"Software\CipherVaultPocTest-{}", Uuid::new_v4()))
        }

        fn set(&self, policy: &str, value_name: &str) {
            let (key, name) = (HSTRING::from(format!(r"{}\{policy}", self.0)), HSTRING::from(value_name));
            let data: Vec<u8> = "--synthetic\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
            unsafe {
                let mut handle = HKEY::default();
                assert_eq!(RegCreateKeyExW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr()), None, None, REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut handle, None), ERROR_SUCCESS);
                assert_eq!(RegSetValueExW(handle, PCWSTR(name.as_ptr()), None, REG_SZ, Some(&data)), ERROR_SUCCESS);
                let _ = RegCloseKey(handle);
            }
        }
    }

    impl Drop for TemporaryPolicy {
        fn drop(&mut self) {
            assert!(self.0.starts_with(r"Software\CipherVaultPocTest-"));
            let key = HSTRING::from(self.0.as_str());
            let _ = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr())) };
        }
    }

    #[test]
    fn a_policy_for_this_executable_or_for_every_executable_is_detected() {
        let absent = TemporaryPolicy::new();
        assert!(!override_exists_under(HKEY_CURRENT_USER, &absent.0, "app.exe"));

        let named = TemporaryPolicy::new();
        named.set("AdditionalBrowserArguments", "app.exe");
        assert!(override_exists_under(HKEY_CURRENT_USER, &named.0, "app.exe"));
        assert!(!override_exists_under(HKEY_CURRENT_USER, &named.0, "other.exe"));

        let everyone = TemporaryPolicy::new();
        everyone.set("BrowserExecutableFolder", "*");
        assert!(override_exists_under(HKEY_CURRENT_USER, &everyone.0, "app.exe"));
    }
}

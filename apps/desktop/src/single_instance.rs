//! One app per data folder. A second launch brings the first window forward and exits before it
//! opens the vault, so two processes never hold the same vault's keys or switch it at once.
//!
//! A named mutex marks the running app. Nothing is sent between the two processes: the second one
//! only looks for the first one's window, so this adds no way for other programs to reach the app.
//! The name is derived from the folder, so separate test folders do not block each other.

use sha2::{Digest, Sha256};
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND, LPARAM};
use windows::Win32::System::Threading::{CreateMutexW, GetCurrentProcessId, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindowVisible, SW_RESTORE, SetForegroundWindow, ShowWindow};
use windows::core::{BOOL, HSTRING, PWSTR};

pub const WINDOW_TITLE: &str = "CIPHER VAULT";

/// Keep it for the life of the app. Windows also releases the name when the process exits.
pub struct Instance(HANDLE);

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// "Local\" keeps the name inside the signed-in Windows session, as each user has their own vault.
pub fn mutex_name(directory: &Path) -> String {
    // Windows paths ignore case, and the canonical form removes "..", short names and links.
    let canonical = std::fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
    let digest = Sha256::digest(canonical.to_string_lossy().to_lowercase().as_bytes());
    let hex: String = digest[..16].iter().map(|byte| format!("{byte:02x}")).collect();
    format!("Local\\CipherVault-{hex}")
}

/// None when the app already runs on this folder; its window has then been brought forward.
pub fn claim(directory: &Path) -> Result<Option<Instance>, String> {
    let name = HSTRING::from(mutex_name(directory));
    let handle = unsafe { CreateMutexW(None, false, &name) }.map_err(|_| "The check for another running copy failed.".to_string())?;
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        let _ = unsafe { CloseHandle(handle) };
        bring_forward_running_window();
        return Ok(None);
    }
    Ok(Some(Instance(handle)))
}

struct Search {
    program: String,
    process: u32,
    found: Option<HWND>,
}

fn program_path(process: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process).ok()?;
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut size);
        let _ = CloseHandle(handle);
        result.ok()?;
        Some(String::from_utf16_lossy(&buffer[..size as usize]).to_lowercase())
    }
}

unsafe extern "system" fn visit(window: HWND, search: LPARAM) -> BOOL {
    let search = unsafe { &mut *(search.0 as *mut Search) };
    let mut title = [0u16; 64];
    let length = unsafe { GetWindowTextW(window, &mut title) }.max(0) as usize;
    if !unsafe { IsWindowVisible(window) }.as_bool() || String::from_utf16_lossy(&title[..length]) != WINDOW_TITLE {
        return true.into();
    }
    let mut process = 0;
    unsafe { GetWindowThreadProcessId(window, Some(&mut process)) };
    // Only this program's window: the Electron app uses the same title.
    if process != search.process && program_path(process).is_some_and(|path| path == search.program) {
        search.found = Some(window);
        return false.into();
    }
    true.into()
}

/// Best effort: the first copy may not have shown its window yet.
fn bring_forward_running_window() {
    let Ok(program) = std::env::current_exe() else {
        return;
    };
    let mut search = Search { program: program.to_string_lossy().to_lowercase(), process: unsafe { GetCurrentProcessId() }, found: None };
    // The enumeration reports an error when the callback stops it, which is the success case here.
    let _ = unsafe { EnumWindows(Some(visit), LPARAM(&mut search as *mut Search as isize)) };
    if let Some(window) = search.found {
        unsafe {
            if IsIconic(window).as_bool() {
                let _ = ShowWindow(window, SW_RESTORE);
            }
            // Windows lets a program the user just started hand the foreground to another one.
            let _ = SetForegroundWindow(window);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("cipher-vault-instance-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn the_same_folder_is_claimed_once_however_it_is_written() {
        let path = folder();
        let first = claim(&path).unwrap();
        assert!(first.is_some());
        let spelled_differently = std::path::PathBuf::from(path.to_string_lossy().to_uppercase()).join(".");
        assert!(claim(&spelled_differently).unwrap().is_none(), "another spelling of the same folder");
        let other = folder();
        assert!(claim(&other).unwrap().is_some(), "another folder is independent");
        drop(first);
        let _ = std::fs::remove_dir(&path);
        let _ = std::fs::remove_dir(&other);
    }

    #[test]
    fn the_name_stays_inside_the_session_and_does_not_show_the_path() {
        let name = mutex_name(Path::new(r"C:\synthetic\folder"));
        assert!(name.starts_with("Local\\CipherVault-"));
        assert_eq!(name.len(), "Local\\CipherVault-".len() + 32);
        assert!(!name.to_lowercase().contains("synthetic"));
    }
}

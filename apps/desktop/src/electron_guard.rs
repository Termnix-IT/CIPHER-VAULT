//! The Electron app opens the same vault folder and has no check against a second app, so this
//! app looks for it before it opens the folder. The Electron program is named after the product
//! (`CIPHER VAULT.exe`), for the setup and for the portable build, which runs a copy from %TEMP%.
//! The Electron app cannot see this one, so starting it while this app runs is not prevented.

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};

pub fn program_name(product_name: &str) -> String {
    format!("{product_name}.exe")
}

pub fn message(product_name: &str) -> String {
    format!("Electron版の{product_name}が起動しています。同じ保管庫を同時に開かないよう、Electron版を終了してから起動してください。")
}

/// Whether a process with the Electron program's name runs in any session this user can see.
pub fn electron_is_running(product_name: &str) -> bool {
    let wanted = program_name(product_name).to_lowercase();
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return false;
    };
    let mut entry = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    let mut found = false;
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while more {
        let length = entry.szExeFile.iter().position(|unit| *unit == 0).unwrap_or(entry.szExeFile.len());
        if String::from_utf16_lossy(&entry.szExeFile[..length]).to_lowercase() == wanted {
            found = true;
            break;
        }
        more = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }
    let _ = unsafe { CloseHandle(snapshot) };
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_program_is_found_by_its_name_only() {
        // The test runner itself is a process whose name is known.
        let exe = std::env::current_exe().unwrap();
        let product = exe.file_stem().unwrap().to_string_lossy().to_uppercase();
        assert!(electron_is_running(&product), "case is ignored, as Windows does");
        assert!(!electron_is_running("CIPHER VAULT Guard Test No Such Program"));
    }

    #[test]
    fn the_message_names_the_product() {
        assert!(message("CIPHER VAULT").contains("Electron版のCIPHER VAULTが起動しています"));
    }
}

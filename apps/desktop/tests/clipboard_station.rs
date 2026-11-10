//! Exercises the real Win32 clipboard calls inside a separate window station. A clipboard belongs
//! to its window station, so this never touches the clipboard of the person running the test.
//! Only one test here uses the clipboard, because the station is switched for the whole process.
#![allow(dead_code)]

#[path = "../src/clipboard.rs"]
mod clipboard;
#[path = "../src/windows_clipboard.rs"]
mod windows_clipboard;

pub fn trace(_event: &str) {}

use clipboard::{ClipboardPort, ExpiringClipboard, visible_text_digest};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber, IsClipboardFormatAvailable, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW, DESKTOP_CONTROL_FLAGS, GetProcessWindowStation, GetThreadDesktop, HDESK, SetProcessWindowStation,
    SetThreadDesktop,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{CreateWindowExW, DestroyWindow, HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE};
use windows::core::{PCWSTR, w};

const GENERIC_ALL: u32 = 0x1000_0000;
const CF_TEXT_FORMAT: u32 = CF_UNICODETEXT.0 as u32;

fn with_clipboard<T>(action: impl FnOnce() -> T) -> T {
    unsafe {
        let window = CreateWindowExW(WINDOW_EX_STYLE(0), w!("STATIC"), PCWSTR::null(), WINDOW_STYLE(0), 0, 0, 0, 0, Some(HWND_MESSAGE), None, None, None).unwrap();
        OpenClipboard(Some(window)).unwrap();
        let result = action();
        CloseClipboard().unwrap();
        DestroyWindow(window).unwrap();
        result
    }
}

fn clipboard_text() -> Option<String> {
    with_clipboard(|| unsafe {
        if IsClipboardFormatAvailable(CF_TEXT_FORMAT).is_err() {
            return None;
        }
        let handle = GetClipboardData(CF_TEXT_FORMAT).ok()?;
        let memory = windows::Win32::Foundation::HGLOBAL(handle.0);
        let pointer = GlobalLock(memory).cast::<u16>();
        let mut units = Vec::new();
        while *pointer.add(units.len()) != 0 {
            units.push(*pointer.add(units.len()));
        }
        let _ = GlobalUnlock(memory);
        Some(String::from_utf16(&units).unwrap())
    })
}

fn raw_set(format: u32, bytes: &[u8]) {
    unsafe {
        let memory = GlobalAlloc(GMEM_MOVEABLE, bytes.len()).unwrap();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), GlobalLock(memory).cast::<u8>(), bytes.len());
        let _ = GlobalUnlock(memory);
        SetClipboardData(format, Some(HANDLE(memory.0))).unwrap();
    }
}

fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

/// Simulates another application replacing the clipboard, optionally keeping the marker.
fn another_application_copies(text: &str, owner_marker: Option<&str>, rich: bool) {
    with_clipboard(|| unsafe {
        EmptyClipboard().unwrap();
        raw_set(CF_TEXT_FORMAT, &wide(text));
        if let Some(marker) = owner_marker {
            raw_set(RegisterClipboardFormatW(w!("CipherVaultOwner")), marker.as_bytes());
        }
        if rich {
            raw_set(RegisterClipboardFormatW(w!("HTML Format")), b"<b>rich</b>\0");
        }
    });
}

fn format_available(name: PCWSTR) -> bool {
    with_clipboard(|| unsafe { IsClipboardFormatAvailable(RegisterClipboardFormatW(name)).is_ok() })
}

#[test]
fn the_real_clipboard_calls_work_without_touching_the_users_clipboard() {
    unsafe {
        let original_station = GetProcessWindowStation().unwrap();
        let original_desktop = GetThreadDesktop(GetCurrentThreadId()).unwrap();
        let users_sequence = GetClipboardSequenceNumber();

        let station = CreateWindowStationW(PCWSTR::null(), 0, GENERIC_ALL, None).unwrap();
        SetProcessWindowStation(station).unwrap();
        let desktop = CreateDesktopW(w!("cipher-vault-clipboard-test"), PCWSTR::null(), None, DESKTOP_CONTROL_FLAGS(0), GENERIC_ALL, None).unwrap();
        SetThreadDesktop(desktop).unwrap();

        exercise_clipboard(desktop);

        SetThreadDesktop(original_desktop).unwrap();
        SetProcessWindowStation(original_station).unwrap();
        let _ = CloseDesktop(desktop);
        let _ = CloseWindowStation(station);
        assert_eq!(GetClipboardSequenceNumber(), users_sequence, "the user's clipboard was not written");
    }
}

fn exercise_clipboard(desktop: HDESK) {
    let port = windows_clipboard::WindowsClipboard;
    let secret = "合成の秘密🔐e\u{301}";
    let digest = visible_text_digest(secret);

    port.write(secret, "owner-1").unwrap();
    assert_eq!(clipboard_text().as_deref(), Some(secret), "Unicode text round-trips");
    assert!(format_available(w!("CipherVaultOwner")));
    assert!(format_available(w!("CanIncludeInClipboardHistory")), "excluded from clipboard history");
    assert!(format_available(w!("CanUploadToCloudClipboard")), "excluded from cloud sync");

    assert!(!port.clear_if_owned("other-owner", &digest).unwrap(), "a different marker is not ours");
    assert!(!port.clear_if_owned("owner-1", &visible_text_digest("other")).unwrap(), "different text is not ours");
    assert_eq!(clipboard_text().as_deref(), Some(secret));
    assert!(port.clear_if_owned("owner-1", &digest).unwrap());
    assert_eq!(clipboard_text(), None, "cleared");

    // Another application's content must survive every way of looking similar.
    port.write(secret, "owner-2").unwrap();
    another_application_copies("someone else's copy", None, false);
    assert!(!port.clear_if_owned("owner-2", &digest).unwrap());
    assert_eq!(clipboard_text().as_deref(), Some("someone else's copy"));

    another_application_copies(secret, None, false);
    assert!(!port.clear_if_owned("owner-2", &digest).unwrap(), "same text without the marker");
    assert_eq!(clipboard_text().as_deref(), Some(secret));

    another_application_copies(secret, Some("owner-2"), true);
    assert!(!port.clear_if_owned("owner-2", &digest).unwrap(), "same text and marker with a rich format");
    assert_eq!(clipboard_text().as_deref(), Some(secret));

    // Text with a NUL is stored in full but only compared up to what a reader sees.
    let notes = "一行目\0終端";
    port.write(notes, "owner-3").unwrap();
    assert_eq!(clipboard_text().as_deref(), Some("一行目"));
    assert!(port.clear_if_owned("owner-3", &visible_text_digest(notes)).unwrap());

    let large = "x".repeat(1024 * 1024);
    port.write(&large, "owner-4").unwrap();
    assert!(port.clear_if_owned("owner-4", &visible_text_digest(&large)).unwrap(), "the largest allowed copy");

    port.write("", "owner-5").unwrap();
    assert!(port.clear_if_owned("owner-5", &visible_text_digest("")).unwrap(), "an empty copy");

    // The whole path through the real port, including the lease.
    let expiring = ExpiringClipboard::new(Box::new(windows_clipboard::WindowsClipboard));
    expiring.copy("期限付きの秘密", || Ok(())).unwrap();
    assert_eq!(clipboard_text().as_deref(), Some("期限付きの秘密"));
    assert!(expiring.clear_owned());
    assert_eq!(clipboard_text(), None);

    // While another program holds the clipboard open, nothing is cleared and the lease survives.
    expiring.copy("保持される秘密", || Ok(())).unwrap();
    let desktop_handle = desktop.0 as isize;
    let (opened, wait_for_open) = std::sync::mpsc::channel();
    let (release, wait_for_release) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || unsafe {
        // A new thread does not inherit the test thread's desktop.
        SetThreadDesktop(HDESK(desktop_handle as *mut _)).unwrap();
        let window = CreateWindowExW(WINDOW_EX_STYLE(0), w!("STATIC"), PCWSTR::null(), WINDOW_STYLE(0), 0, 0, 0, 0, Some(HWND_MESSAGE), None, None, None).unwrap();
        OpenClipboard(Some(window)).unwrap();
        opened.send(()).unwrap();
        wait_for_release.recv().unwrap();
        CloseClipboard().unwrap();
        DestroyWindow(window).unwrap();
    });
    wait_for_open.recv().unwrap();
    assert!(!expiring.clear_owned(), "a busy clipboard is reported instead of being treated as cleared");
    release.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(clipboard_text().as_deref(), Some("保持される秘密"), "nothing was cleared while it was busy");
    assert!(expiring.clear_owned(), "the lease survived for the retry");
    assert_eq!(clipboard_text(), None);
}

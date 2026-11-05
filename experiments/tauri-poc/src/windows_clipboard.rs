//! The real Windows clipboard. The clipboard stays open across the comparison and the clearing,
//! so another application cannot replace the content between those two steps.

use crate::clipboard::{ClipboardPort, ClipboardUnavailable, visible_text_digest};
use std::time::Duration;
use subtle::ConstantTimeEq;
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, EnumClipboardFormats, GetClipboardData, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock};
use windows::Win32::System::Ole::{CF_LOCALE, CF_OEMTEXT, CF_TEXT, CF_UNICODETEXT};
use windows::Win32::UI::WindowsAndMessaging::{CreateWindowExW, DestroyWindow, HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE};
use windows::core::{PCWSTR, w};
use zeroize::Zeroize;

const OPEN_ATTEMPTS: u32 = 10;
const OPEN_RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_OWNER_BYTES: usize = 128;

struct Formats {
    owner: u32,
    history: u32,
    cloud: u32,
}

fn registered_formats() -> Result<Formats, ClipboardUnavailable> {
    let register = |name: PCWSTR| match unsafe { RegisterClipboardFormatW(name) } {
        0 => Err(ClipboardUnavailable),
        format => Ok(format),
    };
    Ok(Formats {
        owner: register(w!("CipherVaultOwner"))?,
        history: register(w!("CanIncludeInClipboardHistory"))?,
        cloud: register(w!("CanUploadToCloudClipboard"))?,
    })
}

/// SetClipboardData needs an owner window, so each operation uses a short-lived message-only one.
fn with_open_clipboard<T>(action: impl FnOnce() -> Result<T, ClipboardUnavailable>) -> Result<T, ClipboardUnavailable> {
    let window = unsafe {
        CreateWindowExW(WINDOW_EX_STYLE(0), w!("STATIC"), PCWSTR::null(), WINDOW_STYLE(0), 0, 0, 0, 0, Some(HWND_MESSAGE), None, None, None)
    }
    .map_err(|_| ClipboardUnavailable)?;
    let result = open_with_retry(window).and_then(|()| {
        let result = action();
        let _ = unsafe { CloseClipboard() };
        result
    });
    let _ = unsafe { DestroyWindow(window) };
    result
}

// Clipboard managers often hold the clipboard for a moment.
fn open_with_retry(window: HWND) -> Result<(), ClipboardUnavailable> {
    for attempt in 0..OPEN_ATTEMPTS {
        if unsafe { OpenClipboard(Some(window)) }.is_ok() {
            return Ok(());
        }
        if attempt + 1 < OPEN_ATTEMPTS {
            std::thread::sleep(OPEN_RETRY_DELAY);
        }
    }
    Err(ClipboardUnavailable)
}

fn set_bytes(format: u32, bytes: &[u8]) -> Result<(), ClipboardUnavailable> {
    unsafe {
        let memory = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)).map_err(|_| ClipboardUnavailable)?;
        let destination = GlobalLock(memory);
        if destination.is_null() {
            let _ = GlobalFree(Some(memory));
            return Err(ClipboardUnavailable);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), destination.cast::<u8>(), bytes.len());
        let _ = GlobalUnlock(memory);
        // On success the system owns the memory. It can no longer be wiped from here, which is
        // why the content is limited by time instead.
        if SetClipboardData(format, Some(HANDLE(memory.0))).is_err() {
            let _ = GlobalFree(Some(memory));
            return Err(ClipboardUnavailable);
        }
    }
    Ok(())
}

fn read_bytes(format: u32, limit: usize) -> Option<Vec<u8>> {
    unsafe {
        let handle = GetClipboardData(format).ok()?;
        let memory = HGLOBAL(handle.0);
        let size = GlobalSize(memory);
        if size == 0 || size > limit {
            return None;
        }
        let source = GlobalLock(memory);
        if source.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(source.cast::<u8>(), size).to_vec();
        let _ = GlobalUnlock(memory);
        Some(bytes)
    }
}

fn only_expected_formats(formats: &Formats) -> bool {
    let synthesized = [u32::from(CF_TEXT.0), u32::from(CF_OEMTEXT.0), u32::from(CF_LOCALE.0), u32::from(CF_UNICODETEXT.0)];
    let mut format = 0;
    loop {
        format = unsafe { EnumClipboardFormats(format) };
        if format == 0 {
            return true;
        }
        // A rich format means another application's copy, even if it reused the plain text.
        if !synthesized.contains(&format) && ![formats.owner, formats.history, formats.cloud].contains(&format) {
            return false;
        }
    }
}

fn digest_of_stored_text() -> Option<[u8; 32]> {
    let mut bytes = read_bytes(u32::from(CF_UNICODETEXT.0), MAX_TEXT_BYTES)?;
    let mut units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|unit| *unit != 0).collect();
    bytes.zeroize();
    let decoded = String::from_utf16(&units).ok();
    units.zeroize();
    let mut text = decoded?;
    let digest = visible_text_digest(&text);
    text.zeroize();
    Some(digest)
}

fn holds_owned_content(formats: &Formats, owner: &str, digest: &[u8; 32]) -> bool {
    if !only_expected_formats(formats) {
        return false;
    }
    // GlobalSize may round up, so only the marker's own length is compared.
    let marker_matches = read_bytes(formats.owner, MAX_OWNER_BYTES).is_some_and(|marker| marker.len() >= owner.len() && &marker[..owner.len()] == owner.as_bytes());
    marker_matches && digest_of_stored_text().is_some_and(|stored| bool::from(stored.ct_eq(digest)))
}

pub struct WindowsClipboard;

impl ClipboardPort for WindowsClipboard {
    fn write(&self, text: &str, owner: &str) -> Result<(), ClipboardUnavailable> {
        let formats = registered_formats()?;
        // Reserved up front so that growing never leaves copies of the text in freed memory.
        let mut wide = Vec::with_capacity((text.len() + 1) * 2);
        wide.extend(text.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes));
        let result = with_open_clipboard(|| {
            unsafe { EmptyClipboard() }.map_err(|_| ClipboardUnavailable)?;
            let written = set_bytes(u32::from(CF_UNICODETEXT.0), &wide)
                .and_then(|()| set_bytes(formats.owner, owner.as_bytes()))
                // A DWORD of 0 asks Windows not to keep this content in history or sync it.
                .and_then(|()| set_bytes(formats.history, &0u32.to_le_bytes()))
                .and_then(|()| set_bytes(formats.cloud, &0u32.to_le_bytes()));
            if written.is_err() {
                // Never leave a secret behind without the marker that allows clearing it.
                let _ = unsafe { EmptyClipboard() };
            }
            written
        });
        wide.zeroize();
        result
    }

    fn clear_if_owned(&self, owner: &str, digest: &[u8; 32]) -> Result<bool, ClipboardUnavailable> {
        let formats = registered_formats()?;
        with_open_clipboard(|| {
            if !holds_owned_content(&formats, owner, digest) {
                return Ok(false);
            }
            unsafe { EmptyClipboard() }.map_err(|_| ClipboardUnavailable)?;
            Ok(true)
        })
    }
}

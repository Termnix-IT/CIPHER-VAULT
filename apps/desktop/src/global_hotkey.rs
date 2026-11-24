//! The system-wide shortcut only asks the desktop to bring its window forward.

use std::cell::OnceCell;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use windows::Win32::Foundation::{ERROR_HOTKEY_ALREADY_REGISTERED, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    HOT_KEY_MODIFIERS, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, RegisterHotKey, UnregisterHotKey, VK_F1, VK_F12, VK_SPACE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE, MSG, PostMessageW, PostQuitMessage, RegisterClassW,
    SendMessageW, WINDOW_EX_STYLE, WM_APP, WM_CLOSE, WM_DESTROY, WM_HOTKEY, WNDCLASSW, WS_OVERLAPPED,
};
use windows::core::{HRESULT, w};

const MODIFIERS: &[(&str, HOT_KEY_MODIFIERS)] = &[("Ctrl", MOD_CONTROL), ("Alt", MOD_ALT), ("Shift", MOD_SHIFT)];
pub const INVALID_SHORTCUT: &str = "ショートカットは Ctrl・Alt・Shift のうち2つ以上と、英数字・F1〜F11・Space の組み合わせにしてください";
const RESERVED_SHORTCUT: &str = "このキーはアプリの中で使っているため選べません";
const HOTKEY_ID: i32 = 1;
const SET_HOTKEY: u32 = WM_APP + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hotkey {
    modifiers: u32,
    key: u32,
}

impl Hotkey {
    pub fn parse(mut text: &str) -> Result<Self, &'static str> {
        let mut modifiers = 0;
        for (name, flag) in MODIFIERS {
            if let Some(rest) = text.strip_prefix(name).and_then(|rest| rest.strip_prefix('+')) {
                modifiers |= flag.0;
                text = rest;
            }
        }
        if modifiers.count_ones() < 2 {
            return Err(INVALID_SHORTCUT);
        }
        let key = match text.as_bytes() {
            [key @ (b'A'..=b'Z' | b'0'..=b'9')] => u32::from(*key),
            [b'F', number @ b'1'..=b'9'] => u32::from(VK_F1.0) + u32::from(number - b'1'),
            // F12 stays with debuggers, as RegisterHotKey's documentation asks.
            [b'F', b'1', number @ b'0'..=b'1'] => u32::from(VK_F1.0) + 9 + u32::from(number - b'0'),
            b"Space" => u32::from(VK_SPACE.0),
            _ => return Err(INVALID_SHORTCUT),
        };
        if modifiers == (MOD_CONTROL | MOD_SHIFT).0 && matches!(text, "C" | "M") {
            return Err(RESERVED_SHORTCUT);
        }
        Ok(Self { modifiers, key })
    }
}

impl fmt::Display for Hotkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, flag) in MODIFIERS {
            if self.modifiers & flag.0 != 0 {
                write!(f, "{name}+")?;
            }
        }
        if self.key == u32::from(VK_SPACE.0) {
            f.write_str("Space")
        } else if (u32::from(VK_F1.0)..=u32::from(VK_F12.0)).contains(&self.key) {
            write!(f, "F{}", self.key - u32::from(VK_F1.0) + 1)
        } else {
            write!(f, "{}", char::from(self.key as u8))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotkeyError {
    InUse,
    Failed,
}

impl HotkeyError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::InUse => "このショートカットはほかのアプリかWindowsが使っているため登録できませんでした",
            Self::Failed => "ショートカットを登録できませんでした",
        }
    }
}

struct SetRequest {
    hotkey: Option<Hotkey>,
    result: Result<(), HotkeyError>,
}

#[derive(Default)]
struct Registration {
    current: Option<Hotkey>,
    pending: Option<SetRequest>,
}

struct ListenerThread {
    registration: Arc<Mutex<Registration>>,
    on_press: Box<dyn Fn() + Send + Sync>,
}

thread_local! {
    static LISTENER: OnceCell<ListenerThread> = const { OnceCell::new() };
}

/// Owns the thread because Windows ties each registration to its window's thread.
pub struct HotkeyListener {
    window: isize,
    thread: Option<JoinHandle<()>>,
    registration: Arc<Mutex<Registration>>,
    requests: Mutex<()>,
}

impl HotkeyListener {
    pub fn start(on_press: Box<dyn Fn() + Send + Sync>) -> Result<Self, String> {
        let registration = Arc::new(Mutex::new(Registration::default()));
        let state = ListenerThread { registration: Arc::clone(&registration), on_press };
        let (ready, result) = std::sync::mpsc::channel();
        let failed = |_| HotkeyError::Failed.message().to_string();
        let thread = thread::Builder::new()
            .name("global-hotkey".into())
            .spawn(move || {
                LISTENER.with(|listener| {
                    let _ = listener.set(state);
                });
                run(ready);
            })
            .map_err(failed)?;
        let window = result.recv().map_err(|_| HotkeyError::Failed.message().to_string())?;
        Ok(Self { window, thread: Some(thread), registration, requests: Mutex::new(()) })
    }

    pub fn set(&self, hotkey: Option<Hotkey>) -> Result<(), HotkeyError> {
        let _request = self.requests.lock().map_err(|_| HotkeyError::Failed)?;
        let address = {
            let mut registration = self.registration.lock().map_err(|_| HotkeyError::Failed)?;
            let request = registration.pending.insert(SetRequest { hotkey, result: Err(HotkeyError::Failed) });
            std::ptr::from_mut(request) as isize
        };
        // The pending slot stays in place until the window has handled the synchronous message.
        unsafe { SendMessageW(self.window(), SET_HOTKEY, None, Some(LPARAM(address))) };
        self.registration.lock().map_err(|_| HotkeyError::Failed)?.pending.take().ok_or(HotkeyError::Failed)?.result
    }

    pub fn registered(&self, hotkey: Hotkey) -> bool {
        self.registration.lock().is_ok_and(|registration| registration.current == Some(hotkey))
    }

    fn window(&self) -> HWND {
        HWND(self.window as _)
    }
}

impl Drop for HotkeyListener {
    fn drop(&mut self) {
        unsafe {
            if PostMessageW(Some(self.window()), WM_CLOSE, WPARAM(0), LPARAM(0)).is_err() {
                SendMessageW(self.window(), WM_CLOSE, None, None);
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(ready: std::sync::mpsc::Sender<isize>) {
    unsafe {
        let Ok(module) = GetModuleHandleW(None) else { return };
        let class =
            WNDCLASSW { lpfnWndProc: Some(window_procedure), hInstance: module.into(), lpszClassName: w!("CipherVaultHotkey"), ..Default::default() };
        // Another listener may already have registered this process-wide class.
        RegisterClassW(&class);
        let Ok(window) = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class.lpszClassName,
            w!(""),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(class.hInstance),
            None,
        ) else {
            return;
        };
        if ready.send(window.0 as isize).is_ok() {
            let mut message = MSG::default();
            while GetMessageW(&mut message, None, 0, 0).0 > 0 {
                DispatchMessageW(&message);
            }
        }
        let _ = DestroyWindow(window);
    }
}

fn register(window: HWND, hotkey: Hotkey) -> Result<(), HotkeyError> {
    unsafe { RegisterHotKey(Some(window), HOTKEY_ID, HOT_KEY_MODIFIERS(hotkey.modifiers) | MOD_NOREPEAT, hotkey.key) }.map_err(|error| {
        if error.code() == HRESULT::from_win32(ERROR_HOTKEY_ALREADY_REGISTERED.0) { HotkeyError::InUse } else { HotkeyError::Failed }
    })
}

fn replace(window: HWND, current: &mut Option<Hotkey>, next: Option<Hotkey>) -> Result<(), HotkeyError> {
    if *current == next {
        return Ok(());
    }
    let previous = *current;
    if previous.is_some() {
        unsafe { UnregisterHotKey(Some(window), HOTKEY_ID) }.map_err(|_| HotkeyError::Failed)?;
        *current = None;
    }
    if let Some(hotkey) = next {
        if let Err(error) = register(window, hotkey) {
            *current = previous.filter(|&hotkey| register(window, hotkey).is_ok());
            return Err(error);
        }
        *current = next;
    }
    Ok(())
}

unsafe extern "system" fn window_procedure(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match message {
        SET_HOTKEY => LISTENER.with(|listener| {
            if let Some(listener) = listener.get()
                && let Ok(mut registration) = listener.registration.lock()
            {
                let Registration { current, pending } = &mut *registration;
                // The slot authenticates the address, so a message cannot supply an arbitrary pointer.
                if let Some(request) = pending
                    && std::ptr::from_mut(request) as isize == lparam.0
                {
                    request.result = replace(window, current, request.hotkey);
                }
            }
        }),
        WM_HOTKEY if wparam.0 == HOTKEY_ID as usize => LISTENER.with(|listener| {
            if let Some(listener) = listener.get() {
                let keys = lparam.0 as u32;
                let current = listener.registration.lock().ok().and_then(|registration| registration.current);
                if current == Some(Hotkey { modifiers: keys & 0xffff & !MOD_NOREPEAT.0, key: keys >> 16 }) {
                    (listener.on_press)();
                }
            }
        }),
        WM_CLOSE => {
            let _ = unsafe { DestroyWindow(window) };
        }
        WM_DESTROY => {
            LISTENER.with(|listener| {
                if let Some(listener) = listener.get()
                    && let Ok(mut registration) = listener.registration.lock()
                    && registration.current.take().is_some()
                {
                    let _ = unsafe { UnregisterHotKey(Some(window), HOTKEY_ID) };
                }
            });
            unsafe { PostQuitMessage(0) };
        }
        _ => return unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
    LRESULT(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_canonical_shortcuts() {
        for text in ["Ctrl+Alt+Space", "Ctrl+Shift+F5", "Alt+Shift+A", "Ctrl+Alt+9", "Ctrl+Alt+Shift+F11", "Ctrl+Alt+F1", "Ctrl+Alt+F10"] {
            assert_eq!(Hotkey::parse(text).unwrap().to_string(), text);
        }
        for text in [
            "Ctrl+A",
            "Alt+F4",
            "Shift+Space",
            "Win+Ctrl+A",
            "ctrl+alt+a",
            "Ctrl+Alt+Tab",
            "Ctrl+Alt+F12",
            "Ctrl+Alt+F13",
            "",
            "Ctrl+Alt+",
            "Alt+Ctrl+A",
            "Ctrl+Ctrl+Alt+A",
            "Ctrl+Alt+F01",
            "Ctrl+Alt+space",
            "Ctrl+Alt+A ",
        ] {
            assert_eq!(Hotkey::parse(text), Err(INVALID_SHORTCUT), "{text}");
        }
        for text in ["Ctrl+Shift+C", "Ctrl+Shift+M"] {
            assert_eq!(Hotkey::parse(text), Err(RESERVED_SHORTCUT), "{text}");
        }
    }

    #[test]
    fn registers_releases_and_refuses_a_taken_shortcut() {
        let shortcut = Hotkey::parse("Ctrl+Alt+Shift+F11").unwrap();
        let first = HotkeyListener::start(Box::new(|| {})).unwrap();
        match first.set(Some(shortcut)) {
            Err(HotkeyError::InUse) => return,
            result => result.unwrap(),
        }
        let second = HotkeyListener::start(Box::new(|| {})).unwrap();
        assert_eq!(second.set(Some(shortcut)), Err(HotkeyError::InUse));
        assert!(first.registered(shortcut));
        first.set(None).unwrap();
        assert!(!first.registered(shortcut));
        second.set(Some(shortcut)).unwrap();
        let previous = Hotkey::parse("Ctrl+Alt+Shift+F10").unwrap();
        first.set(Some(previous)).unwrap();
        assert_eq!(first.set(Some(shortcut)), Err(HotkeyError::InUse));
        assert!(first.registered(previous));
        assert_eq!(second.set(Some(previous)), Err(HotkeyError::InUse));
        drop(first);
        second.set(Some(previous)).unwrap();
    }
}

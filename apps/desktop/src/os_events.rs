//! Screen lock and power notifications, following apps/electron/src/vault-power-guard.ts.
//! Tauri does not expose these on Windows, so a hidden window on its own thread receives them.
//! It must be a top-level window: message-only windows do not get broadcasts.

use cipher_vault_core::LockReason;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTS_CURRENT_SESSION, WTS_CURRENT_SERVER_HANDLE, WTSFreeMemory, WTSINFOEXW, WTSQuerySessionInformationW,
    WTSRegisterSessionNotification, WTSSessionInfoEx,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, HWND_DESKTOP, MSG, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    RegisterClassW, TranslateMessage, WINDOW_EX_STYLE, WM_ENDSESSION, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPED, WTS_SESSION_LOCK,
    WTS_SESSION_UNLOCK,
};
use windows::core::{PWSTR, w};

pub const LOCKED_MESSAGE: &str = "画面ロック・スリープ中は保管庫を操作できません。OSへ戻ってから解除してください";
const SESSION_FLAG_LOCKED: i32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsEvent {
    ScreenLock,
    ScreenUnlock,
    Suspend,
    Resume,
    EndSession,
}

impl OsEvent {
    /// The lock reason the screen shows. Windows signing out or shutting down ends the window too.
    pub fn lock_reason(self) -> LockReason {
        match self {
            Self::ScreenLock => LockReason::ScreenLock,
            Self::ScreenUnlock => LockReason::ScreenUnlock,
            Self::Suspend => LockReason::Suspend,
            Self::Resume => LockReason::Resume,
            Self::EndSession => LockReason::WindowClosed,
        }
    }
}

/// Tracks whether the OS is away. Returning from it never unlocks the vault by itself.
#[derive(Default)]
pub struct PowerGuard {
    screen_locked: AtomicBool,
    suspended: AtomicBool,
}

impl PowerGuard {
    pub fn observe(&self, event: OsEvent) {
        match event {
            OsEvent::ScreenLock => self.screen_locked.store(true, Ordering::SeqCst),
            OsEvent::ScreenUnlock => self.screen_locked.store(false, Ordering::SeqCst),
            OsEvent::Suspend => self.suspended.store(true, Ordering::SeqCst),
            OsEvent::Resume => self.suspended.store(false, Ordering::SeqCst),
            OsEvent::EndSession => {}
        }
    }

    /// `currently_locked` is a live query, so it also covers a lock whose notification never came.
    /// It is not stored: a missed unlock notification must not block the app until a restart.
    pub fn check(&self, currently_locked: Option<bool>) -> Result<(), &'static str> {
        let away = currently_locked == Some(true) || self.screen_locked.load(Ordering::SeqCst) || self.suspended.load(Ordering::SeqCst);
        if away { Err(LOCKED_MESSAGE) } else { Ok(()) }
    }
}

/// None when Windows cannot report it, in which case the idle timeout remains the protection.
pub fn session_is_locked() -> Option<bool> {
    unsafe {
        let mut buffer = PWSTR::null();
        let mut size = 0u32;
        WTSQuerySessionInformationW(Some(WTS_CURRENT_SERVER_HANDLE), WTS_CURRENT_SESSION, WTSSessionInfoEx, &mut buffer, &mut size).ok()?;
        let result = (size as usize >= size_of::<WTSINFOEXW>()).then(|| {
            let info = &*buffer.0.cast::<WTSINFOEXW>();
            info.Level == 1 && info.Data.WTSInfoExLevel1.SessionFlags == SESSION_FLAG_LOCKED
        });
        WTSFreeMemory(buffer.0.cast());
        result
    }
}

type Handler = Box<dyn Fn(OsEvent) + Send + Sync>;
static HANDLER: OnceLock<Handler> = OnceLock::new();

fn event_from_message(message: u32, wparam: usize) -> Option<OsEvent> {
    match (message, wparam as u32) {
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK) => Some(OsEvent::ScreenLock),
        (WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK) => Some(OsEvent::ScreenUnlock),
        (WM_POWERBROADCAST, PBT_APMSUSPEND) => Some(OsEvent::Suspend),
        (WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND) => Some(OsEvent::Resume),
        (WM_ENDSESSION, value) if value != 0 => Some(OsEvent::EndSession),
        _ => None,
    }
}

unsafe extern "system" fn window_procedure(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if let (Some(event), Some(handler)) = (event_from_message(message, wparam.0), HANDLER.get()) {
        handler(event);
    }
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

/// Starts the listener once for the process and returns after its window exists.
pub fn start(handler: Handler) -> Result<isize, String> {
    if HANDLER.set(handler).is_err() {
        return Err("OS event listener is already running".into());
    }
    let (ready, result) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("os-events".into())
        .spawn(move || unsafe {
            let instance: HMODULE = GetModuleHandleW(None).unwrap_or_default();
            let class = WNDCLASSW { lpfnWndProc: Some(window_procedure), hInstance: instance.into(), lpszClassName: w!("CipherVaultOsEvents"), ..Default::default() };
            RegisterClassW(&class);
            let created = CreateWindowExW(WINDOW_EX_STYLE(0), class.lpszClassName, w!("CIPHER VAULT OS events"), WS_OVERLAPPED, 0, 0, 0, 0, Some(HWND_DESKTOP), None, Some(instance.into()), None);
            let window = match created {
                Ok(window) => window,
                Err(_) => {
                    let _ = ready.send(Err("OS event window could not be created".to_string()));
                    return;
                }
            };
            if WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION).is_err() {
                let _ = ready.send(Err("Screen lock notifications could not be registered".to_string()));
                return;
            }
            let _ = ready.send(Ok(window.0 as isize));
            let mut message = MSG::default();
            while GetMessageW(&mut message, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        })
        .map_err(|_| "OS event thread could not start".to_string())?;
    result.recv().map_err(|_| "OS event thread stopped".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use windows::Win32::UI::WindowsAndMessaging::SendMessageW;

    #[test]
    fn locks_and_suspends_block_use_until_the_os_returns() {
        let guard = PowerGuard::default();
        assert_eq!(guard.check(Some(false)), Ok(()));
        guard.observe(OsEvent::ScreenLock);
        assert_eq!(guard.check(Some(false)), Err(LOCKED_MESSAGE));
        guard.observe(OsEvent::Suspend);
        guard.observe(OsEvent::ScreenUnlock);
        assert_eq!(guard.check(Some(false)), Err(LOCKED_MESSAGE), "still suspended");
        guard.observe(OsEvent::Resume);
        assert_eq!(guard.check(Some(false)), Ok(()));
    }

    #[test]
    fn a_lock_found_by_query_blocks_use_when_no_notification_arrived() {
        let guard = PowerGuard::default();
        assert_eq!(guard.check(Some(true)), Err(LOCKED_MESSAGE));
        assert_eq!(guard.check(Some(false)), Ok(()), "the query result is not remembered");
        assert_eq!(guard.check(None), Ok(()), "an unknown state does not block by itself");
    }

    #[test]
    fn every_reason_maps_to_a_reason_the_ui_knows() {
        assert_eq!(OsEvent::ScreenLock.lock_reason().as_str(), "screen-lock");
        assert_eq!(OsEvent::ScreenUnlock.lock_reason().as_str(), "screen-unlock");
        assert_eq!(OsEvent::Suspend.lock_reason().as_str(), "suspend");
        assert_eq!(OsEvent::Resume.lock_reason().as_str(), "resume");
        assert_eq!(OsEvent::EndSession.lock_reason().as_str(), "window-closed");
    }

    #[test]
    fn windows_can_report_the_session_state() {
        assert!(session_is_locked().is_some());
    }

    #[test]
    fn the_hidden_window_turns_messages_into_events_and_ignores_others() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let window = HWND(start(Box::new(move |event| recorder.lock().unwrap().push(event))).unwrap() as *mut _);
        let messages = [
            (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK),
            (WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK),
            (WM_POWERBROADCAST, PBT_APMSUSPEND),
            (WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC),
            (WM_POWERBROADCAST, PBT_APMRESUMESUSPEND),
            (WM_ENDSESSION, 0),
            (WM_ENDSESSION, 1),
            (WM_WTSSESSION_CHANGE, 1),
            (WM_POWERBROADCAST, 0x8013),
        ];
        // Windows refuses to post some of these, and sending returns after they are handled.
        for (message, wparam) in messages {
            unsafe { SendMessageW(window, message, Some(WPARAM(wparam as usize)), Some(LPARAM(0))) };
        }
        assert_eq!(*seen.lock().unwrap(), [OsEvent::ScreenLock, OsEvent::ScreenUnlock, OsEvent::Suspend, OsEvent::Resume, OsEvent::Resume, OsEvent::EndSession]);
    }
}

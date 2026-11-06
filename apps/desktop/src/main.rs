//! CIPHER VAULT on Tauri. It shows the existing React screen from `apps/web` and replaces
//! `apps/electron` and the Node services step by step. Until the vault services move here, the
//! screen can read the vault status command only, which reports that the vault is not available.
//!
//! The `e2e` feature exists for automated checks only. It keeps the WebView2 debugging port
//! available and reports events on stdout. Never distribute it.

#![cfg_attr(not(feature = "e2e"), windows_subsystem = "windows")]

#[cfg_attr(feature = "e2e", allow(dead_code))]
mod webview_hardening;

use tauri::webview::NewWindowResponse;
use tauri::{Url, WebviewUrl, WebviewWindowBuilder};

/// Shown until the vault services are ported, so a build of this stage cannot be mistaken for the app.
const NOT_PORTED: &str = "この版では保管庫をまだ開けません。現行のアプリを使ってください";

/// Reports events to the automated checks. Prints nothing in a normal build.
fn trace(_event: &str) {
    #[cfg(feature = "e2e")]
    {
        use std::io::Write;
        let mut output = std::io::stdout();
        let _ = writeln!(output, "e2e-event {_event}");
        let _ = output.flush();
    }
}

#[tauri::command]
fn vault_status() -> Result<serde_json::Value, String> {
    Err(NOT_PORTED.to_string())
}

/// The bundled screen only. Tauri serves it as http://tauri.localhost on Windows.
fn is_application_url(url: &Url) -> bool {
    matches!((url.scheme(), url.host_str()), ("http", Some("tauri.localhost")) | ("tauri", Some("localhost")))
}

fn fail_startup(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2);
}

fn main() {
    #[cfg(not(feature = "e2e"))]
    {
        // SAFETY: no other thread exists yet.
        unsafe { webview_hardening::remove_webview2_overrides() };
        if webview_hardening::webview2_policy_override_exists() {
            fail_startup("A WebView2 policy overrides this application's browser settings, so it will not start.");
        }
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![vault_status])
        .setup(|app| {
            let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("CIPHER VAULT")
                .inner_size(880.0, 780.0)
                .min_inner_size(780.0, 680.0)
                .initialization_script(include_str!("desktop-api.js"))
                .on_navigation(is_application_url)
                .on_new_window(|_url, _features| NewWindowResponse::Deny)
                .disable_drag_drop_handler()
                .build()?;
            window.with_webview(|webview| {
                match webview_hardening::apply_settings(&webview, || trace("renderer-gone")) {
                    Ok(settings) => trace(&format!("webview-settings {settings}")),
                    // These settings protect secrets, so the window must not stay open without them.
                    Err(_) => fail_startup("The WebView2 security settings could not be applied."),
                }
            })?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the window failed to start");
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

    #[test]
    fn the_status_says_the_vault_is_not_available_yet() {
        assert_eq!(vault_status().unwrap_err(), NOT_PORTED);
    }
}

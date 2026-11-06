// Every command the screen may call is listed here, so Tauri refuses any command that no
// capability in tauri.conf.json grants. Without the list, all commands would be open to every window.
const COMMANDS: &[&str] = &["vault_status"];

fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)))
        .expect("the Tauri build step failed");
}

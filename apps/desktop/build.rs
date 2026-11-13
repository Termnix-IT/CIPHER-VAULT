// Every command the screen may call is listed here, so Tauri refuses any command that no
// capability in tauri.conf.json grants. Without the list, all commands would be open to every window.
const COMMANDS: &[&str] = &[
    "vault_status",
    "vault_activity",
    "vault_setup",
    "vault_unlock",
    "vault_lock",
    "vault_maintenance",
    "entries_list",
    "entries_get",
    "entries_create",
    "entries_update",
    "entries_delete",
    "entries_set_group",
    "entry_icons_get",
    "entry_icon_set",
    "password_generate",
    "backup_export",
    "backup_restore",
    "vault_audit",
    "clipboard_write",
    "update_state",
    "update_check",
    "update_download",
    "update_install",
    "update_open_releases",
];

fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)))
        .expect("the Tauri build step failed");
}

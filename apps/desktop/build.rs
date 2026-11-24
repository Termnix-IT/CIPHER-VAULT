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
    "entry_icon_set",
    "entry_favorite_set",
    "entry_use_record",
    "entry_url_open",
    "settings_auto_lock_set",
    "settings_global_shortcut_get",
    "settings_global_shortcut_set",
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
    "window_set_compact",
    "window_set_always_on_top",
];

fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)))
        .expect("the Tauri build step failed");
}

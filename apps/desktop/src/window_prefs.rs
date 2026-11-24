//! Desktop-only settings live beside the vault so they are available while it is locked.

use crate::global_hotkey::Hotkey;
use cipher_vault_core::files;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const NAME: &str = "window-prefs.json";
const MAX_BYTES: u64 = 4096;
pub const SAVE_FAILED: &str = "設定を保存できませんでした";

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CompactBounds {
    // Windows reports the position in physical pixels, even for a scaled monitor.
    pub x: i32,
    pub y: i32,
    pub width: f64,
    pub height: f64,
}

impl CompactBounds {
    fn parse(value: &Value) -> Option<Self> {
        let x = value.get("x")?.as_i64()?.try_into().ok()?;
        let y = value.get("y")?.as_i64()?.try_into().ok()?;
        let width = value.get("width")?.as_f64()?;
        let height = value.get("height")?.as_f64()?;
        (width > 0.0 && height > 0.0).then_some(Self { x, y, width, height })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WindowPrefs {
    pub global_shortcut: Option<Hotkey>,
    pub summon_compact: bool,
    pub compact_bounds: Option<CompactBounds>,
}

impl Default for WindowPrefs {
    fn default() -> Self {
        Self { global_shortcut: None, summon_compact: true, compact_bounds: None }
    }
}

impl WindowPrefs {
    pub fn load(dir: &Path) -> Self {
        let read = || {
            let dir = files::data_root(dir).ok()?;
            let path = files::safe_path(&dir, &[NAME], false, false).ok()?;
            let bytes = files::bounded_read(&path, MAX_BYTES).ok()?;
            let value: Value = serde_json::from_slice(&bytes).ok()?;
            Some(Self {
                global_shortcut: value.get("globalShortcut").and_then(Value::as_str).and_then(|text| Hotkey::parse(text).ok()),
                summon_compact: value.get("summonCompact").and_then(Value::as_bool).unwrap_or(true),
                compact_bounds: value.get("compactBounds").and_then(CompactBounds::parse),
            })
        };
        read().unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let failed = || SAVE_FAILED.to_string();
        let dir = files::data_root(dir).map_err(|_| failed())?;
        let destination = files::safe_path(&dir, &[NAME], false, true).map_err(|_| failed())?;
        let bounds = self.compact_bounds.map(|bounds| {
            json!({
                "x": bounds.x, "y": bounds.y, "width": bounds.width, "height": bounds.height
            })
        });
        let value = json!({
            "globalShortcut": self.global_shortcut.map(|hotkey| hotkey.to_string()),
            "summonCompact": self.summon_compact,
            "compactBounds": bounds,
        });
        let pending = dir.join(format!(".{NAME}.{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new().write(true).create_new(true).open(&pending).map_err(|_| failed())?;
        let written = file.write_all(value.to_string().as_bytes()).and_then(|_| file.sync_all());
        drop(file);
        // Closing the complete file before renaming lets Windows replace the old settings at once.
        if written.and_then(|_| fs::rename(&pending, &destination)).is_err() {
            let _ = fs::remove_file(pending);
            return Err(failed());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("cipher-vault-window-prefs-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn defaults_for_missing_or_unreadable_settings() {
        let dir = TemporaryDirectory::new();
        assert_eq!(WindowPrefs::load(&dir.0), WindowPrefs { global_shortcut: None, summon_compact: true, compact_bounds: None });
        fs::write(dir.0.join(NAME), b"not JSON").unwrap();
        assert_eq!(WindowPrefs::load(&dir.0), WindowPrefs::default());
    }

    #[test]
    fn writes_and_replaces_settings() {
        let dir = TemporaryDirectory::new();
        let prefs = WindowPrefs {
            global_shortcut: Hotkey::parse("Ctrl+Alt+Space").ok(),
            summon_compact: false,
            compact_bounds: Some(CompactBounds { x: -100, y: 80, width: 400.5, height: 640.0 }),
        };
        prefs.save(&dir.0).unwrap();
        assert_eq!(WindowPrefs::load(&dir.0), prefs);
        let value: Value = serde_json::from_slice(&fs::read(dir.0.join(NAME)).unwrap()).unwrap();
        assert_eq!(
            value,
            json!({
                "globalShortcut": "Ctrl+Alt+Space",
                "summonCompact": false,
                "compactBounds": { "x": -100, "y": 80, "width": 400.5, "height": 640.0 },
            })
        );
        WindowPrefs::default().save(&dir.0).unwrap();
        assert_eq!(WindowPrefs::load(&dir.0), WindowPrefs::default());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn invalid_fields_fall_back_individually() {
        let dir = TemporaryDirectory::new();
        let path = dir.0.join(NAME);
        fs::write(&path, br#"{"globalShortcut":"Ctrl+Shift+C","summonCompact":false,"compactBounds":{"x":10,"y":20,"width":400,"height":640}}"#)
            .unwrap();
        assert_eq!(
            WindowPrefs::load(&dir.0),
            WindowPrefs {
                global_shortcut: None,
                summon_compact: false,
                compact_bounds: Some(CompactBounds { x: 10, y: 20, width: 400.0, height: 640.0 }),
            }
        );
        fs::write(&path, br#"{"globalShortcut":"Ctrl+Alt+A","summonCompact":1,"compactBounds":{"x":10,"y":20,"width":0,"height":640}}"#).unwrap();
        assert_eq!(WindowPrefs::load(&dir.0), WindowPrefs { global_shortcut: Hotkey::parse("Ctrl+Alt+A").ok(), ..WindowPrefs::default() });
    }

    #[test]
    fn oversize_settings_are_ignored() {
        let dir = TemporaryDirectory::new();
        let mut value = br#"{"summonCompact":false}"#.to_vec();
        value.resize(MAX_BYTES as usize + 1, b' ');
        fs::write(dir.0.join(NAME), value).unwrap();
        assert_eq!(WindowPrefs::load(&dir.0), WindowPrefs::default());
    }
}

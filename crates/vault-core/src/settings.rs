//! The auto-lock preference lives beside the vault so it can be applied before unlock.

use crate::error::{Result, VaultError};
use crate::files;
use crate::maintenance::state_files;
use crate::session::DEFAULT_IDLE_TIMEOUT;
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

pub(crate) const NAME: &str = "app-settings.json";
const SETUP_MINUTES: u64 = 15;

pub(crate) fn parse(payload: Option<&Value>) -> Result<Option<u64>> {
    let minutes = payload.and_then(|value| {
        let object = value.as_object().filter(|object| object.len() == 1)?;
        match object.get("autoLockMinutes")? {
            Value::Null => Some(None),
            value => value.as_u64().filter(|minutes| matches!(minutes, 1 | 5 | 10 | 15 | 30 | 60 | 120)).map(Some),
        }
    });
    minutes.ok_or_else(|| VaultError::bad_request("自動ロックの時間が正しくありません"))
}

pub(crate) fn timeout(minutes: Option<u64>) -> Option<Duration> {
    minutes.map(|minutes| Duration::from_secs(minutes * 60))
}

/// Older vaults and unreadable settings keep the original deadline.
pub(crate) fn read(root: &Path) -> Option<Duration> {
    let read = || {
        let path = files::safe_path(root, &[NAME], false, true).ok()?;
        let bytes = files::bounded_read(&path, 4096).ok()?;
        let payload = serde_json::from_slice(&bytes).ok()?;
        parse(Some(&payload)).ok()
    };
    read().map_or(Some(DEFAULT_IDLE_TIMEOUT), timeout)
}

pub(crate) fn write(root: &Path, minutes: Option<u64>, exclusive: bool) -> Result<()> {
    state_files::write_state(root, NAME, &json!({ "autoLockMinutes": minutes }), &|| Ok(()), exclusive)
        .map_err(|_| VaultError::new(500, "設定を保存できませんでした"))
}

/// A first vault gets a longer deadline even when its preference cannot be saved.
pub(crate) fn setup(root: &Path) -> Option<Duration> {
    if !matches!(files::present(&root.join(NAME)), Ok(false)) {
        return read(root);
    }
    let minutes = Some(SETUP_MINUTES);
    if write(root, minutes, true).is_err() && matches!(files::present(&root.join(NAME)), Ok(true)) {
        return read(root);
    }
    timeout(minutes)
}

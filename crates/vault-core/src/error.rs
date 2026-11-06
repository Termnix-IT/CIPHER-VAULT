//! The errors the screen sees. Each carries the HTTP status the TypeScript services use for the
//! same case, so the differential tests can compare both, and the message the screen shows.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultError {
    pub status: u16,
    pub message: String,
}

pub type Result<T> = std::result::Result<T, VaultError>;

impl VaultError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }

    pub fn too_large(message: impl Into<String>) -> Self {
        Self::new(413, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, message)
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for VaultError {}

pub const LOCKED: &str = "保管庫はロックされています";
pub const CHANGED: &str = "保管庫の状態が変わりました。もう一度操作してください";
pub const NOT_FOUND: &str = "エントリが見つかりません";
pub const WRONG_PASSWORD: &str = "マスターパスワードが正しくありません";
pub const CONTEXT_FAILED: &str = "保管庫の検証に失敗しました。再起動して復旧を確認してください";
pub const WRITE_CONFLICT: &str = "保管庫の処理が競合しました。もう一度操作してください";
pub const KEY_LIMIT: &str = "保管庫の鍵更新が必要です";
pub const ENTRY_LIMIT: &str = "保管庫への新規登録は10000件まで対応しています";

pub fn locked() -> VaultError {
    VaultError::new(423, LOCKED)
}

pub fn changed() -> VaultError {
    VaultError::conflict(CHANGED)
}

pub fn not_found() -> VaultError {
    VaultError::new(404, NOT_FOUND)
}

pub fn context_failed() -> VaultError {
    VaultError::new(503, CONTEXT_FAILED)
}

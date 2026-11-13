//! The CIPHER VAULT core for the Rust app. It was ported from the TypeScript services of the
//! Electron app and returns the same results and messages, so the formats and the screen did not
//! change. Those services were removed after v0.9.0; the TypeScript files and functions that the
//! module comments name are in `apps/api` and `apps/electron` at the git tag v0.9.0.

pub mod audit;
pub mod backup;
pub mod crypto;
pub mod error;
pub mod files;
pub mod icons;
pub mod input;
pub mod maintenance;
pub mod password;
pub mod selection;
pub mod session;
pub mod unlock_guard;
pub mod v2;
pub mod vault;

pub use error::VaultError;
pub use session::LockReason;
pub use vault::Vault;

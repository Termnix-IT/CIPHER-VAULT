//! The CIPHER VAULT core for the Rust app. It follows the TypeScript services in apps/api, which
//! stay the reference until the Rust app replaces them, and returns the same results and messages.

pub mod audit;
pub mod backup;
pub mod crypto;
pub mod error;
pub mod files;
pub mod input;
pub mod legacy;
pub mod password;
pub mod selection;
pub mod session;
pub mod unlock_guard;
pub mod v2;
pub mod vault;

pub use error::VaultError;
pub use session::LockReason;
pub use vault::Vault;

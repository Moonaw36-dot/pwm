//! Platform-independent core of the Aegis password manager: the vault file
//! format, key derivation, data model, TOTP and password generation.
//!
//! No file I/O, UI or networking lives here, so the same code backs the
//! desktop app and the iOS app.

pub mod format;
pub mod generator;
pub mod model;
pub mod totp;
pub mod vault;

pub use format::KdfParams;
pub use model::{PasswordEntry, PasswordList, PasswordType};
pub use vault::UnlockedVault;

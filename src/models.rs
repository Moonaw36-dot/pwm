use serde::{Serialize, Deserialize};
use zeroize::Zeroizing;
use std::path::PathBuf;
use std::time::Instant;
use crate::strength::GenMode;
use arboard::Clipboard;
use crate::strength::StrengthResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub totp_secret: Option<String>,
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub custom_fields: Vec<(String, String)>,
    #[serde(default)]
    pub is_secure_note: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordList {
    pub entries: Vec<PasswordEntry>,
}

pub struct Vault {
    pub file_name: String,
    pub file_path: Option<PathBuf>,
    pub store: Option<PasswordList>,
    pub encryption_key: Option<Zeroizing<[u8; 32]>>,
    pub last_activity: Instant,
    pub lock_timeout_secs: u64,
    pub keyfile: Option<PathBuf>,
    pub keyfile_hash: Option<[u8; 32]>,
}

pub struct EntryForm {
    pub label: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub totp: String,
    pub url: String,
    pub tag: String,
    pub custom_fields: Vec<(String, String)>,
    pub is_secure_note: bool,
}

pub struct Generator {
    pub mode: GenMode,
    pub length: i32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub special: bool,
    pub ambiguous: bool,
    pub word_count: i32,
    pub separator: String,
}

pub struct Modals {
    pub add_password: bool,
    pub settings: bool,
    pub error_password: bool,
    pub warning_password: bool,
    pub gen_password: bool,
    pub gen_from_add: bool,
    pub filename: bool,
    pub master: bool,
    pub master_is_create: bool,
    pub confirm_delete: bool,
}

pub struct ClipboardState {
    pub handle: Clipboard,
    pub clear_at: Option<Instant>,
    pub copied_field: Option<String>,
    pub copied_clear_at: Option<Instant>,
}

pub struct AppState {
    pub vault: Vault,
    pub form: EntryForm,
    pub generator: Generator,
    pub modals: Modals,
    pub clipboard: ClipboardState,

    // One-off fields that don't belong in any group.
    pub search: String,
    pub filename_input: String,
    pub master_input: Zeroizing<String>,
    pub settings_timeout_mins: i32,
    pub edit_index: Option<usize>,
    pub delete_idx: Option<usize>,
    pub custom_error_message: Option<String>,
    pub custom_success_message: Option<String>,
    pub strength_cache: Option<(String, StrengthResult)>,
    pub hibp_cache: std::collections::HashMap<String, bool>,
}

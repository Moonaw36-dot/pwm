use serde::{Serialize, Deserialize};
use zeroize::Zeroizing;
use std::path::PathBuf;
use std::time::Instant;
use crate::strength::GenMode;
use arboard::Clipboard;
use crate::strength::StrengthResult;
use totp_rs::TOTP;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub notes: String,
    pub totp_secret: Option<String>,
    pub tags: Option<Vec<String>>,
    pub url: String,
    pub custom_fields: Vec<(String, String)>,
    pub is_secure_note: bool,
    pub created_at: Option<u64>,
    #[serde(skip)]
    pub totp_cache: Option<TOTP>,
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
    pub password: Zeroizing<String>,
    pub notes: String,
    pub totp: String,
    pub url: String,
    pub tag: String,
    pub custom_fields: Vec<(String, String)>,
    pub is_secure_note: bool,
}

pub struct Generator {
    pub mode: GenMode,
    pub length: u32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub special: bool,
    pub ambiguous: bool,
    pub word_count: u32,
    pub separator: String,
}

pub struct Modals {
    pub add_password: bool,
    pub close_add_password: bool,
    pub settings: bool,
    pub error_password: bool,
    pub warning_password: bool,
    pub gen_password: bool,
    pub gen_from_add: bool,
    pub filename: bool,
    pub master: bool,
    pub master_is_create: bool,
    pub confirm_delete: bool,
    pub show_success: bool,
    pub confirm_unsaved: bool,
}

pub struct ClipboardState {
    pub handle: Option<Clipboard>,
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
    pub settings_timeout_mins: u32,
    pub edit_index: Option<usize>,
    pub delete_idx: Option<usize>,
    pub custom_error_message: Option<String>,
    pub custom_success_message: Option<String>,
    pub strength_cache: Option<(Zeroizing<String>, StrengthResult)>,
    pub hibp_cache: std::collections::HashMap<String, bool>,
    pub pending_exit: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_entry_serde_roundtrip() {
        let entry = PasswordEntry {
            label: "example".into(),
            username: "alice".into(),
            password: Zeroizing::new("hunter2".into()),
            notes: "my note".into(),
            totp_secret: Some("SECRET".into()),
            tags: Some(vec!["tag1".into(), "tag2".into()]),
            url: "https://example.com".into(),
            custom_fields: vec![("key".into(), "value".into())],
            is_secure_note: false,
            created_at: Some(1234567890),
            totp_cache: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: PasswordEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.label, "example");
        assert_eq!(deserialized.password.as_str(), "hunter2");
        assert_eq!(deserialized.totp_secret.as_deref(), Some("SECRET"));
        let tags = deserialized.tags.unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0], "tag1");
        assert_eq!(tags[1], "tag2");
        assert_eq!(deserialized.custom_fields[0].0, "key");
        assert_eq!(deserialized.created_at, Some(1234567890));
    }

    #[test]
    fn test_password_entry_default() {
        let entry = PasswordEntry::default();
        assert!(entry.label.is_empty());
        assert!(entry.password.is_empty());
        assert!(entry.custom_fields.is_empty());
        assert!(!entry.is_secure_note);
    }

    #[test]
    fn test_password_list_serde() {
        let list = PasswordList {
            entries: vec![
                PasswordEntry {
                    label: "a".into(),
                    ..Default::default()
                },
                PasswordEntry {
                    label: "b".into(),
                    ..Default::default()
                },
            ],
        };

        let json = serde_json::to_string(&list).unwrap();
        let deserialized: PasswordList = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.entries.len(), 2);
        assert_eq!(deserialized.entries[0].label, "a");
    }
}

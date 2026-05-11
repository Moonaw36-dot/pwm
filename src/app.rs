pub use crate::models::{AppState, PasswordEntry, PasswordList};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;
use crate::file_ops::{open_file_dialog, save_store};
use crate::strength::{StrengthResult, manual_strength};

impl AppState {
    pub fn new() -> Self {
        Self {
            vault: crate::models::Vault {
                file_name: String::new(),
                file_path: None,
                store: None,
                encryption_key: None,
                last_activity: Instant::now(),
                lock_timeout_secs: crate::config::load().lock_timeout_secs,
                keyfile: None,
                keyfile_hash: None,
                keyfile_bytes: None,
            },
            form: crate::models::EntryForm {
                label: String::with_capacity(256),
                username: String::with_capacity(256),
                password: Zeroizing::new(String::with_capacity(256)),
                notes: String::with_capacity(256),
                totp: String::with_capacity(256),
                url: String::with_capacity(256),
                tag: String::with_capacity(256),
                is_secure_note: false,
                custom_fields: Vec::new(),
            },
            generator: crate::models::Generator {
                mode: crate::strength::GenMode::Password,
                length: 24,
                uppercase: true,
                lowercase: true,
                numbers: true,
                special: true,
                ambiguous: true,
                word_count: 5,
                separator: String::from("-"),
            },
            modals: crate::models::Modals {
                add_password: false,
                close_add_password: false,
                settings: false,
                error_password: false,
                warning_password: false,
                gen_password: false,
                gen_from_add: false,
                filename: false,
                master: false,
                master_is_create: false,
                confirm_delete: false,
                show_success: false,
                confirm_unsaved: false,
            },
            clipboard: crate::models::ClipboardState {
                handle: arboard::Clipboard::new()
                    .map_err(|_| log::warn!("System clipboard unavailable; clipboard operations disabled"))
                    .ok(),
                clear_at: None,
                copied_field: None,
                copied_clear_at: None,
            },

            search: String::with_capacity(256),
            filename_input: String::with_capacity(256),
            master_input: Zeroizing::new(String::new()),
            settings_timeout_mins: 0,
            edit_index: None,
            delete_idx: None,
            custom_error_message: None,
            custom_success_message: None,
            strength_cache: None,
            hibp_cache: std::collections::HashMap::new(),
            pending_exit: false,
        }
    }

    pub fn open_file(&mut self) {
        if let Some((name, path)) = open_file_dialog() {
            self.vault.file_name = name;
            let config = crate::config::load();
            self.vault.keyfile_hash = config.keyfile_hashes.get(path.as_path()).copied();
            self.vault.file_path = Some(path);
            self.modals.master = true;
        }
    }

    pub fn close_file(&mut self) {
        self.vault.store = None;
        self.vault.file_path = None;
        self.vault.file_name.clear();
        self.vault.encryption_key = None;
        self.vault.keyfile = None;
        self.vault.keyfile_hash = None;
        self.vault.keyfile_bytes = None;
    }

    pub fn clear_inputs(&mut self) {
        self.form.password = Zeroizing::new(String::new());
        self.form.custom_fields.clear();
        self.form.url.clear();
        self.form.label.clear();
        self.form.username.clear();
        self.form.notes.clear();
        self.form.tag.clear();
        self.form.totp.clear();
        self.form.is_secure_note = false;
    }

    pub fn cached_strength(&mut self, password: &str) -> StrengthResult {
        if let Some((ref cached_pw, result)) = self.strength_cache
            && **cached_pw == password
        {
            return result;
        }
        let result = manual_strength(password);
        self.strength_cache = Some((Zeroizing::new(password.to_string()), result));
        result
    }

    pub fn copy_to_clipboard(&mut self, text: &str, field_name: &str) {
        if let Some(ref mut handle) = self.clipboard.handle {
            crate::clipboard::set_excluded_from_history(handle, text);
        }
        self.clipboard.clear_at = Some(Instant::now() + Duration::from_secs(10));
        self.clipboard.copied_field = Some(field_name.to_string());
        self.clipboard.copied_clear_at = Some(Instant::now() + Duration::from_secs(3));
    }

    pub fn save(&mut self) {
        if let Some(key) = &self.vault.encryption_key
            && let Some(store) = &self.vault.store
            && let Err(e) = save_store(&self.vault.file_path, store, key) {
            self.custom_error_message = Some(e);
        }
    }
}

pub fn hash_password(password: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    password.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_cached_strength_cache_hit() {
        let mut state = AppState::new();
        let result = state.cached_strength("Abcdefg1!hijklmn");
        let cached = state.strength_cache.as_ref().unwrap();
        assert_eq!(cached.0.as_str(), "Abcdefg1!hijklmn");
        assert_eq!(cached.1, result);
    }

    #[test]
    fn test_cached_strength_cache_miss_updates() {
        let mut state = AppState::new();
        let r1 = state.cached_strength("weak");
        let r2 = state.cached_strength("Abcdefg1!hijklmn");
        assert_ne!(r1, r2);
        assert_eq!(state.strength_cache.as_ref().unwrap().0.as_str(), "Abcdefg1!hijklmn");
    }

    #[test]
    fn test_clear_inputs_zeroizes_password() {
        let mut state = AppState::new();
        state.form.password = Zeroizing::new("secret".into());
        state.form.label = "mylabel".into();
        state.form.custom_fields.push(("k".into(), "v".into()));

        state.clear_inputs();

        assert!(state.form.password.is_empty());
        assert!(state.form.label.is_empty());
        assert!(state.form.custom_fields.is_empty());
        assert!(!state.form.is_secure_note);
    }

    #[test]
    fn test_close_file_clears_store() {
        let mut state = AppState::new();
        state.vault.store = Some(PasswordList { entries: vec![] });
        state.vault.file_path = Some(PathBuf::from("/tmp/test.aegis"));
        state.vault.file_name = "test".into();
        state.vault.encryption_key = Some(Zeroizing::new([1u8; 32]));

        state.close_file();

        assert!(state.vault.store.is_none());
        assert!(state.vault.file_path.is_none());
        assert!(state.vault.file_name.is_empty());
        assert!(state.vault.encryption_key.is_none());
    }
}

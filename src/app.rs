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
            },
            form: crate::models::EntryForm {
                label: String::with_capacity(256),
                username: String::with_capacity(256),
                password: String::with_capacity(256),
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
                settings: false,
                error_password: false,
                warning_password: false,
                gen_password: false,
                gen_from_add: false,
                filename: false,
                master: false,
                master_is_create: false,
                confirm_delete: false,
            },
            clipboard: crate::models::ClipboardState {
                handle: arboard::Clipboard::new().expect("Failed to access system clipboard"),
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
    }

    pub fn clear_inputs(&mut self) {
        self.form.password.clear();
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
            && cached_pw == password
        {
            return result;
        }
        let result = manual_strength(password);
        self.strength_cache = Some((password.to_string(), result));
        result
    }

    pub fn copy_to_clipboard(&mut self, text: &str, field_name: &str) {
        crate::clipboard::set_excluded_from_history(&mut self.clipboard.handle, text);
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

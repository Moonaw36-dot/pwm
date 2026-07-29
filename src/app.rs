use crate::file_ops::{open_file_dialog, save_store};
pub use crate::models::{AppState, PasswordEntry, PasswordList};
use crate::models::{ClipboardState, EntryForm, Generator, Modals, PasswordType, Vault};
use crate::strength::{StrengthResult, manual_strength};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const INPUT_CAPACITY: usize = 256;
const CLIPBOARD_CLEAR_SECS: u64 = 10;
const COPIED_NOTICE_SECS: u64 = 3;

impl Vault {
    fn new(config: &crate::config::Config) -> Self {
        Self {
            file_name: String::new(),
            file_path: None,
            filesize: None,
            store: None,
            encryption_key: None,
            last_activity: Instant::now(),
            lock_timeout_secs: config.lock_timeout_secs,
            iterations: 3,
            keyfile: None,
            keyfile_hash: None,
            keyfile_bytes: None,
        }
    }
}

impl EntryForm {
    fn new() -> Self {
        Self {
            iterations_entry: 3,
            label: String::with_capacity(INPUT_CAPACITY),
            username: String::with_capacity(INPUT_CAPACITY),
            password: Zeroizing::new(String::with_capacity(INPUT_CAPACITY)),
            notes: Zeroizing::new(String::with_capacity(INPUT_CAPACITY)),
            totp: Zeroizing::new(String::with_capacity(INPUT_CAPACITY)),
            url: String::with_capacity(INPUT_CAPACITY),
            tag: String::with_capacity(INPUT_CAPACITY),
            custom_fields: Zeroizing::new(Vec::new()),
            password_type: PasswordType::Normal,
            is_secure_note: false,
            number: Zeroizing::new(String::with_capacity(INPUT_CAPACITY)),
            expiration_date: Zeroizing::new(String::with_capacity(INPUT_CAPACITY)),
            cvc: Zeroizing::new(String::with_capacity(INPUT_CAPACITY)),
        }
    }

    fn clear(&mut self) {
        *self = Self::new();
    }
}

impl Generator {
    fn new() -> Self {
        Self {
            mode: crate::strength::GenMode::Password,
            length: 24,
            uppercase: true,
            lowercase: true,
            numbers: true,
            special: true,
            ambiguous: true,
            word_count: 5,
            separator: String::from("-"),
        }
    }
}

impl Modals {
    fn new() -> Self {
        Self {
            add_password: false,
            add_entry_popup: false,
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
        }
    }
}

impl ClipboardState {
    fn new() -> Self {
        Self {
            handle: arboard::Clipboard::new()
                .map_err(|_| {
                    log::warn!("System clipboard unavailable; clipboard operations disabled")
                })
                .ok(),
            clear_at: None,
            copied_field: None,
            copied_clear_at: None,
        }
    }

    fn clear_clipboard_text(&mut self) {
        if let Some(ref mut handle) = self.handle {
            crate::clipboard::set_excluded_from_history(handle, "");
        }
    }

    pub fn clear_expired(&mut self, now: Instant) {
        if self.clear_at.is_some_and(|clear_at| now >= clear_at) {
            self.clear_clipboard_text();
            self.clear_at = None;
        }

        if self.copied_clear_at.is_some_and(|clear_at| now >= clear_at) {
            self.copied_clear_at = None;
            self.copied_field = None;
        }
    }

    fn reset(&mut self) {
        self.clear_clipboard_text();
        self.clear_at = None;
        self.copied_field = None;
        self.copied_clear_at = None;
    }

    fn copy(&mut self, text: &str, field_name: &str) {
        if let Some(ref mut handle) = self.handle {
            crate::clipboard::set_excluded_from_history(handle, text);
        }

        let now = Instant::now();
        self.clear_at = Some(now + Duration::from_secs(CLIPBOARD_CLEAR_SECS));
        self.copied_field = Some(field_name.to_string());
        self.copied_clear_at = Some(now + Duration::from_secs(COPIED_NOTICE_SECS));
    }
}

impl AppState {
    pub fn new() -> Self {
        let config = crate::config::load();

        Self {
            vault: Vault::new(&config),
            form: EntryForm::new(),
            generator: Generator::new(),
            modals: Modals::new(),
            clipboard: ClipboardState::new(),

            has_chosen_type: false,
            search: String::with_capacity(INPUT_CAPACITY),
            filename_input: String::with_capacity(INPUT_CAPACITY),
            master_input: Zeroizing::new(String::new()),
            master_confirm_input: Zeroizing::new(String::new()),
            settings_timeout_mins: 0,
            edit_index: None,
            delete_idx: None,
            custom_error_message: None,
            custom_success_message: None,
            strength_cache: None,
            hibp_cache: std::collections::HashMap::new(),
            hibp_pending: None,
            pending_exit: false,
            should_exit: false,
            light_mode: config.light_mode,
            settings_light_mode: config.light_mode,
            self_destruct_pass: config.self_destruct_pass,
            card_texture: None,
        }
    }

    pub fn open_file(&mut self) {
        if let Some((name, path)) = open_file_dialog() {
            self.close_file();
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
        self.clear_inputs();
        self.master_input = Zeroizing::new(String::new());
        self.master_confirm_input = Zeroizing::new(String::new());
        self.strength_cache = None;
        self.edit_index = None;
        self.delete_idx = None;
        self.clipboard.reset();
        self.hibp_cache.clear();
        self.hibp_pending = None;
    }

    pub fn clear_inputs(&mut self) {
        self.form.clear();
        self.has_chosen_type = false;
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
        self.clipboard.copy(text, field_name);
    }

    pub fn save_result(&mut self) -> Result<(), String> {
        if let Some(key) = &self.vault.encryption_key
            && let Some(store) = &self.vault.store
        {
            save_store(&self.vault.file_path, store, key, self.vault.iterations)?;
        }
        Ok(())
    }

    pub fn save(&mut self) {
        if let Err(e) = self.save_result() {
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
        assert_eq!(
            state.strength_cache.as_ref().unwrap().0.as_str(),
            "Abcdefg1!hijklmn"
        );
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

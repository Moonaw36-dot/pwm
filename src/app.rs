use crate::config;
use crate::file_ops::{VaultKdfParams, open_file_dialog, save_store};
pub use crate::models::{AppState, PasswordEntry, PasswordList};
use crate::models::{ClipboardState, EntryForm, Generator, Modals, PasswordType, Vault};
use crate::strength::{StrengthResult, manual_strength};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

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
            kdf_params: None,
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
            use_lastused_file: false,
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
            external_copy_pending: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn backend_signal(&self) -> Arc<AtomicBool> {
        self.external_copy_pending.clone()
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
        self.external_copy_pending.store(false, Ordering::Release);
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

    pub fn sync_external_copy(&mut self) {
        if !self.external_copy_pending.swap(false, Ordering::AcqRel) {
            return;
        }

        let now = Instant::now();
        self.clear_at = Some(now + Duration::from_secs(CLIPBOARD_CLEAR_SECS));
        self.copied_field = Some("value".to_string());
        self.copied_clear_at = Some(now + Duration::from_secs(COPIED_NOTICE_SECS));
    }
}

impl AppState {
    pub fn new() -> Self {
        let config = crate::config::load();

        let mut modals = Modals::new();
        modals.use_lastused_file = config.last_used_file.is_file();

        Self {
            vault: Vault::new(&config),
            form: EntryForm::new(),
            generator: Generator::new(),
            modals,
            clipboard: ClipboardState::new(),

            has_chosen_type: false,
            search: String::with_capacity(INPUT_CAPACITY),
            filename_input: String::with_capacity(INPUT_CAPACITY),
            master_input: Zeroizing::new(String::new()),
            master_confirm_input: Zeroizing::new(String::new()),
            settings_timeout_mins: 0,
            edit_index: None,
            delete_idx: None,
            trash_purge_pending: None,
            trash_empty_pending: false,
            custom_error_message: None,
            custom_success_message: None,
            strength_cache: None,
            generated_password: Zeroizing::new(String::new()),
            hibp_cache: std::collections::HashMap::new(),
            hibp_pending: Vec::new(),
            hibp_cancel: None,
            health_cache: None,
            search_cache: None,
            should_exit: false,
            failed_unlocks: 0,
            unlock_penalty_until: None,
            light_mode: config.light_mode,
            settings_light_mode: config.light_mode,
            hide_user: config.hide_user,
            // input buffer only; the stored value is a hash
            self_destruct_pass: Zeroizing::new(String::new()),
            invert_copy_controls: false,
            card_texture: None,
        }
    }

    pub fn open_file(&mut self) {
        if let Some((name, path)) = open_file_dialog() {
            self.close_file();
            self.vault.file_name = name;
            let mut config = crate::config::load();
            config.last_used_file = path.clone();
            let _ = config::save(&config);
            self.vault.keyfile_hash = config.keyfile_hashes.get(path.as_path()).copied();
            self.vault.file_path = Some(path);
            self.modals.master = true;
        }
    }

    pub fn close_file(&mut self) {
        self.lock_file();
        self.vault.file_path = None;
        self.vault.file_name.clear();
        self.vault.keyfile_hash = None;
    }

    pub fn clear_inputs(&mut self) {
        self.form.clear();
        self.has_chosen_type = false;
    }

    pub fn invalidate_vault_caches(&mut self) {
        self.health_cache = None;
        self.search_cache = None;
    }

    pub fn cancel_unlock(&mut self) {
        self.master_input.zeroize();
        self.master_confirm_input.zeroize();
        self.vault.keyfile = None;
        self.vault.keyfile_bytes = None;
        self.vault.keyfile_hash = None;
        self.vault.kdf_params = None;
        self.vault.file_path = None;
        self.vault.file_name.clear();
        self.vault.filesize = None;
        self.filename_input.clear();
        self.clear_inputs();
        self.clipboard.reset();
        self.modals.master_is_create = false;
    }

    pub fn lock_file(&mut self) {
        self.vault.store = None;
        self.vault.encryption_key = None;
        self.vault.kdf_params = None;
        self.vault.keyfile = None;
        self.vault.keyfile_bytes = None;
        self.clear_inputs();
        self.master_input.zeroize();
        self.master_confirm_input.zeroize();
        self.self_destruct_pass.zeroize();
        self.search.clear();
        self.strength_cache = None;
        self.hibp_cache.clear();
        self.invalidate_vault_caches();
        if let Some(cancel) = self.hibp_cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        self.hibp_pending = Vec::new();
        self.edit_index = None;
        self.delete_idx = None;
        self.trash_purge_pending = None;
        self.trash_empty_pending = false;
        self.custom_error_message = None;
        self.custom_success_message = None;
        self.modals = Modals::new();
        self.clipboard.reset();
        self.vault.last_activity = Instant::now();
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
            let params = self.vault.kdf_params.unwrap_or(VaultKdfParams {
                m_cost: 65536,
                t_cost: self.vault.iterations,
                p_cost: 1,
            });
            save_store(&self.vault.file_path, store, key, params)?;
        }
        Ok(())
    }

    pub fn save(&mut self) {
        if let Err(e) = self.save_result() {
            self.custom_error_message = Some(e);
        }
    }
}

pub fn hash_password(password: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(password.as_bytes()).into()
}

/// Backoff before the next unlock attempt, in seconds, after the given number
/// of failed attempts. The first three failures are free; each subsequent
/// failure doubles the wait, capped at one minute. This is an in-app speed
/// bump only: it resets when the app restarts and does not protect the vault
/// file from offline attacks — Argon2id remains the real defense.
pub fn unlock_penalty_secs(failed_unlocks: u32) -> u64 {
    if failed_unlocks < 3 {
        return 0;
    }
    1u64 << (failed_unlocks - 3).min(6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_unlock_penalty_schedule() {
        assert_eq!(unlock_penalty_secs(0), 0);
        assert_eq!(unlock_penalty_secs(1), 0);
        assert_eq!(unlock_penalty_secs(2), 0);
        assert_eq!(unlock_penalty_secs(3), 1);
        assert_eq!(unlock_penalty_secs(4), 2);
        assert_eq!(unlock_penalty_secs(5), 4);
        assert_eq!(unlock_penalty_secs(8), 32);
        assert_eq!(unlock_penalty_secs(9), 64);
        assert_eq!(unlock_penalty_secs(50), 64);
    }

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
    fn test_copy_to_clipboard_schedules_auto_clear() {
        let mut state = AppState::new();
        state.copy_to_clipboard("s3cret", "password");

        let clear_at = state
            .clipboard
            .clear_at
            .expect("copy must arm the 10s auto-clear timer");
        assert_eq!(state.clipboard.copied_field.as_deref(), Some("password"));

        state
            .clipboard
            .clear_expired(clear_at - Duration::from_secs(1));
        assert!(state.clipboard.clear_at.is_some());

        state
            .clipboard
            .clear_expired(clear_at + Duration::from_secs(1));
        assert!(state.clipboard.clear_at.is_none());
    }

    #[test]
    fn test_external_clipboard_copy_schedules_auto_clear() {
        let mut state = AppState::new();
        state
            .clipboard
            .external_copy_pending
            .store(true, std::sync::atomic::Ordering::Release);

        state.clipboard.sync_external_copy();

        assert!(state.clipboard.clear_at.is_some());
        assert_eq!(state.clipboard.copied_field.as_deref(), Some("value"));
    }

    #[test]
    fn test_cancel_unlock_clears_keyfile_and_path_state() {
        let mut state = AppState::new();
        state.vault.file_path = Some(PathBuf::from("/tmp/vault.aegis"));
        state.vault.file_name = "vault.aegis".into();
        state.vault.keyfile = Some(PathBuf::from("/tmp/keyfile.aegis"));
        state.vault.keyfile_bytes = Some(Zeroizing::new(vec![1, 2, 3]));
        state.vault.keyfile_hash = Some([4; 32]);
        state.master_input = Zeroizing::new("secret".into());

        state.cancel_unlock();

        assert!(state.vault.file_path.is_none());
        assert!(state.vault.keyfile.is_none());
        assert!(state.vault.keyfile_bytes.is_none());
        assert!(state.vault.keyfile_hash.is_none());
        assert!(state.master_input.is_empty());
    }

    #[test]
    fn test_lock_file_clears_sensitive_state_but_keeps_path() {
        let mut state = AppState::new();
        state.vault.store = Some(PasswordList { entries: vec![] });
        state.vault.file_path = Some(PathBuf::from("/tmp/test.aegis"));
        state.vault.encryption_key = Some(crate::locked_buf::LockedKey::from_array([1u8; 32]));
        state.vault.keyfile = Some(PathBuf::from("/tmp/keyfile.aegis"));
        state.vault.keyfile_bytes = Some(Zeroizing::new(vec![2u8; 32]));
        state.form.password = Zeroizing::new("secret".into());
        state.master_input = Zeroizing::new("master".into());
        state.self_destruct_pass = Zeroizing::new("duress".into());
        state.search = "secret".into();
        state.modals.add_password = true;
        let hibp_cancel = Arc::new(AtomicBool::new(false));
        state.hibp_cancel = Some(hibp_cancel.clone());

        state.lock_file();

        assert!(state.vault.store.is_none());
        assert!(state.vault.encryption_key.is_none());
        assert!(state.vault.keyfile.is_none());
        assert!(state.vault.keyfile_bytes.is_none());
        assert!(state.vault.file_path.is_some());
        assert!(state.form.password.is_empty());
        assert!(state.master_input.is_empty());
        assert!(state.self_destruct_pass.is_empty());
        assert!(state.search.is_empty());
        assert!(!state.modals.add_password);
        assert!(hibp_cancel.load(Ordering::Acquire));
    }

    #[test]
    fn test_close_file_clears_store() {
        let mut state = AppState::new();
        state.vault.store = Some(PasswordList { entries: vec![] });
        state.vault.file_path = Some(PathBuf::from("/tmp/test.aegis"));
        state.vault.file_name = "test".into();
        state.vault.encryption_key = Some(crate::locked_buf::LockedKey::from_array([1u8; 32]));

        state.close_file();

        assert!(state.vault.store.is_none());
        assert!(state.vault.file_path.is_none());
        assert!(state.vault.file_name.is_empty());
        assert!(state.vault.encryption_key.is_none());
    }
}

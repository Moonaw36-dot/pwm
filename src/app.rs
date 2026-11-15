use crate::clipboard;
use crate::config;
use crate::file_ops::{VaultKdfParams, open_file_dialog, save_store};
pub use crate::models::{AppState, PasswordEntry, PasswordList};
use crate::models::{ClipboardState, EntryForm, Generator, Modals, PasswordType, Vault};
use crate::strength::{StrengthResult, live_strength};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime};
use zeroize::{Zeroize, Zeroizing};

const INPUT_CAPACITY: usize = 256;
const CLIPBOARD_CLEAR_SECS: u64 = 10;
const CLIPBOARD_CLEAR_RETRY_SECS: u64 = 2;
const COPIED_NOTICE_SECS: u64 = 3;
const CLIPBOARD_RETRIES: u32 = 3;

/// AEGIS_FRAME_DEBUG, read once; never set in release builds.
pub fn frame_debug() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    cfg!(debug_assertions) && *FLAG.get_or_init(|| std::env::var_os("AEGIS_FRAME_DEBUG").is_some())
}

impl Vault {
    fn new(config: &crate::config::Config) -> Self {
        Self {
            file_name: String::new(),
            file_path: None,
            store: None,
            encryption_key: None,
            last_activity: Instant::now(),
            last_activity_wall: SystemTime::now(),
            lock_timeout_secs: config.lock_timeout_secs,
            iterations: 3,
            kdf_params: None,
            keyfile: None,
            keyfile_hash: None,
            keyfile_bytes: None,
            file_stamp: None,
            stamp_checked: Instant::now(),
        }
    }
}

impl Vault {
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        self.last_activity_wall = SystemTime::now();
    }

    /// Time since the last activity. Instant stops during suspend on some
    /// platforms, so the wall clock is consulted too and the larger wins.
    pub fn idle_for(&self) -> Duration {
        let wall = self.last_activity_wall.elapsed().unwrap_or_default();
        self.last_activity.elapsed().max(wall)
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
            warning_password: false,
            gen_password: false,
            gen_into_form: false,
            filename: false,
            master: false,
            master_is_create: false,
            modify_entry: false,
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
            clear_at_wall: None,
            copied_field: None,
            copied_clear_at: None,
            copied_fingerprint: None,
            external_copy_pending: Arc::new(AtomicBool::new(false)),
            external_copy_fingerprint: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn backend_signal(&self) -> Arc<AtomicBool> {
        self.external_copy_pending.clone()
    }

    pub fn backend_fingerprint_signal(&self) -> Arc<AtomicU64> {
        self.external_copy_fingerprint.clone()
    }

    /// Wipe the clipboard when it still holds what we wrote. Returns true
    /// when there is nothing left to clear (either wiped or given up on).
    fn clear_clipboard_text(&mut self) -> bool {
        let Some(ref mut handle) = self.handle else {
            return true;
        };

        // Never destroy a value the user copied in the meantime. When the
        // clipboard holds non-text data, leave it alone too. Other read
        // errors are usually transient, so try a few times before deferring.
        if let Some(fingerprint) = self.copied_fingerprint {
            let mut current = None;
            for attempt in 0..CLIPBOARD_RETRIES {
                match handle.get_text() {
                    Ok(text) => {
                        current = Some(text);
                        break;
                    }
                    Err(arboard::Error::ContentNotAvailable) => {
                        self.copied_fingerprint = None;
                        return true;
                    }
                    Err(_) if attempt + 1 < CLIPBOARD_RETRIES => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => {}
                }
            }
            let Some(current) = current else {
                return false;
            };
            if clipboard::fingerprint(&current) != fingerprint {
                self.copied_fingerprint = None;
                return true;
            }
        }

        if clipboard::set_excluded_from_history(handle, "").is_ok() {
            self.copied_fingerprint = None;
            return true;
        }
        false
    }

    pub fn clear_expired(&mut self, now: Instant) {
        // The monotonic clock can pause across suspend; the wall clock cannot.
        let wall_due = self
            .clear_at_wall
            .is_some_and(|due| SystemTime::now() >= due);
        if wall_due || self.clear_at.is_some_and(|clear_at| now >= clear_at) {
            if self.clear_clipboard_text() {
                self.clear_at = None;
                self.clear_at_wall = None;
            } else {
                // Transient clipboard failure: retry shortly instead of
                // leaving the secret on the system clipboard forever.
                self.clear_at = Some(now + Duration::from_secs(CLIPBOARD_CLEAR_RETRY_SECS));
                self.clear_at_wall =
                    Some(SystemTime::now() + Duration::from_secs(CLIPBOARD_CLEAR_RETRY_SECS));
            }
        }

        if self.copied_clear_at.is_some_and(|clear_at| now >= clear_at) {
            self.copied_clear_at = None;
            self.copied_field = None;
        }
    }

    fn reset(&mut self) {
        // Lock and close wipe the clipboard unconditionally: a residual
        // secret outliving the vault is worse than clobbering unrelated
        // clipboard content.
        self.copied_fingerprint = None;
        for attempt in 0..CLIPBOARD_RETRIES {
            if self.clear_clipboard_text() {
                break;
            }
            if attempt + 1 < CLIPBOARD_RETRIES {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        self.clear_at = None;
        self.clear_at_wall = None;
        self.copied_field = None;
        self.copied_clear_at = None;
        self.external_copy_pending.store(false, Ordering::Release);
        self.external_copy_fingerprint.store(0, Ordering::Release);
    }

    fn arm_clear(&mut self, now: Instant) {
        let after = Duration::from_secs(CLIPBOARD_CLEAR_SECS);
        self.clear_at = Some(now + after);
        self.clear_at_wall = Some(SystemTime::now() + after);
    }

    fn copy(&mut self, text: &str, field_name: &str) -> bool {
        let Some(ref mut handle) = self.handle else {
            return false;
        };
        if clipboard::set_excluded_from_history(handle, text).is_err() {
            return false;
        }

        self.copied_fingerprint = Some(clipboard::fingerprint(text));
        let now = Instant::now();
        self.arm_clear(now);
        self.copied_field = Some(field_name.to_string());
        self.copied_clear_at = Some(now + Duration::from_secs(COPIED_NOTICE_SECS));
        true
    }

    pub fn sync_external_copy(&mut self) {
        if !self.external_copy_pending.swap(false, Ordering::AcqRel) {
            return;
        }

        self.copied_fingerprint = Some(self.external_copy_fingerprint.swap(0, Ordering::AcqRel));
        let now = Instant::now();
        self.arm_clear(now);
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
            settings_hide_user: config.hide_user,
            settings_invert_copy_controls: config.invert_copy_controls,
            hide_user: config.hide_user,
            // input buffer only; the stored value is a hash
            self_destruct_pass: Zeroizing::new(String::new()),
            invert_copy_controls: config.invert_copy_controls,
            card_texture: None,
            font_bold: None,
            health_worker: None,
            health_generation: 0,
            list_search: String::with_capacity(INPUT_CAPACITY),
        }
    }

    pub fn open_file(&mut self) {
        if let Some((name, path)) = open_file_dialog() {
            self.close_file();
            self.vault.file_name = name;
            let mut config = crate::config::load();
            config.last_used_file = path.clone();
            if let Err(e) = config::save(&config) {
                self.custom_error_message = Some(e);
            }
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

    pub fn lock_if_idle(&mut self) {
        let timeout = self.vault.lock_timeout_secs;
        if self.vault.store.is_none() || timeout == 0 {
            return;
        }
        if self.vault.idle_for().as_secs() >= timeout {
            self.lock_file();
            self.modals.master = true;
        }
    }

    pub fn clear_inputs(&mut self) {
        self.form.clear();
        self.has_chosen_type = false;
    }

    pub fn invalidate_vault_caches(&mut self) {
        self.health_cache = None;
        self.health_worker = None;
        self.health_generation += 1;
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
        self.vault.file_stamp = None;
        self.clear_inputs();
        self.master_input.zeroize();
        self.master_confirm_input.zeroize();
        self.self_destruct_pass.zeroize();
        self.search.clear();
        self.list_search.clear();
        self.filename_input.clear();
        self.generated_password = Zeroizing::new(String::new());
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
        self.vault.touch();
    }

    pub fn cached_strength(&mut self, password: &str) -> StrengthResult {
        if let Some((ref cached_pw, result)) = self.strength_cache
            && **cached_pw == password
        {
            return result;
        }
        let t = Instant::now();
        let result = live_strength(password);
        if frame_debug() {
            eprintln!("[strength] zxcvbn recompute took {:?}", t.elapsed());
        }
        self.strength_cache = Some((Zeroizing::new(password.to_string()), result));
        result
    }

    pub fn copy_to_clipboard(&mut self, text: &str, field_name: &str) {
        if !self.clipboard.copy(text, field_name) {
            self.custom_error_message = Some("Could not access the system clipboard.".to_string());
        }
    }

    pub fn save_result(&mut self) -> Result<(), String> {
        let (Some(key), Some(store)) = (&self.vault.encryption_key, &self.vault.store) else {
            return Err("No unlocked vault to save.".to_string());
        };
        // Another process (the extension host) may have written since we
        // loaded; saving now would silently drop its changes.
        if let Some((path, known)) = &self.vault.file_stamp
            && self.vault.file_path.as_ref() == Some(path)
            && std::fs::metadata(path).and_then(|m| m.modified()).ok() != Some(*known)
        {
            return Err(
                "The vault changed on disk since it was loaded. Nothing was saved; it will reload, then repeat your change."
                    .to_string(),
            );
        }
        let params = self.vault.kdf_params.unwrap_or(VaultKdfParams {
            m_cost: crate::file_ops::DEFAULT_M_COST,
            t_cost: self.vault.iterations,
            p_cost: 1,
        });
        save_store(&self.vault.file_path, store, key, params)?;
        self.record_file_stamp();
        Ok(())
    }

    fn record_file_stamp(&mut self) {
        self.vault.file_stamp = self.vault.file_path.as_ref().and_then(|path| {
            let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
            Some((path.clone(), modified))
        });
    }

    /// The browser-extension host writes to the same vault file. Re-read it
    /// when it changed, so the next GUI save cannot overwrite those writes.
    pub fn reload_if_changed_on_disk(&mut self) {
        if self.vault.store.is_none()
            || self.vault.stamp_checked.elapsed() < std::time::Duration::from_secs(1)
        {
            return;
        }
        self.vault.stamp_checked = Instant::now();

        let Some(path) = self.vault.file_path.clone() else {
            return;
        };
        let Some(modified) = std::fs::metadata(&path).and_then(|m| m.modified()).ok() else {
            return;
        };
        // First look at this vault: nothing to compare against yet.
        let Some((known_path, known_time)) = self.vault.file_stamp.clone() else {
            self.vault.file_stamp = Some((path, modified));
            return;
        };
        if known_path != path {
            self.vault.file_stamp = Some((path, modified));
            return;
        }
        if known_time == modified {
            return;
        }

        let Some(key) = &self.vault.encryption_key else {
            return;
        };
        match crate::file_ops::reload_store_with_key(&path, key) {
            Ok(store) => {
                self.vault.store = Some(store);
                self.vault.file_stamp = Some((path, modified));
                self.invalidate_vault_caches();
                // Indices pointed into the old list.
                if self.edit_index.take().is_some() {
                    self.clear_inputs();
                }
                self.modals.modify_entry = false;
                self.delete_idx = None;
                self.trash_purge_pending = None;
                self.trash_empty_pending = false;
            }
            // The stamp stays old, so saves are refused until a reload works.
            Err(error) => log::warn!("Vault changed on disk but could not be reloaded: {error}"),
        }
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
/// failure doubles the wait, capped at 64 seconds. This is an in-app speed
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
    fn reload_picks_up_writes_from_another_process() {
        let _env = crate::file_ops::config_env_guard();
        use crate::file_ops::{VaultKdfParams, load_store, save_store, write_new_vault_file};
        use rand::RngExt;

        let path = std::env::temp_dir().join(format!(
            "aegis-reload-{:016x}.aegis",
            rand::rng().random::<u64>()
        ));
        let params = VaultKdfParams {
            m_cost: 2048,
            t_cost: 2,
            p_cost: 1,
        };
        let initial = PasswordList {
            entries: vec![PasswordEntry {
                label: "first".into(),
                ..Default::default()
            }],
        };
        write_new_vault_file(&path, &initial, "master pw 123", params, None).unwrap();
        let (store, key, params) = load_store(&path, "master pw 123", None).unwrap();

        let mut state = AppState::new();
        state.vault.file_path = Some(path.clone());
        state.vault.store = Some(store);
        state.vault.encryption_key = Some(key);
        let overdue = Instant::now() - std::time::Duration::from_secs(5);

        // First look only records the file's timestamp.
        state.vault.stamp_checked = overdue;
        state.reload_if_changed_on_disk();
        assert_eq!(state.vault.store.as_ref().unwrap().entries.len(), 1);

        // Unchanged file: nothing to do, even when the check is due.
        state.vault.stamp_checked = overdue;
        state.reload_if_changed_on_disk();
        assert_eq!(state.vault.store.as_ref().unwrap().entries.len(), 1);

        // Another process (the browser-extension host) appends an entry.
        let (mut external, external_key, _) = load_store(&path, "master pw 123", None).unwrap();
        external.entries.push(PasswordEntry {
            label: "from extension".into(),
            ..Default::default()
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        save_store(&Some(path.clone()), &external, &external_key, params).unwrap();

        // Not due yet: the once-per-second throttle holds.
        state.vault.stamp_checked = Instant::now();
        state.reload_if_changed_on_disk();
        assert_eq!(state.vault.store.as_ref().unwrap().entries.len(), 1);

        state.vault.stamp_checked = overdue;
        state.reload_if_changed_on_disk();
        let labels: Vec<_> = state
            .vault
            .store
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .map(|e| e.label.as_str())
            .collect();
        assert_eq!(labels, ["first", "from extension"]);

        // Our own save must not be mistaken for an external change.
        state.save();
        state.vault.stamp_checked = overdue;
        state.reload_if_changed_on_disk();
        assert_eq!(state.vault.store.as_ref().unwrap().entries.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

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
        state.generated_password = Zeroizing::new("g3n3rated".into());
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
        assert!(state.generated_password.is_empty());
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

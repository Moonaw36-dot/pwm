use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Set when the config on disk could not be read or parsed; saving would
/// then replace records we failed to load (duress, keyfile hashes).
static LOAD_FAILURE: Mutex<Option<String>> = Mutex::new(None);

fn note_load_failure(message: String) {
    if let Ok(mut slot) = LOAD_FAILURE.lock() {
        *slot = Some(message);
    }
}

// Same cost as the vault KDF defaults. Older hashes have no recorded costs
// and keep verifying with the Argon2 crate defaults they were made with.
const DURESS_M_COST: u32 = crate::file_ops::DEFAULT_M_COST;
const DURESS_T_COST: u32 = 3;
const DURESS_P_COST: u32 = 1;
const DURESS_MAX_M_COST: u32 = 1 << 20;
const DURESS_MAX_T_COST: u32 = 20;

/// Duress password, stored as an Argon2id hash with a random salt.
/// The plaintext is never written to disk.
#[derive(Serialize, Deserialize)]
pub struct Duress {
    #[serde(default)]
    salt: Zeroizing<String>,
    #[serde(default)]
    hash: Zeroizing<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    costs: Option<[u32; 3]>,
}

impl Default for Duress {
    fn default() -> Self {
        Self {
            salt: Zeroizing::new(String::new()),
            hash: Zeroizing::new(String::new()),
            costs: None,
        }
    }
}

fn duress_argon(costs: Option<[u32; 3]>) -> Option<Argon2<'static>> {
    let Some([m, t, p]) = costs else {
        return Some(Argon2::default());
    };
    if m > DURESS_MAX_M_COST || t > DURESS_MAX_T_COST {
        return None;
    }
    let params = Params::new(m, t, p, Some(32)).ok()?;
    Some(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

impl Duress {
    /// Build a duress hash for `password`.
    pub fn new(password: &str) -> Self {
        let mut duress = Self::default();
        duress.set(password);
        duress
    }

    /// Set a new duress password; an empty password disables duress mode.
    pub fn set(&mut self, password: &str) {
        if password.is_empty() {
            self.salt = Zeroizing::new(String::new());
            self.hash = Zeroizing::new(String::new());
            self.costs = None;
            return;
        }
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let mut hash = [0u8; 32];
        let costs = [DURESS_M_COST, DURESS_T_COST, DURESS_P_COST];
        duress_argon(Some(costs))
            .expect("duress params are valid")
            .hash_password_into(password.as_bytes(), &salt, &mut hash)
            .expect("duress params are valid");
        self.salt = Zeroizing::new(hex(&salt));
        self.hash = Zeroizing::new(hex(&hash));
        self.costs = Some(costs);
    }

    /// True when no duress password is configured.
    pub fn is_empty(&self) -> bool {
        self.salt.is_empty() && self.hash.is_empty()
    }

    /// True if a duress password is configured and `password` matches it.
    pub fn matches(&self, password: &str) -> bool {
        let (Ok(salt), Ok(expected)) = (unhex(&self.salt), unhex(&self.hash)) else {
            return false;
        };
        let Some(argon) = duress_argon(self.costs) else {
            return false;
        };
        let mut actual = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(password.as_bytes(), &salt, &mut *actual)
            .is_ok()
            && ct_eq(&*actual, &expected)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unhex(s: &str) -> Result<Vec<u8>, ()> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hi = hex_val(pair[0]).ok_or(())?;
            let lo = hex_val(pair[1]).ok_or(())?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub light_mode: bool,
    #[serde(default = "default_lock_timeout_secs")]
    pub lock_timeout_secs: u64,
    /// Duress password per vault path; entering it at that vault's unlock
    /// opens the vault's decoy instead of the real vault.
    #[serde(default)]
    pub duress_by_vault: HashMap<PathBuf, Duress>,
    /// Pre-decoy configs kept one global duress hash under the "duress" key.
    /// Migrated to `duress_by_vault` on load. Never written back.
    #[serde(default, rename = "duress", skip_serializing)]
    legacy_duress: Duress,
    /// Legacy plaintext field, migrated to `duress_by_vault` on load. Never written back.
    #[serde(default, skip_serializing)]
    pub self_destruct_pass: Zeroizing<String>,
    #[serde(default)]
    pub keyfile_hashes: HashMap<PathBuf, [u8; 32]>,
    #[serde(default)]
    pub last_used_file: PathBuf,
    #[serde(default)]
    pub hide_user: bool,
    #[serde(default = "default_invert_copy_controls")]
    pub invert_copy_controls: bool,
    /// Directory for automatic vault backups; `None` disables backups.
    #[serde(default)]
    pub backup_dir: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            light_mode: false,
            lock_timeout_secs: default_lock_timeout_secs(),
            duress_by_vault: HashMap::new(),
            legacy_duress: Duress::default(),
            self_destruct_pass: Zeroizing::new(String::new()),
            keyfile_hashes: Default::default(),
            last_used_file: PathBuf::new(),
            hide_user: false,
            invert_copy_controls: true,
            backup_dir: None,
        }
    }
}

fn default_lock_timeout_secs() -> u64 {
    300
}

fn default_invert_copy_controls() -> bool {
    true
}

fn config_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("aegis").join("config.json"))
}

/// Keep an unparseable config around instead of overwriting it with defaults,
/// so duress and keyfile records stay recoverable by hand.
fn quarantine_corrupt_config(path: &Path) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let backup = path.with_extension(format!("json.corrupt-{stamp}"));
    match std::fs::rename(path, &backup) {
        Ok(()) => log::warn!("Corrupt config moved to {}", backup.display()),
        Err(error) => log::warn!("Could not quarantine corrupt config: {error}"),
    }
}

pub fn load() -> Config {
    let path = match config_path() {
        Some(p) => p,
        None => return Config::default(),
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Config::default(),
        Err(error) => {
            log::error!("Failed to read config, using defaults: {error}");
            note_load_failure(format!(
                "The config file could not be read ({error}), so settings are not saved to avoid overwriting it."
            ));
            return Config::default();
        }
    };

    let mut config: Config = match serde_json::from_str(&data) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to parse config, using default config: {e}");
            quarantine_corrupt_config(&path);
            note_load_failure(format!(
                "The config file was corrupt and has been set aside as config.json.corrupt-*; settings are not saved this session so it can be restored. ({e})"
            ));
            return Config::default();
        }
    };

    if let Ok(mut slot) = LOAD_FAILURE.lock() {
        *slot = None;
    }
    if config.migrate_legacy_duress()
        && let Err(error) = save(&config)
    {
        log::error!("Failed to persist migrated config: {error}");
    }
    config
}

impl Config {
    /// Pre-decoy configs kept a single global duress password, hashed under
    /// the "duress" key or plaintext in `self_destruct_pass`. Re-attribute it
    /// to the last-used vault, or drop it when that cannot be determined.
    fn migrate_legacy_duress(&mut self) -> bool {
        let legacy = std::mem::take(&mut self.legacy_duress);
        let plaintext = std::mem::take(&mut self.self_destruct_pass);
        if legacy.is_empty() && plaintext.is_empty() {
            return false;
        }
        let duress = if legacy.is_empty() {
            Duress::new(&plaintext)
        } else {
            legacy
        };
        if self.last_used_file.as_os_str().is_empty() {
            log::warn!(
                "old duress password could not be attributed to a vault; re-set it in Settings"
            );
        } else {
            self.duress_by_vault
                .insert(self.last_used_file.clone(), duress);
        }
        true
    }
}

pub fn save(config: &Config) -> Result<(), String> {
    if let Ok(slot) = LOAD_FAILURE.lock()
        && let Some(message) = slot.as_ref()
    {
        return Err(message.clone());
    }
    let Some(path) = config_path() else {
        return Err("Could not determine config directory".to_string());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    crate::file_ops::atomic_write_private_file(&path, json.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_config_defaults() {
        let config = Config::default();
        assert_eq!(config.lock_timeout_secs, 300);
        assert!(config.keyfile_hashes.is_empty());
        assert!(config.duress_by_vault.is_empty());
        assert!(config.legacy_duress.is_empty());
    }

    #[test]
    fn test_duress_per_vault_isolation_and_roundtrip() {
        let vault_a = PathBuf::from("/tmp/a.aegis");
        let vault_b = PathBuf::from("/tmp/b.aegis");
        let mut config = Config::default();
        config
            .duress_by_vault
            .insert(vault_a.clone(), Duress::new("panic-button"));

        assert!(config.duress_by_vault[&vault_a].matches("panic-button"));
        assert!(!config.duress_by_vault[&vault_a].matches("wrong"));
        assert!(
            !config
                .duress_by_vault
                .get(&vault_b)
                .is_some_and(|duress| duress.matches("panic-button"))
        );

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(!json.contains("panic-button"));

        let loaded: Config = serde_json::from_str(&json).unwrap();
        assert!(loaded.duress_by_vault[&vault_a].matches("panic-button"));
        assert!(!loaded.duress_by_vault[&vault_a].matches("wrong"));
        assert!(
            !loaded
                .duress_by_vault
                .get(&vault_b)
                .is_some_and(|duress| duress.matches("panic-button"))
        );
    }

    #[test]
    fn test_duress_hash_without_recorded_costs_still_verifies() {
        let salt = [7u8; 16];
        let mut hash = [0u8; 32];
        Argon2::default()
            .hash_password_into(b"old-duress", &salt, &mut hash)
            .unwrap();
        let json = format!(r#"{{"salt":"{}","hash":"{}"}}"#, hex(&salt), hex(&hash));
        let old: Duress = serde_json::from_str(&json).unwrap();
        assert!(old.matches("old-duress"));
        assert!(!old.matches("other"));
    }

    #[test]
    fn test_duress_empty_clears() {
        let mut duress = Duress::new("temporary");
        assert!(!duress.is_empty());
        duress.set("");
        assert!(duress.is_empty());
        assert!(!duress.matches("temporary"));
    }

    #[test]
    fn test_duress_salt_refreshes() {
        let vault = PathBuf::from("/tmp/v.aegis");
        let mut config = Config::default();
        config
            .duress_by_vault
            .insert(vault.clone(), Duress::new("same-password"));
        let first = config.duress_by_vault[&vault].salt.clone();
        config
            .duress_by_vault
            .insert(vault.clone(), Duress::new("same-password"));
        assert_ne!(config.duress_by_vault[&vault].salt, first);
    }

    #[test]
    fn test_legacy_plaintext_duress_migrates_to_last_used_vault() {
        let vault = PathBuf::from("/tmp/keep.aegis");
        let mut config = Config {
            self_destruct_pass: Zeroizing::new("legacy-pass".into()),
            last_used_file: vault.clone(),
            ..Default::default()
        };

        assert!(config.migrate_legacy_duress());
        assert!(config.self_destruct_pass.is_empty());
        assert!(config.duress_by_vault[&vault].matches("legacy-pass"));
        assert!(!config.migrate_legacy_duress());
    }

    #[test]
    fn test_legacy_global_duress_json_migrates_to_last_used_vault() {
        let legacy = serde_json::to_string(&Duress::new("old-global")).unwrap();
        let json = format!(
            r#"{{"lock_timeout_secs": 300, "duress": {legacy}, "last_used_file": "/tmp/old.aegis"}}"#
        );
        let mut config: Config = serde_json::from_str(&json).unwrap();

        assert!(config.migrate_legacy_duress());
        let vault = PathBuf::from("/tmp/old.aegis");
        assert!(config.duress_by_vault[&vault].matches("old-global"));

        let persisted = serde_json::to_string(&config).unwrap();
        assert!(!persisted.contains("\"duress\""));
    }

    #[test]
    fn test_legacy_duress_without_vault_is_dropped() {
        let legacy = serde_json::to_string(&Duress::new("orphan")).unwrap();
        let json = format!(r#"{{"lock_timeout_secs": 300, "duress": {legacy}}}"#);
        let mut config: Config = serde_json::from_str(&json).unwrap();

        assert!(config.migrate_legacy_duress());
        assert!(config.duress_by_vault.is_empty());
    }

    #[test]
    fn test_legacy_duress_absent_or_empty_is_noop() {
        let mut config: Config = serde_json::from_str(r#"{"lock_timeout_secs": 60}"#).unwrap();
        assert!(!config.migrate_legacy_duress());
        assert!(config.duress_by_vault.is_empty());

        let empty_duress = serde_json::to_string(&Duress::default()).unwrap();
        let json = format!(r#"{{"lock_timeout_secs": 60, "duress": {empty_duress}}}"#);
        let mut config: Config = serde_json::from_str(&json).unwrap();
        assert!(!config.migrate_legacy_duress());
        assert!(config.duress_by_vault.is_empty());
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let mut config = Config {
            lock_timeout_secs: 600,
            ..Default::default()
        };
        config
            .keyfile_hashes
            .insert(PathBuf::from("/tmp/vault.aegis"), [42u8; 32]);
        config.backup_dir = Some(PathBuf::from("/tmp/vault-backups"));

        let json = serde_json::to_string_pretty(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.lock_timeout_secs, 600);
        assert_eq!(
            deserialized
                .keyfile_hashes
                .get(PathBuf::from("/tmp/vault.aegis").as_path()),
            Some(&[42u8; 32])
        );
        assert_eq!(
            deserialized.backup_dir,
            Some(PathBuf::from("/tmp/vault-backups"))
        );

        let without: Config = serde_json::from_str(r#"{"lock_timeout_secs": 60}"#).unwrap();
        assert_eq!(without.backup_dir, None);
    }

    #[test]
    fn test_config_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("aegis_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config_path = dir.join("config.json");
        let config = Config {
            lock_timeout_secs: 120,
            ..Default::default()
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        std::fs::write(&config_path, json).unwrap();

        let loaded = std::fs::read_to_string(&config_path).unwrap();
        let loaded_config: Config = serde_json::from_str(&loaded).unwrap();
        assert_eq!(loaded_config.lock_timeout_secs, 120);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

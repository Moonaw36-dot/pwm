use argon2::Argon2;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Duress password, stored as an Argon2id hash with a random salt.
/// The plaintext is never written to disk.
#[derive(Serialize, Deserialize)]
pub struct Duress {
    #[serde(default)]
    salt: Zeroizing<String>,
    #[serde(default)]
    hash: Zeroizing<String>,
}

impl Default for Duress {
    fn default() -> Self {
        Self {
            salt: Zeroizing::new(String::new()),
            hash: Zeroizing::new(String::new()),
        }
    }
}

impl Duress {
    /// Set a new duress password; an empty password disables duress mode.
    pub fn set(&mut self, password: &str) {
        if password.is_empty() {
            self.salt = Zeroizing::new(String::new());
            self.hash = Zeroizing::new(String::new());
            return;
        }
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let mut hash = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut hash)
            .expect("argon2 default params are valid");
        self.salt = Zeroizing::new(hex(&salt));
        self.hash = Zeroizing::new(hex(&hash));
    }

    /// True if a duress password is configured and `password` matches it.
    pub fn matches(&self, password: &str) -> bool {
        let (Ok(salt), Ok(expected)) = (unhex(&self.salt), unhex(&self.hash)) else {
            return false;
        };
        let mut actual = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut actual)
            .is_ok()
            && ct_eq(&actual, &expected)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub light_mode: bool,
    pub lock_timeout_secs: u64,
    #[serde(default)]
    pub duress: Duress,
    /// Legacy plaintext field, migrated to `duress` on load. Never written back.
    #[serde(default, skip_serializing)]
    pub self_destruct_pass: Zeroizing<String>,
    #[serde(default)]
    pub keyfile_hashes: HashMap<PathBuf, [u8; 32]>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            light_mode: false,
            lock_timeout_secs: 300,
            duress: Duress::default(),
            self_destruct_pass: Zeroizing::new(String::new()),
            keyfile_hashes: Default::default(),
        }
    }
}

fn config_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("aegis").join("config.json"))
}

pub fn load() -> Config {
    let path = match config_path() {
        Some(p) => p,
        None => return Config::default(),
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Config::default(),
    };

    let mut config: Config = match serde_json::from_str(&data) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to parse config, using default config: {e}");
            return Config::default();
        }
    };

    if config.migrate_legacy_duress() {
        let _ = save(&config);
    }
    config
}

impl Config {
    /// Old configs kept the duress password in plaintext; hash it once and
    /// drop the plaintext.
    fn migrate_legacy_duress(&mut self) -> bool {
        if self.self_destruct_pass.is_empty() {
            return false;
        }
        self.duress.set(&self.self_destruct_pass);
        self.self_destruct_pass = Zeroizing::new(String::new());
        true
    }
}

pub fn save(config: &Config) -> Result<(), String> {
    let Some(path) = config_path() else {
        return Err("Could not determine config directory".to_string());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
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
        assert!(!config.duress.matches("anything"));
    }

    #[test]
    fn test_duress_roundtrip() {
        let mut config = Config::default();
        config.duress.set("panic-button");

        assert!(config.duress.matches("panic-button"));
        assert!(!config.duress.matches("wrong"));

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(!json.contains("panic-button"));

        let loaded: Config = serde_json::from_str(&json).unwrap();
        assert!(loaded.duress.matches("panic-button"));
        assert!(!loaded.duress.matches("wrong"));
    }

    #[test]
    fn test_duress_empty_disables() {
        let mut config = Config::default();
        config.duress.set("temporary");
        config.duress.set("");
        assert!(!config.duress.matches("temporary"));
    }

    #[test]
    fn test_duress_salt_refreshes() {
        let mut config = Config::default();
        config.duress.set("same-password");
        let first = config.duress.salt.clone();
        config.duress.set("same-password");
        assert_ne!(config.duress.salt, first);
    }

    #[test]
    fn test_legacy_duress_migrates() {
        let mut config = Config {
            self_destruct_pass: Zeroizing::new("legacy-pass".into()),
            ..Default::default()
        };

        assert!(config.migrate_legacy_duress());
        assert!(config.self_destruct_pass.is_empty());
        assert!(config.duress.matches("legacy-pass"));
        assert!(!config.migrate_legacy_duress());
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

        let json = serde_json::to_string_pretty(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.lock_timeout_secs, 600);
        assert_eq!(
            deserialized
                .keyfile_hashes
                .get(PathBuf::from("/tmp/vault.aegis").as_path()),
            Some(&[42u8; 32])
        );
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

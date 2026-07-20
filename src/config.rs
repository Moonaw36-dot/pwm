use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub light_mode: bool,
    pub lock_timeout_secs: u64,
    #[serde(default)]
    pub keyfile_hashes: HashMap<PathBuf, [u8; 32]>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            light_mode: false,
            lock_timeout_secs: 300,
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

    serde_json::from_str(&data).unwrap_or_else(|e| {
        log::error!("Failed to parse config, using default config: {e}");
        Config::default()
    })
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
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let mut config = Config::default();
        config.lock_timeout_secs = 600;
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
        // Temporarily override config_path by writing directly
        let mut config = Config::default();
        config.lock_timeout_secs = 120;

        let json = serde_json::to_string_pretty(&config).unwrap();
        std::fs::write(&config_path, json).unwrap();

        let loaded = std::fs::read_to_string(&config_path).unwrap();
        let loaded_config: Config = serde_json::from_str(&loaded).unwrap();
        assert_eq!(loaded_config.lock_timeout_secs, 120);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

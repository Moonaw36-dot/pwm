use std::path::PathBuf;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub lock_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self { lock_timeout_secs: 300 }
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
    serde_json::from_str(&data).unwrap_or_default()
}

pub fn save(config: &Config) {
    let path = match config_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(config) {
        let _ = std::fs::write(path, json);
    }
}

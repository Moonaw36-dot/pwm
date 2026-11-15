//! Vault contents, serde-compatible with the desktop app's `PasswordList`.
//!
//! Fields this version doesn't know about are kept in `extra` and written
//! back unchanged, so an older client never strips data a newer one added.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

pub const PASSWORD_HISTORY_CAP: usize = 10;

#[derive(Copy, PartialEq, Eq, Clone, Default, Debug, Serialize, Deserialize)]
pub enum PasswordType {
    #[default]
    Normal,
    Card,
    WiFi,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PasswordHistory {
    pub password: Zeroizing<String>,
    pub changed_at: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub notes: Zeroizing<String>,
    pub totp_secret: Zeroizing<Option<String>>,
    pub tags: Option<Vec<String>>,
    pub url: String,
    pub custom_fields: Zeroizing<Vec<(String, String)>>,
    pub is_secure_note: bool,
    pub created_at: Option<u64>,
    pub password_type: PasswordType,
    pub number: Option<Zeroizing<String>>,
    pub expiration_date: Option<Zeroizing<String>>,
    pub cvc: Option<Zeroizing<String>>,
    pub favorite: Option<bool>,
    pub trashed_at: Option<u64>,
    pub password_history: Vec<PasswordHistory>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// Hand-written so a stray {:?} or panic message never prints a secret.
impl std::fmt::Debug for PasswordHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordHistory")
            .field("changed_at", &self.changed_at)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PasswordEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordEntry")
            .field("label", &self.label)
            .field("password_type", &self.password_type)
            .field("created_at", &self.created_at)
            .field("trashed_at", &self.trashed_at)
            .finish_non_exhaustive()
    }
}

impl PasswordEntry {
    pub fn is_trashed(&self) -> bool {
        self.trashed_at.is_some()
    }

    /// Set a new password, pushing the old one into the capped history.
    pub fn set_password(&mut self, new_password: &str, now: u64) {
        if self.password.as_str() == new_password {
            return;
        }
        self.password_history.push(PasswordHistory {
            password: self.password.clone(),
            changed_at: now,
        });
        if self.password_history.len() > PASSWORD_HISTORY_CAP {
            let overflow = self.password_history.len() - PASSWORD_HISTORY_CAP;
            self.password_history.drain(..overflow);
        }
        *self.password = new_password.to_string();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PasswordList {
    pub entries: Vec<PasswordEntry>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PasswordList {
    pub fn from_json(json: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(json).map_err(|e| {
            // The payload decrypted, so a data error means it's well-formed
            // JSON whose values we don't understand: a newer Aegis wrote it.
            if e.classify() == serde_json::error::Category::Data {
                "This vault was created by a newer version of Aegis".to_string()
            } else {
                format!("Corrupted vault contents: {e}")
            }
        })
    }

    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        serde_json::to_vec_pretty(self)
            .map(Zeroizing::new)
            .map_err(|e| e.to_string())
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

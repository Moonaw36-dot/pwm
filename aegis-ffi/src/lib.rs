//! UniFFI bindings exposing `aegis-core` to Swift for the iOS app.
//!
//! The Swift side only ever sees plain records; the decrypted vault and its
//! key stay in Rust behind the `Vault` object until `lock()` drops them.

use std::sync::{Arc, Mutex, MutexGuard};

use aegis_core::model::now_unix;
use aegis_core::{KdfParams, PasswordEntry, PasswordType, UnlockedVault};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

const LOCKED: &str = "Vault is locked";

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AegisError {
    #[error("{message}")]
    Failed { message: String },
}

impl AegisError {
    fn new(message: impl Into<String>) -> Self {
        AegisError::Failed {
            message: message.into(),
        }
    }
}

impl From<String> for AegisError {
    fn from(message: String) -> Self {
        AegisError::Failed { message }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EntryType {
    Normal,
    Card,
    WiFi,
}

impl From<PasswordType> for EntryType {
    fn from(t: PasswordType) -> Self {
        match t {
            PasswordType::Normal => EntryType::Normal,
            PasswordType::Card => EntryType::Card,
            PasswordType::WiFi => EntryType::WiFi,
        }
    }
}

impl From<EntryType> for PasswordType {
    fn from(t: EntryType) -> Self {
        match t {
            EntryType::Normal => PasswordType::Normal,
            EntryType::Card => PasswordType::Card,
            EntryType::WiFi => PasswordType::WiFi,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CustomField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Entry {
    /// Runtime-stable id assigned by `Vault` at open/add. Not persisted;
    /// ignored by `add_entry`.
    pub id: u64,
    pub label: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub url: String,
    pub totp_secret: Option<String>,
    pub tags: Vec<String>,
    pub entry_type: EntryType,
    pub is_secure_note: bool,
    pub favorite: bool,
    pub card_number: Option<String>,
    pub card_expiration: Option<String>,
    pub card_cvc: Option<String>,
    pub custom_fields: Vec<CustomField>,
    pub created_at: Option<u64>,
    pub trashed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
}

fn to_entry(id: u64, e: &PasswordEntry) -> Entry {
    Entry {
        id,
        label: e.label.clone(),
        username: e.username.clone(),
        password: e.password.to_string(),
        notes: e.notes.to_string(),
        url: e.url.clone(),
        totp_secret: (*e.totp_secret).clone(),
        tags: e.tags.clone().unwrap_or_default(),
        entry_type: e.password_type.into(),
        is_secure_note: e.is_secure_note,
        favorite: e.favorite.unwrap_or(false),
        card_number: e.number.as_ref().map(|s| s.to_string()),
        card_expiration: e.expiration_date.as_ref().map(|s| s.to_string()),
        card_cvc: e.cvc.as_ref().map(|s| s.to_string()),
        custom_fields: e
            .custom_fields
            .iter()
            .map(|(name, value)| CustomField {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        created_at: e.created_at,
        trashed: e.is_trashed(),
    }
}

fn normalize_totp(secret: Option<String>) -> Option<String> {
    secret.filter(|s| !s.trim().is_empty())
}

/// Map `entry` onto an existing `PasswordEntry` in place, so fields the FFI
/// doesn't expose (`extra`, `password_history`, ...) survive, and an
/// unchanged entry serializes byte-for-byte the same.
fn apply_entry(target: &mut PasswordEntry, entry: Entry, now: u64) {
    target.label = entry.label;
    target.username = entry.username;
    target.set_password(&entry.password, now);
    *target.notes = entry.notes;
    target.url = entry.url;

    let totp = normalize_totp(entry.totp_secret);
    if totp != normalize_totp((*target.totp_secret).clone()) {
        *target.totp_secret = totp;
    }

    let old_tags_empty = target.tags.as_ref().is_none_or(|t| t.is_empty());
    if !(entry.tags.is_empty() && old_tags_empty) {
        target.tags = if entry.tags.is_empty() {
            None
        } else {
            Some(entry.tags)
        };
    }

    target.password_type = entry.entry_type.into();
    target.is_secure_note = entry.is_secure_note;
    if entry.favorite || target.favorite.is_some() {
        target.favorite = Some(entry.favorite);
    }

    target.number = entry.card_number.map(Zeroizing::new);
    target.expiration_date = entry.card_expiration.map(Zeroizing::new);
    target.cvc = entry.card_cvc.map(Zeroizing::new);

    *target.custom_fields = entry
        .custom_fields
        .into_iter()
        .map(|f| (f.name, f.value))
        .collect();

    match (entry.trashed, target.trashed_at.is_some()) {
        (true, false) => target.trashed_at = Some(now),
        (false, true) => target.trashed_at = None,
        _ => {}
    }
}

struct Inner {
    vault: Option<UnlockedVault>,
    /// Ids parallel to `vault.list.entries`.
    ids: Vec<u64>,
    next_id: u64,
}

impl Inner {
    fn new(vault: UnlockedVault) -> Self {
        let n = vault.list.entries.len() as u64;
        Inner {
            vault: Some(vault),
            ids: (1..=n).collect(),
            next_id: n + 1,
        }
    }

    fn vault(&mut self) -> Result<&mut UnlockedVault, AegisError> {
        self.vault.as_mut().ok_or_else(|| AegisError::new(LOCKED))
    }

    fn index_of(&self, id: u64) -> Result<usize, AegisError> {
        if self.vault.is_none() {
            return Err(AegisError::new(LOCKED));
        }
        self.ids
            .iter()
            .position(|&i| i == id)
            .ok_or_else(|| AegisError::new(format!("No entry with id {id}")))
    }

    fn entry_mut(&mut self, id: u64) -> Result<&mut PasswordEntry, AegisError> {
        let idx = self.index_of(id)?;
        Ok(&mut self.vault()?.list.entries[idx])
    }
}

#[derive(uniffi::Object)]
pub struct Vault {
    inner: Mutex<Inner>,
}

impl Vault {
    fn wrap(vault: UnlockedVault) -> Arc<Self> {
        Arc::new(Vault {
            inner: Mutex::new(Inner::new(vault)),
        })
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[uniffi::export]
impl Vault {
    /// Decrypt vault file bytes.
    #[uniffi::constructor]
    pub fn open(
        data: Vec<u8>,
        password: String,
        keyfile: Option<Vec<u8>>,
    ) -> Result<Arc<Self>, AegisError> {
        let password = Zeroizing::new(password);
        let keyfile = keyfile.map(Zeroizing::new);
        let vault = UnlockedVault::open(&data, &password, keyfile.as_ref().map(|k| k.as_slice()))?;
        Ok(Self::wrap(vault))
    }

    /// A new, empty vault with default KDF parameters.
    #[uniffi::constructor]
    pub fn create(password: String, keyfile: Option<Vec<u8>>) -> Result<Arc<Self>, AegisError> {
        let password = Zeroizing::new(password);
        let keyfile = keyfile.map(Zeroizing::new);
        let vault = UnlockedVault::create(
            &password,
            KdfParams::default(),
            keyfile.as_ref().map(|k| k.as_slice()),
        )?;
        Ok(Self::wrap(vault))
    }

    /// All entries, including trashed ones, in file order. Empty when locked.
    pub fn entries(&self) -> Vec<Entry> {
        let inner = self.inner();
        match &inner.vault {
            Some(v) => v
                .list
                .entries
                .iter()
                .zip(&inner.ids)
                .map(|(e, &id)| to_entry(id, e))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Append a new entry and return its id. `entry.id` is ignored.
    pub fn add_entry(&self, entry: Entry) -> Result<u64, AegisError> {
        let mut inner = self.inner();
        let now = now_unix();
        let created_at = entry.created_at.unwrap_or(now);
        let mut new = PasswordEntry {
            created_at: Some(created_at),
            ..Default::default()
        };
        apply_entry(&mut new, entry, now);
        inner.vault()?.list.entries.push(new);
        let id = inner.next_id;
        inner.next_id += 1;
        inner.ids.push(id);
        Ok(id)
    }

    /// Update the entry with `entry.id`, keeping fields the FFI doesn't expose.
    pub fn update_entry(&self, entry: Entry) -> Result<(), AegisError> {
        let mut inner = self.inner();
        let target = inner.entry_mut(entry.id)?;
        apply_entry(target, entry, now_unix());
        Ok(())
    }

    pub fn trash_entry(&self, id: u64) -> Result<(), AegisError> {
        let mut inner = self.inner();
        inner.entry_mut(id)?.trashed_at = Some(now_unix());
        Ok(())
    }

    pub fn restore_entry(&self, id: u64) -> Result<(), AegisError> {
        let mut inner = self.inner();
        inner.entry_mut(id)?.trashed_at = None;
        Ok(())
    }

    /// Permanently remove an entry.
    pub fn delete_entry(&self, id: u64) -> Result<(), AegisError> {
        let mut inner = self.inner();
        let idx = inner.index_of(id)?;
        inner.vault()?.list.entries.remove(idx);
        inner.ids.remove(idx);
        Ok(())
    }

    /// Encrypted vault file bytes for the current contents.
    pub fn seal(&self) -> Result<Vec<u8>, AegisError> {
        Ok(self.inner().vault()?.seal()?)
    }

    pub fn change_password(
        &self,
        new_password: String,
        keyfile: Option<Vec<u8>>,
    ) -> Result<(), AegisError> {
        let new_password = Zeroizing::new(new_password);
        let keyfile = keyfile.map(Zeroizing::new);
        self.inner()
            .vault()?
            .change_password(&new_password, keyfile.as_ref().map(|k| k.as_slice()))?;
        Ok(())
    }

    /// Drop the decrypted contents and key. Later calls fail with "Vault is locked".
    pub fn lock(&self) {
        let mut inner = self.inner();
        inner.vault = None;
        inner.ids.clear();
    }
}

#[uniffi::export]
pub fn totp_code(secret: String, unix_time: u64) -> Option<TotpCode> {
    aegis_core::totp::code_at(&secret, unix_time).map(|c| TotpCode {
        code: c.code,
        seconds_remaining: c.seconds_remaining,
        period: c.period,
    })
}

#[uniffi::export]
pub fn generate_password(
    length: u32,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    special: bool,
    ambiguous: bool,
) -> String {
    aegis_core::generator::generate_password(
        length as usize,
        uppercase,
        lowercase,
        numbers,
        special,
        ambiguous,
    )
}

#[uniffi::export]
pub fn generate_passphrase(word_count: u32, separator: String) -> String {
    aegis_core::generator::generate_passphrase(word_count as usize, &separator)
}

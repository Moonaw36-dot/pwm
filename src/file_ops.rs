use crate::app::{AppState, PasswordEntry, PasswordList};
use crate::models::PasswordType;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use argon2::Argon2;
use rand::{Rng, RngExt};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAGIC: [u8; 4] = *b"AEGS";
const FORMAT_VERSION: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const ITER_LEN: usize = 4;
const HEADER_LEN: usize = SALT_LEN + ITER_LEN + NONCE_LEN;
const HEADER_LEN_LEGACY: usize = SALT_LEN + NONCE_LEN;
const HEADER_LEN_V2: usize = MAGIC.len() + 1 + SALT_LEN + 12 + NONCE_LEN;
const MAX_BACKUPS: usize = 10;

/// Argon2id memory cost (KiB) used when a vault does not record its own.
pub(crate) const DEFAULT_M_COST: u32 = 65536;
/// Bounds on KDF parameters read from the vault header, which is untrusted
/// input: absurd values must fail fast instead of hanging or OOMing.
const MIN_M_COST: u32 = 8;
const MAX_M_COST: u32 = 1_048_576;
const MAX_T_COST: u32 = 20;
const MAX_P_COST: u32 = 8;
const KEYFILE_MAX_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultKdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

fn validate_kdf_params(params: VaultKdfParams) -> Result<(), String> {
    if !(MIN_M_COST..=MAX_M_COST).contains(&params.m_cost)
        || !(1..=MAX_T_COST).contains(&params.t_cost)
        || !(1..=MAX_P_COST).contains(&params.p_cost)
    {
        return Err("Vault file is corrupted".to_string());
    }
    Ok(())
}

fn set_private_permissions(path: &Path) -> Result<(), String> {
    #[cfg(not(unix))]
    let _ = path;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

fn write_private_file_new(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(data).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    set_private_permissions(path)
}

fn temp_path_for(path: &Path) -> PathBuf {
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("vault");
    let random = rand::rng().random::<u64>();
    path.with_file_name(format!(".{file_name}.{random:016x}.tmp"))
}

fn replace_file(tmp: &Path, destination: &Path) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        std::fs::rename(tmp, destination).map_err(|e| e.to_string())?;
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };

        let source: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
        let target: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                target.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }

    Ok(())
}

pub(crate) fn atomic_write_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = temp_path_for(path);
    if let Err(error) = write_private_file_new(&tmp, data) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }

    if let Err(error) = replace_file(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }

    set_private_permissions(path)?;

    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let directory = std::fs::File::open(parent).map_err(|e| e.to_string())?;
        directory.sync_all().map_err(|e| e.to_string())?;
    }

    Ok(())
}

pub fn open_file_dialog() -> Option<(String, PathBuf)> {
    let path = rfd::FileDialog::new()
        .add_filter("Aegis vault", &["aegis", "json"])
        .add_filter("All Files", &["*"])
        .set_directory(".")
        .pick_file()?;

    let name = path.file_name()?.to_string_lossy().to_string();

    Some((name, path))
}

fn open_csv_dialog() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("CSV", &["csv"])
        .add_filter("All Files", &["*"])
        .set_directory(".")
        .pick_file()
}

fn save_csv_dialog() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("CSV", &["csv"])
        .save_file()
}

fn header_index(headers: &csv::StringRecord, names: &[&str]) -> Option<usize> {
    names.iter().find_map(|name| {
        headers
            .iter()
            .position(|header| header.eq_ignore_ascii_case(name))
    })
}

fn record_value(record: &csv::StringRecord, idx: Option<usize>) -> String {
    csv_unsafe(idx.and_then(|i| record.get(i)).unwrap_or("").trim())
}

/// Secrets must be preserved verbatim: trimming a password alters it.
fn record_value_raw(record: &csv::StringRecord, idx: Option<usize>) -> String {
    csv_unsafe(idx.and_then(|i| record.get(i)).unwrap_or(""))
}

fn optional_record_value(record: &csv::StringRecord, idx: Option<usize>) -> Option<String> {
    let value = record_value(record, idx);
    if value.is_empty() { None } else { Some(value) }
}

fn optional_record_value_raw(record: &csv::StringRecord, idx: Option<usize>) -> Option<String> {
    let value = record_value_raw(record, idx);
    if value.is_empty() { None } else { Some(value) }
}

/// Characters a spreadsheet evaluates as a formula when a cell starts with
/// them; a leading quote disables that.
const CSV_FORMULA_PREFIXES: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Fields starting with a quote are guarded too, so that `csv_unsafe` can
/// always tell a guard quote from a quote the user typed.
fn csv_needs_guard(field: &str) -> bool {
    field.starts_with(CSV_FORMULA_PREFIXES) || field.starts_with('\'')
}

/// Neutralize spreadsheet formula injection on export.
fn csv_safe(field: &str) -> String {
    if csv_needs_guard(field) {
        format!("'{field}")
    } else {
        field.to_string()
    }
}

/// Undo `csv_safe`: strip the guard quote when what follows it is a formula
/// trigger or another quote. Round-trips are lossless; a third-party field
/// that genuinely starts with `'` plus a trigger is the known trade-off.
fn csv_unsafe(field: &str) -> String {
    if (field.starts_with('\'') && field[1..].starts_with(CSV_FORMULA_PREFIXES))
        || field.starts_with("''")
    {
        field[1..].to_string()
    } else {
        field.to_string()
    }
}

pub fn import_csv() -> Result<Option<PasswordList>, String> {
    let Some(path) = open_csv_dialog() else {
        return Ok(None);
    };
    let mut reader = csv::Reader::from_path(path).map_err(|e| e.to_string())?;

    let headers = reader.headers().map_err(|e| e.to_string())?.clone();
    let idx_label = header_index(&headers, &["label", "name", "title"]);
    let idx_username = header_index(&headers, &["username", "login", "email"]);
    let idx_password = header_index(&headers, &["password", "pass"]);
    let idx_url = header_index(&headers, &["url", "website", "site"]);
    let idx_notes = header_index(&headers, &["notes", "note", "comment"]);
    let idx_tags = header_index(&headers, &["tags", "tag"]);
    let idx_totp = header_index(&headers, &["totp_secret", "totp", "otp"]);
    let idx_type = header_index(&headers, &["type", "password_type"]);
    let idx_number = header_index(&headers, &["number", "card_number"]);
    let idx_expiration = header_index(&headers, &["expiration_date", "expiry"]);
    let idx_cvc = header_index(&headers, &["cvc"]);
    let idx_secure_note = header_index(&headers, &["secure_note", "secure"]);
    let idx_custom_fields = header_index(&headers, &["custom_fields", "fields"]);
    let idx_favorite = header_index(&headers, &["favorite", "favourite"]);
    let idx_created_at = header_index(&headers, &["created_at"]);
    let idx_trashed_at = header_index(&headers, &["trashed_at"]);
    let idx_password_history = header_index(&headers, &["password_history"]);

    let mut entries = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|e| e.to_string())?;

        let tags = optional_record_value(&record, idx_tags)
            .map(|tags| tags.split(';').map(|s| s.trim().to_string()).collect());
        let totp_secret = optional_record_value(&record, idx_totp);
        let password_type = match optional_record_value(&record, idx_type)
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("card") => PasswordType::Card,
            Some("wifi") | Some("wi-fi") => PasswordType::WiFi,
            Some(other) => {
                log::warn!("CSV import: unknown type \"{other}\", imported as a normal entry");
                PasswordType::Normal
            }
            None => PasswordType::Normal,
        };
        let custom_fields = match optional_record_value(&record, idx_custom_fields) {
            Some(value) => serde_json::from_str(&value)
                .map_err(|error| format!("Invalid custom_fields JSON: {error}"))?,
            None => Vec::new(),
        };
        let password_history = match optional_record_value(&record, idx_password_history) {
            Some(value) => serde_json::from_str(&value)
                .map_err(|error| format!("Invalid password_history JSON: {error}"))?,
            None => Vec::new(),
        };
        let is_secure_note = optional_record_value(&record, idx_secure_note)
            .is_some_and(|value| value.eq_ignore_ascii_case("true") || value == "1");
        let favorite = optional_record_value(&record, idx_favorite).and_then(|value| {
            if value.eq_ignore_ascii_case("true") || value == "1" {
                Some(true)
            } else if value.eq_ignore_ascii_case("false") || value == "0" {
                Some(false)
            } else {
                None
            }
        });
        let created_at =
            optional_record_value(&record, idx_created_at).and_then(|value| value.parse().ok());
        let trashed_at =
            optional_record_value(&record, idx_trashed_at).and_then(|value| value.parse().ok());

        entries.push(PasswordEntry {
            label: record_value(&record, idx_label),
            username: record_value(&record, idx_username),
            password: Zeroizing::new(record_value_raw(&record, idx_password)),
            url: record_value(&record, idx_url),
            notes: Zeroizing::new(record_value(&record, idx_notes)),
            tags,
            totp_secret: totp_secret.into(),
            custom_fields: Zeroizing::new(custom_fields),
            is_secure_note,
            created_at,
            totp_cache: None,
            password_type,
            number: optional_record_value_raw(&record, idx_number).map(Zeroizing::new),
            expiration_date: optional_record_value_raw(&record, idx_expiration).map(Zeroizing::new),
            cvc: optional_record_value_raw(&record, idx_cvc).map(Zeroizing::new),
            favorite,
            totp_code_cache: None,
            trashed_at,
            password_history,
        });
    }

    Ok(Some(PasswordList { entries }))
}

pub fn export_csv(store: &PasswordList) -> Result<(), String> {
    if rfd::MessageDialog::new()
        .set_title("Export warning")
        .set_description("Passwords will be exported in plaintext (unencrypted). Continue?")
        .set_buttons(rfd::MessageButtons::OkCancel)
        .show()
        != rfd::MessageDialogResult::Ok
    {
        return Ok(());
    }

    let Some(path) = save_csv_dialog() else {
        return Ok(());
    };

    let mut csv_data = Zeroizing::new(Vec::new());
    let mut writer = csv::Writer::from_writer(&mut *csv_data);

    writer
        .write_record([
            "label",
            "username",
            "password",
            "url",
            "notes",
            "tags",
            "totp_secret",
            "type",
            "number",
            "expiration_date",
            "cvc",
            "secure_note",
            "custom_fields",
            "favorite",
            "created_at",
            "trashed_at",
            "password_history",
        ])
        .map_err(|e| e.to_string())?;

    for entry in store
        .entries
        .iter()
        .filter(|e| !crate::models::is_trashed(e))
    {
        let tags = entry
            .tags
            .as_deref()
            .map(|t| t.join(";"))
            .unwrap_or_default();
        let totp = entry.totp_secret.as_deref().unwrap_or("").to_string();
        let entry_type = match entry.password_type {
            PasswordType::Normal => "normal",
            PasswordType::Card => "card",
            PasswordType::WiFi => "wifi",
        }
        .to_string();
        let number = entry
            .number
            .as_ref()
            .map(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let expiration = entry
            .expiration_date
            .as_ref()
            .map(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let cvc = entry
            .cvc
            .as_ref()
            .map(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let secure_note = entry.is_secure_note.to_string();
        let custom_fields =
            serde_json::to_string(&*entry.custom_fields).map_err(|e| e.to_string())?;
        let favorite = entry
            .favorite
            .map(|value| value.to_string())
            .unwrap_or_default();
        let created_at = entry
            .created_at
            .map(|value| value.to_string())
            .unwrap_or_default();
        let trashed_at = entry
            .trashed_at
            .map(|value| value.to_string())
            .unwrap_or_default();
        let password_history =
            serde_json::to_string(&entry.password_history).map_err(|e| e.to_string())?;
        let record = [
            entry.label.clone(),
            entry.username.clone(),
            entry.password.to_string(),
            entry.url.clone(),
            entry.notes.to_string(),
            tags,
            totp,
            entry_type,
            number,
            expiration,
            cvc,
            secure_note,
            custom_fields,
            favorite,
            created_at,
            trashed_at,
            password_history,
        ];
        writer
            .write_record(record.iter().map(|field| csv_safe(field)))
            .map_err(|e| e.to_string())?;
    }

    writer.flush().map_err(|e| e.to_string())?;
    drop(writer);
    atomic_write_private_file(&path, &csv_data)
}

pub(crate) fn derive_key_params(
    password: &str,
    salt: &[u8; 16],
    params: VaultKdfParams,
    keyfile_bytes: Option<&[u8]>,
) -> Result<crate::locked_buf::LockedKey, String> {
    validate_kdf_params(params)?;
    let raw = argon2_key(password, salt, params)?;
    Ok(match keyfile_bytes {
        Some(kf) => mix_keyfile(&raw, kf),
        None => raw,
    })
}

/// Raw Argon2id output before any keyfile is mixed in.
fn argon2_key(
    password: &str,
    salt: &[u8; 16],
    params: VaultKdfParams,
) -> Result<crate::locked_buf::LockedKey, String> {
    let mut key = crate::locked_buf::LockedKey::zeroed();
    let argon_params = argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| format!("Argon2 params: {e}"))?;
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    )
    .hash_password_into(password.as_bytes(), salt, &mut *key)
    .map_err(|e| format!("Key derivation failed: {e}"))?;
    Ok(key)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_LEN: usize = 64;
    let mut padded = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    inner.update(padded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(message);
    outer.update(padded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// HKDF-SHA256 with the Argon2id output as salt and the keyfile as input key
/// material, so the vault key needs both factors to reconstruct.
fn combine_keyfile(argon_key: &[u8; 32], keyfile: &[u8]) -> [u8; 32] {
    const INFO: &[u8] = b"aegis keyfile";
    let prk = hmac_sha256(argon_key, keyfile);
    hmac_sha256(&prk, &[INFO, &[1u8]].concat())
}

/// Vaults saved before the HKDF combiner used a bare SHA-256 over the
/// concatenated keys; kept so those vaults still open.
fn combine_keyfile_legacy(argon_key: &[u8; 32], keyfile: &[u8]) -> [u8; 32] {
    let mut combined = Zeroizing::new(Vec::with_capacity(32 + keyfile.len()));
    combined.extend_from_slice(argon_key);
    combined.extend_from_slice(keyfile);
    Sha256::digest(&*combined).into()
}

/// Derive the vault key from the raw Argon2id output plus keyfile bytes.
fn mix_keyfile(raw: &crate::locked_buf::LockedKey, keyfile: &[u8]) -> crate::locked_buf::LockedKey {
    let mut key = crate::locked_buf::LockedKey::zeroed();
    key.copy_from_slice(&combine_keyfile(raw, keyfile));
    key
}

pub(crate) fn encrypt_store(
    store: &PasswordList,
    key: &[u8; 32],
    salt: &[u8; 16],
    params: VaultKdfParams,
) -> Result<Vec<u8>, String> {
    let json = Zeroizing::new(serde_json::to_string_pretty(store).map_err(|e| e.to_string())?);

    // Build the header first and authenticate it as AAD, so every parameter
    // the key was derived from is bound to the ciphertext.
    let mut out = Vec::with_capacity(HEADER_LEN_V2 + json.len() + 16);
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(salt);
    out.extend_from_slice(&params.m_cost.to_le_bytes());
    out.extend_from_slice(&params.t_cost.to_le_bytes());
    out.extend_from_slice(&params.p_cost.to_le_bytes());
    let nonce_offset = out.len();
    out.resize(nonce_offset + NONCE_LEN, 0);

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    out[nonce_offset..nonce_offset + NONCE_LEN].copy_from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: json.as_bytes(),
                aad: &out,
            },
        )
        .map_err(|e| e.to_string())?;

    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn create_file(file_name: &str, state: &mut AppState) -> Result<(), String> {
    let file_name = file_name.trim();
    if file_name.is_empty() {
        return Err("File name cannot be empty".to_string());
    }
    if Path::new(file_name).file_name().and_then(|s| s.to_str()) != Some(file_name) {
        return Err("File name cannot contain path separators".to_string());
    }

    let Some(dir) = rfd::FileDialog::new().set_directory(".").pick_folder() else {
        return Err("No file selected".to_string());
    };

    let path: PathBuf = if file_name.ends_with(".aegis") {
        dir.join(file_name)
    } else {
        dir.join(format!("{file_name}.aegis"))
    };
    let vault_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(file_name)
        .to_string();

    if state.vault.store.is_some() {
        return Err("Close the current vault before creating a new one".to_string());
    }
    if path.exists() {
        return Err("A vault already exists at that path".to_string());
    }

    let empty_store = PasswordList {
        entries: Vec::new(),
    };

    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    let iterations = state.form.iterations_entry;
    let params = VaultKdfParams {
        m_cost: DEFAULT_M_COST,
        t_cost: iterations,
        p_cost: 1,
    };
    let key = derive_key_params(&state.master_input, &salt, params, None)?;
    let filedata = encrypt_store(&empty_store, &key, &salt, params)?;
    write_private_file_new(&path, &filedata)?;

    state.vault.store = Some(empty_store);
    state.vault.encryption_key = Some(key);
    state.vault.file_path = Some(path);
    state.vault.file_name = vault_name;
    state.vault.iterations = iterations;
    state.vault.kdf_params = Some(params);
    state.invalidate_vault_caches();
    Ok(())
}

pub fn load_keyfile(state: &mut AppState) -> Result<(), String> {
    let path = rfd::FileDialog::new()
        .add_filter("Aegis keyfile", &["aegis"])
        .pick_file()
        .ok_or("No file selected".to_string())?;

    let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    if metadata.len() > KEYFILE_MAX_BYTES {
        return Err(format!(
            "Keyfile is too large (limit is {} MiB).",
            KEYFILE_MAX_BYTES / (1024 * 1024)
        ));
    }
    let bytes = Zeroizing::new(std::fs::read(&path).map_err(|e| e.to_string())?);
    let hash: [u8; 32] = Sha256::digest(&bytes).into();

    // Only check the hash when a record exists, a lost config must not lock
    // the vault out of its keyfile. Decryption is the real arbiter either way.
    if let Some(expected) = state.vault.keyfile_hash
        && hash != expected
    {
        return Err("Invalid keyfile: hash does not match.".to_string());
    }

    state.vault.keyfile = Some(path);
    state.vault.keyfile_bytes = Some(bytes);
    Ok(())
}

pub fn remember_keyfile_hash(state: &mut AppState) -> Result<(), String> {
    if state.vault.keyfile_hash.is_some() {
        return Ok(());
    }
    let Some(bytes) = &state.vault.keyfile_bytes else {
        return Ok(());
    };
    let Some(vault_path) = &state.vault.file_path else {
        return Ok(());
    };

    let hash: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
    let mut config = crate::config::load();
    config.keyfile_hashes.insert(vault_path.clone(), hash);
    crate::config::save(&config)?;
    state.vault.keyfile_hash = Some(hash);
    Ok(())
}

pub fn create_key_file(state: &mut AppState) -> Result<(), String> {
    let path = rfd::FileDialog::new()
        .set_file_name("keyfile.aegis")
        .add_filter("Aegis keyfile", &["aegis"])
        .save_file()
        .ok_or("No folder selected".to_string())?;

    let path = if path.extension().and_then(|e| e.to_str()) != Some("aegis") {
        path.with_extension("aegis")
    } else {
        path
    };

    let mut key = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(key.as_mut());

    let hash: [u8; 32] = Sha256::digest(*key).into();

    let previous_keyfile = state.vault.keyfile.clone();
    let previous_keyfile_hash = state.vault.keyfile_hash;
    let previous_keyfile_bytes = state.vault.keyfile_bytes.clone();

    write_private_file_new(&path, key.as_ref())?;

    state.vault.keyfile_hash = Some(hash);
    state.vault.keyfile = Some(path.clone());
    state.vault.keyfile_bytes = Some(Zeroizing::new(key.to_vec()));

    // Re-encrypt vault with combined key so the keyfile actually protects it
    if let (Some(enc_key), Some(store)) =
        (state.vault.encryption_key.take(), state.vault.store.take())
    {
        let mut new_key = crate::locked_buf::LockedKey::zeroed();
        new_key.copy_from_slice(&combine_keyfile(&enc_key, &*key));

        let params = state.vault.kdf_params.unwrap_or(VaultKdfParams {
            m_cost: DEFAULT_M_COST,
            t_cost: state.vault.iterations,
            p_cost: 1,
        });
        if let Err(e) = save_store(&state.vault.file_path, &store, &new_key, params) {
            state.vault.encryption_key = Some(enc_key);
            state.vault.store = Some(store);
            state.vault.keyfile = previous_keyfile;
            state.vault.keyfile_hash = previous_keyfile_hash;
            state.vault.keyfile_bytes = previous_keyfile_bytes;
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        state.vault.encryption_key = Some(new_key);
        state.vault.store = Some(store);
    }

    if let Some(vault_path) = &state.vault.file_path {
        let mut config = crate::config::load();
        config.keyfile_hashes.insert(vault_path.clone(), hash);
        crate::config::save(&config)?;
    }

    Ok(())
}

fn parse_iterations_from_header(data: &[u8]) -> u32 {
    if data.len() >= SALT_LEN + ITER_LEN {
        let val = u32::from_le_bytes(
            data[SALT_LEN..SALT_LEN + ITER_LEN]
                .try_into()
                .unwrap_or([0; 4]),
        );
        if (1..=20).contains(&val) {
            return val;
        }
    }
    3
}

fn try_decrypt(
    password: &str,
    salt: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    params: VaultKdfParams,
    keyfile_bytes: Option<&[u8]>,
) -> Option<(PasswordList, crate::locked_buf::LockedKey)> {
    let raw = derive_key_params(password, salt, params, None).ok()?;

    // Vault-format v1 predates the HKDF combiner, so legacy vaults may have
    // been keyed with either combiner; try both before giving up.
    let mut candidate_keys = Vec::new();
    match keyfile_bytes {
        Some(kf) => {
            let mut legacy = crate::locked_buf::LockedKey::zeroed();
            legacy.copy_from_slice(&combine_keyfile_legacy(&raw, kf));
            candidate_keys.push(mix_keyfile(&raw, kf));
            candidate_keys.push(legacy);
        }
        None => candidate_keys.push(raw),
    }

    for key in candidate_keys {
        let cipher = Aes256Gcm::new((&*key).into());
        let Ok(plaintext) = cipher.decrypt(nonce.into(), ciphertext) else {
            continue;
        };
        let plaintext = Zeroizing::new(plaintext);
        let json = Zeroizing::new(String::from_utf8(plaintext.to_vec()).ok()?);
        let store: PasswordList = serde_json::from_str(&json).ok()?;
        return Some((store, key));
    }
    None
}

fn load_store_v2(
    data: &[u8],
    password: &str,
    keyfile_bytes: Option<&[u8]>,
) -> Result<(PasswordList, crate::locked_buf::LockedKey, VaultKdfParams), String> {
    if data.len() <= HEADER_LEN_V2 {
        return Err("Vault file is truncated or corrupted".to_string());
    }

    let version = data[MAGIC.len()];
    if version != FORMAT_VERSION {
        return Err(format!(
            "Vault version {version} is not supported by this version of Aegis"
        ));
    }

    let mut offset = MAGIC.len() + 1;
    let salt: [u8; 16] = data[offset..offset + SALT_LEN]
        .try_into()
        .map_err(|_| "Vault file is truncated or corrupted".to_string())?;
    offset += SALT_LEN;
    let m_cost = u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Vault file is truncated or corrupted".to_string())?,
    );
    offset += 4;
    let t_cost = u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Vault file is truncated or corrupted".to_string())?,
    );
    offset += 4;
    let p_cost = u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Vault file is truncated or corrupted".to_string())?,
    );
    offset += 4;
    let nonce: [u8; 12] = data[offset..HEADER_LEN_V2]
        .try_into()
        .map_err(|_| "Vault file is truncated or corrupted".to_string())?;

    let params = VaultKdfParams {
        m_cost,
        t_cost,
        p_cost,
    };
    validate_kdf_params(params)?;
    let ciphertext = &data[HEADER_LEN_V2..];

    // Vaults saved before the header was authenticated as AAD, and before the
    // HKDF keyfile combiner, must still open: try the current forms first,
    // then fall back per candidate key.
    let raw = argon2_key(password, &salt, params)?;
    let mut candidate_keys = Vec::new();
    match keyfile_bytes {
        Some(kf) => {
            let mut legacy = crate::locked_buf::LockedKey::zeroed();
            legacy.copy_from_slice(&combine_keyfile_legacy(&raw, kf));
            candidate_keys.push(mix_keyfile(&raw, kf));
            candidate_keys.push(legacy);
        }
        None => candidate_keys.push(raw),
    }

    let decrypt_error = "Decryption failed: wrong master password or corrupted file".to_string();
    let header_aad = &data[..HEADER_LEN_V2];
    for key in candidate_keys {
        let cipher = Aes256Gcm::new((&*key).into());
        let plaintext = cipher
            .decrypt(
                (&nonce).into(),
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: header_aad,
                },
            )
            .or_else(|_| cipher.decrypt((&nonce).into(), ciphertext))
            .ok();
        let Some(plaintext) = plaintext.map(Zeroizing::new) else {
            continue;
        };
        let json = match String::from_utf8(plaintext.to_vec()) {
            Ok(json) => Zeroizing::new(json),
            Err(_) => return Err(decrypt_error),
        };
        let store: PasswordList = match serde_json::from_str(&json) {
            Ok(store) => store,
            Err(e) if e.to_string().contains("unknown variant") => {
                return Err("This vault was created by a newer version of Aegis".to_string());
            }
            Err(e) => return Err(format!("Corrupted vault contents: {e}")),
        };
        return Ok((store, key, params));
    }

    Err(decrypt_error)
}

pub fn load_store(
    path: &PathBuf,
    password: &str,
    keyfile_bytes: Option<&[u8]>,
) -> Result<(PasswordList, crate::locked_buf::LockedKey, VaultKdfParams), String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read vault: {e}"))?;

    if data.len() < SALT_LEN {
        return Err("File is too short to be a valid store".to_string());
    }

    if data.starts_with(&MAGIC) {
        return load_store_v2(&data, password, keyfile_bytes);
    }

    let salt: [u8; 16] = data[..SALT_LEN]
        .try_into()
        .map_err(|_| "Invalid salt".to_string())?;

    if data.len() > HEADER_LEN_LEGACY {
        let nonce: [u8; 12] = data[SALT_LEN..HEADER_LEN_LEGACY]
            .try_into()
            .map_err(|_| "Invalid nonce".to_string())?;
        let ciphertext = &data[HEADER_LEN_LEGACY..];
        for (m_cost, t_cost) in [(19456u32, 2u32), (65536u32, 3u32)] {
            let params = VaultKdfParams {
                m_cost,
                t_cost,
                p_cost: 1,
            };
            if let Some(result) =
                try_decrypt(password, &salt, &nonce, ciphertext, params, keyfile_bytes)
            {
                return Ok((result.0, result.1, params));
            }
        }
    }

    if data.len() > HEADER_LEN {
        let nonce: [u8; 12] = data[SALT_LEN + ITER_LEN..HEADER_LEN]
            .try_into()
            .map_err(|_| "Invalid nonce".to_string())?;
        let ciphertext = &data[HEADER_LEN..];
        let iterations = parse_iterations_from_header(&data);
        for (m_cost, t_cost) in [
            (65536u32, iterations),
            (65536u32, 3u32),
            (19456u32, 2u32),
            (65536u32, 2u32),
        ] {
            let params = VaultKdfParams {
                m_cost,
                t_cost,
                p_cost: 1,
            };
            if let Some(result) =
                try_decrypt(password, &salt, &nonce, ciphertext, params, keyfile_bytes)
            {
                return Ok((result.0, result.1, params));
            }
        }
    }

    Err("Decryption failed: wrong master password or corrupted file".to_string())
}

fn read_existing_salt(path: &Path) -> Result<[u8; SALT_LEN], String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("Failed to read vault before save: {e}"))?;
    let mut head = [0u8; MAGIC.len() + 1 + SALT_LEN];
    let mut read_len = 0;
    while read_len < head.len() {
        match file.read(&mut head[read_len..]) {
            Ok(0) => break,
            Ok(n) => read_len += n,
            Err(e) => return Err(e.to_string()),
        }
    }

    if head[..MAGIC.len()] == MAGIC {
        if read_len < MAGIC.len() + 1 + SALT_LEN {
            return Err("File is too short to be a valid store".to_string());
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&head[MAGIC.len() + 1..MAGIC.len() + 1 + SALT_LEN]);
        Ok(salt)
    } else if read_len >= SALT_LEN {
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&head[..SALT_LEN]);
        Ok(salt)
    } else {
        Err("File is too short to be a valid store".to_string())
    }
}

pub fn save_store(
    path: &Option<PathBuf>,
    store: &PasswordList,
    key: &[u8; 32],
    params: VaultKdfParams,
) -> Result<(), String> {
    let Some(p) = path else {
        return Err("No vault file is open".to_string());
    };

    let salt = read_existing_salt(p)?;
    let filedata = encrypt_store(store, key, &salt, params)?;
    atomic_write_private_file(p, &filedata)?;
    backup_vault(p);
    Ok(())
}

/// Best-effort timestamped copy of the freshly saved vault, pruned to
/// `MAX_BACKUPS` per vault. Never fails the save.
///
/// The name embeds a hash of the vault path so two vaults that share a file
/// name in different folders never collide in the shared backup directory.
fn backup_vault(path: &Path) {
    let backup_dir = crate::config::load().backup_dir;
    let Some(dir) = backup_dir else {
        return;
    };
    if let Err(error) = std::fs::create_dir_all(&dir) {
        log::warn!("Backup directory {} unavailable: {error}", dir.display());
        return;
    }
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return;
    };

    let unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64);
    let prefix = backup_prefix(path, stem);
    let backup_path = dir.join(format!("{prefix}.backup.{unix_nanos}.aegis"));
    if let Err(error) = std::fs::copy(path, &backup_path) {
        log::warn!(
            "Failed to back up vault to {}: {error}",
            backup_path.display()
        );
    }
    prune_backups(&dir, &prefix);
}

/// `{stem}.{hash8(path)}` prefix identifying one vault's backups.
fn backup_prefix(path: &Path, stem: &str) -> String {
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    format!(
        "{stem}.{:08x}",
        u32::from_be_bytes(digest[..4].try_into().unwrap_or([0; 4]))
    )
}

/// Remove the oldest `{prefix}.backup.*.aegis` copies beyond `MAX_BACKUPS`,
/// ordering by the numeric timestamp in the name.
fn prune_backups(dir: &Path, prefix: &str) {
    let stamp_prefix = format!("{prefix}.backup.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut stamps: Vec<u64> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            name.to_str()?
                .strip_prefix(&stamp_prefix)?
                .strip_suffix(".aegis")?
                .parse::<u64>()
                .ok()
        })
        .collect();
    if stamps.len() <= MAX_BACKUPS {
        return;
    }
    stamps.sort_unstable();
    for stamp in &stamps[..stamps.len() - MAX_BACKUPS] {
        let stale = dir.join(format!("{stamp_prefix}{stamp}.aegis"));
        if let Err(error) = std::fs::remove_file(&stale) {
            log::warn!("Failed to remove old backup {}: {error}", stale.display());
        }
    }
}

pub(crate) fn write_new_vault_file(
    path: &Path,
    store: &PasswordList,
    password: &str,
    params: VaultKdfParams,
    keyfile_bytes: Option<&[u8]>,
) -> Result<crate::locked_buf::LockedKey, String> {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let key = derive_key_params(password, &salt, params, keyfile_bytes)?;
    let filedata = encrypt_store(store, &key, &salt, params)?;
    write_private_file_new(path, &filedata)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PasswordEntry;

    fn temp_vault_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-file-ops-{tag}-{:016x}.aegis",
            rand::rng().random::<u64>()
        ))
    }

    fn sample_store() -> PasswordList {
        PasswordList {
            entries: vec![
                PasswordEntry {
                    label: "test".into(),
                    username: "user".into(),
                    password: Zeroizing::new("secret123".into()),
                    url: "https://example.com".into(),
                    notes: Zeroizing::new("my note".to_string()),
                    totp_secret: Some("JBSWY3DPEHPK3PXP".into()).into(),
                    tags: Some(vec!["work".into(), "dev".into()]),
                    ..Default::default()
                },
                PasswordEntry {
                    label: "empty".into(),
                    ..Default::default()
                },
            ],
        }
    }

    #[test]
    fn test_v2_header_layout_and_roundtrip() {
        let store = sample_store();
        let password = "master_password";
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let params = VaultKdfParams {
            m_cost: 2048,
            t_cost: 2,
            p_cost: 1,
        };

        let key = derive_key_params(password, &salt, params, None).unwrap();
        let encrypted = encrypt_store(&store, &key, &salt, params).unwrap();

        assert_eq!(&encrypted[..4], &MAGIC);
        assert_eq!(encrypted[4], FORMAT_VERSION);
        assert_eq!(&encrypted[5..21], &salt);
        assert_eq!(&encrypted[21..25], &params.m_cost.to_le_bytes());
        assert_eq!(&encrypted[25..29], &params.t_cost.to_le_bytes());
        assert_eq!(&encrypted[29..33], &params.p_cost.to_le_bytes());
        let nonce: [u8; 12] = encrypted[33..HEADER_LEN_V2].try_into().unwrap();
        assert!(encrypted.len() > HEADER_LEN_V2);

        let path = temp_vault_path("v2-roundtrip");
        write_private_file_new(&path, &encrypted).unwrap();
        let (loaded_store, loaded_key, loaded_params) = load_store(&path, password, None).unwrap();

        assert_eq!(loaded_params, params);
        assert_eq!(loaded_key, key);
        assert_eq!(loaded_store.entries.len(), 2);
        assert_eq!(loaded_store.entries[0].label, "test");
        assert_eq!(loaded_store.entries[0].password.as_str(), "secret123");
        assert_eq!(
            loaded_store.entries[0].totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(loaded_store.entries[1].label, "empty");
        assert!(loaded_store.entries[1].password.is_empty());

        let reread = std::fs::read(&path).unwrap();
        assert_eq!(reread.len(), encrypted.len());
        assert_eq!(&reread[..HEADER_LEN_V2], &encrypted[..HEADER_LEN_V2]);
        assert_eq!(&reread[33..HEADER_LEN_V2], &nonce);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_encrypt_decrypt_wrong_key_fails() {
        let store = PasswordList { entries: vec![] };
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let params = VaultKdfParams {
            m_cost: 2048,
            t_cost: 2,
            p_cost: 1,
        };

        let key = derive_key_params("correct", &salt, params, None).unwrap();
        let encrypted = encrypt_store(&store, &key, &salt, params).unwrap();

        let nonce: [u8; 12] = encrypted[33..HEADER_LEN_V2].try_into().unwrap();
        let ciphertext = &encrypted[HEADER_LEN_V2..];

        assert!(try_decrypt("wrong", &salt, &nonce, ciphertext, params, None).is_none());
    }

    #[test]
    fn test_legacy_no_iterations_format_loads() {
        let store = PasswordList {
            entries: vec![PasswordEntry {
                label: "legacy".into(),
                password: Zeroizing::new("p4ss".into()),
                ..Default::default()
            }],
        };

        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let legacy_params = VaultKdfParams {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
        };
        let legacy_key = derive_key_params("mypass", &salt, legacy_params, None).unwrap();
        let json = serde_json::to_string_pretty(&store).unwrap();
        let cipher = Aes256Gcm::new((&*legacy_key).into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, json.as_bytes()).unwrap();
        let mut encrypted = Vec::with_capacity(HEADER_LEN_LEGACY + ciphertext.len());
        encrypted.extend_from_slice(&salt);
        encrypted.extend_from_slice(&nonce);
        encrypted.extend_from_slice(&ciphertext);

        let path = temp_vault_path("legacy-noiter");
        write_private_file_new(&path, &encrypted).unwrap();
        let (decrypted, key, params) = load_store(&path, "mypass", None).unwrap();
        assert_eq!(decrypted.entries[0].label, "legacy");
        assert_eq!(key, legacy_key);
        assert_eq!(params, legacy_params);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_legacy_iterations_format_loads() {
        let store = PasswordList {
            entries: vec![PasswordEntry {
                label: "legacy-iter".into(),
                ..Default::default()
            }],
        };

        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let legacy_params = VaultKdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
        };
        let legacy_key = derive_key_params("mypass", &salt, legacy_params, None).unwrap();
        let json = serde_json::to_string_pretty(&store).unwrap();
        let cipher = Aes256Gcm::new((&*legacy_key).into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, json.as_bytes()).unwrap();
        let mut encrypted = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        encrypted.extend_from_slice(&salt);
        encrypted.extend_from_slice(&3u32.to_le_bytes());
        encrypted.extend_from_slice(&nonce);
        encrypted.extend_from_slice(&ciphertext);

        let path = temp_vault_path("legacy-iter");
        write_private_file_new(&path, &encrypted).unwrap();
        let (decrypted, key, params) = load_store(&path, "mypass", None).unwrap();
        assert_eq!(decrypted.entries[0].label, "legacy-iter");
        assert_eq!(key, legacy_key);
        assert_eq!(params, legacy_params);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_unknown_version_errors() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.push(9);
        data.extend_from_slice(&[0u8; 64]);

        let path = temp_vault_path("unknown-version");
        write_private_file_new(&path, &data).unwrap();
        let error = load_store(&path, "pw", None).unwrap_err();
        assert_eq!(
            error,
            "Vault version 9 is not supported by this version of Aegis"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_truncated_v2_header_errors() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.push(FORMAT_VERSION);
        data.extend_from_slice(&[0u8; 20]);

        let path = temp_vault_path("truncated-v2");
        write_private_file_new(&path, &data).unwrap();
        let error = load_store(&path, "pw", None).unwrap_err();
        assert_eq!(error, "Vault file is truncated or corrupted");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_v2_wrong_password_fails() {
        let store = PasswordList { entries: vec![] };
        let path = temp_vault_path("v2-wrong-pw");
        write_new_vault_file(
            &path,
            &store,
            "correct",
            VaultKdfParams {
                m_cost: 2048,
                t_cost: 2,
                p_cost: 1,
            },
            None,
        )
        .unwrap();

        let error = load_store(&path, "wrong", None).unwrap_err();
        assert_eq!(
            error,
            "Decryption failed: wrong master password or corrupted file"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_write_new_vault_file_roundtrip() {
        let store = sample_store();
        let path = temp_vault_path("write-new");
        let params = VaultKdfParams {
            m_cost: 2048,
            t_cost: 2,
            p_cost: 1,
        };
        let key = write_new_vault_file(&path, &store, "password", params, None).unwrap();

        let (loaded, loaded_key, loaded_params) = load_store(&path, "password", None).unwrap();
        assert_eq!(loaded_key, key);
        assert_eq!(loaded_params, params);
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.entries[0].password.as_str(), "secret123");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_save_and_load_current_format() {
        // This save writes a backup via `crate::config::load()`; serialize it
        // against the Linux backup tests, which redirect the process-global
        // XDG_CONFIG_HOME while they run.
        #[cfg(target_os = "linux")]
        let _config_env_guard = backup_tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let path = temp_vault_path("save-load");
        let store = PasswordList {
            entries: vec![PasswordEntry {
                label: "saved".into(),
                password: Zeroizing::new("secret".into()),
                ..Default::default()
            }],
        };
        let params = VaultKdfParams {
            m_cost: 2048,
            t_cost: 2,
            p_cost: 1,
        };
        let key = write_new_vault_file(&path, &store, "password", params, None).unwrap();

        let loaded = load_store(&path, "password", None).unwrap();
        assert_eq!(loaded.0.entries[0].label, "saved");
        assert_eq!(loaded.2, params);
        save_store(&Some(path.clone()), &store, &key, params).unwrap();
        let reloaded = load_store(&path, "password", None).unwrap();
        assert_eq!(reloaded.0.entries[0].password.as_str(), "secret");
        assert_eq!(reloaded.2, params);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex_encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    fn hex_encode(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_keyfile_roundtrip_and_legacy_fallback() {
        let password = "master_password";
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let params = VaultKdfParams {
            m_cost: 2048,
            t_cost: 2,
            p_cost: 1,
        };
        let keyfile = b"arbitrary keyfile bytes";

        let raw = argon2_key(password, &salt, params).unwrap();
        let modern_key = mix_keyfile(&raw, keyfile);
        let mut legacy_key = crate::locked_buf::LockedKey::zeroed();
        legacy_key.copy_from_slice(&combine_keyfile_legacy(&raw, keyfile));

        let encrypted = encrypt_store(&sample_store(), &modern_key, &salt, params).unwrap();

        // Current combiner opens it.
        let loaded = load_store_v2(&encrypted, password, Some(keyfile)).unwrap();
        assert_eq!(loaded.1, modern_key);

        // A vault saved with the old combiner also still opens.
        let legacy_encrypted = encrypt_store(&sample_store(), &legacy_key, &salt, params).unwrap();
        let loaded = load_store_v2(&legacy_encrypted, password, Some(keyfile)).unwrap();
        assert_eq!(loaded.1, legacy_key);

        // Wrong keyfile fails.
        let encrypted = encrypt_store(&sample_store(), &modern_key, &salt, params).unwrap();
        assert!(load_store_v2(&encrypted, password, Some(b"wrong")).is_err());
    }

    #[test]
    fn test_pre_aad_v2_vault_still_loads() {
        // Vaults saved by versions before header authentication were encrypted
        // without AAD; they must keep opening with the correct password.
        let store = sample_store();
        let password = "master_password";
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let params = VaultKdfParams {
            m_cost: 2048,
            t_cost: 2,
            p_cost: 1,
        };

        let key = derive_key_params(password, &salt, params, None).unwrap();
        let json = serde_json::to_vec(&store).unwrap();
        let cipher = Aes256Gcm::new((&*key).into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, &*json).unwrap();

        let mut encrypted = Vec::with_capacity(HEADER_LEN_V2 + ciphertext.len());
        encrypted.extend_from_slice(&MAGIC);
        encrypted.push(FORMAT_VERSION);
        encrypted.extend_from_slice(&salt);
        encrypted.extend_from_slice(&params.m_cost.to_le_bytes());
        encrypted.extend_from_slice(&params.t_cost.to_le_bytes());
        encrypted.extend_from_slice(&params.p_cost.to_le_bytes());
        encrypted.extend_from_slice(&nonce);
        encrypted.extend_from_slice(&ciphertext);

        let (loaded, loaded_key, loaded_params) =
            load_store_v2(&encrypted, password, None).unwrap();
        assert_eq!(loaded_key, key);
        assert_eq!(loaded_params, params);
        assert_eq!(loaded.entries[0].label, "test");
    }

    #[test]
    fn test_kdf_params_bounds_are_enforced() {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        for bad in [
            VaultKdfParams {
                m_cost: u32::MAX,
                t_cost: 3,
                p_cost: 1,
            },
            VaultKdfParams {
                m_cost: DEFAULT_M_COST,
                t_cost: 0,
                p_cost: 1,
            },
            VaultKdfParams {
                m_cost: DEFAULT_M_COST,
                t_cost: u32::MAX,
                p_cost: 1,
            },
            VaultKdfParams {
                m_cost: DEFAULT_M_COST,
                t_cost: 3,
                p_cost: 0,
            },
        ] {
            assert!(derive_key_params("pw", &salt, bad, None).is_err());
        }
    }

    #[test]
    fn test_csv_safe_neutralizes_formula_injection() {
        assert_eq!(csv_safe("=HYPERLINK(1)"), "'=HYPERLINK(1)");
        assert_eq!(csv_safe("+1+2"), "'+1+2");
        assert_eq!(csv_safe("-cmd"), "'-cmd");
        assert_eq!(csv_safe("@SUM(1)"), "'@SUM(1)");
        assert_eq!(csv_safe("normal label"), "normal label");
        assert_eq!(csv_safe(""), "");
    }

    #[test]
    fn test_csv_guard_roundtrip_is_lossless() {
        for original in [
            "=HYPERLINK(1)",
            "+1+2",
            "-cmd",
            "@SUM(1)",
            "\tnotes",
            "'-quoted",
            "'=quoted",
            "'plain quote",
            "'",
            "''-quoted",
            "password'",
            "normal label",
            "",
        ] {
            assert_eq!(csv_unsafe(&csv_safe(original)), original);
        }
    }

    // Backup tests redirect `crate::config::load()` at a temporary config
    // directory via XDG_CONFIG_HOME, which only `dirs` on Linux honors.
    #[cfg(target_os = "linux")]
    mod backup_tests {
        use super::*;
        use crate::config::Config;
        use std::ffi::OsString;
        use std::sync::{Mutex, MutexGuard};

        pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

        struct TestConfig {
            previous: Option<OsString>,
            config_dir: PathBuf,
            _lock: MutexGuard<'static, ()>,
        }

        impl TestConfig {
            fn new(tag: &str, config: &Config) -> Self {
                let lock = ENV_LOCK
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let config_dir = unique_dir(&format!("config-{tag}"));
                std::fs::create_dir_all(config_dir.join("aegis")).unwrap();
                std::fs::write(
                    config_dir.join("aegis").join("config.json"),
                    serde_json::to_string(config).unwrap(),
                )
                .unwrap();
                let previous = std::env::var_os("XDG_CONFIG_HOME");
                unsafe { std::env::set_var("XDG_CONFIG_HOME", &config_dir) };
                Self {
                    previous,
                    config_dir,
                    _lock: lock,
                }
            }
        }

        impl Drop for TestConfig {
            fn drop(&mut self) {
                match &self.previous {
                    Some(value) => unsafe { std::env::set_var("XDG_CONFIG_HOME", value) },
                    None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
                }
                let _ = std::fs::remove_dir_all(&self.config_dir);
            }
        }

        /// `legacy_duress` is private, so build the config through serde.
        fn config_with_backup_dir(backup_dir: &Path) -> Config {
            serde_json::from_str(&format!(
                r#"{{"lock_timeout_secs": 300, "backup_dir": {}}}"#,
                serde_json::to_string(&backup_dir).unwrap()
            ))
            .unwrap()
        }

        fn unique_dir(tag: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "aegis-backup-{tag}-{:016x}",
                rand::rng().random::<u64>()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        fn saved_vault(
            tag: &str,
        ) -> (
            PathBuf,
            PasswordList,
            crate::locked_buf::LockedKey,
            VaultKdfParams,
        ) {
            let vault = temp_vault_path(tag);
            let store = sample_store();
            let params = VaultKdfParams {
                m_cost: 2048,
                t_cost: 2,
                p_cost: 1,
            };
            let key = write_new_vault_file(&vault, &store, "password", params, None).unwrap();
            (vault, store, key, params)
        }

        fn backup_stamps(backup_dir: &Path, vault: &Path) -> Vec<u64> {
            let prefix = format!("{}.backup.", backup_prefix(vault, vault_file_stem(vault)));
            let mut stamps: Vec<u64> = std::fs::read_dir(backup_dir)
                .unwrap()
                .map(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .strip_prefix(&prefix)
                        .unwrap()
                        .strip_suffix(".aegis")
                        .unwrap()
                        .parse()
                        .unwrap()
                })
                .collect();
            stamps.sort_unstable();
            stamps
        }

        fn vault_file_stem(vault: &Path) -> &str {
            vault.file_stem().unwrap().to_str().unwrap()
        }

        fn unix_now_nanos() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        }

        #[test]
        fn test_save_store_writes_timestamped_backup() {
            let backup_dir = unique_dir("naming");
            let _config_env = TestConfig::new("naming", &config_with_backup_dir(&backup_dir));

            let (vault, store, key, params) = saved_vault("save-backup");
            save_store(&Some(vault.clone()), &store, &key, params).unwrap();

            let prefix = format!("{}.backup.", backup_prefix(&vault, vault_file_stem(&vault)));
            let names: Vec<String> = std::fs::read_dir(&backup_dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(names.len(), 1);
            let stamp = names[0]
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".aegis"))
                .unwrap_or_else(|| panic!("unexpected backup name {}", names[0]));
            stamp.parse::<u64>().expect("backup stamp is unix nanos");
            assert_eq!(
                std::fs::read(backup_dir.join(&names[0])).unwrap(),
                std::fs::read(&vault).unwrap()
            );

            let _ = std::fs::remove_file(vault);
            let _ = std::fs::remove_dir_all(backup_dir);
        }

        #[test]
        fn test_backup_names_differ_per_vault_path() {
            let backup_dir = unique_dir("collision");
            let _config_env = TestConfig::new("collision", &config_with_backup_dir(&backup_dir));

            let (vault_a, store, key, params) = saved_vault("collision-a");
            let vault_b = vault_a
                .parent()
                .unwrap()
                .join("other")
                .join(vault_a.file_name().unwrap());
            std::fs::create_dir_all(vault_b.parent().unwrap()).unwrap();
            write_new_vault_file(&vault_b, &store, "password", params, None).unwrap();

            save_store(&Some(vault_a.clone()), &store, &key, params).unwrap();
            save_store(&Some(vault_b.clone()), &store, &key, params).unwrap();

            let names: Vec<String> = std::fs::read_dir(&backup_dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(names.len(), 2, "same-stem vaults must not collide");

            let _ = std::fs::remove_file(vault_a);
            let _ = std::fs::remove_file(vault_b);
            let _ = std::fs::remove_dir_all(backup_dir);
        }

        #[test]
        fn test_save_store_keeps_only_newest_backups() {
            let backup_dir = unique_dir("prune");
            let _config_env = TestConfig::new("prune", &config_with_backup_dir(&backup_dir));

            let (vault, store, key, params) = saved_vault("prune-backup");
            let prefix = format!("{}.backup.", backup_prefix(&vault, vault_file_stem(&vault)));
            let now = unix_now_nanos();

            // Seed older stamps so pruning is observable without sleeping;
            // nanosecond names keep rapid saves from collapsing into one file.
            for age in 1..=(MAX_BACKUPS as u64 + 2) {
                std::fs::write(
                    backup_dir.join(format!("{prefix}{}.aegis", now - age)),
                    b"stale",
                )
                .unwrap();
            }

            for _ in 0..(MAX_BACKUPS + 3) {
                save_store(&Some(vault.clone()), &store, &key, params).unwrap();
            }

            let stamps = backup_stamps(&backup_dir, &vault);
            assert_eq!(stamps.len(), MAX_BACKUPS);
            assert!(stamps.iter().all(|stamp| *stamp >= now));
            for age in 1..=(MAX_BACKUPS as u64 + 2) {
                assert!(
                    !backup_dir
                        .join(format!("{prefix}{}.aegis", now - age))
                        .exists()
                );
            }

            let _ = std::fs::remove_file(vault);
            let _ = std::fs::remove_dir_all(backup_dir);
        }

        #[test]
        fn test_save_store_without_backup_dir_creates_no_backups() {
            let backup_dir = std::env::temp_dir().join(format!(
                "aegis-backup-disabled-{:016x}",
                rand::rng().random::<u64>()
            ));
            let _config_env = TestConfig::new("disabled", &Config::default());

            let (vault, store, key, params) = saved_vault("no-backup");
            save_store(&Some(vault.clone()), &store, &key, params).unwrap();

            assert!(!backup_dir.exists());
            let _ = std::fs::remove_file(vault);
        }
    }
}

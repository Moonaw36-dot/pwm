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

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const ITER_LEN: usize = 4;
const HEADER_LEN: usize = SALT_LEN + ITER_LEN + NONCE_LEN;
const HEADER_LEN_LEGACY: usize = SALT_LEN + NONCE_LEN;

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
    idx.and_then(|i| record.get(i))
        .unwrap_or("")
        .trim()
        .to_string()
}

fn optional_record_value(record: &csv::StringRecord, idx: Option<usize>) -> Option<String> {
    let value = record_value(record, idx);
    if value.is_empty() { None } else { Some(value) }
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
            _ => PasswordType::Normal,
        };
        let custom_fields = match optional_record_value(&record, idx_custom_fields) {
            Some(value) => serde_json::from_str(&value)
                .map_err(|error| format!("Invalid custom_fields JSON: {error}"))?,
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

        entries.push(PasswordEntry {
            label: record_value(&record, idx_label),
            username: record_value(&record, idx_username),
            password: Zeroizing::new(record_value(&record, idx_password)),
            url: record_value(&record, idx_url),
            notes: Zeroizing::new(record_value(&record, idx_notes)),
            tags,
            totp_secret: totp_secret.into(),
            custom_fields: Zeroizing::new(custom_fields),
            is_secure_note,
            created_at: None,
            totp_cache: None,
            password_type,
            number: optional_record_value(&record, idx_number).map(Zeroizing::new),
            expiration_date: optional_record_value(&record, idx_expiration).map(Zeroizing::new),
            cvc: optional_record_value(&record, idx_cvc).map(Zeroizing::new),
            favorite,
            totp_code_cache: None,
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
        ])
        .map_err(|e| e.to_string())?;

    for entry in &store.entries {
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
        writer
            .write_record([
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
            ])
            .map_err(|e| e.to_string())?;
    }

    writer.flush().map_err(|e| e.to_string())?;
    drop(writer);
    atomic_write_private_file(&path, &csv_data)
}

fn derive_key(
    password: &str,
    salt: &[u8; 16],
    keyfile_bytes: Option<&[u8]>,
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, String> {
    derive_key_params(password, salt, 65536, iterations, keyfile_bytes)
}

fn derive_key_params(
    password: &str,
    salt: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    keyfile_bytes: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    let params = argon2::Params::new(m_cost, t_cost, 1, Some(32))
        .map_err(|e| format!("Argon2 params: {e}"))?;
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    if let Some(kf) = keyfile_bytes {
        let mut combined = Zeroizing::new(Vec::with_capacity(32 + kf.len()));
        let key_ref: &[u8; 32] = &key;
        combined.extend_from_slice(key_ref);
        combined.extend_from_slice(kf);
        key.copy_from_slice(&Sha256::digest(&*combined));
    }

    Ok(key)
}
fn encrypt_store(
    store: &PasswordList,
    key: &[u8; 32],
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, String> {
    let json = Zeroizing::new(serde_json::to_string_pretty(store).map_err(|e| e.to_string())?);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, json.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&iterations.to_le_bytes());
    out.extend_from_slice(&nonce);
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

    let iterations = state.form.iterations_entry as u32;
    let key = derive_key(&state.master_input, &salt, None, iterations)?;
    let filedata = encrypt_store(&empty_store, &key, &salt, iterations)?;
    write_private_file_new(&path, &filedata)?;

    state.vault.store = Some(empty_store);
    state.vault.encryption_key = Some(key);
    state.vault.file_path = Some(path);
    state.vault.file_name = vault_name;
    state.vault.iterations = iterations;
    state.invalidate_vault_caches();
    Ok(())
}

pub fn load_keyfile(state: &mut AppState) -> Result<(), String> {
    let path = rfd::FileDialog::new()
        .add_filter("Aegis keyfile", &["aegis"])
        .pick_file()
        .ok_or("No file selected".to_string())?;

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
        let mut combined = Zeroizing::new(Vec::with_capacity(32 + 32));
        let enc_arr: &[u8; 32] = &enc_key;
        combined.extend_from_slice(enc_arr);
        combined.extend_from_slice(&*key);
        let digest = Sha256::digest(&*combined);
        let mut new_key = Zeroizing::new([0u8; 32]);
        new_key.copy_from_slice(&digest);

        if let Err(e) = save_store(
            &state.vault.file_path,
            &store,
            &new_key,
            state.vault.iterations,
        ) {
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
    m_cost: u32,
    t_cost: u32,
    keyfile_bytes: Option<&[u8]>,
) -> Option<(PasswordList, Zeroizing<[u8; 32]>)> {
    let key = derive_key_params(password, salt, m_cost, t_cost, keyfile_bytes).ok()?;
    let cipher = Aes256Gcm::new((&*key).into());
    let plaintext = Zeroizing::new(cipher.decrypt(nonce.into(), ciphertext).ok()?);
    let json = Zeroizing::new(String::from_utf8(plaintext.to_vec()).ok()?);
    let store: PasswordList = serde_json::from_str(&json).ok()?;
    Some((store, key))
}

pub fn load_store(
    path: &PathBuf,
    password: &str,
    keyfile_bytes: Option<&[u8]>,
) -> Result<(PasswordList, Zeroizing<[u8; 32]>), String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read vault: {e}"))?;

    if data.len() < SALT_LEN {
        return Err("File is too short to be a valid store".to_string());
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
            if let Some(result) = try_decrypt(
                password,
                &salt,
                &nonce,
                ciphertext,
                m_cost,
                t_cost,
                keyfile_bytes,
            ) {
                return Ok(result);
            }
        }
    }

    if data.len() > HEADER_LEN {
        let nonce: [u8; 12] = data[SALT_LEN + ITER_LEN..HEADER_LEN]
            .try_into()
            .map_err(|_| "Invalid nonce".to_string())?;
        let ciphertext = &data[HEADER_LEN..];
        let iterations = parse_iterations_from_header(&data);
        if let Some(result) = try_decrypt(
            password,
            &salt,
            &nonce,
            ciphertext,
            65536,
            iterations,
            keyfile_bytes,
        )
        .or_else(|| try_decrypt(password, &salt, &nonce, ciphertext, 65536, 3, keyfile_bytes))
        .or_else(|| try_decrypt(password, &salt, &nonce, ciphertext, 19456, 2, keyfile_bytes))
        .or_else(|| try_decrypt(password, &salt, &nonce, ciphertext, 65536, 2, keyfile_bytes))
        {
            return Ok(result);
        }
    }

    Err("Decryption failed: wrong master password or corrupted file".to_string())
}

pub fn save_store(
    path: &Option<PathBuf>,
    store: &PasswordList,
    key: &[u8; 32],
    iterations: u32,
) -> Result<(), String> {
    let Some(p) = path else { return Ok(()) };

    let mut existing =
        std::fs::File::open(p).map_err(|e| format!("Failed to read vault before save: {e}"))?;
    let mut salt = [0u8; SALT_LEN];
    existing
        .read_exact(&mut salt)
        .map_err(|_| "File is too short to be a valid store".to_string())?;

    let filedata = encrypt_store(store, key, &salt, iterations)?;
    atomic_write_private_file(p, &filedata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PasswordEntry;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let store = PasswordList {
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
        };

        let password = "master_password";
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);

        let key = derive_key_params(password, &salt, 65536, 3, None).unwrap();
        let encrypted = encrypt_store(&store, &key, &salt, 3).unwrap();

        assert!(encrypted.len() > HEADER_LEN);
        assert_eq!(&encrypted[..SALT_LEN], &salt);
        assert_eq!(
            &encrypted[SALT_LEN..SALT_LEN + ITER_LEN],
            &3u32.to_le_bytes()
        );

        let nonce: [u8; 12] = encrypted[SALT_LEN + ITER_LEN..HEADER_LEN]
            .try_into()
            .unwrap();
        let ciphertext = &encrypted[HEADER_LEN..];

        let (decrypted_store, _) =
            try_decrypt(password, &salt, &nonce, ciphertext, 65536, 3, None).unwrap();

        assert_eq!(decrypted_store.entries.len(), 2);
        assert_eq!(decrypted_store.entries[0].label, "test");
        assert_eq!(decrypted_store.entries[0].password.as_str(), "secret123");
        assert_eq!(
            decrypted_store.entries[0].totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(decrypted_store.entries[1].label, "empty");
        assert!(decrypted_store.entries[1].password.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_wrong_key_fails() {
        let store = PasswordList { entries: vec![] };
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);

        let key = derive_key_params("correct", &salt, 65536, 3, None).unwrap();
        let encrypted = encrypt_store(&store, &key, &salt, 3).unwrap();

        let nonce: [u8; 12] = encrypted[SALT_LEN + ITER_LEN..HEADER_LEN]
            .try_into()
            .unwrap();
        let ciphertext = &encrypted[HEADER_LEN..];

        assert!(try_decrypt("wrong", &salt, &nonce, ciphertext, 65536, 3, None).is_none());
    }

    #[test]
    fn test_legacy_fallback() {
        let store = PasswordList {
            entries: vec![PasswordEntry {
                label: "legacy".into(),
                password: Zeroizing::new("p4ss".into()),
                ..Default::default()
            }],
        };

        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let legacy_key = derive_key_params("mypass", &salt, 19456, 2, None).unwrap();
        let json = serde_json::to_string_pretty(&store).unwrap();
        let cipher = Aes256Gcm::new((&*legacy_key).into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, json.as_bytes()).unwrap();
        let mut encrypted = Vec::with_capacity(HEADER_LEN_LEGACY + ciphertext.len());
        encrypted.extend_from_slice(&salt);
        encrypted.extend_from_slice(&nonce);
        encrypted.extend_from_slice(&ciphertext);

        let (decrypted, new_key) = load_store_for_test(&encrypted, "mypass").unwrap();
        assert_eq!(decrypted.entries[0].label, "legacy");
        assert_eq!(new_key, legacy_key);
    }

    #[test]
    fn test_save_and_load_current_format() {
        let path = std::env::temp_dir().join(format!(
            "aegis-save-test-{:016x}.aegis",
            rand::rng().random::<u64>()
        ));
        let store = PasswordList {
            entries: vec![PasswordEntry {
                label: "saved".into(),
                password: Zeroizing::new("secret".into()),
                ..Default::default()
            }],
        };
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let key = derive_key_params("password", &salt, 65536, 3, None).unwrap();
        let encrypted = encrypt_store(&store, &key, &salt, 3).unwrap();
        write_private_file_new(&path, &encrypted).unwrap();

        let loaded = load_store(&path, "password", None).unwrap();
        assert_eq!(loaded.0.entries[0].label, "saved");
        save_store(&Some(path.clone()), &store, &key, 3).unwrap();
        let reloaded = load_store(&path, "password", None).unwrap();
        assert_eq!(reloaded.0.entries[0].password.as_str(), "secret");
        let _ = std::fs::remove_file(path);
    }

    fn load_store_for_test(
        data: &[u8],
        password: &str,
    ) -> Option<(PasswordList, Zeroizing<[u8; 32]>)> {
        if data.len() > HEADER_LEN_LEGACY {
            let salt: [u8; 16] = data[..SALT_LEN].try_into().ok()?;
            let nonce: [u8; 12] = data[SALT_LEN..HEADER_LEN_LEGACY].try_into().ok()?;
            let ct = &data[HEADER_LEN_LEGACY..];
            if let Some(result) = try_decrypt(password, &salt, &nonce, ct, 19456, 2, None)
                .or_else(|| try_decrypt(password, &salt, &nonce, ct, 65536, 3, None))
            {
                return Some(result);
            }
        }
        if data.len() > HEADER_LEN {
            let salt: [u8; 16] = data[..SALT_LEN].try_into().ok()?;
            let nonce: [u8; 12] = data[SALT_LEN + ITER_LEN..HEADER_LEN].try_into().ok()?;
            let ct = &data[HEADER_LEN..];
            let iterations = parse_iterations_from_header(data);
            try_decrypt(password, &salt, &nonce, ct, 65536, iterations, None)
                .or_else(|| try_decrypt(password, &salt, &nonce, ct, 65536, 3, None))
                .or_else(|| try_decrypt(password, &salt, &nonce, ct, 65536, 2, None))
        } else {
            None
        }
    }
}

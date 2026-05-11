use std::path::PathBuf;
use rand::Rng;
use argon2::Argon2;
use aes_gcm::{Aes256Gcm, KeyInit, AeadCore};
use aes_gcm::aead::{Aead, OsRng};
use sha2::{Sha256, Digest};
use zeroize::{Zeroize, Zeroizing};
use crate::app::{AppState, PasswordEntry, PasswordList};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = SALT_LEN + NONCE_LEN;

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

pub fn import_csv() -> Result<Option<PasswordList>, String> {
    let Some(path) = open_csv_dialog() else { return Ok(None) };
    let mut reader = csv::Reader::from_path(path).map_err(|e| e.to_string())?;

    let headers = reader.headers().map_err(|e| e.to_string())?.clone();
    let col = |name: &str| headers.iter().position(|h| h.eq_ignore_ascii_case(name));

    let idx_label    = col("label").or_else(|| col("name")).or_else(|| col("title"));
    let idx_username = col("username").or_else(|| col("login").or_else(|| col("email")));
    let idx_password = col("password").or_else(|| col("pass"));
    let idx_url      = col("url").or_else(|| col("website").or_else(|| col("site")));
    let idx_notes    = col("notes").or_else(|| col("note").or_else(|| col("comment")));
    let idx_tags     = col("tags").or_else(|| col("tag"));
    let idx_totp     = col("totp_secret").or_else(|| col("totp").or_else(|| col("otp")));

    let get = |r: &csv::StringRecord, idx: Option<usize>| -> String {
        idx.and_then(|i| r.get(i)).unwrap_or("").trim().to_string()
    };

    let mut entries = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|e| e.to_string())?;

        let tags_raw = get(&record, idx_tags);
        let tags = if tags_raw.is_empty() {
            None
        } else {
            Some(tags_raw.split(';').map(|s| s.trim().to_string()).collect())
        };

        let totp_raw = get(&record, idx_totp);
        let totp_secret = if totp_raw.is_empty() { None } else { Some(totp_raw) };

        entries.push(PasswordEntry {
            label:    get(&record, idx_label),
            username: get(&record, idx_username),
            password: Zeroizing::new(get(&record, idx_password)),
            url:      get(&record, idx_url),
            notes:    get(&record, idx_notes),
            tags,
            totp_secret,
            custom_fields: Vec::new(),
            is_secure_note: false,
            created_at: None,
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
        != rfd::MessageDialogResult::Yes
    {
        return Ok(());
    }

    let Some(path) = save_csv_dialog() else { return Ok(()) };

    let mut writer = csv::Writer::from_path(&path).map_err(|e| e.to_string())?;

    writer.write_record(["label", "username", "password", "url", "notes", "tags", "totp_secret"])
        .map_err(|e| e.to_string())?;

    for entry in &store.entries {
        let tags = entry.tags.as_deref().map(|t| t.join(";")).unwrap_or_default();
        let totp = entry.totp_secret.as_deref().unwrap_or("");
        writer.write_record([
            &entry.label,
            &entry.username,
            entry.password.as_str(),
            &entry.url,
            &entry.notes,
            &tags,
            totp,
        ]).map_err(|e| e.to_string())?;
    }

    writer.flush().map_err(|e| e.to_string())
}

fn derive_key(password: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, String> {
    derive_key_params(password, salt, 65536, 3)
}

fn derive_key_legacy(password: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, String> {
    derive_key_params(password, salt, 19456, 2)
}

fn derive_key_params(password: &str, salt: &[u8; 16], m_cost: u32, t_cost: u32) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    let params = argon2::Params::new(m_cost, t_cost, 1, Some(32))
        .map_err(|e| format!("Argon2 params: {e}"))?;
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    Ok(key)
}

fn encrypt_store(store: &PasswordList, key: &[u8; 32], salt: &[u8]) -> Result<Vec<u8>, String> {
    let json = Zeroizing::new(serde_json::to_string_pretty(store).map_err(|e| e.to_string())?);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, json.as_bytes()).map_err(|e| e.to_string())?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn create_file(file_name: &str, state: &mut AppState) -> Result<(), String> {
    let Some(dir) = rfd::FileDialog::new().set_directory(".").pick_folder() else {
        return Err("No file selected".parse().unwrap());
    };

    let path: PathBuf = if file_name.ends_with(".aegis") {
        dir.join(file_name)
    } else {
        dir.join(format!("{file_name}.aegis"))
    };

    let empty_store = PasswordList { entries: Vec::new() };

    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    let key = derive_key(&state.master_input, &salt)?;
    let filedata = encrypt_store(&empty_store, &key, &salt)?;
    std::fs::write(&path, filedata).map_err(|e| e.to_string())?;

    state.vault.store = Some(empty_store);
    state.vault.encryption_key = Some(key);
    state.vault.file_path = Some(path);
    state.vault.file_name = file_name.to_string();
    Ok(())
}

pub fn load_keyfile(state: &mut AppState) -> Result<(), String> {
    let path = rfd::FileDialog::new()
        .add_filter("Aegis keyfile", &["aegis"])
        .pick_file()
        .ok_or("No file selected".to_string())?;

    let bytes = Zeroizing::new(std::fs::read(&path).map_err(|e| e.to_string())?);
    let hash: [u8; 32] = Sha256::digest(&bytes).into();



    if Some(hash) != state.vault.keyfile_hash {
        return Err("Invalid hash.".to_string());
    }

    state.vault.keyfile = Some(path);
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

    std::fs::write(&path, *key).map_err(|e| e.to_string())?;

    state.vault.keyfile_hash = Some(hash);
    state.vault.keyfile = Some(path);

    if let Some(vault_path) = &state.vault.file_path {
        let mut config = crate::config::load();
        config.keyfile_hashes.insert(vault_path.clone(), hash);
        let _ = crate::config::save(&config);
    }

    Ok(())
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
                    notes: "my note".into(),
                    totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
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

        let key = derive_key_params(password, &salt, 65536, 3).unwrap();
        let encrypted = encrypt_store(&store, &key, &salt).unwrap();

        assert!(encrypted.len() > HEADER_LEN);
        assert_eq!(&encrypted[..SALT_LEN], &salt);

        let nonce: [u8; 12] = encrypted[SALT_LEN..HEADER_LEN].try_into().unwrap();
        let ciphertext = &encrypted[HEADER_LEN..];

        let (decrypted_store, _) = try_decrypt(password, &salt, &nonce, ciphertext, false).unwrap();

        assert_eq!(decrypted_store.entries.len(), 2);
        assert_eq!(decrypted_store.entries[0].label, "test");
        assert_eq!(decrypted_store.entries[0].password.as_str(), "secret123");
        assert_eq!(decrypted_store.entries[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(decrypted_store.entries[1].label, "empty");
        assert!(decrypted_store.entries[1].password.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_wrong_key_fails() {
        let store = PasswordList { entries: vec![] };
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);

        let key = derive_key_params("correct", &salt, 65536, 3).unwrap();
        let encrypted = encrypt_store(&store, &key, &salt).unwrap();

        let nonce: [u8; 12] = encrypted[SALT_LEN..HEADER_LEN].try_into().unwrap();
        let ciphertext = &encrypted[HEADER_LEN..];

        assert!(try_decrypt("wrong", &salt, &nonce, ciphertext, false).is_none());
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
        let legacy_key = derive_key_params("mypass", &salt, 19456, 2).unwrap();
        let encrypted = encrypt_store(&store, &legacy_key, &salt).unwrap();

        let (decrypted, new_key) = load_store_for_test(&encrypted, "mypass").unwrap();
        assert_eq!(decrypted.entries[0].label, "legacy");
        assert_eq!(new_key, legacy_key);
    }

    fn load_store_for_test(data: &[u8], password: &str) -> Option<(PasswordList, Zeroizing<[u8; 32]>)> {
        if data.len() < HEADER_LEN + 1 { return None; }
        let salt: [u8; 16] = data[..SALT_LEN].try_into().ok()?;
        let nonce: [u8; 12] = data[SALT_LEN..HEADER_LEN].try_into().ok()?;
        let ct = &data[HEADER_LEN..];
        try_decrypt(password, &salt, &nonce, ct, false)
            .or_else(|| try_decrypt(password, &salt, &nonce, ct, true))
    }
}

fn try_decrypt(password: &str, salt: &[u8; 16], nonce: &[u8; 12], ciphertext: &[u8], legacy: bool) -> Option<(PasswordList, Zeroizing<[u8; 32]>)> {
    let key = if legacy { derive_key_legacy(password, salt) } else { derive_key(password, salt) }.ok()?;
    let cipher = Aes256Gcm::new((&*key).into());
    let plaintext = cipher.decrypt(nonce.into(), ciphertext).ok()?;
    let mut json = String::from_utf8(plaintext).ok()?;
    let store: PasswordList = serde_json::from_str(&json).ok()?;
    json.zeroize();
    Some((store, key))
}

pub fn load_store(path: &PathBuf, password: &str) -> Result<(PasswordList, Zeroizing<[u8; 32]>), String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read vault: {e}"))?;
    if data.len() < HEADER_LEN + 1 {
        return Err("File is too short to be a valid vault".to_string());
    }

    let salt: [u8; 16] = data[..SALT_LEN].try_into()
        .map_err(|_| "Invalid salt".to_string())?;
    let nonce_bytes: [u8; 12] = data[SALT_LEN..HEADER_LEN].try_into()
        .map_err(|_| "Invalid nonce".to_string())?;
    let ciphertext = &data[HEADER_LEN..];

    if let Some(result) = try_decrypt(password, &salt, &nonce_bytes, ciphertext, false) {
        return Ok(result);
    }

    if let Some(result) = try_decrypt(password, &salt, &nonce_bytes, ciphertext, true) {
        return Ok(result);
    }

    Err("Decryption failed: wrong master password or corrupted file".to_string())
}

pub fn save_store(path: &Option<PathBuf>, store: &PasswordList, key: &[u8; 32]) -> Result<(), String> {
    let Some(p) = path else { return Ok(()) };

    let existing = std::fs::read(p).map_err(|e| e.to_string())?;
    if existing.len() < SALT_LEN {
        return Err("File is too short to be a valid store".to_string());
    }
    let salt = &existing[..SALT_LEN];

    let filedata = encrypt_store(store, key, salt)?;
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, filedata).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, p).map_err(|e| e.to_string())?;
    Ok(())
}

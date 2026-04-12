use std::path::PathBuf;
use rand::Rng;
use argon2::Argon2;
use aes_gcm::{Aes256Gcm, KeyInit, AeadCore};
use aes_gcm::aead::{Aead, OsRng};
use zeroize::Zeroizing;
use crate::app::{AppState, PasswordEntry, PasswordList};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = SALT_LEN + NONCE_LEN;

pub fn open_file_dialog() -> Option<(String, PathBuf)> {
    let path = rfd::FileDialog::new()
        .add_filter("CSV", &["csv"])
        .add_filter("JSON", &["json"])
        .add_filter("All Files", &["*"])
        .set_directory(".")
        .pick_file()?;

    let name = path.file_name()?.to_string_lossy().to_string();
    Some((name, path))
}

pub fn save_file_dialog() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("CSV", &["csv"])
        .save_file()
}

pub fn import_csv() -> Result<Option<PasswordList>, String> {
    let Some((_, path)) = open_file_dialog() else { return Ok(None) };
    let mut csv = csv::Reader::from_path(path).map_err(|e| e.to_string())?;

    let mut entries = Vec::new();

    for result in csv.records() {
        let record = result.map_err(|e| e.to_string())?;
        let tags_raw = record.get(5).unwrap_or("").trim().to_string();
        let tags = if tags_raw.is_empty() {
            None
        } else {
            Some(tags_raw.split(';').map(|s| s.to_string()).collect())
        };
        entries.push(PasswordEntry {
            label:    record.get(0).unwrap_or("").to_string(),
            username: record.get(1).unwrap_or("").to_string(),
            password: record.get(2).unwrap_or("").to_string(),
            url:      record.get(3).unwrap_or("").to_string(),
            notes:    record.get(4).unwrap_or("").to_string(),
            totp_secret: None,
            tags,
        });
    }

    Ok(Some(PasswordList { entries }))                                                              
}

pub fn export_csv(store: &PasswordList) -> Result<(), String> {
    let Some(path) = save_file_dialog() else { return Ok(()) };

    let mut csv = String::from("label,username,password,url,notes,tags\n");
    for entry in &store.entries {
        let tags = entry.tags.as_deref().map(|t| t.join(";")).unwrap_or_default();
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            escape_csv(&entry.label),
            escape_csv(&entry.username),
            escape_csv(&entry.password),
            escape_csv(&entry.url),
            escape_csv(&entry.notes),
            escape_csv(&tags),
        ));
    }

    std::fs::write(&path, csv).map_err(|e| e.to_string())
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn derive_key(password: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let _ = Argon2::default().hash_password_into(password.as_bytes(), salt, &mut *key);
    key
}

fn encrypt_store(store: &PasswordList, key: &[u8; 32], salt: &[u8]) -> Result<Vec<u8>, String> {
    let json = serde_json::to_string_pretty(store).map_err(|e| e.to_string())?;
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
        return Ok(());
    };

    let path = dir.join(format!("{file_name}.json"));
    let empty_store = PasswordList { entries: Vec::new() };

    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    let key = derive_key(&state.master_input, &salt);
    let filedata = encrypt_store(&empty_store, &key, &salt)?;
    std::fs::write(&path, filedata).map_err(|e| e.to_string())?;

    state.store = Some(empty_store);
    state.encryption_key = Some(key);
    state.selected_file = Some(path);
    state.selected_file_name = file_name.to_string();
    Ok(())
}

pub fn load_store(path: &PathBuf, password: &str) -> Option<(PasswordList, Zeroizing<[u8; 32]>)> {
    let data = std::fs::read(path).ok()?;
    if data.len() < HEADER_LEN + 1 {
        return None;
    }

    let salt: [u8; 16] = data[..SALT_LEN].try_into().ok()?;
    let nonce_bytes: [u8; 12] = data[SALT_LEN..HEADER_LEN].try_into().ok()?;
    let ciphertext = &data[HEADER_LEN..];

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new((&*key).into());
    let plaintext = cipher.decrypt(&nonce_bytes.into(), ciphertext).ok()?;

    let json = String::from_utf8(plaintext).ok()?;
    let store: PasswordList = serde_json::from_str(&json).ok()?;

    Some((store, key))
}

pub fn save_store(path: &Option<PathBuf>, store: &PasswordList, key: &[u8; 32]) -> Result<(), String> {
    let Some(p) = path else { return Ok(()) };

    let existing = std::fs::read(p).map_err(|e| e.to_string())?;
    if existing.len() < SALT_LEN {
        return Err("File is too short to be a valid store".to_string());
    }
    let salt = &existing[..SALT_LEN];

    let filedata = encrypt_store(store, key, salt)?;
    std::fs::write(p, filedata).map_err(|e| e.to_string())?;
    Ok(())
}

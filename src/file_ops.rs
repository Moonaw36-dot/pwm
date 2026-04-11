use std::path::PathBuf;
use rand::Rng;
use argon2::Argon2;
use aes_gcm::{Aes256Gcm, KeyInit, AeadCore};
use aes_gcm::aead::{Aead, OsRng};
use crate::app::{AppState, PasswordList};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = SALT_LEN + NONCE_LEN;

pub fn open_file_dialog() -> Option<(String, PathBuf)> {
    let path = rfd::FileDialog::new()
        .add_filter("JSON", &["json"])
        .add_filter("All Files", &["*"])
        .set_directory(".")
        .pick_file()?;

    let name = path.file_name()?.to_string_lossy().to_string();
    Some((name, path))
}

fn derive_key(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("key derivation failed");
    key
}

fn encrypt_store(store: &PasswordList, key: &[u8; 32], salt: &[u8]) -> Vec<u8> {
    let json = serde_json::to_string_pretty(store).expect("failed to serialize");
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, json.as_bytes()).expect("encryption failed");

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

pub fn create_file(file_name: &str, state: &mut AppState) {
    let Some(dir) = rfd::FileDialog::new().set_directory(".").pick_folder() else {
        return;
    };

    let path = dir.join(format!("{file_name}.json"));
    let empty_store = PasswordList { entries: Vec::new() };

    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    let key = derive_key(&state.master_input, &salt);
    let filedata = encrypt_store(&empty_store, &key, &salt);
    std::fs::write(&path, filedata).expect("failed to write");

    state.store = Some(empty_store);
    state.encryption_key = Some(key);
    state.selected_file = Some(path);
    state.selected_file_name = file_name.to_string();
}

pub fn load_store(path: &PathBuf, password: &str) -> Option<(PasswordList, [u8; 32])> {
    let data = std::fs::read(path).ok()?;
    if data.len() < HEADER_LEN + 1 {
        return None;
    }

    let salt: [u8; 16] = data[..SALT_LEN].try_into().ok()?;
    let nonce_bytes: [u8; 12] = data[SALT_LEN..HEADER_LEN].try_into().ok()?;
    let ciphertext = &data[HEADER_LEN..];

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(&key.into());
    let plaintext = cipher.decrypt(&nonce_bytes.into(), ciphertext).ok()?;

    let json = String::from_utf8(plaintext).ok()?;
    let store: PasswordList = serde_json::from_str(&json).ok()?;

    Some((store, key))
}

pub fn save_store(path: &Option<PathBuf>, store: &PasswordList, key: &[u8; 32]) {
    let Some(p) = path else { return };

    let existing = match std::fs::read(p) {
        Ok(d) if d.len() >= SALT_LEN => d,
        _ => return,
    };
    let salt = &existing[..SALT_LEN];

    let filedata = encrypt_store(store, key, salt);
    std::fs::write(p, filedata).ok();
}

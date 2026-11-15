use crate::app::{AppState, PasswordEntry, PasswordList};
use crate::file_ops::{VaultKdfParams, create_file, load_store, write_new_vault_file};
use crate::models::PasswordType;
use crate::strength::master_password_issue;
use crate::{config, strength, theme};
use rand::RngExt;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::result::Result::Ok;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

enum Unlocked {
    Real(PasswordList, crate::locked_buf::LockedKey, VaultKdfParams),
    Decoy(
        PasswordList,
        crate::locked_buf::LockedKey,
        VaultKdfParams,
        PathBuf,
    ),
    NeedKeyfile,
    Failed(String),
}

thread_local! {
    // The UI runs on one thread, so the pending unlock lives here.
    static UNLOCK_JOB: RefCell<Option<Receiver<Unlocked>>> = const { RefCell::new(None) };
}

/// Abort an unlock in flight and wipe the unlock inputs.
pub(crate) fn cancel(state: &mut AppState) {
    UNLOCK_JOB.with(|job| job.borrow_mut().take());
    state.cancel_unlock();
}

fn unlocking() -> bool {
    UNLOCK_JOB.with(|job| job.borrow().is_some())
}

fn start_unlock(state: &AppState, path: PathBuf) {
    let password = Zeroizing::new(state.master_input.to_string());
    let keyfile = state.vault.keyfile_bytes.clone();
    let keyfile_missing = state.vault.keyfile_hash.is_some() && keyfile.is_none();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = unlock_worker(&path, &password, keyfile.as_ref(), keyfile_missing);
        // A dropped receiver means the user cancelled.
        let _ = sender.send(outcome);
    });
    UNLOCK_JOB.with(|job| *job.borrow_mut() = Some(receiver));
}

fn unlock_worker(
    path: &PathBuf,
    password: &str,
    keyfile: Option<&Zeroizing<Vec<u8>>>,
    keyfile_missing: bool,
) -> Unlocked {
    // The real vault goes first, so a duress password equal to the master
    // password can never lock the owner out.
    let mut real_error = None;
    if !keyfile_missing {
        match load_store(path, password, keyfile.map(|v| v.as_slice())) {
            Ok((store, key, params)) => return Unlocked::Real(store, key, params),
            Err(error) => real_error = Some(error),
        }
    }

    let duress_hit = config::load()
        .duress_by_vault
        .get(path)
        .is_some_and(|duress| duress.matches(password));
    if duress_hit {
        return match load_or_create_decoy(path, password) {
            Ok((store, key, params, decoy_path)) => Unlocked::Decoy(store, key, params, decoy_path),
            Err(_) => Unlocked::Failed(
                "Decryption failed: wrong master password or corrupted file".to_string(),
            ),
        };
    }

    match real_error {
        Some(error) => Unlocked::Failed(error),
        None => Unlocked::NeedKeyfile,
    }
}

fn register_failed_unlock(state: &mut AppState) {
    state.failed_unlocks = state.failed_unlocks.saturating_add(1);
    let secs = crate::app::unlock_penalty_secs(state.failed_unlocks);
    if secs > 0 {
        state.unlock_penalty_until = Some(Instant::now() + Duration::from_secs(secs));
    }
}

fn finish_unlock(ui: &imgui::Ui, state: &mut AppState, outcome: Unlocked) {
    match outcome {
        Unlocked::Real(store, key, params) => {
            if let Some(path) = state.vault.file_path.clone() {
                if let Err(error) = crate::file_ops::remember_keyfile_hash(state) {
                    state.custom_error_message = Some(error);
                }
                let name = state.vault.file_name.clone();
                open_unlocked_vault(state, path, &name, store, key, params);
                ui.close_current_popup();
            }
        }
        Unlocked::Decoy(store, key, params, decoy_path) => {
            // The decoy never has a keyfile, even when the real vault has one.
            state.vault.keyfile = None;
            state.vault.keyfile_bytes = None;
            state.vault.keyfile_hash = None;
            // Keep the real file name so nothing in the UI hints at the decoy.
            let name = state.vault.file_name.clone();
            open_unlocked_vault(state, decoy_path, &name, store, key, params);
            ui.close_current_popup();
        }
        Unlocked::NeedKeyfile => {
            state.custom_error_message =
                Some("Please select your keyfile before unlocking.".to_string());
        }
        Unlocked::Failed(error) => {
            register_failed_unlock(state);
            state.custom_error_message = Some(error);
        }
    }
}

pub fn enter_master_password(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);

    let finished = UNLOCK_JOB.with(|job| {
        let mut job = job.borrow_mut();
        let result = match job.as_ref()?.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Some(Unlocked::Failed(
                "Unlock worker stopped unexpectedly".to_string(),
            )),
        };
        *job = None;
        result
    });
    if let Some(outcome) = finished {
        finish_unlock(ui, state, outcome);
        return;
    }
    if unlocking() {
        ui.text("Unlocking...");
        if ui.button("Cancel##unlocking") {
            cancel(state);
            ui.close_current_popup();
        }
        return;
    }

    if state.modals.master_is_create {
        ui.text("Set a master password for your new file.");
        ui.text("DO NOT FORGET IT. There is no way to recover it.");
    } else {
        ui.text("Enter your master password to unlock the file.");
    }
    ui.separator();

    ui.input_text("Master password", &mut state.master_input)
        .password(true)
        .build();

    if state.modals.master_is_create {
        ui.input_text("Confirm master password", &mut state.master_confirm_input)
            .password(true)
            .build();
    }

    let button_label = if state.modals.master_is_create {
        "Create"
    } else {
        "Unlock"
    };

    if state.vault.keyfile.is_some() {
        ui.text("Keyfile selected.");
        if ui.button("Clear keyfile") {
            state.vault.keyfile = None;
            state.vault.keyfile_bytes = None;
        }
    } else {
        if state.vault.keyfile_hash.is_some() {
            ui.text("This vault requires a keyfile. Select it to unlock.");
        } else {
            ui.text("If this vault was created with a keyfile, select it here.");
        }
        if ui.button("Select keyfile") {
            match crate::file_ops::load_keyfile(state) {
                Ok(_) => {
                    state.custom_success_message =
                        Some("Successfully selected keyfile!".to_string());
                    state.modals.show_success = true;
                }
                Err(error) => {
                    state.custom_error_message = Some(error);
                    return;
                }
            }
        }
    }

    if let Some(until) = state.unlock_penalty_until {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining > Duration::ZERO {
            ui.text_colored(
                [0.85, 0.15, 0.15, 1.0],
                format!(
                    "Too many failed attempts — next try in {} s.",
                    remaining.as_secs().max(1)
                ),
            );
        }
    }

    if ui.button(button_label) {
        if let Some(until) = state.unlock_penalty_until {
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining > Duration::ZERO {
                state.custom_error_message = Some(format!(
                    "Too many failed unlock attempts. Try again in {} s.",
                    remaining.as_secs().max(1)
                ));
                return;
            }
            state.unlock_penalty_until = None;
        }
        if state.modals.master_is_create {
            if state.master_input.is_empty() {
                state.custom_error_message = Some("Master password cannot be empty.".to_string());
                return;
            }
            if state.master_input.as_str() != state.master_confirm_input.as_str() {
                state.custom_error_message =
                    Some("Master password confirmation does not match.".to_string());
                return;
            }
            if let Some(issue) = master_password_issue(state.master_input.as_str()) {
                state.custom_error_message = Some(issue.to_string());
                return;
            }
            let filename = state.filename_input.clone();
            match create_file(&filename, state) {
                Ok(_) => {
                    state.custom_success_message = Some("Vault created successfully!".to_string());
                    state.modals.show_success = true;
                    state.filename_input.clear();
                    state.master_input.zeroize();
                    state.master_confirm_input.zeroize();
                    state.modals.master_is_create = false;
                    ui.close_current_popup();
                }
                Err(e) => {
                    state.custom_error_message = Some(e);
                }
            }
        } else if let Some(path) = state.vault.file_path.clone() {
            start_unlock(state, path);
        }
    }

    ui.same_line();
    if ui.button("Cancel") {
        cancel(state);
        ui.close_current_popup();
    }
}

fn open_unlocked_vault(
    state: &mut AppState,
    path: PathBuf,
    name: &str,
    store: PasswordList,
    key: crate::locked_buf::LockedKey,
    params: VaultKdfParams,
) {
    state.vault.store = Some(store);
    state.vault.encryption_key = Some(key);
    state.vault.kdf_params = Some(params);
    state.vault.file_path = Some(path);
    state.vault.file_name = name.to_string();
    state.invalidate_vault_caches();
    state.failed_unlocks = 0;
    state.unlock_penalty_until = None;
    state.master_input.zeroize();
    state.master_confirm_input.zeroize();
}

/// Open `<vault>.decoy.aegis` with the duress password, generating it first
/// when it does not exist yet.
pub(crate) fn load_or_create_decoy(
    vault_path: &Path,
    duress_password: &str,
) -> Result<
    (
        PasswordList,
        crate::locked_buf::LockedKey,
        VaultKdfParams,
        PathBuf,
    ),
    String,
> {
    let decoy_path = decoy_path_for(vault_path);
    let create = |decoy_path: &PathBuf| {
        write_new_vault_file(
            decoy_path,
            &build_decoy_store(),
            duress_password,
            VaultKdfParams {
                m_cost: crate::file_ops::DEFAULT_M_COST,
                t_cost: 3,
                p_cost: 1,
            },
            None,
        )?;
        load_store(decoy_path, duress_password, None)
    };
    let (store, key, params) = match std::fs::metadata(&decoy_path) {
        Ok(_) => match load_store(&decoy_path, duress_password, None) {
            Ok(opened) => opened,
            Err(error) if error.starts_with("Failed to read") => return Err(error),
            Err(_) => {
                // Left over from an earlier duress password; start over.
                std::fs::remove_file(&decoy_path)
                    .map_err(|e| format!("Failed to replace decoy vault: {e}"))?;
                create(&decoy_path)?
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create(&decoy_path)?,
        Err(error) => return Err(format!("Failed to read vault: {error}")),
    };
    Ok((store, key, params, decoy_path))
}

pub(crate) fn is_decoy_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".decoy.aegis"))
}

pub(crate) fn decoy_path_for(vault_path: &Path) -> PathBuf {
    let stem = vault_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("vault");
    vault_path.with_file_name(format!("{stem}.decoy.aegis"))
}

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn random_totp_secret() -> String {
    let mut rng = rand::rng();
    (0..16)
        .map(|_| BASE32_ALPHABET[rng.random_range(..BASE32_ALPHABET.len())] as char)
        .collect()
}

fn luhn_card_number() -> String {
    let mut digits: Vec<u8> = (0..15).map(|_| rand::rng().random_range(0..10)).collect();
    let mut sum = 0u32;
    for (index, digit) in digits.iter().rev().enumerate() {
        if index % 2 == 0 {
            let doubled = u32::from(*digit) * 2;
            sum += doubled / 10 + doubled % 10;
        } else {
            sum += u32::from(*digit);
        }
    }
    digits.push(((10 - sum % 10) % 10) as u8);
    digits.iter().map(|d| (b'0' + d) as char).collect()
}

fn random_card_expiry() -> String {
    let month = rand::rng().random_range(1..=12u32);
    let year = 27 + rand::rng().random_range(0..=5u32);
    format!("{month:02}/{year}")
}

fn decoy_login(
    label: &str,
    username: &str,
    url: &str,
    passphrase: bool,
    created_at: u64,
) -> PasswordEntry {
    let password = if passphrase {
        strength::generate_passphrase(5, "-")
    } else {
        strength::generate_password(20, true, true, true, true, false)
    };
    PasswordEntry {
        label: label.to_string(),
        username: username.to_string(),
        password: Zeroizing::new(password),
        url: url.to_string(),
        notes: Zeroizing::new(String::new()),
        tags: None,
        totp_secret: Zeroizing::new(None),
        custom_fields: Zeroizing::new(Vec::new()),
        is_secure_note: false,
        created_at: Some(created_at),
        totp_cache: None,
        password_type: PasswordType::Normal,
        number: None,
        expiration_date: None,
        cvc: None,
        favorite: None,
        totp_code_cache: None,
        trashed_at: None,
        password_history: Vec::new(),
        passkeys: Vec::new(),
    }
}

fn build_decoy_store() -> PasswordList {
    let now = now_unix();
    let mut entries = vec![
        decoy_login(
            "GitHub",
            "morgan.reid@proton.me",
            "https://github.com/login",
            false,
            now,
        ),
        decoy_login(
            "Gmail",
            "morgan.reid@gmail.com",
            "https://mail.google.com",
            true,
            now,
        ),
        decoy_login(
            "Chase Bank",
            "morgan.reid92",
            "https://secure.chase.com",
            false,
            now,
        ),
        decoy_login(
            "Amazon",
            "morgan.reid@gmail.com",
            "https://www.amazon.com",
            true,
            now,
        ),
        decoy_login(
            "Netflix",
            "morgan.reid@gmail.com",
            "https://www.netflix.com",
            false,
            now,
        ),
        decoy_login(
            "Work VPN",
            "m.reid",
            "https://vpn.northwind-corp.com",
            true,
            now,
        ),
        decoy_login(
            "Microsoft 365",
            "m.reid@northwind-corp.com",
            "https://login.microsoftonline.com",
            false,
            now,
        ),
        decoy_login(
            "AWS Console",
            "mreid-deploy",
            "https://console.aws.amazon.com",
            true,
            now,
        ),
        decoy_login(
            "Dropbox",
            "morgan.reid@gmail.com",
            "https://www.dropbox.com",
            false,
            now,
        ),
        decoy_login(
            "Steam",
            "reidplays",
            "https://store.steampowered.com",
            true,
            now,
        ),
    ];
    for entry in entries.iter_mut().take(2) {
        entry.totp_secret = Zeroizing::new(Some(random_totp_secret()));
    }

    let mut card = decoy_login("Visa Debit", "Morgan Reid", "", false, now);
    card.password_type = PasswordType::Card;
    card.password = Zeroizing::new(String::new());
    card.number = Some(Zeroizing::new(luhn_card_number()));
    card.expiration_date = Some(Zeroizing::new(random_card_expiry()));
    card.cvc = Some(Zeroizing::new(strength::generate_password(
        3, false, false, true, false, false,
    )));
    entries.push(card);

    let mut note = decoy_login("Recovery codes", "", "", false, now);
    note.is_secure_note = true;
    note.password = Zeroizing::new(String::new());
    note.notes = Zeroizing::new(
        "GitHub: 8412 3390 5567\nGmail: 7712 0045 9932\nWork VPN: 55810 2201 4477".to_string(),
    );
    entries.push(note);

    PasswordList { entries }
}

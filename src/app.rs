use std::path::PathBuf;
use std::time::Instant;
use serde::{Serialize, Deserialize};
use crate::file_ops::{open_file_dialog, save_store};
use arboard::Clipboard;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub totp_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordList {
    pub entries: Vec<PasswordEntry>,
}

#[derive(PartialEq)]
pub enum PasswordSafety {
    TooShort,
    MissingNumbers,
    MissingSpecialChars,
    NoLowerCase,
    NoUpperCase,
}

pub struct AppState {
    pub selected_file_name: String,
    pub selected_file: Option<PathBuf>,
    pub store: Option<PasswordList>,
    pub encryption_key: Option<[u8; 32]>,

    // Modal flags
    pub add_password_modal: bool,
    pub error_password_modal: bool,
    pub warning_password_modal: bool,
    pub gen_password_modal: bool,
    pub filename_modal: bool,
    pub master_modal: bool,
    pub master_mode_is_create: bool,

    // Input buffers
    pub label_input: String,
    pub username_input: String,
    pub password_input: String,
    pub notes_input: String,
    pub totp_input: String,
    pub password_search_input: String,
    pub filename_input: String,
    pub master_input: String,
    pub delete_line_input: String,
    pub edit_line_input: String,

    // Password generator
    pub password_length: i32,
    pub gen_uppercase: bool,
    pub gen_lowercase: bool,
    pub gen_numbers: bool,
    pub gen_special: bool,

    // Clipboard
    pub clipboard: Clipboard,
    pub clipboard_clear_at: Option<Instant>,

    // Edit state
    pub edit_index: Option<usize>,

    // Transient UI state
    pub copied_field: Option<String>,
    pub copied_clear_at: Option<Instant>,
    pub custom_error_message: Option<String>,
}

pub fn verify_password(password: &str) -> Vec<PasswordSafety> {
    let mut issues = Vec::new();

    if password.len() < 15 {
        issues.push(PasswordSafety::TooShort);
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        issues.push(PasswordSafety::MissingSpecialChars);
    }
    if !password.chars().any(|c| c.is_numeric()) {
        issues.push(PasswordSafety::MissingNumbers);
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        issues.push(PasswordSafety::NoLowerCase);
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        issues.push(PasswordSafety::NoUpperCase);
    }

    issues
}

pub fn generate_password(length: usize, uppercase: bool, lowercase: bool, numbers: bool, special: bool) -> String {
    use rand::seq::IndexedRandom;

    let mut charset: Vec<u8> = Vec::new();
    if uppercase { charset.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if lowercase { charset.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz"); }
    if numbers   { charset.extend_from_slice(b"0123456789"); }
    if special   { charset.extend_from_slice(b"!@#$%^&*-_=?"); }

    if charset.is_empty() {
        return String::new();
    }

    let mut rng = rand::rng();
    (0..length)
        .map(|_| *charset.choose(&mut rng).unwrap() as char)
        .collect()
}

impl AppState {
    pub fn new() -> Self {
        Self {
            selected_file_name: String::new(),
            selected_file: None,
            store: None,
            encryption_key: None,

            add_password_modal: false,
            error_password_modal: false,
            warning_password_modal: false,
            gen_password_modal: false,
            filename_modal: false,
            master_modal: false,
            master_mode_is_create: false,

            label_input: String::with_capacity(256),
            username_input: String::with_capacity(256),
            password_input: String::with_capacity(256),
            notes_input: String::with_capacity(256),
            totp_input: String::with_capacity(256),
            password_search_input: String::with_capacity(256),
            filename_input: String::with_capacity(256),
            master_input: String::new(),
            delete_line_input: String::with_capacity(256),
            edit_line_input: String::with_capacity(256),

            password_length: 24,
            gen_uppercase: true,
            gen_lowercase: true,
            gen_numbers: true,
            gen_special: true,

            clipboard: Clipboard::new().expect("Failed to access system clipboard"),
            clipboard_clear_at: None,

            edit_index: None,

            copied_field: None,
            copied_clear_at: None,
            custom_error_message: None,
        }
    }

    pub fn open_file(&mut self) {
        if let Some((name, path)) = open_file_dialog() {
            self.selected_file_name = name;
            self.selected_file = Some(path);
            self.master_modal = true;
        }
    }

    pub fn close_file(&mut self) {
        self.store = None;
        self.selected_file = None;
        self.selected_file_name.clear();
        self.encryption_key = None;
    }

    pub fn copy_to_clipboard(&mut self, text: &str, field_name: &str) {
        crate::clipboard::set_excluded_from_history(&mut self.clipboard, text);
        self.clipboard_clear_at = Some(Instant::now() + std::time::Duration::from_secs(10));
        self.copied_field = Some(field_name.to_string());
        self.copied_clear_at = Some(Instant::now() + std::time::Duration::from_secs(3));
    }
}

fn render_entry_list(ui: &imgui::Ui, store: &PasswordList) {
    for (i, entry) in store.entries.iter().enumerate() {
        ui.text(format!("{}. [{}] {}", i, entry.label, entry.username));
    }
    ui.separator();
}

pub fn build_ui(ui: &imgui::Ui, state: &mut AppState) {
    // Auto-clear clipboard after 10s
    if let Some(clear_at) = state.clipboard_clear_at && Instant::now() >= clear_at {
        crate::clipboard::set_excluded_from_history(&mut state.clipboard, "");
        state.clipboard_clear_at = None;
    }

    // Auto-clear "copied" toast after 3s
    if let Some(clear_at) = state.copied_clear_at && Instant::now() >= clear_at {
        state.copied_clear_at = None;
        state.copied_field = None;
    }

    ui.window("Password Manager")
        .size([500.0, 200.0], imgui::Condition::FirstUseEver)
        .menu_bar(true)
        .build(|| {
            ui.menu_bar(|| {
                ui.menu("Files", || {
                    if ui.menu_item("Open") {
                        state.open_file();
                    }
                    if ui.menu_item("Create") {
                        state.filename_modal = true;
                    }
                    if ui.menu_item("Close") {
                        state.close_file();
                    }
                });
            });

            imgui::TabBar::new("my_tabs").build(ui, || {
                imgui::TabItem::new("View passwords").build(ui, || {
                    ui.text("Welcome to Moonaw's password manager, fully written in Rust.");
                    ui.separator();

                    if let Some(store) = &state.store {
                        ui.input_text("Search", &mut state.password_search_input).build();

                        let mut pending_copy: Option<(String, &str)> = None;

                        for entry in &store.entries {
                            if !state.password_search_input.is_empty()
                                && !entry.label.contains(&state.password_search_input)
                                && !entry.username.contains(&state.password_search_input)
                            {
                                continue;
                            }

                            let mut totp_code: Option<String> = None;

                            ui.group(|| {
                                if entry.notes.is_empty() {
                                    ui.text(format!("[{}] {}", entry.label, entry.username));
                                } else {
                                    ui.text(format!("[{}] {} ? {}", entry.label, entry.username, &entry.notes));
                                }

                                if let Some(secret) = &entry.totp_secret {
                                    use totp_rs::{Algorithm, Secret, TOTP};
                                    if let Ok(bytes) = Secret::Encoded(secret.replace(" ", "").to_uppercase()).to_bytes()
                                        && let Ok(totp) = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes)
                                        && let Ok(code) = totp.generate_current()
                                    {
                                        ui.same_line();
                                        ui.text(format!("TOTP: {}", code));
                                        totp_code = Some(code);
                                    }
                                }
                            });

                            if ui.is_item_clicked() {
                                pending_copy = Some((entry.password.clone(), "password"));
                            } else if ui.is_item_clicked_with_button(imgui::MouseButton::Right) {
                                pending_copy = Some((entry.username.clone(), "username"));
                            } else if ui.is_item_clicked_with_button(imgui::MouseButton::Middle)
                                && let Some(code) = totp_code
                            {
                                pending_copy = Some((code, "TOTP code"));
                            }

                            if ui.is_item_hovered() {
                                ui.tooltip(|| {
                                    ui.text(&entry.password);
                                    ui.separator();
                                    ui.text("Left click to copy the password.");
                                    ui.text("Right click to copy the username.");
                                    ui.text("Middle click to copy the TOTP.");
                                });
                            }
                        }

                        if let Some((text, field)) = pending_copy {
                            state.copy_to_clipboard(&text, field);
                        }

                        if let Some(field) = &state.copied_field {
                            ui.separator();
                            ui.text(format!("The {} has been copied to the clipboard!", field));
                        }
                    } else {
                        ui.text("Open a file to get started.");
                    }
                });

                imgui::TabItem::new("Add").build(ui, || {
                    if state.store.is_none(){
                        ui.text("Open a file to get started.");
                        return;
                    }

                    ui.text("Add passwords to your current password list.");

                    if ui.button("Add new password") {
                        state.add_password_modal = true;
                    }
                });

                imgui::TabItem::new("Delete").build(ui, || {
                    if state.store.is_none(){
                        ui.text("Open a file to get started.");
                        return;
                    }

                    ui.text("Delete passwords.");
                    render_entry_list(ui, state.store.as_ref().unwrap());
                    if ui.input_text("Entry to delete", &mut state.delete_line_input)
                        .enter_returns_true(true)
                        .build()
                    {
                        if let Ok(idx) = state.delete_line_input.trim().parse::<usize>()
                            && let Some(store) = &mut state.store
                            && idx < store.entries.len()
                        {
                            store.entries.remove(idx);
                            if let Some(key) = &state.encryption_key
                                && let Err(e) = save_store(&state.selected_file, store, key) {
                                    state.custom_error_message = Some(e);
                                }
                        }
                        state.delete_line_input.clear();
                    }
                });

                imgui::TabItem::new("Modify").build(ui, || {
                    if state.store.is_none(){
                        ui.text("Open a file to get started.");
                        return;
                    }

                    ui.text("Modify passwords.");
                    render_entry_list(ui, state.store.as_ref().unwrap());
                    if ui.input_text("Entry to modify", &mut state.edit_line_input)
                        .enter_returns_true(true)
                        .build()
                    {
                        if let Ok(idx) = state.edit_line_input.trim().parse::<usize>()
                            && let Some(store) = &state.store
                            && idx < store.entries.len()
                        {
                            let entry = &store.entries[idx];
                            state.label_input = entry.label.clone();
                            state.username_input = entry.username.clone();
                            state.password_input = entry.password.clone();
                            state.notes_input = entry.notes.clone();
                            state.totp_input = entry.totp_secret.clone().unwrap_or_default();
                            state.edit_index = Some(idx);
                        }
                        state.edit_line_input.clear();
                    }
                });

                imgui::TabItem::new("About").build(ui, || {
                    ui.text("This is a password manager written in Rust, by Moonaw.");
                    ui.separator();
                    ui.text("https://moonaw.org");
                });
            });
        });

    // Modal dispatch — set flag on one frame, open_popup on the next

    if state.master_modal {
        ui.open_popup("Master password");
        state.master_modal = false;
    }
    if let Some(_token) = ui.begin_modal_popup("Master password") {
        crate::modals::enter_master_password(ui, state);
    }

    if state.filename_modal {
        ui.open_popup("Create new file");
        state.filename_modal = false;
    }
    if let Some(_token) = ui.begin_modal_popup("Create new file") {
        crate::modals::new_file_title_modal(ui, state);
    }

    if state.add_password_modal {
        ui.open_popup("Add a password");
        state.add_password_modal = false;
    }
    if let Some(_token) = ui.begin_modal_popup("Add a password") {
        crate::modals::password_modal(ui, state);

        if state.error_password_modal {
            ui.open_popup("Error");
            state.error_password_modal = false;
        }
        if let Some(_token) = ui.begin_modal_popup("Error") {
            crate::modals::error_password_modal(ui);
        }

        if state.warning_password_modal {
            ui.open_popup("Warning");
            state.warning_password_modal = false;
        }
        if let Some(_token) = ui.begin_modal_popup("Warning") {
            crate::modals::warning_modal(ui, state);
        }

        if state.gen_password_modal {
            ui.open_popup("Generate password");
            state.gen_password_modal = false;
        }
        if let Some(_token) = ui.begin_modal_popup("Generate password") {
            crate::modals::generate_password_modal(ui, state);
        }
    }

    if state.edit_index.is_some() {
        ui.open_popup("Modify entry");
    }
    if let Some(_token) = ui.begin_modal_popup("Modify entry") {
        crate::modals::modify_entry_modal(ui, state);
    }

    if state.custom_error_message.is_some() {
        ui.open_popup("Error modal");
    }
    if let Some(_token) = ui.begin_modal_popup("Error modal") {
        crate::modals::custom_error_modal(ui, state);
    }
}



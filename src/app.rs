use std::path::PathBuf;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use zeroize::Zeroizing;
use crate::file_ops::open_file_dialog;
use crate::strength::{GenMode, StrengthResult, haveibeenpwned, manual_strength};
use crate::theme;
use arboard::Clipboard;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub totp_secret: Option<String>,
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub custom_fields: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordList {
    pub entries: Vec<PasswordEntry>,
}


pub struct Vault {
    pub file_name: String,
    pub file_path: Option<PathBuf>,
    pub store: Option<PasswordList>,
    pub encryption_key: Option<Zeroizing<[u8; 32]>>,
    pub last_activity: Instant,
    pub lock_timeout_secs: u64,
}


pub struct EntryForm {
    pub label: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub totp: String,
    pub url: String,
    pub tag: String,
    pub custom_fields: Vec<(String, String)>,
}

pub struct Generator {
    pub mode: GenMode,
    pub length: i32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub special: bool,
    pub ambiguous: bool,
    pub word_count: i32,
    pub separator: String,
}

pub struct Modals {
    pub add_password: bool,
    pub settings: bool,
    pub error_password: bool,
    pub warning_password: bool,
    pub gen_password: bool,
    pub gen_from_add: bool,
    pub filename: bool,
    pub master: bool,
    pub master_is_create: bool,
    pub confirm_delete: bool,
}


pub struct ClipboardState {
    pub handle: Clipboard,
    pub clear_at: Option<Instant>,
    pub copied_field: Option<String>,
    pub copied_clear_at: Option<Instant>,
}

pub struct AppState {
    pub vault: Vault,
    pub form: EntryForm,
    pub generator: Generator,
    pub modals: Modals,
    pub clipboard: ClipboardState,

    // One-off fields that don't belong in any group.
    pub search: String,
    pub filename_input: String,
    pub master_input: Zeroizing<String>,
    pub settings_timeout_mins: i32,
    pub edit_index: Option<usize>,
    pub delete_idx: Option<usize>,
    pub custom_error_message: Option<String>,
    pub strength_cache: Option<(String, StrengthResult)>,
    pub hibp_cache: std::collections::HashMap<String, bool>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            vault: Vault {
                file_name: String::new(),
                file_path: None,
                store: None,
                encryption_key: None,
                last_activity: Instant::now(),
                lock_timeout_secs: crate::config::load().lock_timeout_secs,
            },
            form: EntryForm {
                label: String::with_capacity(256),
                username: String::with_capacity(256),
                password: String::with_capacity(256),
                notes: String::with_capacity(256),
                totp: String::with_capacity(256),
                url: String::with_capacity(256),
                tag: String::with_capacity(256),
                custom_fields: Vec::new(),
            },
            generator: Generator {
                mode: GenMode::Password,
                length: 24,
                uppercase: true,
                lowercase: true,
                numbers: true,
                special: true,
                ambiguous: true,
                word_count: 5,
                separator: String::from("-"),
            },
            modals: Modals {
                add_password: false,
                settings: false,
                error_password: false,
                warning_password: false,
                gen_password: false,
                gen_from_add: false,
                filename: false,
                master: false,
                master_is_create: false,
                confirm_delete: false,
            },
            clipboard: ClipboardState {
                handle: Clipboard::new().expect("Failed to access system clipboard"),
                clear_at: None,
                copied_field: None,
                copied_clear_at: None,
            },

            search: String::with_capacity(256),
            filename_input: String::with_capacity(256),
            master_input: Zeroizing::new(String::new()),
            settings_timeout_mins: 0,
            edit_index: None,
            delete_idx: None,
            custom_error_message: None,
            strength_cache: None,
            hibp_cache: std::collections::HashMap::new(),
        }
    }

    pub fn open_file(&mut self) {
        if let Some((name, path)) = open_file_dialog() {
            self.vault.file_name = name;
            self.vault.file_path = Some(path);
            self.modals.master = true;
        }
    }

    pub fn close_file(&mut self) {
        self.vault.store = None;
        self.vault.file_path = None;
        self.vault.file_name.clear();
        self.vault.encryption_key = None;
    }

    pub fn cached_strength(&mut self, password: &str) -> StrengthResult {
        if let Some((ref cached_pw, result)) = self.strength_cache
            && cached_pw == password
        {
            return result;
        }
        let result = manual_strength(password);
        self.strength_cache = Some((password.to_string(), result));
        result
    }

    pub fn copy_to_clipboard(&mut self, text: &str, field_name: &str) {
        crate::clipboard::set_excluded_from_history(&mut self.clipboard.handle, text);
        self.clipboard.clear_at = Some(Instant::now() + Duration::from_secs(10));
        self.clipboard.copied_field = Some(field_name.to_string());
        self.clipboard.copied_clear_at = Some(Instant::now() + Duration::from_secs(3));
    }
}

fn render_view_tab(ui: &imgui::Ui, state: &mut AppState) {
    ui.text("Welcome to Aegis, Moonaw's password manager fully written in Rust.");
    ui.separator();

    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    if ui.io().key_ctrl && ui.is_key_pressed(imgui::Key::F) {
        ui.set_keyboard_focus_here();
    }

    ui.input_text("Search", &mut state.search).build();

    let search_query = state.search.to_lowercase();
    let mut pending_copy: Option<(String, &'static str)> = None;

    if let Some(store) = &state.vault.store {
        ui.text(format!("Entry count: {}", store.entries.len()));

        for entry in &store.entries {
            if !search_query.is_empty()
                && !entry.label.to_lowercase().contains(&search_query)
                && !entry.username.to_lowercase().contains(&search_query)
                && !entry.tags.as_deref().unwrap_or(&[]).iter().any(|t| t.to_lowercase().contains(&search_query))
            {
                continue;
            }

            let mut totp_code: Option<String> = None;
            let mut totp_timeout: Option<String> = None;
            if let Some(secret) = &entry.totp_secret {
                use totp_rs::{Algorithm, Secret, TOTP};
                if let Ok(bytes) = Secret::Encoded(secret.replace(" ", "").to_uppercase()).to_bytes()
                    && let Ok(totp) = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes)
                    && let Ok(code) = totp.generate_current()
                {
                    totp_code = Some(code);
                    totp_timeout = Some(totp.ttl().unwrap().to_string());
                }
            }

            let url_clicked = std::cell::Cell::new(false);
            ui.group(|| {
                let totp_suffix = totp_code.as_deref()
                    .map(|c| format!(" | TOTP: {} ({}s)", c, totp_timeout.as_deref().unwrap_or("?")))
                    .unwrap_or_default();

                let notes_part = if entry.notes.is_empty() {
                    String::new()
                } else {
                    format!(" ? {}", entry.notes)
                };

                let tags_part = entry.tags.as_deref()
                    .map(|t| format!("[{}] ", t.join(", ")))
                    .unwrap_or_default();

                ui.text(format!(
                    "{}[{}] | {}{}{}",
                    tags_part, entry.label, entry.username, notes_part, totp_suffix
                ));

                if !entry.url.is_empty() {
                    ui.same_line();

                    let _color = ui.push_style_color(imgui::StyleColor::Text, theme::LINK_COLOR);
                    ui.text(format!("@ {}", entry.url));
                    drop(_color);

                    if ui.is_item_clicked() {
                        url_clicked.set(true);
                        let _ = open::that(&entry.url);
                    }
                    if ui.is_item_hovered() {
                        ui.tooltip(|| {
                            ui.text("Click to open in browser.");
                            ui.separator();
                        })
                    }
                }
            });

            if !url_clicked.get() {
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
                        ui.text("Left click to copy the password.");
                        ui.separator();
                        ui.text("Right click to copy the username.");
                        ui.separator();
                        ui.text("Middle click to copy the TOTP.");
                        if !entry.custom_fields.is_empty() {
                            ui.separator();
                            for (name, value) in &entry.custom_fields {
                                ui.text(format!("{}: {}", name, value));
                            }
                        }
                    });
                }
            }
        }
    }

    if let Some((text, field)) = pending_copy {
        state.copy_to_clipboard(&text, field);
    }

    if let Some(field) = &state.clipboard.copied_field {
        ui.separator();
        ui.text(format!("The {} has been copied to the clipboard!", field));
    }
}

fn render_add_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Add passwords to your current password list.");

    if ui.button("Add new password") {
        state.modals.add_password = true;
    }
}

fn render_delete_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Delete passwords.");

    if let Some(store) = &state.vault.store {
        for (i, entry) in store.entries.iter().enumerate() {
            ui.text(format!("{} - {}", entry.label, entry.username));
            ui.same_line();
            if ui.button(format!("Remove##remove{}", i)) {
                state.modals.confirm_delete = true;
                state.delete_idx = Some(i);
            }
        }
    }
}

fn render_modify_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Modify passwords.");

    let mut clicked_idx = None;
    if let Some(store) = &state.vault.store {
        for (i, entry) in store.entries.iter().enumerate() {
            ui.text(format!("{} - {}", entry.label, entry.username));
            ui.same_line();
            if ui.button(format!("Modify##modify{}", i)) {
                clicked_idx = Some(i);
            }
        }
    }

    if let Some(idx) = clicked_idx
        && let Some(store) = &state.vault.store
        && idx < store.entries.len()
    {
        let entry = &store.entries[idx];
        state.form.label = entry.label.clone();
        state.form.username = entry.username.clone();
        state.form.password = entry.password.clone();
        state.form.notes = entry.notes.clone();
        state.form.totp = entry.totp_secret.clone().unwrap_or_default();
        state.form.url = entry.url.clone();
        state.form.tag = entry.tags.as_deref().map(|t| t.join(", ")).unwrap_or_default();
        state.form.custom_fields = entry.custom_fields.clone();
        state.edit_index = Some(idx);
    }
}

fn render_health_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    if let Some(store) = &state.vault.store {
        ui.text("Weak passwords:");
        for entry in &store.entries {
            let (score, _label, _) = manual_strength(&entry.password);
            if score < 3 {
                ui.text(format!("{} - {}", entry.label, entry.username));
            }
        }
        ui.separator();

        use std::collections::HashMap;
        let mut seen: HashMap<&str, Vec<&str>> = HashMap::new();

        ui.text("Reused passwords:");
        for entry in &store.entries {
            seen.entry(entry.password.as_str()).or_default().push(entry.username.as_str());
        }

        for labels in seen.values() {
            if labels.len() > 1 {
                ui.text(format!("Reused by: {}", labels.join(", ")));
            }
        }

        ui.separator();

        ui.text("Pwned passwords:");
        for i in 0..store.entries.len() {
            let password = store.entries[i].password.clone();
            if !state.hibp_cache.contains_key(&password) {
                let result = haveibeenpwned(&password);
                state.hibp_cache.insert(password.clone(), result);
            }
            if state.hibp_cache[&password] {
                ui.text(format!("The password \"{}\" has been pwned! Click the button to modify the password.", password));
                ui.same_line();
                if ui.button("Modify password") {
                    state.modals.gen_password = true;
                }
            }
        }
    }
}

pub fn build_ui(ui: &imgui::Ui, state: &mut AppState) {
    if let Some(clear_at) = state.clipboard.clear_at && Instant::now() >= clear_at {
        crate::clipboard::set_excluded_from_history(&mut state.clipboard.handle, "");
        state.clipboard.clear_at = None;
    }

    if let Some(clear_at) = state.clipboard.copied_clear_at && Instant::now() >= clear_at {
        state.clipboard.copied_clear_at = None;
        state.clipboard.copied_field = None;
    }

    if state.vault.store.is_some()
        && state.vault.lock_timeout_secs > 0
        && state.vault.last_activity.elapsed().as_secs() >= state.vault.lock_timeout_secs
    {
        state.vault.store = None;
        state.vault.encryption_key = None;
        state.modals.master = true;
        state.vault.last_activity = Instant::now();
    }

    ui.window("Aegis")
        .size([550.0, 200.0], imgui::Condition::FirstUseEver)
        .menu_bar(true)
        .build(|| {
            ui.menu_bar(|| {
                ui.menu("Files", || {
                    if ui.menu_item("Open") {
                        state.open_file();
                    }
                    if ui.menu_item("Create") {
                        state.modals.filename = true;
                    }
                    if ui.menu_item("Close") {
                        state.close_file();
                    }
                    if ui.menu_item("Import from CSV") {
                        match crate::file_ops::import_csv() {
                            Ok(Some(imported)) => {
                                if let Some(store) = &mut state.vault.store {
                                    store.entries.extend(imported.entries);
                                }
                            }
                            Ok(None) => {}
                            Err(e) => state.custom_error_message = Some(e),
                        }
                    }
                    if ui.menu_item("Export to CSV")
                        && let Some(store) = &state.vault.store
                        && let Err(e) = crate::file_ops::export_csv(store) {
                            state.custom_error_message = Some(e);
                    }
                    ui.separator();
                    if ui.menu_item("Settings") {
                        state.settings_timeout_mins = (state.vault.lock_timeout_secs / 60) as i32;
                        state.modals.settings = true;
                    }
                });
                if state.vault.store.is_some() {
                    ui.menu("Passwords", || {
                        if ui.menu_item("Generate password") {
                            state.modals.gen_password = true;
                        }
                        if ui.menu_item("Add a password") {
                            state.modals.add_password = true;
                        }
                    });
                }
            });

            imgui::TabBar::new("my_tabs").build(ui, || {
                imgui::TabItem::new("View passwords").build(ui, || {
                    render_view_tab(ui, state);
                });
                imgui::TabItem::new("Add").build(ui, || {
                    render_add_tab(ui, state);
                });
                imgui::TabItem::new("Delete").build(ui, || {
                    render_delete_tab(ui, state);
                });
                imgui::TabItem::new("Modify").build(ui, || {
                    render_modify_tab(ui, state);
                });
                imgui::TabItem::new("Health").build(ui, || {
                    render_health_tab(ui, state);
                });
                imgui::TabItem::new("About").build(ui, || {
                    ui.text("Aegis — a password manager written in Rust, by Moonaw.");
                    ui.separator();

                    let _color = ui.push_style_color(imgui::StyleColor::Text, theme::LINK_COLOR);
                    ui.text("https://moonaw.org");
                    drop(_color);

                    if ui.is_item_clicked() {
                        let _ = open::that("https://moonaw.org");
                    }

                    if ui.is_item_hovered() {
                        ui.tooltip(|| ui.text("Click to open the link in browser."));
                    }
                });
            });
        });

    // Modal dispatch — flags are set on one frame, open_popup is called on the next.
    // imgui requires this two-frame pattern to nest popups correctly.

    if state.modals.gen_password && !state.modals.add_password {
        ui.open_popup("Generate a password");
        state.modals.gen_password = false;
    }

    if let Some(_token) = ui.begin_modal_popup("Generate a password") {
        crate::modals::generate_password_modal(ui, state);
    }

    if state.modals.confirm_delete {
        ui.open_popup("Confirm Delete");
        state.modals.confirm_delete = false;
    }

    if let Some(_token) = ui.begin_modal_popup("Confirm Delete") {
        crate::modals::confirm_delete_modal(ui, state);
    }

    if state.modals.master {
        ui.open_popup("Master password");
        state.modals.master = false;
    }
    if let Some(_token) = ui.begin_modal_popup("Master password") {
        crate::modals::enter_master_password(ui, state);
    }

    if state.modals.filename {
        ui.open_popup("Create new file");
        state.modals.filename = false;
    }
    if let Some(_token) = ui.begin_modal_popup("Create new file") {
        crate::modals::new_file_title_modal(ui, state);
    }

    if state.modals.add_password {
        ui.open_popup("Add a password");
        state.modals.add_password = false;
    }
    if let Some(_token) = ui.begin_modal_popup("Add a password") {
        crate::modals::password_modal(ui, state);

        if state.modals.error_password {
            ui.open_popup("Error");
            state.modals.error_password = false;
        }
        if let Some(_token) = ui.begin_modal_popup("Error") {
            crate::modals::error_password_modal(ui);
        }

        if state.modals.warning_password {
            ui.open_popup("Warning");
            state.modals.warning_password = false;
        }
        if let Some(_token) = ui.begin_modal_popup("Warning") {
            crate::modals::warning_modal(ui, state);
        }

        if state.modals.gen_password {
            ui.open_popup("Generate password");
            state.modals.gen_password = false;
            state.modals.gen_from_add = true;
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

    if state.modals.settings {
        ui.open_popup("Settings");
        state.modals.settings = false;
    }
    if let Some(_token) = ui.begin_modal_popup("Settings") {
        crate::modals::settings_modal(ui, state);
    }
}

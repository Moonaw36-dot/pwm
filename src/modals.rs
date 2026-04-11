use crate::app::{generate_passphrase, generate_password, verify_password, AppState, GenMode, PasswordEntry, PasswordSafety, StrengthResult};
use crate::file_ops::{create_file, load_store, save_store};

pub fn generate_password_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([440.0, 0.0]);

    let mut mode_idx = if state.gen_mode == GenMode::Passphrase { 1i32 } else { 0i32 };
    {
        let _col1 = ui.push_style_color(imgui::StyleColor::CheckMark, [0.75, 0.75, 0.75, 1.0]);
        let _col2 = ui.push_style_color(imgui::StyleColor::FrameBgActive, [0.30, 0.30, 0.30, 1.0]);
        ui.radio_button("Random password##mode", &mut mode_idx, 0);
        ui.same_line();
        ui.radio_button("Passphrase##mode", &mut mode_idx, 1);
    }
    state.gen_mode = if mode_idx == 1 { GenMode::Passphrase } else { GenMode::Password };

    ui.separator();

    if state.gen_mode == GenMode::Password {
        ui.slider("Length", 8, 64, &mut state.password_length);
        ui.checkbox("Uppercase (A-Z)", &mut state.gen_uppercase);
        ui.checkbox("Lowercase (a-z)", &mut state.gen_lowercase);
        ui.checkbox("Numbers (0-9)", &mut state.gen_numbers);
        ui.checkbox("Special (!@#...)", &mut state.gen_special);
    } else {
        ui.slider("Word count", 3, 10, &mut state.gen_word_count);
        ui.input_text("Separator", &mut state.gen_separator).build();
    }

    ui.separator();

    if !state.password_input.is_empty() {
        ui.text_disabled(&state.password_input);
        let pw = state.password_input.clone();
        let strength = state.cached_strength(&pw);
        render_strength_bar(ui, strength);
    }

    ui.separator();

    if ui.button("Generate##gen") {
        state.password_input = if state.gen_mode == GenMode::Passphrase {
            generate_passphrase(state.gen_word_count as usize, &state.gen_separator.clone())
        } else {
            generate_password(
                state.password_length as usize,
                state.gen_uppercase,
                state.gen_lowercase,
                state.gen_numbers,
                state.gen_special,
            )
        };
    }

    ui.same_line();
    if ui.button("Use this##gen") {
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel##gen") {
        state.password_input.clear();
        ui.close_current_popup();
    }
}

fn render_strength_bar(ui: &imgui::Ui, (score, label, color): StrengthResult) {
    let fraction = (score + 1) as f32 / 5.0;
    let _col = ui.push_style_color(imgui::StyleColor::PlotHistogram, color);
    imgui::ProgressBar::new(fraction).size([200.0, 16.0]).overlay_text(label).build(ui);
}

pub fn password_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([400.0, 0.0]);

    ui.input_text("Label##add", &mut state.label_input).build();
    ui.input_text("Username##add", &mut state.username_input).build();
    ui.input_text("Password##add", &mut state.password_input).build();

    let pw = state.password_input.clone();
    let strength = state.cached_strength(&pw);
    render_strength_bar(ui, strength);

    if ui.button("Generate password") {
        state.gen_password_modal = true;
    }

    ui.input_text("TOTP##add", &mut state.totp_input).build();
    ui.input_text("Notes##add", &mut state.notes_input).build();
    ui.separator();

    if ui.button("Confirm") {
        if state.username_input.is_empty() || state.password_input.is_empty() {
            state.error_password_modal = true;
        } else if !verify_password(&state.password_input).is_empty() {
            state.warning_password_modal = true;
        } else {
            add_entry_from_inputs(state);
            ui.close_current_popup();
        }
    }

    ui.same_line();
    if ui.button("Close") {
        ui.close_current_popup();
    }
}

pub fn enter_master_password(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([400.0, 0.0]);

    if state.master_mode_is_create {
        ui.text("Set a master password for your new file.");
        ui.text("DO NOT FORGET IT. There is no way to recover it.");
    } else {
        ui.text("Enter your master password to unlock the file.");
    }
    ui.separator();

    ui.input_text("Master password", &mut state.master_input)
        .password(true)
        .build();

    let button_label = if state.master_mode_is_create { "Create" } else { "Unlock" };

    if ui.button(button_label) {
        if state.master_mode_is_create {
            let filename = state.filename_input.clone();
            match create_file(&filename, state) {
                Ok(_) => {
                    state.filename_input.clear();
                    state.master_input.clear();
                    state.master_mode_is_create = false;
                    ui.close_current_popup();
                }
                Err(e) => {
                    state.custom_error_message = Some(e);
                }
            }
        } else if let Some(path) = &state.selected_file
            && let Some((store, key)) = load_store(path, &state.master_input.clone())
        {
            state.store = Some(store);
            state.encryption_key = Some(key);
            state.master_input.clear();
            ui.close_current_popup();
        }
    }

    ui.same_line();
    if ui.button("Cancel") {
        state.master_input.clear();
        state.master_mode_is_create = false;
        state.selected_file = None;
        state.selected_file_name.clear();
        state.filename_input.clear();
        ui.close_current_popup();
    }
}

pub fn error_password_modal(ui: &imgui::Ui) {
    ui.text("One of the required fields (username or password) is empty.");

    if ui.button("OK") {
        ui.close_current_popup();
    }
}

pub fn warning_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.text("Your password has issues:");

    for issue in verify_password(&state.password_input) {
        match issue {
            PasswordSafety::TooShort => ui.text("- Too short (minimum 15 characters)"),
            PasswordSafety::MissingSpecialChars => ui.text("- No special characters"),
            PasswordSafety::MissingNumbers => ui.text("- No numbers"),
            PasswordSafety::NoUpperCase => ui.text("- No uppercase letters"),
            PasswordSafety::NoLowerCase => ui.text("- No lowercase letters"),
        };
    }

    ui.separator();
    ui.text("What do you want to do?");

    if ui.button("Generate a strong password") {
        state.password_input = generate_password(24, true, true, true, true);
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Ignore") {
        add_entry_from_inputs(state);
        ui.close_current_popup();
    }
}

fn sanitize_totp(s: String) -> Option<String> {
    let s = s.trim().replace(' ', "").to_uppercase();
    if s.is_empty() { None } else { Some(s) }
}

fn add_entry_from_inputs(state: &mut AppState) {
    let entry = PasswordEntry {
        label: std::mem::take(&mut state.label_input),
        username: std::mem::take(&mut state.username_input),
        password: std::mem::take(&mut state.password_input),
        notes: std::mem::take(&mut state.notes_input),
        totp_secret: sanitize_totp(std::mem::take(&mut state.totp_input)),
    };

    if let Some(store) = &mut state.store {
        store.entries.push(entry);
        if let Some(key) = &state.encryption_key
            && let Err(e) = save_store(&state.selected_file, store, key) {
                state.custom_error_message = Some(e);
            }
    }
}

pub fn new_file_title_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([400.0, 0.0]);
    ui.text("Enter a name for the new vault file.");

    ui.input_text("Name", &mut state.filename_input).build();

    if ui.button("OK") {
        state.filename_input = state.filename_input.trim().to_string();
        state.master_mode_is_create = true;
        state.master_modal = true;
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel##filename") {
        ui.close_current_popup();
    }
}

pub fn custom_error_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([400.0, 0.0]);
    ui.text("Uh oh! The app has encountered an error.");
    if let Some(err) = &state.custom_error_message {
        ui.text_colored([1.0, 0.0, 0.0, 1.0], format!("Error: {}", err));
    }

    if ui.button("Close") {
        state.custom_error_message = None;
        ui.close_current_popup();
    }
}

pub fn modify_entry_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([400.0, 0.0]);
    ui.text("Modify the fields you want to change:");
    ui.separator();

    ui.input_text("Label", &mut state.label_input).build();
    ui.input_text("Username", &mut state.username_input).build();
    ui.input_text("Password", &mut state.password_input).build();

    let pw = state.password_input.clone();
    let strength = state.cached_strength(&pw);
    render_strength_bar(ui, strength);

    ui.input_text("Notes", &mut state.notes_input).build();
    ui.input_text("TOTP###MODIFY", &mut state.totp_input).build();

    if ui.button("Save")
        && let Some(idx) = state.edit_index
        && let Some(store) = &mut state.store
    {
        store.entries[idx] = PasswordEntry {
            label: state.label_input.clone(),
            username: state.username_input.clone(),
            password: state.password_input.clone(),
            notes: state.notes_input.clone(),
            totp_secret: sanitize_totp(std::mem::take(&mut state.totp_input)),
        };
        if let Some(key) = &state.encryption_key
            && let Err(e) = save_store(&state.selected_file, store, key) {
                state.custom_error_message = Some(e);
            }
        state.edit_index = None;
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel") {
        state.edit_index = None;
        state.label_input.clear();
        state.username_input.clear();
        state.password_input.clear();
        state.notes_input.clear();
        state.totp_input.clear();
        ui.close_current_popup();
    }
}

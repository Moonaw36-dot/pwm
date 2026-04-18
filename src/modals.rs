use std::time::Instant;
use zeroize::Zeroize;
use crate::app::{AppState, PasswordEntry};
use crate::strength::{GenMode, PasswordSafety, StrengthResult, generate_passphrase, generate_password, verify_password};
use crate::file_ops::{create_file, load_store};
use crate::theme;

pub fn confirm_delete_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);

    ui.text("Are you sure you want to delete the password?");
    if ui.button("Yes"){
        if let (Some(idx), Some(store)) = (state.delete_idx, &mut state.vault.store) {
            state.hibp_cache.remove(&store.entries[idx].password);
            store.entries.remove(idx);
        }
        state.save();
        state.delete_idx = None;
        ui.close_current_popup();
    }

    ui.same_line();

    if ui.button("No"){
        ui.close_current_popup();
    }
}

pub fn generate_password_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_GENERATOR, 0.0]);

    let mut mode_idx = if state.generator.mode == GenMode::Passphrase { 1i32 } else { 0i32 };
    {
        let _col1 = ui.push_style_color(imgui::StyleColor::CheckMark, [0.75, 0.75, 0.75, 1.0]);
        let _col2 = ui.push_style_color(imgui::StyleColor::FrameBgActive, [0.30, 0.30, 0.30, 1.0]);
        ui.radio_button("Random password##mode", &mut mode_idx, 0);
        ui.same_line();
        ui.radio_button("Passphrase##mode", &mut mode_idx, 1);
    }
    state.generator.mode = if mode_idx == 1 { GenMode::Passphrase } else { GenMode::Password };

    ui.separator();

    if state.generator.mode == GenMode::Password {
        ui.slider("Length", 8, 64, &mut state.generator.length);
        ui.checkbox("Uppercase (A-Z)", &mut state.generator.uppercase);
        ui.checkbox("Lowercase (a-z)", &mut state.generator.lowercase);
        ui.checkbox("Numbers (0-9)", &mut state.generator.numbers);
        ui.checkbox("Special (!@#...)", &mut state.generator.special);
        ui.checkbox("Ambiguous characters (O0...)", &mut state.generator.ambiguous);
    } else {
        ui.slider("Word count", 3, 64, &mut state.generator.word_count);
        ui.input_text("Separator", &mut state.generator.separator).build();
    }

    ui.separator();

    if !state.form.password.is_empty() {
        ui.text_disabled(&state.form.password);
        let pw = state.form.password.clone();
        let strength = state.cached_strength(&pw);
        render_strength_bar(ui, strength);
    }

    ui.separator();

    if ui.button("Generate##gen") {
        state.form.password = if state.generator.mode == GenMode::Passphrase {
            generate_passphrase(state.generator.word_count as usize, &state.generator.separator)
        } else {
            generate_password(
                state.generator.length as usize,
                state.generator.uppercase,
                state.generator.lowercase,
                state.generator.numbers,
                state.generator.special,
                state.generator.ambiguous,
            )
        };
    }

    if state.modals.gen_from_add {
        ui.same_line();
        if ui.button("Use this##gen") {
            state.modals.gen_from_add = false;
            ui.close_current_popup();
        }

        ui.same_line();
        if ui.button("Cancel##gen") {
            state.form.password.clear();
            state.modals.gen_from_add = false;
            ui.close_current_popup();
        }
    } else {
        if ui.button("Copy to clipboard###gen") {
            crate::clipboard::set_excluded_from_history(&mut state.clipboard.handle, &state.form.password);
            ui.close_current_popup();
        }

        if ui.button("Close") {
            ui.close_current_popup();
        }

    }


}

fn render_strength_bar(ui: &imgui::Ui, (score, label, color): StrengthResult) {
    let fraction = (score + 1) as f32 / 5.0;
    let bar_width = ui.calc_item_width();
    let bar_height = 16.0f32;

    let cursor = ui.cursor_screen_pos();
    let text_size = ui.calc_text_size(label);

    let _col = ui.push_style_color(imgui::StyleColor::PlotHistogram, color);
    imgui::ProgressBar::new(fraction)
        .size([bar_width, bar_height])
        .overlay_text("")
        .build(ui);

    let text_x = cursor[0] + (bar_width - text_size[0]) / 2.0;
    let text_y = cursor[1] + (bar_height - text_size[1]) / 2.0;
    ui.get_window_draw_list().add_text([text_x, text_y], [1.0, 1.0, 1.0, 1.0], label);
}

pub fn password_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);

    ui.checkbox("Secure notes", &mut state.form.is_secure_note);

    ui.input_text("Label##add", &mut state.form.label).build();
    ui.input_text("Tag##add", &mut state.form.tag).build();
    ui.input_text("URL / Website##add", &mut state.form.url).build();


    if state.form.is_secure_note{
        state.form.username.clear();
        state.form.password.clear();
    }

    if !state.form.is_secure_note{

        ui.input_text("Username##add", &mut state.form.username).build();
        ui.input_text("Password##add", &mut state.form.password).password(true).build();

        let pw = state.form.password.clone();
        let strength = state.cached_strength(&pw);
        render_strength_bar(ui, strength);

        if ui.button("Generate password") {
            state.modals.gen_password = true;
        }

        ui.input_text("TOTP##add", &mut state.form.totp).build();
    }

    ui.input_text("Notes##add", &mut state.form.notes).build();
    ui.separator();


    if ui.button("Add field") {
        state.form.custom_fields.push((String::new(), String::new()));

    }


    let mut remove_idx = None;
    for (i, (key, val)) in state.form.custom_fields.iter_mut().enumerate() {
        ui.set_next_item_width(theme::CUSTOM_FIELD_NAME_WIDTH);
        ui.input_text(format!("##add_field_name_{i}"), key).hint("Field name").build();
        ui.same_line();
        ui.set_next_item_width(theme::CUSTOM_FIELD_VALUE_WIDTH);
        ui.input_text(format!("##add_field_value_{i}"), val).build();
        ui.same_line();
        if ui.button(format!("x##add_field_remove_{i}")) {
            remove_idx = Some(i);
        }
    }
    if let Some(i) = remove_idx {
        state.form.custom_fields.remove(i);
    }

    if ui.button("Add") {
        let is_valid = !state.form.label.is_empty() &&
                            (state.form.is_secure_note && !state.form.notes.is_empty() ||  (!state.form.username.is_empty() && !state.form.password.is_empty()));
        if !is_valid {
            state.modals.error_password = true;
        } else if !state.form.is_secure_note && !verify_password(&state.form.password).is_empty() {
            state.modals.warning_password = true;
        } else {
            add_entry_from_inputs(state);
            state.clear_inputs();
            ui.close_current_popup();
        }
    }

    ui.same_line();
    if ui.button("Cancel##add") {
        state.form.custom_fields.clear();
        state.clear_inputs();
        ui.close_current_popup();
    }
}

pub fn success_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text_colored(theme::SUCCESS_COLOR, state.custom_success_message.as_ref().unwrap_or(&String::new()));

    if ui.button("Close") {
        state.custom_success_message = None;
        ui.close_current_popup();
    }
}

pub fn enter_master_password(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);

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

    let button_label = if state.modals.master_is_create { "Create" } else { "Unlock" };

    if state.vault.keyfile_hash.is_some() {
        ui.text("Your vault has a keyfile. Please press the button to select it.");
        if ui.button("Select keyfile") {
            match crate::file_ops::load_keyfile(state){
                Ok(_) => { state.custom_success_message = Some("Successfully selected keyfile!".to_string()); },
                Err(error) => {
                    state.custom_error_message = Some(error);
                    return;
                }
            }
        }
    }

    if ui.button(button_label) {
        if state.modals.master_is_create {
            let filename = state.filename_input.clone();
            match create_file(&filename, state) {
                Ok(_) => {
                    state.filename_input.clear();
                    state.master_input.zeroize();
                    state.modals.master_is_create = false;
                    ui.close_current_popup();
                }
                Err(e) => {
                    state.custom_error_message = Some(e);
                }
            }
        } else if state.vault.keyfile_hash.is_some() && state.vault.keyfile.is_none() {
            state.custom_error_message = Some("Please select your keyfile before unlocking.".to_string());
        } else if let Some(path) = &state.vault.file_path
            && let Some((store, key)) = load_store(path, &state.master_input)
        {
            state.vault.store = Some(store);
            state.vault.encryption_key = Some(key);
            state.master_input.zeroize();
            ui.close_current_popup();
        }
    }

    ui.same_line();
    if ui.button("Cancel") {
        state.master_input.zeroize();
        state.modals.master_is_create = false;
        state.vault.file_path = None;
        state.vault.file_name.clear();
        state.filename_input.clear();
        ui.close_current_popup();
    }
}

pub fn error_password_modal(ui: &imgui::Ui) {
    ui.text("One of the required fields (username or password or Label) is empty.");

    if ui.button("OK") {
        ui.close_current_popup();
    }
}

pub fn warning_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.text("Your password has issues:");

    for issue in verify_password(&state.form.password) {
        match issue {
            PasswordSafety::TooShort => ui.text("- Too short (minimum 15 characters)"),
            PasswordSafety::MissingSpecialChars => ui.text("- No special characters"),
            PasswordSafety::MissingNumbers => ui.text("- No numbers"),
            PasswordSafety::NoUpperCase => ui.text("- No uppercase letters"),
            PasswordSafety::NoLowerCase => ui.text("- No lowercase letters"),
            PasswordSafety::TooFewWords => ui.text("- Passphrase too short (minimum 4 words)"),
        };
    }

    ui.separator();
    ui.text("What do you want to do?");

    if ui.button("Generate a strong password") {
        state.form.password = generate_password(24, true, true, true, true, false);
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Ignore") {
        state.clear_inputs();
        add_entry_from_inputs(state);
        ui.close_current_popup();
    }
}

fn parse_tags(s: String) -> Option<Vec<String>> {
    let v: Vec<String> = s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if v.is_empty() { None } else { Some(v) }
}

fn sanitize_totp(s: String) -> Option<String> {
    let s = s.trim().replace(' ', "").to_uppercase();
    if s.is_empty() { None } else { Some(s) }
}

fn add_entry_from_inputs(state: &mut AppState) {
    let entry = PasswordEntry {
        label: std::mem::take(&mut state.form.label),
        username: std::mem::take(&mut state.form.username),
        password: std::mem::take(&mut state.form.password),
        notes: std::mem::take(&mut state.form.notes),
        url: std::mem::take(&mut state.form.url),
        totp_secret: sanitize_totp(std::mem::take(&mut state.form.totp)),
        tags: parse_tags(state.form.tag.clone()),
        custom_fields: std::mem::take(&mut state.form.custom_fields)
            .into_iter()
            .filter(|(k, _)| !k.trim().is_empty())
            .collect(),
        is_secure_note: state.form.is_secure_note,
        created_at: Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
    };

    if let Some(store) = &mut state.vault.store {
        store.entries.push(entry);
    }
    state.save();
}

pub fn new_file_title_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text("Enter a name for the new vault file.");

    ui.input_text("Name", &mut state.filename_input).build();

    if ui.button("OK") {
        state.filename_input = state.filename_input.trim().to_string();
        state.modals.master_is_create = true;
        state.modals.master = true;
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel##filename") {
        ui.close_current_popup();
    }
}

pub fn settings_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_SETTINGS, 0.0]);

    ui.slider("Auto-lock timeout (minutes)", 0, 120, &mut state.settings_timeout_mins);
    if state.settings_timeout_mins == 0 {
        ui.text_disabled("Auto-lock is disabled.");
    } else {
        ui.text_disabled(format!(
            "Vault locks after {} minute{}.",
            state.settings_timeout_mins,
            if state.settings_timeout_mins == 1 { "" } else { "s" }
        ));
    }

    ui.separator();

    if ui.button("Save") {
        state.vault.lock_timeout_secs = (state.settings_timeout_mins * 60) as u64;

        let mut config = crate::config::load();
        config.lock_timeout_secs = state.vault.lock_timeout_secs;

        if let Err(e) = crate::config::save(&config) {
            state.custom_error_message = Some(e);
        }


        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel##settings") {
        ui.close_current_popup();
    }
}

pub fn custom_error_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text("Uh oh! The app has encountered an error.");
    if let Some(err) = &state.custom_error_message {
        ui.text_colored(theme::ERROR_COLOR, format!("Error: {}", err));
    }

    if ui.button("Close") {
        state.custom_error_message = None;
        ui.close_current_popup();
    }
}

pub fn modify_entry_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text("Modify the fields you want to change:");
    ui.separator();

    ui.input_text("Label", &mut state.form.label).build();
    ui.input_text("Tag", &mut state.form.tag).build();
    ui.input_text("URL / Website", &mut state.form.url).build();
    ui.input_text("Username", &mut state.form.username).build();
    ui.input_text("Password", &mut state.form.password).password(true).build();

    let pw = state.form.password.clone();
    let strength = state.cached_strength(&pw);
    if ui.button("Generate password") {
        state.modals.gen_password = true;
    }
    render_strength_bar(ui, strength);

    ui.input_text("Notes", &mut state.form.notes).build();
    ui.input_text("TOTP###MODIFY", &mut state.form.totp).build();
    ui.separator();

    if ui.button("Add field##modify") {
        state.form.custom_fields.push((String::new(), String::new()));
    }

    let mut remove_idx = None;
    for (i, (key, val)) in state.form.custom_fields.iter_mut().enumerate() {
        ui.set_next_item_width(theme::CUSTOM_FIELD_NAME_WIDTH);
        ui.input_text(format!("##edit_field_name_{i}"), key).hint("Field name").build();
        ui.same_line();
        ui.set_next_item_width(theme::CUSTOM_FIELD_VALUE_WIDTH);
        ui.input_text(format!("##edit_field_value_{i}"), val).build();
        ui.same_line();
        if ui.button(format!("x##edit_field_remove_{i}")) {
            remove_idx = Some(i);
        }
    }
    if let Some(i) = remove_idx {
        state.form.custom_fields.remove(i);
    }

    if ui.button("Save")
        && let Some(idx) = state.edit_index
        && let Some(store) = &mut state.vault.store
    {
        state.hibp_cache.remove(&store.entries[idx].password);
        store.entries[idx] = PasswordEntry {
            label: state.form.label.clone(),
            username: state.form.username.clone(),
            password: state.form.password.clone(),
            notes: state.form.notes.clone(),
            url: state.form.url.clone(),
            totp_secret: sanitize_totp(std::mem::take(&mut state.form.totp)),
            tags: parse_tags(std::mem::take(&mut state.form.tag)),
            custom_fields: std::mem::take(&mut state.form.custom_fields)
                .into_iter()
                .filter(|(k, _)| !k.trim().is_empty())
                .collect(),
            is_secure_note: state.form.is_secure_note,
            created_at: store.entries[idx].created_at,
            };        state.save();
        state.edit_index = None;
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel") {
        state.edit_index = None;
        state.clear_inputs();
        ui.close_current_popup();
    }
}

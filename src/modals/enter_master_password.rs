use zeroize::Zeroize;
use crate::app::AppState;
use crate::file_ops::{create_file, load_store};
use crate::theme;

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
                Ok(_) => {
                    state.custom_success_message = Some("Successfully selected keyfile!".to_string());
                    state.modals.show_success = true;
                },
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
                    state.custom_success_message = Some("Vault created successfully!".to_string());
                    state.modals.show_success = true;
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
        } else if let Some(path) = &state.vault.file_path {
            match load_store(path, &state.master_input, state.vault.keyfile_bytes.as_ref().map(|v| v.as_slice())) {
                Ok((store, key)) => {
                    state.vault.store = Some(store);
                    state.vault.encryption_key = Some(key);
                    state.master_input.zeroize();
                    ui.close_current_popup();
                }
                Err(e) => {
                    state.custom_error_message = Some(e);
                }
            }
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

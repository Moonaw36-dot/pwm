use crate::app::AppState;
use crate::modals::{add_entry_from_inputs, render_strength_bar};
use crate::strength::verify_password;
use crate::theme;
use zeroize::Zeroizing;

pub fn render(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);

    ui.checkbox("Secure notes", &mut state.form.is_secure_note);

    ui.input_text("Label##add", &mut state.form.label).build();
    ui.input_text("Tag##add", &mut state.form.tag).build();
    ui.input_text("URL / Website##add", &mut state.form.url)
        .build();
    ui.input_text("Notes##add", &mut state.form.notes).build();

    if state.modals.close_add_password {
        ui.close_current_popup();
        add_entry_from_inputs(state);
        state.clear_inputs();
        state.modals.close_add_password = false;
    }

    if state.form.is_secure_note {
        state.form.username.clear();
        state.form.password = Zeroizing::new(String::new());
    }

    if !state.form.is_secure_note {
        ui.input_text("Username##add", &mut state.form.username)
            .build();
        ui.input_text("Password##add", &mut state.form.password)
            .password(true)
            .build();

        ui.same_line();

        if ui.button("Copy password") {
            let password = state.form.password.clone();
            state.copy_to_clipboard(&password, "password");
        }

        let pw = state.form.password.clone();
        let strength = state.cached_strength(&pw);
        render_strength_bar(ui, strength);

        if ui.button("Generate password") {
            state.modals.gen_password = true;
        }

        ui.input_text("TOTP##add", &mut state.form.totp).build();
    }

    ui.separator();

    crate::modals::render_custom_fields_editor(ui, &mut state.form.custom_fields, "add");

    if ui.button("Add") {
        let is_valid = !state.form.label.is_empty()
            && (state.form.is_secure_note && !state.form.notes.is_empty()
                || (!state.form.username.is_empty() && !state.form.password.is_empty()));
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

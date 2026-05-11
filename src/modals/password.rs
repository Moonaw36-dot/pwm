use zeroize::Zeroizing;
use crate::app::AppState;
use crate::modals::{add_entry_from_inputs, render_strength_bar};
use crate::strength::verify_password;
use crate::theme;

pub fn password_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);

    ui.checkbox("Secure notes", &mut state.form.is_secure_note);

    ui.input_text("Label##add", &mut state.form.label).build();
    ui.input_text("Tag##add", &mut state.form.tag).build();
    ui.input_text("URL / Website##add", &mut state.form.url).build();

    if state.modals.close_add_password {
        ui.close_current_popup();
        add_entry_from_inputs(state);
        state.clear_inputs();
        state.modals.close_add_password = false;
    }


    if state.form.is_secure_note{
        state.form.username.clear();
        state.form.password = Zeroizing::new(String::new());
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

use zeroize::Zeroizing;
use crate::app::{AppState, PasswordEntry};
use crate::modals::render_strength_bar;
use crate::theme;

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

pub fn modify_entry_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text("Modify the fields you want to change:");
    ui.separator();

    ui.checkbox("Secure note", &mut state.form.is_secure_note);

    ui.input_text("Label", &mut state.form.label).build();
    ui.input_text("Tag", &mut state.form.tag).build();
    ui.input_text("URL / Website", &mut state.form.url).build();

    if state.form.is_secure_note{
        state.form.username.clear();
        state.form.password = Zeroizing::new(String::new());
    }

    if !state.form.is_secure_note{
        ui.input_text("Username", &mut state.form.username).build();
        ui.input_text("Password", &mut state.form.password).password(true).build();

        let pw = state.form.password.clone();
        let strength = state.cached_strength(&pw);
        if ui.button("Generate password") {
            state.modals.gen_password = true;
        }
        render_strength_bar(ui, strength);
    }

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
        state.hibp_cache.remove(store.entries[idx].password.as_str());
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

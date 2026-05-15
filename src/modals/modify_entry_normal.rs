use zeroize::Zeroizing;
use crate::app::{AppState, PasswordEntry};
use crate::modals::render_strength_bar;
use crate::theme;

pub fn render(ui: &imgui::Ui, state: &mut AppState) {
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

    crate::modals::render_custom_fields_editor(ui, &mut state.form.custom_fields, "modify");

    if ui.button("Save")
        && let Some(idx) = state.edit_index
        && let Some(store) = &mut state.vault.store
    {
        state.hibp_cache.remove(&crate::app::hash_password(store.entries[idx].password.as_str()));
        store.entries[idx] = PasswordEntry {
            label: state.form.label.clone(),
            username: state.form.username.clone(),
            password: state.form.password.clone(),
            notes: state.form.notes.clone(),
            url: state.form.url.clone(),
            totp_secret: crate::modals::modify_entry::sanitize_totp(std::mem::take(&mut state.form.totp)),
            tags: crate::modals::modify_entry::parse_tags(std::mem::take(&mut state.form.tag)),
            custom_fields: std::mem::take(&mut state.form.custom_fields)
                .into_iter()
                .filter(|(k, _)| !k.trim().is_empty())
                .collect(),
            is_secure_note: state.form.is_secure_note,
            created_at: store.entries[idx].created_at,
            totp_cache: None,
            password_type: store.entries[idx].password_type,
            number: store.entries[idx].number.clone(),
            expiration_date: store.entries[idx].expiration_date.clone(),
            cvc: store.entries[idx].cvc.clone(),
        };        state.save();
        state.edit_index = None;
        state.clear_inputs();
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel") {
        state.edit_index = None;
        state.clear_inputs();
        ui.close_current_popup();
    }
}
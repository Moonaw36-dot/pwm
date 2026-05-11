use crate::models::AppState;

pub fn render_modify_tab(ui: &imgui::Ui, state: &mut AppState) {
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
        state.form.is_secure_note = entry.is_secure_note;
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

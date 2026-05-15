use crate::models::{AppState, PasswordType};



pub fn render_modify_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Modify passwords.");

    if let Some((idx, entry)) = crate::modals::render_entries_list(ui, state, "Modify") {
        crate::modals::copy_entries(state, entry.password_type, &entry);
        state.edit_index = Some(idx as usize);
    }
}

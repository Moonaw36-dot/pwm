use crate::models::{AppState, PasswordType};

pub fn render_delete_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Delete passwords.");


    if let Some((idx, _entry)) = crate::modals::render_entries_list(ui, state, "Delete") {
        state.delete_idx = Some(idx as usize);
    }

}

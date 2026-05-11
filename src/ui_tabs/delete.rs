use crate::models::AppState;

pub fn render_delete_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Delete passwords.");

    if let Some(store) = &state.vault.store {
        for (i, entry) in store.entries.iter().enumerate() {
            ui.text(format!("{} - {}", entry.label, entry.username));
            ui.same_line();
            if ui.button(format!("Remove##remove{}", i)) {
                state.modals.confirm_delete = true;
                state.delete_idx = Some(i);
            }
        }
    }
}

use crate::models::AppState;

pub fn render_add_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Add passwords to your current password list.");

    if ui.button("Add new password") {
        state.modals.add_password = true;
    }
}

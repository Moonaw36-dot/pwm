use crate::models::AppState;

pub fn render_delete_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    let _bold = crate::ui::push_bold(ui, state);
    ui.text("Delete passwords.");
    drop(_bold);

    if let Some((idx, _entry)) = crate::modals::render_entries_list(ui, state, "Delete") {
        state.delete_idx = Some(idx as usize);
    }
}

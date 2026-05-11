use crate::app::AppState;
use crate::theme;

pub fn confirm_delete_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);

    ui.text("Are you sure you want to delete the password?");
    if ui.button("Yes"){
        if let (Some(idx), Some(store)) = (state.delete_idx, &mut state.vault.store) {
            state.hibp_cache.remove(store.entries[idx].password.as_str());
            store.entries.remove(idx);
        }
        state.save();
        state.delete_idx = None;
        ui.close_current_popup();
    }

    ui.same_line();

    if ui.button("No"){
        ui.close_current_popup();
    }
}

use crate::app::AppState;
use crate::models::now_unix;
use crate::theme;

pub fn confirm_delete_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);

    ui.text("Are you sure you want to delete the password?");
    ui.text("It will be moved to the trash.");
    if ui.button("Yes") {
        if let (Some(idx), Some(store)) = (state.delete_idx, &mut state.vault.store)
            && let Some(entry) = store.entries.get_mut(idx)
        {
            entry.trashed_at = Some(now_unix());
        }
        state.invalidate_vault_caches();
        state.save();
        state.delete_idx = None;
        ui.close_current_popup();
    }

    ui.same_line();

    if ui.button("No") {
        state.delete_idx = None;
        ui.close_current_popup();
    }

    ui.same_line();

    if ui.button("No") {
        state.delete_idx = None;
        ui.close_current_popup();
    }
}

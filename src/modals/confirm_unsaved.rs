use crate::app::AppState;
use crate::theme;

pub fn confirm_unsaved_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text("You have unsaved changes. What would you like to do?");

    if ui.button("Save and Exit") {
        match state.save_result() {
            Ok(()) => {
                state.pending_exit = false;
                state.should_exit = true;
                ui.close_current_popup();
            }
            Err(e) => state.custom_error_message = Some(e),
        }
    }

    ui.same_line();
    if ui.button("Exit without Saving") {
        state.pending_exit = false;
        state.should_exit = true;
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel") {
        state.pending_exit = false;
        ui.close_current_popup();
    }
}

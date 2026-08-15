use crate::app::AppState;
use crate::theme;

pub fn new_file_title_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text("Enter a name for the new vault file.");

    ui.input_text("Name", &mut state.filename_input).build();
    ui.slider("Iterations", 1, 20, &mut state.form.iterations_entry);

    if ui.button("OK") {
        state.filename_input = if state.filename_input.is_empty() {
            return;
        } else {
            state.filename_input.trim().to_string()
        };

        state.modals.master_is_create = true;
        state.modals.master = true;
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel##filename") {
        state.clear_inputs();
        ui.close_current_popup();
    }
}

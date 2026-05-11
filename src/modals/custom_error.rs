use crate::app::AppState;
use crate::theme;

pub fn custom_error_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text("Uh oh! The app has encountered an error.");
    if let Some(err) = &state.custom_error_message {
        ui.text_colored(theme::ERROR_COLOR, format!("Error: {}", err));
    }

    if ui.button("Close") {
        state.custom_error_message = None;
        ui.close_current_popup();
    }
}

use crate::app::AppState;
use crate::theme;

pub fn success_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text_colored(theme::SUCCESS_COLOR, state.custom_success_message.as_ref().unwrap_or(&String::new()));

    if ui.button("Close") {
        state.custom_success_message = None;
        ui.close_current_popup();
    }
}

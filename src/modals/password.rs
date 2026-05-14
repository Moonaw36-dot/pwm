use crate::app::AppState;
use crate::models::PasswordType;

pub fn password_modal(ui: &imgui::Ui, state: &mut AppState) {
    if !state.has_chosen_type {
        ui.text("Select the password type: ");

        ui.radio_button("Normal", &mut state.form.password_type , PasswordType::Normal);
        ui.radio_button("Card", &mut state.form.password_type, PasswordType::Card);

        if ui.button("Confirm") {
            state.has_chosen_type = true;
        }
    } else {
        match state.form.password_type {
            PasswordType::Normal => { crate::modals::password_modal_normal::render(ui, state); }
            PasswordType::WiFi => { }
            PasswordType::Card => { crate::modals::password_modal_card::render(ui, state); }
        }
    }
}

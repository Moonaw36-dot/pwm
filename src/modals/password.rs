use crate::app::AppState;
use crate::models::PasswordType;

pub fn password_modal(ui: &imgui::Ui, state: &mut AppState) {
    if !state.has_chosen_type {
        ui.text("Select the password type: ");

        ui.radio_button(
            "Normal",
            &mut state.form.password_type,
            PasswordType::Normal,
        );
        match state.card_texture {
            Some(card_tex) => {
                ui.radio_button("##", &mut state.form.password_type, PasswordType::Card);
                ui.same_line();
                imgui::Image::new(card_tex, [24.0, 24.0]).build(ui);
            }
            None => {
                ui.radio_button("Card", &mut state.form.password_type, PasswordType::Card);
            }
        }

        ui.radio_button("Wi-Fi", &mut state.form.password_type, PasswordType::WiFi);

        if ui.button("Confirm") {
            ui.close_current_popup();
            state.has_chosen_type = true;
            state.modals.add_entry_popup = true;
        }

        ui.same_line();

        if ui.button("Cancel") {
            ui.close_current_popup();
        }
    } else {
        match state.form.password_type {
            PasswordType::Normal => {
                crate::modals::password_modal_normal::render(ui, state);
            }
            PasswordType::Card => {
                crate::modals::password_modal_card::render(ui, state);
            }
            PasswordType::WiFi => {}
        }
    }
}

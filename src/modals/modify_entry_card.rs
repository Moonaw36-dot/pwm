use zeroize::Zeroizing;
use imgui::Ui;
use crate::app::AppState;
use crate::models::PasswordType;
use crate::theme;

pub fn render(ui: &Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text("Modify the fields you want to change:");
    ui.separator();

    crate::modals::render_card_fields(ui, state);

    if ui.button("Cancel") {
        state.edit_index = None;
        state.clear_inputs();
        ui.close_current_popup();
    }

    ui.same_line();

    if ui.button("Save")
        && let Some(idx) = state.edit_index
        && let Some(store) = &mut state.vault.store
    {
        let mut entry = store.entries[idx].clone();
        entry.number = Some(std::mem::replace(&mut state.form.number, Zeroizing::new(String::new())));
        entry.expiration_date = Some(std::mem::replace(&mut state.form.expiration_date, Zeroizing::new(String::new())));
        entry.cvc = Some(std::mem::replace(&mut state.form.cvc, Zeroizing::new(String::new())));
        entry.password_type = PasswordType::Card;
        entry.totp_cache = None;
        store.entries[idx] = entry;
        state.save();
        state.edit_index = None;
        state.clear_inputs();
        ui.close_current_popup();
    }

}
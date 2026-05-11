use zeroize::Zeroizing;
use crate::app::AppState;
use crate::modals::add_entry_from_inputs;
use crate::strength::{PasswordSafety, generate_password, verify_password};

pub fn warning_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.text("Your password has issues:");

    for issue in verify_password(&state.form.password) {
        match issue {
            PasswordSafety::TooShort => ui.text("- Too short (minimum 15 characters)"),
            PasswordSafety::MissingSpecialChars => ui.text("- No special characters"),
            PasswordSafety::MissingNumbers => ui.text("- No numbers"),
            PasswordSafety::NoUpperCase => ui.text("- No uppercase letters"),
            PasswordSafety::NoLowerCase => ui.text("- No lowercase letters"),
            PasswordSafety::TooFewWords => ui.text("- Passphrase too short (minimum 4 words)"),
        };
    }

    ui.separator();
    ui.text("What do you want to do?");

    if ui.button("Generate a strong password") {
        state.form.password = Zeroizing::new(generate_password(24, true, true, true, true, false));
        ui.close_current_popup();
        state.modals.close_add_password = true;
    }

    ui.same_line();
    if ui.button("Ignore") {
        add_entry_from_inputs(state);
        ui.close_current_popup();
    }
}

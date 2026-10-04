use crate::app::AppState;
use crate::theme;
use zeroize::Zeroizing;

pub fn settings_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_SETTINGS, 0.0]);

    ui.slider(
        "Auto-lock timeout (minutes)",
        0,
        120,
        &mut state.settings_timeout_mins,
    );
    if state.settings_timeout_mins == 0 {
        ui.text_disabled("Auto-lock is disabled.");
    } else {
        ui.text_disabled(format!(
            "Vault locks after {} minute{}.",
            state.settings_timeout_mins,
            if state.settings_timeout_mins == 1 {
                ""
            } else {
                "s"
            }
        ));
    }

    ui.separator();

    ui.checkbox("Light mode", &mut state.settings_light_mode);

    ui.input_text("Self destruct password", &mut state.self_destruct_pass)
        .password(true)
        .build();
    ui.text_disabled("Stored as a salted hash. Leave empty to disable.");

    ui.checkbox("Hide Email", &mut state.hide_user);
    ui.text_disabled("This will censor your username / email in the \"View passwords\" tab.");

    ui.checkbox("Invert copy controls", &mut state.invert_copy_controls);
    ui.text_disabled("This will make left click copy the username, and right click copy the password in \"View passwords\" tab. ");

    if ui.button("Save") {
        state.vault.lock_timeout_secs = (state.settings_timeout_mins * 60) as u64;
        state.light_mode = state.settings_light_mode;

        let mut config = crate::config::load();
        config.light_mode = state.light_mode;
        config.lock_timeout_secs = state.vault.lock_timeout_secs;
        config.duress.set(&state.self_destruct_pass);
        state.self_destruct_pass = Zeroizing::new(String::new());
        config.hide_user = state.hide_user;
        config.invert_copy_controls = state.invert_copy_controls;

        if let Err(e) = crate::config::save(&config) {
            state.custom_error_message = Some(e);
        }

        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel##settings") {
        ui.close_current_popup();
    }
}

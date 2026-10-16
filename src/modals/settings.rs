use crate::app::AppState;
use crate::config::{Config, Duress};
use crate::theme;
use std::path::PathBuf;
use zeroize::Zeroize;

pub fn settings_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_SETTINGS, 0.0]);

    // One read per frame for the status displays; the action handlers below
    // reload before writing so they never clobber concurrent changes.
    let current = crate::config::load();

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

    ui.separator();

    ui.text("Duress password (this vault)");
    match state.vault.file_path.clone() {
        Some(path) => duress_controls(ui, state, path, &current),
        None => ui.text_disabled("Open a vault to configure its duress password."),
    }

    ui.separator();

    ui.text("Backups");
    backup_controls(ui, state, &current);

    ui.separator();

    // Staged like the light-mode toggle: nothing below takes effect until
    // Save, so closing the modal with Cancel leaves behavior unchanged.
    ui.checkbox("Hide Email", &mut state.settings_hide_user);
    ui.text_disabled("This will censor your username / email in the \"View passwords\" tab.");

    ui.checkbox(
        "Invert copy controls",
        &mut state.settings_invert_copy_controls,
    );
    ui.text_disabled("This will make left click copy the username, and right click copy the password in \"View passwords\" tab. ");

    if ui.button("Save") {
        state.vault.lock_timeout_secs = u64::from(state.settings_timeout_mins) * 60;
        state.light_mode = state.settings_light_mode;
        state.hide_user = state.settings_hide_user;
        state.invert_copy_controls = state.settings_invert_copy_controls;

        let mut config = crate::config::load();
        config.light_mode = state.light_mode;
        config.lock_timeout_secs = state.vault.lock_timeout_secs;
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

fn duress_controls(ui: &imgui::Ui, state: &mut AppState, path: PathBuf, current: &Config) {
    let enabled = current.duress_by_vault.contains_key(&path);
    ui.text_disabled(if enabled {
        "Duress is enabled for this vault."
    } else {
        "Duress is disabled for this vault."
    });

    ui.input_text("Password", &mut state.self_destruct_pass)
        .password(true)
        .build();
    if state.self_destruct_pass.is_empty() {
        ui.text_disabled("Enter a password to set, or remove the existing one.");
    }

    if ui.button("Set duress password") && !state.self_destruct_pass.is_empty() {
        let mut config = crate::config::load();
        config
            .duress_by_vault
            .insert(path.clone(), Duress::new(state.self_destruct_pass.as_str()));
        finish_duress_change(ui, state, config, "Duress password set for this vault.");
        return;
    }

    if enabled && ui.button("Remove duress password") {
        let mut config = crate::config::load();
        config.duress_by_vault.remove(&path);
        finish_duress_change(ui, state, config, "Duress password removed for this vault.");
    }
}

fn finish_duress_change(ui: &imgui::Ui, state: &mut AppState, config: Config, message: &str) {
    if let Err(e) = crate::config::save(&config) {
        state.custom_error_message = Some(e);
    } else {
        state.custom_success_message = Some(message.to_string());
        state.modals.show_success = true;
    }
    state.self_destruct_pass.zeroize();
    ui.close_current_popup();
}

fn backup_controls(ui: &imgui::Ui, state: &mut AppState, current: &Config) {
    match &current.backup_dir {
        Some(dir) => ui.text_disabled(format!("Backups are saved to {}.", dir.display())),
        None => ui.text_disabled("Backups are disabled."),
    }

    if ui.button("Choose backup folder")
        && let Some(path) = rfd::FileDialog::new().pick_folder()
    {
        let mut config = crate::config::load();
        config.backup_dir = Some(path);
        if let Err(e) = crate::config::save(&config) {
            state.custom_error_message = Some(e);
        }
    }

    if current.backup_dir.is_some() && ui.button("Disable backups") {
        let mut config = crate::config::load();
        config.backup_dir = None;
        if let Err(e) = crate::config::save(&config) {
            state.custom_error_message = Some(e);
        }
    }
}

use crate::app::AppState;
use crate::config::{Config, Duress};
use crate::modals::enter_master_password::{decoy_path_for, is_decoy_path};
use crate::theme;
use std::cell::RefCell;
use std::path::PathBuf;
use zeroize::Zeroize;

/// What the modal shows of the config, read once when it opens.
struct Snapshot {
    duress_enabled: bool,
    backup_dir: Option<PathBuf>,
}

thread_local! {
    static SNAPSHOT: RefCell<Option<Snapshot>> = const { RefCell::new(None) };
}

fn snapshot_of(config: &Config, path: Option<&PathBuf>) -> Snapshot {
    Snapshot {
        duress_enabled: path.is_some_and(|p| config.duress_by_vault.contains_key(p)),
        backup_dir: config.backup_dir.clone(),
    }
}

pub fn settings_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_SETTINGS, 0.0]);

    // Read the config when the modal opens (and after an action changes it);
    // the handlers below reload before writing so they never clobber
    // concurrent changes.
    let stale = SNAPSHOT.with(|snap| snap.borrow().is_none());
    if ui.is_window_appearing() || stale {
        let snap = snapshot_of(&crate::config::load(), state.vault.file_path.as_ref());
        SNAPSHOT.with(|cell| *cell.borrow_mut() = Some(snap));
    }
    let (duress_enabled, backup_dir) = SNAPSHOT.with(|snap| {
        snap.borrow()
            .as_ref()
            .map(|s| (s.duress_enabled, s.backup_dir.clone()))
            .unwrap_or_default()
    });

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
        Some(path) => duress_controls(ui, state, path, duress_enabled),
        None => ui.text_disabled("Open a vault to configure its duress password."),
    }

    ui.separator();

    ui.text("Backups");
    backup_controls(ui, state, backup_dir.as_ref());

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

        state.self_destruct_pass.zeroize();
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel##settings") {
        state.self_destruct_pass.zeroize();
        ui.close_current_popup();
    }
}

fn duress_controls(ui: &imgui::Ui, state: &mut AppState, path: PathBuf, enabled: bool) {
    // Inside the decoy, Settings looks like a real vault with duress set, but
    // changes never reach the real vault's config.
    let in_decoy = is_decoy_path(&path);
    let enabled = enabled || in_decoy;
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
        if in_decoy {
            finish_duress_change(ui, state, None, "Duress password set for this vault.");
            return;
        }
        let mut config = crate::config::load();
        config
            .duress_by_vault
            .insert(path.clone(), Duress::new(state.self_destruct_pass.as_str()));
        finish_duress_change(
            ui,
            state,
            Some((config, &path)),
            "Duress password set for this vault.",
        );
        return;
    }

    if enabled && ui.button("Remove duress password") {
        if in_decoy {
            finish_duress_change(ui, state, None, "Duress password removed for this vault.");
            return;
        }
        let mut config = crate::config::load();
        config.duress_by_vault.remove(&path);
        finish_duress_change(
            ui,
            state,
            Some((config, &path)),
            "Duress password removed for this vault.",
        );
    }
}

fn finish_duress_change(
    ui: &imgui::Ui,
    state: &mut AppState,
    change: Option<(Config, &PathBuf)>,
    message: &str,
) {
    let saved = match change {
        Some((config, vault_path)) => match crate::config::save(&config) {
            Ok(()) => {
                // The old decoy is encrypted with the previous duress password.
                let decoy = decoy_path_for(vault_path);
                if let Err(e) = std::fs::remove_file(&decoy)
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    log::warn!("Could not remove old decoy vault: {e}");
                }
                true
            }
            Err(e) => {
                state.custom_error_message = Some(e);
                false
            }
        },
        None => true,
    };
    if saved {
        state.custom_success_message = Some(message.to_string());
        state.modals.show_success = true;
    }
    state.self_destruct_pass.zeroize();
    SNAPSHOT.with(|snap| *snap.borrow_mut() = None);
    ui.close_current_popup();
}

fn backup_controls(ui: &imgui::Ui, state: &mut AppState, backup_dir: Option<&PathBuf>) {
    match backup_dir {
        Some(dir) => ui.text_disabled(format!("Backups are saved to {}.", dir.display())),
        None => ui.text_disabled("Backups are disabled."),
    }

    if ui.button("Choose backup folder")
        && let Some(path) = rfd::FileDialog::new().pick_folder()
    {
        let mut config = crate::config::load();
        config.backup_dir = Some(path);
        save_backup_change(state, &config);
    }

    if backup_dir.is_some() && ui.button("Disable backups") {
        let mut config = crate::config::load();
        config.backup_dir = None;
        save_backup_change(state, &config);
    }
}

fn save_backup_change(state: &mut AppState, config: &Config) {
    if let Err(e) = crate::config::save(config) {
        state.custom_error_message = Some(e);
    }
    SNAPSHOT.with(|snap| *snap.borrow_mut() = None);
}

use crate::AppState;
use crate::theme;

pub fn use_lastused_file(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);

    ui.text("Aegis has detected a file being previously used, do you want to use that file again?");
    if ui.button("Yes") {
        let config = crate::config::load();
        state.vault.file_name = config
            .last_used_file
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "vault.aegis".to_string());
        state.vault.keyfile_hash = config
            .keyfile_hashes
            .get(config.last_used_file.as_path())
            .copied();
        state.vault.file_path = Some(config.last_used_file);
        ui.close_current_popup();
        state.modals.master = true;
    }
    if ui.button("No") {
        ui.close_current_popup();
    }
}

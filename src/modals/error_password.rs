pub fn error_password_modal(ui: &imgui::Ui) {
    ui.text("One of the required fields (username or password or Label) is empty.");

    if ui.button("OK") {
        ui.close_current_popup();
    }
}

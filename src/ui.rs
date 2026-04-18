use crate::models::AppState;
use crate::{ui_tabs, theme};

pub fn build_ui(ui: &imgui::Ui, state: &mut AppState) {
    if let Some(clear_at) = state.clipboard.clear_at && std::time::Instant::now() >= clear_at {
        crate::clipboard::set_excluded_from_history(&mut state.clipboard.handle, "");
        state.clipboard.clear_at = None;
    }

    if let Some(clear_at) = state.clipboard.copied_clear_at && std::time::Instant::now() >= clear_at {
        state.clipboard.copied_clear_at = None;
        state.clipboard.copied_field = None;
    }

    if state.vault.store.is_some()
        && state.vault.lock_timeout_secs > 0
        && state.vault.last_activity.elapsed().as_secs() >= state.vault.lock_timeout_secs
    {
        state.vault.store = None;
        state.vault.encryption_key = None;
        state.modals.master = true;
        state.vault.last_activity = std::time::Instant::now();
    }

    let [width, height] = ui.io().display_size;
    ui.window("Aegis")
        .position([0.0, 0.0], imgui::Condition::Always)
        .size([width, height], imgui::Condition::Always)
        .menu_bar(true)
        .build(|| {
            ui.menu_bar(|| {
                ui.menu("Files", || {
                    if ui.menu_item("Open") {
                        state.open_file();
                    }
                    if ui.menu_item("Create") {
                        state.modals.filename = true;
                    }
                    if ui.menu_item("Close") {
                        state.close_file();
                    }
                    if ui.menu_item("Add a key-file") && state.vault.keyfile.is_none(){
                        match crate::file_ops::create_key_file(state){
                            Ok(_) => { }
                            Err(error) => {
                                state.custom_error_message = Some(error);
                            }
                        }
                    }
                    if ui.menu_item("Import from CSV") {
                        match crate::file_ops::import_csv() {
                            Ok(Some(imported)) => {
                                if let Some(store) = &mut state.vault.store {
                                    store.entries.extend(imported.entries);
                                }
                            }
                            Ok(None) => {}
                            Err(e) => state.custom_error_message = Some(e),
                        }
                    }
                    if ui.menu_item("Export to CSV")
                        && let Some(store) = &state.vault.store
                        && let Err(e) = crate::file_ops::export_csv(store) {
                            state.custom_error_message = Some(e);
                    }
                    ui.separator();
                    if ui.menu_item("Settings") {
                        state.settings_timeout_mins = (state.vault.lock_timeout_secs / 60) as i32;
                        state.modals.settings = true;
                    }
                });
                if state.vault.store.is_some() {
                    ui.menu("Passwords", || {
                        if ui.menu_item("Generate password") {
                            state.modals.gen_password = true;
                        }
                        if ui.menu_item("Add a password") {
                            state.modals.add_password = true;
                        }
                    });
                }
            });

            imgui::TabBar::new("my_tabs").build(ui, || {
                imgui::TabItem::new("View passwords").build(ui, || {
                    ui_tabs::render_view_tab(ui, state);
                });
                imgui::TabItem::new("Add").build(ui, || {
                    ui_tabs::render_add_tab(ui, state);
                });
                imgui::TabItem::new("Delete").build(ui, || {
                    ui_tabs::render_delete_tab(ui, state);
                });
                imgui::TabItem::new("Modify").build(ui, || {
                    ui_tabs::render_modify_tab(ui, state);
                });
                imgui::TabItem::new("Health").build(ui, || {
                    ui_tabs::render_health_tab(ui, state);
                });
                imgui::TabItem::new("About").build(ui, || {
                    ui.text("Aegis — a password manager written in Rust, by Moonaw.");
                    ui.separator();

                    let _color = ui.push_style_color(imgui::StyleColor::Text, theme::LINK_COLOR);
                    ui.text("https://moonaw.org");
                    drop(_color);

                    if ui.is_item_clicked() {
                        let _ = open::that("https://moonaw.org");
                    }

                    if ui.is_item_hovered() {
                        ui.tooltip(|| ui.text("Click to open the link in browser."));
                    }
                });
            });
        });

    // Modal dispatch — flags are set on one frame, open_popup is called on the next.
    // imgui requires this two-frame pattern to nest popups correctly.

    if state.modals.gen_password && !state.modals.add_password {
        ui.open_popup("Generate a password");
        state.modals.gen_password = false;
    }

    if let Some(_token) = ui.begin_modal_popup("Generate a password") {
        crate::modals::generate_password_modal(ui, state);
    }

    if state.modals.confirm_delete {
        ui.open_popup("Confirm Delete");
        state.modals.confirm_delete = false;
    }

    if let Some(_token) = ui.begin_modal_popup("Confirm Delete") {
        crate::modals::confirm_delete_modal(ui, state);
    }

    if state.modals.master {
        ui.open_popup("Master password");
        state.modals.master = false;
    }

    if let Some(_token) = ui.begin_modal_popup("Master password") {
        crate::modals::enter_master_password(ui, state);

        if state.custom_success_message.is_some() {
            ui.open_popup("Success");
        }

        if let Some(_token) = ui.begin_modal_popup("Success") {
            crate::modals::success_modal(ui, state);
        }
    }


    if state.modals.filename {
        ui.open_popup("Create new file");
        state.modals.filename = false;
    }
    if let Some(_token) = ui.begin_modal_popup("Create new file") {
        crate::modals::new_file_title_modal(ui, state);
    }

    if state.modals.add_password {
        ui.open_popup("Add a password");
        state.modals.add_password = false;
    }

    if let Some(_token) = ui.begin_modal_popup("Add a password") {
        crate::modals::password_modal(ui, state);

        if state.modals.error_password {
            ui.open_popup("Error");
            state.modals.error_password = false;
        }
        if let Some(_token) = ui.begin_modal_popup("Error") {
            crate::modals::error_password_modal(ui);
        }

        if state.modals.warning_password {
            ui.open_popup("Warning");
            state.modals.warning_password = false;
        }
        if let Some(_token) = ui.begin_modal_popup("Warning") {
            crate::modals::warning_modal(ui, state);
        }

        if state.modals.gen_password {
            ui.open_popup("Generate password");
            state.modals.gen_password = false;
            state.modals.gen_from_add = true;
        }
        if let Some(_token) = ui.begin_modal_popup("Generate password") {
            crate::modals::generate_password_modal(ui, state);
        }
    }

    if state.edit_index.is_some() {
        ui.open_popup("Modify entry");
    }
    if let Some(_token) = ui.begin_modal_popup("Modify entry") {
        crate::modals::modify_entry_modal(ui, state);
    }



    if state.custom_error_message.is_some() {
        ui.open_popup("Error modal");
    }
    if let Some(_token) = ui.begin_modal_popup("Error modal") {
        crate::modals::custom_error_modal(ui, state);
    }

    if state.modals.settings {
        ui.open_popup("Settings");
        state.modals.settings = false;
    }
    if let Some(_token) = ui.begin_modal_popup("Settings") {
        crate::modals::settings_modal(ui, state);
    }
}

use crate::models::AppState;
use crate::{theme, ui_tabs};
use std::time::Instant;

pub fn build_ui(ui: &imgui::Ui, state: &mut AppState) {
    state.clipboard.clear_expired(Instant::now());
    auto_lock_if_idle(state);

    let [width, height] = ui.io().display_size;
    ui.window("Aegis")
        .position([0.0, 0.0], imgui::Condition::Always)
        .size([width, height], imgui::Condition::Always)
        .menu_bar(true)
        .build(|| {
            render_menu_bar(ui, state);
            render_tabs(ui, state);
        });

    render_modals(ui, state);
}

fn auto_lock_if_idle(state: &mut AppState) {
    if state.vault.store.is_none() || state.vault.lock_timeout_secs == 0 {
        return;
    }

    if state.vault.last_activity.elapsed().as_secs() < state.vault.lock_timeout_secs {
        return;
    }

    state.vault.store = None;
    state.clear_inputs();
    state.vault.encryption_key = None;
    state.modals.master = true;
    state.vault.last_activity = Instant::now();
}

fn render_menu_bar(ui: &imgui::Ui, state: &mut AppState) {
    ui.menu_bar(|| {
        render_file_menu(ui, state);
        if state.vault.store.is_some() {
            render_password_menu(ui, state);
        }
    });
}

fn render_file_menu(ui: &imgui::Ui, state: &mut AppState) {
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
        if ui.menu_item("Add a key-file")
            && state.vault.keyfile.is_none()
            && let Err(error) = crate::file_ops::create_key_file(state)
        {
            state.custom_error_message = Some(error);
        }
        if ui.menu_item("Import from CSV") {
            import_csv(state);
        }
        if ui.menu_item("Export to CSV")
            && let Some(store) = &state.vault.store
            && let Err(error) = crate::file_ops::export_csv(store)
        {
            state.custom_error_message = Some(error);
        }
        ui.separator();
        if ui.menu_item("Settings") {
            state.settings_timeout_mins = (state.vault.lock_timeout_secs / 60) as u32;
            state.modals.settings = true;
        }
    });
}

fn import_csv(state: &mut AppState) {
    match crate::file_ops::import_csv() {
        Ok(Some(imported)) => {
            if let Some(store) = &mut state.vault.store {
                store.entries.extend(imported.entries);
            }
        }
        Ok(None) => {}
        Err(error) => state.custom_error_message = Some(error),
    }
}

fn render_password_menu(ui: &imgui::Ui, state: &mut AppState) {
    ui.menu("Passwords", || {
        if ui.menu_item("Generate password") {
            state.modals.gen_password = true;
        }
        if ui.menu_item("Add a password") {
            state.modals.add_password = true;
        }
    });
}

fn render_tabs(ui: &imgui::Ui, state: &mut AppState) {
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
            render_about_tab(ui);
        });
    });
}

fn render_about_tab(ui: &imgui::Ui) {
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
}

fn open_popup_once(ui: &imgui::Ui, should_open: &mut bool, name: &str) {
    if *should_open {
        ui.open_popup(name);
        *should_open = false;
    }
}

fn render_modals(ui: &imgui::Ui, state: &mut AppState) {
    if state.modals.gen_password && !state.modals.add_password {
        open_popup_once(ui, &mut state.modals.gen_password, "Generate a password");
    }

    if let Some(_token) = ui.begin_modal_popup("Generate a password") {
        crate::modals::generate_password_modal(ui, state);
    }

    open_popup_once(ui, &mut state.modals.confirm_delete, "Confirm Delete");

    if let Some(_token) = ui.begin_modal_popup("Confirm Delete") {
        crate::modals::confirm_delete_modal(ui, state);
    }

    open_popup_once(ui, &mut state.modals.confirm_unsaved, "Unsaved Changes");

    if let Some(_token) = ui.begin_modal_popup("Unsaved Changes") {
        crate::modals::confirm_unsaved_modal(ui, state);
    }

    open_popup_once(ui, &mut state.modals.master, "Master password");

    if let Some(_token) = ui.begin_modal_popup("Master password") {
        crate::modals::enter_master_password(ui, state);
    }

    open_popup_once(ui, &mut state.modals.show_success, "Success");
    if let Some(_token) = ui.begin_modal_popup("Success") {
        crate::modals::success_modal(ui, state);
    }

    open_popup_once(ui, &mut state.modals.filename, "Create new file");
    if let Some(_token) = ui.begin_modal_popup("Create new file") {
        crate::modals::new_file_title_modal(ui, state);
    }

    if state.modals.add_password {
        state.has_chosen_type = false;
        open_popup_once(ui, &mut state.modals.add_password, "Add a password");
    }

    if let Some(_token) = ui.begin_modal_popup("Add a password") {
        render_add_password_modal(ui, state);
    }

    if state.edit_index.is_some() {
        ui.open_popup("Modify entry");
    }
    if let Some(_token) = ui.begin_modal_popup("Modify entry") {
        crate::modals::modify_entry_modal(ui, state);
    }

    if state.delete_idx.is_some() {
        ui.open_popup("Delete entry");
    }
    if let Some(_token) = ui.begin_modal_popup("Delete entry") {
        crate::modals::confirm_delete_modal(ui, state);
    }

    if state.custom_error_message.is_some() {
        ui.open_popup("Error modal");
    }
    if let Some(_token) = ui.begin_modal_popup("Error modal") {
        crate::modals::custom_error_modal(ui, state);
    }

    open_popup_once(ui, &mut state.modals.settings, "Settings");
    if let Some(_token) = ui.begin_modal_popup("Settings") {
        crate::modals::settings_modal(ui, state);
    }
}

fn render_add_password_modal(ui: &imgui::Ui, state: &mut AppState) {
    crate::modals::password_modal(ui, state);

    open_popup_once(ui, &mut state.modals.error_password, "Error");
    if let Some(_token) = ui.begin_modal_popup("Error") {
        crate::modals::error_password_modal(ui);
    }

    open_popup_once(ui, &mut state.modals.warning_password, "Warning");
    if let Some(_token) = ui.begin_modal_popup("Warning") {
        crate::modals::warning_modal(ui, state);
    }

    if state.modals.gen_password {
        state.modals.gen_from_add = true;
        open_popup_once(ui, &mut state.modals.gen_password, "Generate password");
    }
    if let Some(_token) = ui.begin_modal_popup("Generate password") {
        crate::modals::generate_password_modal(ui, state);
    }
}

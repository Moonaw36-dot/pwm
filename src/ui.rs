use crate::models::AppState;
use crate::{theme, ui_tabs};
use std::time::Instant;
use zeroize::Zeroizing;

pub fn build_ui(ui: &imgui::Ui, state: &mut AppState) {
    state.clipboard.sync_external_copy();
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

    state.lock_file();
    state.modals.master = true;
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
        if state.vault.store.is_none() && ui.menu_item("Create") {
            state.modals.filename = true;
        }
        if ui.menu_item("Close") {
            state.close_file();
        }
        if state.vault.store.is_some()
            && ui.menu_item("Add a key-file")
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
            state.settings_timeout_mins =
                u32::try_from(state.vault.lock_timeout_secs / 60).unwrap_or(u32::MAX);
            state.settings_light_mode = state.light_mode;
            state.settings_hide_user = state.hide_user;
            state.settings_invert_copy_controls = state.invert_copy_controls;
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
            state.invalidate_vault_caches();
            state.save();
        }
        Ok(None) => {}
        Err(error) => state.custom_error_message = Some(error),
    }
}

fn render_password_menu(ui: &imgui::Ui, state: &mut AppState) {
    ui.menu("Passwords", || {
        if ui.menu_item("Generate password") {
            // Standalone generator: no form to fill, start from a clean slate.
            state.modals.gen_password = true;
            state.modals.gen_into_form = false;
            state.generated_password = Zeroizing::new(String::new());
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
        imgui::TabItem::new("Trash").build(ui, || {
            ui_tabs::render_trash_tab(ui, state);
        });
        imgui::TabItem::new("About").build(ui, || {
            render_about_tab(ui);
        });
    });
}

fn render_about_tab(ui: &imgui::Ui) {
    ui.text("Aegis, a password manager written in Rust, by Moonaw.");
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

    open_popup_once(
        ui,
        &mut state.modals.use_lastused_file,
        "Use last used file",
    );
    if let Some(_token) = ui.begin_modal_popup("Use last used file") {
        crate::modals::lastusedfile::use_lastused_file(ui, state);
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
        state.modals.add_entry_popup = false;
        open_popup_once(ui, &mut state.modals.add_password, "Select password type");
    }

    render_add_password_modal(ui, state);

    if let Some(_token) = ui.begin_modal_popup("Modify entry") {
        // Only the focused popup reacts to Esc, so dismissing a popup opened
        // above this one never wipes the form beneath it.
        if ui.is_window_focused() && ui.is_key_pressed(imgui::Key::Escape) {
            state.edit_index = None;
            state.clear_inputs();
        }
        crate::modals::modify_entry_modal(ui, state);
    }

    if state.delete_idx.is_some() {
        ui.open_popup("Delete entry");
    }
    if let Some(_token) = ui.begin_modal_popup("Delete entry") {
        if ui.is_window_focused() && ui.is_key_pressed(imgui::Key::Escape) {
            state.delete_idx = None;
            ui.close_current_popup();
        }
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
    if !state.has_chosen_type
        && let Some(_token) = ui.begin_modal_popup("Select password type")
    {
        crate::modals::password_modal(ui, state);
    }

    if state.has_chosen_type {
        let add_title = match state.form.password_type {
            crate::models::PasswordType::Card => "Add card",
            crate::models::PasswordType::WiFi => "Add Wi-Fi",
            _ => "Add a password",
        };
        open_popup_once(ui, &mut state.modals.add_entry_popup, add_title);
        if let Some(_token) = ui.begin_modal_popup(add_title) {
            crate::modals::password_modal(ui, state);
        }
    }

    open_popup_once(ui, &mut state.modals.warning_password, "Warning");
    if let Some(_token) = ui.begin_modal_popup("Warning") {
        crate::modals::warning_modal(ui, state);
    }

    if state.modals.gen_password {
        open_popup_once(ui, &mut state.modals.gen_password, "Generate password");
    }
    if let Some(_token) = ui.begin_modal_popup("Generate password") {
        crate::modals::generate_password_modal(ui, state);
    }
}

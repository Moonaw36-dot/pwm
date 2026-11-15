use crate::models::{AppState, PasswordEntry, PasswordList};
use crate::{theme, ui_tabs};
use std::cell::{Cell, RefCell};
use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

/// Identity of an entry an open modal refers to by index.
pub(crate) type EntryKey = (String, Option<u64>);
pub(crate) type PinnedEntry = Option<(usize, EntryKey)>;

thread_local! {
    static EDIT_PIN: RefCell<PinnedEntry> = const { RefCell::new(None) };
    static DELETE_PIN: RefCell<PinnedEntry> = const { RefCell::new(None) };
    static EXPORT_CONFIRM: Cell<bool> = const { Cell::new(false) };
}

fn key_of(entry: &PasswordEntry) -> EntryKey {
    (entry.label.clone(), entry.created_at)
}

/// True while `index` still points at the entry it pointed at when first
/// seen. The first sighting pins it; a mismatch (the vault was reloaded or
/// changed underneath the modal) unpins and returns false.
pub(crate) fn index_still_valid(
    pin: &mut PinnedEntry,
    index: Option<usize>,
    store: Option<&PasswordList>,
) -> bool {
    let Some(index) = index else {
        *pin = None;
        return true;
    };
    let current = store.and_then(|store| store.entries.get(index)).map(key_of);
    match (pin.as_ref(), current) {
        (_, None) => {
            *pin = None;
            false
        }
        (Some((pinned_index, pinned_key)), Some(current)) if *pinned_index == index => {
            let same = *pinned_key == current;
            if !same {
                *pin = None;
            }
            same
        }
        (_, Some(current)) => {
            *pin = Some((index, current));
            true
        }
    }
}

fn drop_stale_indices(state: &mut AppState) {
    let valid = EDIT_PIN.with(|pin| {
        index_still_valid(
            &mut pin.borrow_mut(),
            state.edit_index,
            state.vault.store.as_ref(),
        )
    });
    if !valid {
        state.edit_index = None;
        state.clear_inputs();
    }
    let valid = DELETE_PIN.with(|pin| {
        index_still_valid(
            &mut pin.borrow_mut(),
            state.delete_idx,
            state.vault.store.as_ref(),
        )
    });
    if !valid {
        state.delete_idx = None;
    }
}

/// Draw the enclosed widgets with the bold face. Pops when the returned
/// token drops; bind it to keep the bold font scoped:
///
/// ```ignore
/// let _bold = push_bold(ui, state);
/// ui.text("Header");
/// ```
///
/// Returns `None` (normal font) when no bold face is registered, e.g. in
/// the headless perf probe.
pub fn push_bold<'a>(ui: &'a imgui::Ui, state: &AppState) -> Option<imgui::FontStackToken<'a>> {
    state.font_bold.map(|font| ui.push_font(font))
}

pub fn build_ui(ui: &imgui::Ui, state: &mut AppState) {
    state.clipboard.sync_external_copy();
    state.clipboard.clear_expired(Instant::now());
    auto_lock_if_idle(state);
    state.reload_if_changed_on_disk();
    drop_stale_indices(state);

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
        if ui.menu_item("Export to CSV") && state.vault.store.is_some() {
            EXPORT_CONFIRM.with(|flag| flag.set(true));
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
    if state.vault.store.is_none() {
        state.custom_error_message = Some("Open a vault before importing.".to_string());
        return;
    }
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
            render_about_tab(ui, state);
        });
    });
}

fn render_about_tab(ui: &imgui::Ui, state: &AppState) {
    let _bold = crate::ui::push_bold(ui, state);
    ui.text("Aegis, a password manager written in Rust, by Moonaw.");
    drop(_bold);
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
        if ui.is_window_focused() && ui.is_key_pressed(imgui::Key::Escape) {
            crate::modals::enter_master_password::cancel(state);
        }
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
        state.clear_inputs();
        state.modals.add_entry_popup = false;
        open_popup_once(ui, &mut state.modals.add_password, "Select password type");
    }

    render_add_password_modal(ui, state);

    open_popup_once(ui, &mut state.modals.modify_entry, "Modify entry");
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
        if ui.is_window_focused() && ui.is_key_pressed(imgui::Key::Escape) {
            state.self_destruct_pass.zeroize();
        }
        crate::modals::settings_modal(ui, state);
    }

    if EXPORT_CONFIRM.with(|flag| flag.replace(false)) {
        ui.open_popup("Export to CSV");
    }
    if let Some(_token) = ui.begin_modal_popup("Export to CSV") {
        render_export_confirm(ui, state);
    }
}

fn render_export_confirm(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text_wrapped(
        "The CSV file is not encrypted: every password in it is readable by anyone who can open the file.",
    );
    if ui.button("Export anyway") {
        if let Some(store) = &state.vault.store
            && let Err(error) = crate::file_ops::export_csv(store)
        {
            state.custom_error_message = Some(error);
        }
        ui.close_current_popup();
    }
    ui.same_line();
    if ui.button("Cancel##export") {
        ui.close_current_popup();
    }
}

fn render_add_password_modal(ui: &imgui::Ui, state: &mut AppState) {
    if !state.has_chosen_type
        && let Some(_token) = ui.begin_modal_popup("Select password type")
    {
        dismiss_add_form_on_escape(ui, state);
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
            dismiss_add_form_on_escape(ui, state);
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

/// Esc closes the popup on its own; this makes sure the half-filled form
/// goes with it. Only the focused popup reacts, so closing the generator or
/// an error above it leaves the form alone.
fn dismiss_add_form_on_escape(ui: &imgui::Ui, state: &mut AppState) {
    if ui.is_window_focused() && ui.is_key_pressed(imgui::Key::Escape) {
        state.clear_inputs();
    }
}

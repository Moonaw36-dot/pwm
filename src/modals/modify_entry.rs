use crate::app::AppState;
use crate::modals::modify_entry_normal::render;
use crate::models::PasswordType;

pub fn parse_tags(s: String) -> Option<Vec<String>> {
    let v: Vec<String> = s
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if v.is_empty() { None } else { Some(v) }
}

pub fn sanitize_totp(s: impl AsRef<str>) -> Option<String> {
    let s = s.as_ref().trim().replace(' ', "").to_uppercase();
    if s.is_empty() { None } else { Some(s) }
}

pub fn modify_entry_modal(ui: &imgui::Ui, state: &mut AppState) {
    let Some(entry_type) = state
        .edit_index
        .and_then(|idx| state.vault.store.as_ref()?.entries.get(idx))
        .map(|entry| entry.password_type)
    else {
        state.edit_index = None;
        ui.close_current_popup();
        return;
    };

    match entry_type {
        PasswordType::Normal => render(ui, state),
        PasswordType::Card => crate::modals::modify_entry_card::render(ui, state),
        _ => {}
    }
}

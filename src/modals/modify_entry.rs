use crate::app::AppState;
use crate::modals::modify_entry_normal::render;
use crate::models::PasswordType;

pub fn parse_tags(s: String) -> Option<Vec<String>> {
    let v: Vec<String> = s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if v.is_empty() { None } else { Some(v) }
}

pub fn sanitize_totp(s: String) -> Option<String> {
    let s = s.trim().replace(' ', "").to_uppercase();
    if s.is_empty() { None } else { Some(s) }
}

pub fn modify_entry_modal(ui: &imgui::Ui, state: &mut AppState) {
    let entries = &state.vault.store.as_ref().unwrap().entries;
    let entry = entries[state.edit_index.unwrap()].clone();

    match entry.password_type {
        PasswordType::Normal => render(ui, state),
        PasswordType::Card  => crate::modals::modify_entry_card::render(ui, state),
        _ => { }
    }
}

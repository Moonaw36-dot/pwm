pub mod confirm_delete;
pub mod confirm_unsaved;
pub mod custom_error;
pub mod enter_master_password;
pub mod error_password;
pub mod generate_password;
pub mod modify_entry;
mod modify_entry_card;
mod modify_entry_normal;
pub mod new_file;
pub mod password;
mod password_modal_card;
mod password_modal_normal;
pub mod settings;
pub mod success;
pub mod warning;

pub use confirm_delete::confirm_delete_modal;
pub use confirm_unsaved::confirm_unsaved_modal;
pub use custom_error::custom_error_modal;
pub use enter_master_password::enter_master_password;
pub use error_password::error_password_modal;
pub use generate_password::generate_password_modal;
pub use modify_entry::modify_entry_modal;
pub use new_file::new_file_title_modal;
pub use password::password_modal;
pub use settings::settings_modal;
pub use success::success_modal;
pub use warning::warning_modal;

use crate::app::{AppState, PasswordEntry};
use crate::models::PasswordType;
use crate::strength::{StrengthResult, get_card_issuer};
use crate::theme;
use zeroize::Zeroizing;

pub(crate) fn render_strength_bar(ui: &imgui::Ui, (score, label, color): StrengthResult) {
    let fraction = (score + 1) as f32 / 5.0;
    let bar_width = ui.calc_item_width();
    let bar_height = 16.0f32;

    let cursor = ui.cursor_screen_pos();
    let text_size = ui.calc_text_size(label);

    let _col = ui.push_style_color(imgui::StyleColor::PlotHistogram, color);
    imgui::ProgressBar::new(fraction)
        .size([bar_width, bar_height])
        .overlay_text("")
        .build(ui);

    let text_x = cursor[0] + (bar_width - text_size[0]) / 2.0;
    let text_y = cursor[1] + (bar_height - text_size[1]) / 2.0;
    ui.get_window_draw_list()
        .add_text([text_x, text_y], [1.0, 1.0, 1.0, 1.0], label);
}

fn add_entry_from_inputs(state: &mut AppState) {
    let entry = PasswordEntry {
        label: std::mem::take(&mut state.form.label),
        username: std::mem::take(&mut state.form.username),
        password: std::mem::replace(&mut state.form.password, Zeroizing::new(String::new())),
        notes: std::mem::replace(&mut state.form.notes, Zeroizing::new(String::new())),
        url: std::mem::take(&mut state.form.url),
        totp_secret: crate::modals::modify_entry::sanitize_totp(std::mem::replace(
            &mut state.form.totp,
            Zeroizing::new(String::new()),
        ))
        .into(),
        tags: crate::modals::modify_entry::parse_tags(state.form.tag.clone()),
        custom_fields: Zeroizing::new(
            std::mem::take(&mut *state.form.custom_fields)
                .into_iter()
                .filter(|(k, _)| !k.trim().is_empty())
                .collect::<Vec<_>>(),
        ),
        is_secure_note: state.form.is_secure_note,
        created_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ),
        totp_cache: None,
        password_type: state.form.password_type,
        number: std::mem::replace(&mut state.form.number, Zeroizing::new(String::new())).into(),
        expiration_date: std::mem::replace(
            &mut state.form.expiration_date,
            Zeroizing::new(String::new()),
        )
        .into(),
        cvc: std::mem::replace(&mut state.form.cvc, Zeroizing::new(String::new())).into(),
    };

    if let Some(store) = &mut state.vault.store {
        store.entries.push(entry);
    }
    state.save();
}

pub(crate) fn render_card_fields(ui: &imgui::Ui, state: &mut AppState) {
    if ui
        .input_text("Card number", &mut state.form.number)
        .password(true)
        .chars_decimal(true)
        .build()
    {
        state.form.number.truncate(16);
    }

    let card = state.form.number.as_str();
    if !card.is_empty() {
        let issuer = get_card_issuer(card);
        ui.text_colored([0.5, 0.5, 0.5, 1.0], issuer);

        let valid = crate::modals::password_modal_card::luhn_check(card);
        if valid {
            ui.text_colored([0.0, 0.8, 0.0, 1.0], "Valid");
        } else if card.len() >= 13 {
            ui.text_colored([0.8, 0.0, 0.0, 1.0], "Invalid");
        }
    }

    if ui
        .input_text("Expiry date", &mut state.form.expiration_date)
        .chars_decimal(true)
        .build()
    {
        let mut digits: String = state
            .form
            .expiration_date
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        digits.truncate(4);
        if digits.len() >= 3 {
            state.form.expiration_date = format!("{}/{}", &digits[..2], &digits[2..]).into();
        } else {
            state.form.expiration_date = digits.into();
        }
    }

    if ui
        .input_text("CVC", &mut state.form.cvc)
        .password(true)
        .chars_decimal(true)
        .build()
    {
        state.form.cvc.truncate(4);
    }
}

pub(crate) fn render_custom_fields_editor(
    ui: &imgui::Ui,
    fields: &mut Vec<(String, String)>,
    id_prefix: &str,
) {
    if ui.button(format!("Add field##{id_prefix}")) {
        fields.push((String::new(), String::new()));
    }

    let mut remove_idx = None;
    for (i, (key, val)) in fields.iter_mut().enumerate() {
        ui.set_next_item_width(theme::CUSTOM_FIELD_NAME_WIDTH);
        ui.input_text(format!("##{id_prefix}_field_name_{i}"), key)
            .hint("Field name")
            .build();
        ui.same_line();
        ui.set_next_item_width(theme::CUSTOM_FIELD_VALUE_WIDTH);
        ui.input_text(format!("##{id_prefix}_field_value_{i}"), val)
            .build();
        ui.same_line();
        if ui.button(format!("x##{id_prefix}_field_remove_{i}")) {
            remove_idx = Some(i);
        }
    }
    if let Some(i) = remove_idx {
        fields.remove(i);
    }
}

pub(crate) fn copy_entries(state: &mut AppState, pw_type: PasswordType, entry: &PasswordEntry) {
    match pw_type {
        PasswordType::Normal => {
            state.form.label = entry.label.clone();
            state.form.is_secure_note = entry.is_secure_note;
            state.form.username = entry.username.clone();
            state.form.password = entry.password.clone();
            state.form.notes = Zeroizing::new(entry.notes.to_string());
            state.form.totp =
                Zeroizing::new(entry.totp_secret.as_deref().unwrap_or_default().to_owned());
            state.form.url = entry.url.clone();
            state.form.tag = entry
                .tags
                .as_deref()
                .map(|t| t.join(", "))
                .unwrap_or_default();
            state.form.custom_fields = entry.custom_fields.clone();
            state.edit_index = None;
        }
        PasswordType::Card => {
            state.form.number = entry.number.clone().unwrap_or_default();
            state.form.cvc = entry.cvc.clone().unwrap_or_default();
            state.form.expiration_date = entry.expiration_date.clone().unwrap_or_default();
        }
        _ => {}
    }
}

fn mask_card_number(number: Option<&String>) -> String {
    let Some(number) = number else {
        return "[CARD]".to_string();
    };
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() > 4 {
        format!("**** **** **** {}", &digits[digits.len() - 4..])
    } else {
        "****".to_string()
    }
}

pub(crate) fn render_entries_list(
    ui: &imgui::Ui,
    state: &mut AppState,
    from: &str,
) -> Option<(u32, PasswordEntry)> {
    if let Some(store) = &state.vault.store {
        let mut clicked_idx = None;
        let mut clicked_entry = None;
        for (i, entry) in store.entries.iter().enumerate() {
            if entry.password_type == PasswordType::Card {
                let label = if entry.label.is_empty() {
                    "Card"
                } else {
                    entry.label.as_str()
                };
                ui.text(format!(
                    "{} - {}",
                    label,
                    mask_card_number(entry.number.as_deref())
                ));
                ui.same_line();
            } else if entry.password_type == PasswordType::Normal {
                ui.text(format!("{} - {}", entry.label, entry.username));
                ui.same_line();
            }

            if ui.button(format!("{}##{}{}", from, from, i)) {
                clicked_idx = Some(i);
                clicked_entry = Some(entry);
            }
        }
        if let Some(idx) = clicked_idx
            && let Some(entry) = clicked_entry
        {
            return Some((idx as u32, entry.clone()));
        }
        return None;
    }
    None
}

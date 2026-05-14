pub mod confirm_delete;
pub mod confirm_unsaved;
pub mod custom_error;
pub mod enter_master_password;
pub mod error_password;
pub mod generate_password;
pub mod modify_entry;
pub mod new_file;
pub mod password;
pub mod settings;
pub mod success;
pub mod warning;
mod password_modal_normal;
mod password_modal_card;

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

use zeroize::Zeroizing;
use crate::app::{AppState, PasswordEntry};
use crate::strength::StrengthResult;

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
    ui.get_window_draw_list().add_text([text_x, text_y], [1.0, 1.0, 1.0, 1.0], label);
}

fn parse_tags(s: String) -> Option<Vec<String>> {
    let v: Vec<String> = s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if v.is_empty() { None } else { Some(v) }
}

fn sanitize_totp(s: String) -> Option<String> {
    let s = s.trim().replace(' ', "").to_uppercase();
    if s.is_empty() { None } else { Some(s) }
}

fn add_entry_from_inputs(state: &mut AppState) {
    let entry = PasswordEntry {
        label: std::mem::take(&mut state.form.label),
        username: std::mem::take(&mut state.form.username),
        password: std::mem::replace(&mut state.form.password, Zeroizing::new(String::new())),
        notes: std::mem::take(&mut state.form.notes),
        url: std::mem::take(&mut state.form.url),
        totp_secret: sanitize_totp(std::mem::take(&mut state.form.totp)),
        tags: parse_tags(state.form.tag.clone()),
        custom_fields: std::mem::take(&mut state.form.custom_fields)
            .into_iter()
            .filter(|(k, _)| !k.trim().is_empty())
            .collect(),
        is_secure_note: state.form.is_secure_note,
        created_at: Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()),
        totp_cache: None,
        password_type: state.form.password_type,
        number: std::mem::replace(&mut state.form.number, Zeroizing::new(String::new())).into(),
        expiration_date: std::mem::replace(&mut state.form.expiration_date, Zeroizing::new(String::new())).into(),
        cvc: std::mem::replace(&mut state.form.cvc, Zeroizing::new(String::new())).into(),
    };

    if let Some(store) = &mut state.vault.store {
        store.entries.push(entry);
    }
    state.save();
}

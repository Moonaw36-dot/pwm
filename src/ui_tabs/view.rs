use crate::models::{AppState, PasswordEntry, PasswordType};
use crate::theme;
use totp_rs::{Algorithm, TOTP};

const TOTP_STEP_SECS: u64 = 30;
const URL_ERROR: &str = "Only http:// and https:// URLs can be opened from vault entries.";

#[derive(Default)]
struct EntryResponse {
    copy: Option<(String, &'static str)>,
    error: Option<String>,
}

fn is_allowed_external_url(url: &str) -> bool {
    let lower = url.trim_start().to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
}

fn entry_matches_search(entry: &PasswordEntry, query: &str) -> bool {
    query.is_empty()
        || entry.label.to_lowercase().contains(query)
        || entry.username.to_lowercase().contains(query)
        || entry
            .tags
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|tag| tag.to_lowercase().contains(query))
}

fn tags_prefix(tags: Option<&[String]>) -> String {
    tags.map(|tags| format!("[{}] ", tags.join(", ")))
        .unwrap_or_default()
}

fn masked_card_number(entry: &PasswordEntry) -> String {
    entry
        .number
        .as_ref()
        .map(|number| {
            let number = number.as_str();
            if number.len() > 4 {
                format!("**** **** **** {}", &number[number.len() - 4..])
            } else {
                number.to_string()
            }
        })
        .unwrap_or_default()
}

fn render_secure_note(ui: &imgui::Ui, entry: &PasswordEntry) -> EntryResponse {
    let mut response = EntryResponse::default();
    let masked = "*".repeat(entry.notes.len().min(64));

    ui.text(format!(
        "{}[{}] | {}",
        tags_prefix(entry.tags.as_deref()),
        entry.label,
        masked
    ));

    if ui.is_item_clicked() {
        response.copy = Some((entry.notes.to_string(), "note"));
    }

    if ui.is_item_hovered() {
        ui.tooltip(|| {
            ui.text("This is a secure note.");
            ui.separator();
            ui.text("Left click to copy the note.");
        })
    }

    response
}

fn render_card_entry(ui: &imgui::Ui, entry: &PasswordEntry) -> EntryResponse {
    let mut response = EntryResponse::default();
    let expiry = entry
        .expiration_date
        .as_ref()
        .map(|date| date.as_str())
        .unwrap_or("");

    ui.text(format!("[CARD] {} | {}", masked_card_number(entry), expiry));

    if ui.is_item_clicked()
        && let Some(number) = &entry.number
    {
        response.copy = Some((number.to_string(), "card number"));
    }

    if ui.is_item_clicked_with_button(imgui::MouseButton::Right)
        && let Some(cvc) = &entry.cvc
    {
        response.copy = Some((cvc.to_string(), "CVC"));
    }

    if ui.is_item_hovered() {
        ui.tooltip(|| {
            ui.text("Left click to copy the card number.");
            ui.separator();
            ui.text("Right click to copy the CVC.");
            render_custom_fields(ui, entry);
        });
    }

    response
}

fn ensure_totp_cache(entry: &mut PasswordEntry) {
    if entry.totp_secret.is_none() || entry.totp_cache.is_some() {
        return;
    }

    let Some(secret) = entry.totp_secret.as_deref() else {
        return;
    };

    let clean_secret = secret.replace(" ", "").to_uppercase();
    if let Some(bytes) = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &clean_secret)
    {
        match TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "".to_string()) {
            Ok(totp) => entry.totp_cache = Some(totp),
            Err(error) => log::error!("TOTP error for {}: {:?}", entry.label, error),
        }
    } else {
        log::error!("Failed to decode Base32 secret for {}", entry.label);
    }
}

fn current_totp(entry: &PasswordEntry) -> (Option<String>, Option<String>) {
    if let Some(totp) = &entry.totp_cache
        && let Ok(code) = totp.generate_current()
    {
        return (Some(code), current_totp_timeout());
    }

    (None, None)
}

fn current_totp_timeout() -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let ttl = TOTP_STEP_SECS - (now.as_secs() % TOTP_STEP_SECS);
    Some(ttl.to_string())
}

fn render_custom_fields(ui: &imgui::Ui, entry: &PasswordEntry) {
    if entry.custom_fields.is_empty() {
        return;
    }

    ui.separator();
    for (name, value) in entry.custom_fields.iter() {
        ui.text(format!("{}: {}", name, value));
    }
}

fn render_normal_entry(
    ui: &imgui::Ui,
    entry: &PasswordEntry,
    totp_code: Option<&str>,
    totp_timeout: Option<&str>,
) -> EntryResponse {
    let mut response = EntryResponse::default();
    let url_clicked = std::cell::Cell::new(false);

    ui.group(|| {
        let totp_suffix = totp_code
            .map(|code| format!(" | TOTP: {} ({}s)", code, totp_timeout.unwrap_or("?")))
            .unwrap_or_default();

        let notes_part = if entry.notes.is_empty() {
            String::new()
        } else {
            format!(" ? {}", entry.notes.as_str())
        };

        ui.text(format!(
            "{}[{}] | {}{}{}",
            tags_prefix(entry.tags.as_deref()),
            entry.label,
            entry.username,
            notes_part,
            totp_suffix
        ));

        if !entry.url.is_empty() {
            ui.same_line();

            let _color = ui.push_style_color(imgui::StyleColor::Text, theme::LINK_COLOR);
            ui.text(format!("@ {}", entry.url));
            drop(_color);

            if ui.is_item_clicked() {
                url_clicked.set(true);
                if is_allowed_external_url(&entry.url) {
                    let _ = open::that(entry.url.trim());
                } else {
                    response.error = Some(URL_ERROR.to_string());
                }
            }
            if ui.is_item_hovered() {
                ui.tooltip(|| {
                    ui.text("Click to open in browser.");
                    ui.separator();
                })
            }
        }
    });

    if !url_clicked.get() {
        if ui.is_item_clicked() {
            response.copy = Some((entry.password.to_string(), "password"));
        } else if ui.is_item_clicked_with_button(imgui::MouseButton::Right) {
            response.copy = Some((entry.username.clone(), "username"));
        } else if ui.is_item_clicked_with_button(imgui::MouseButton::Middle)
            && let Some(code) = totp_code
        {
            response.copy = Some((code.to_string(), "TOTP code"));
        }

        if ui.is_item_hovered() {
            ui.tooltip(|| {
                ui.text("Left click to copy the password.");
                ui.separator();
                ui.text("Right click to copy the username.");
                ui.separator();
                ui.text("Middle click to copy the TOTP.");
                render_custom_fields(ui, entry);
            });
        }
    }

    response
}

pub fn render_view_tab(ui: &imgui::Ui, state: &mut AppState) {
    ui.text("Welcome to Aegis, Moonaw's password manager fully written in Rust.");
    ui.separator();

    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    if ui.io().key_ctrl && ui.is_key_pressed(imgui::Key::F) {
        ui.set_keyboard_focus_here();
    }

    ui.input_text("Search", &mut state.search).build();

    let search_query = state.search.to_lowercase();
    let mut pending_copy: Option<(String, &'static str)> = None;
    let mut pending_error: Option<String> = None;

    if let Some(store) = &mut state.vault.store {
        ui.text(format!("Entry count: {}", store.entries.len()));

        for entry in &mut store.entries {
            if !entry_matches_search(entry, &search_query) {
                continue;
            }

            let response = if entry.is_secure_note {
                render_secure_note(ui, entry)
            } else if entry.password_type == PasswordType::Card {
                render_card_entry(ui, entry)
            } else {
                ensure_totp_cache(entry);
                let (totp_code, totp_timeout) = current_totp(entry);
                render_normal_entry(ui, entry, totp_code.as_deref(), totp_timeout.as_deref())
            };

            if let Some(copy) = response.copy {
                pending_copy = Some(copy);
            }
            if let Some(error) = response.error {
                pending_error = Some(error);
            }
        }
    }

    if let Some((text, field)) = pending_copy {
        state.copy_to_clipboard(&text, field);
    }

    if let Some(error) = pending_error {
        state.custom_error_message = Some(error);
    }

    if let Some(field) = &state.clipboard.copied_field {
        ui.separator();
        ui.text(format!("The {} has been copied to the clipboard!", field));
    }
}

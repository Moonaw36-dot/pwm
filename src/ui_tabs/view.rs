use crate::models::{AppState, PasswordEntry, PasswordType, is_trashed};
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

pub(crate) fn entry_matches_search(entry: &PasswordEntry, query: &str) -> bool {
    query.is_empty()
        || entry.label.to_lowercase().contains(query)
        || entry.username.to_lowercase().contains(query)
        || entry.url.to_lowercase().contains(query)
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
            let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() > 4 {
                format!("**** **** **** {}", &digits[digits.len() - 4..])
            } else {
                digits
            }
        })
        .unwrap_or_default()
}

fn render_secure_note(ui: &imgui::Ui, entry: &PasswordEntry) -> EntryResponse {
    let mut response = EntryResponse::default();
    let masked = crate::ui_tabs::health::mask_password(&entry.notes);

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

    ui.text(format!(
        "[CARD] {} | {} | {}",
        entry.label,
        masked_card_number(entry),
        expiry
    ));

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

fn build_totp(secret: &str) -> Option<TOTP> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }

    if secret.starts_with("otpauth://") {
        return TOTP::<Vec<u8>>::from_url(secret).ok();
    }

    let clean_secret = secret.replace(' ', "").to_uppercase();
    let bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &clean_secret)?;
    TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "".to_string()).ok()
}

fn ensure_totp_cache(entry: &mut PasswordEntry) {
    if entry.totp_secret.is_none() || entry.totp_cache.is_some() {
        return;
    }

    let Some(secret) = entry.totp_secret.as_deref() else {
        return;
    };

    match build_totp(secret) {
        Some(totp) => entry.totp_cache = Some(totp),
        None => log::error!("Failed to build TOTP for {}", entry.label),
    }
}

fn current_totp(entry: &mut PasswordEntry) -> (Option<String>, Option<String>) {
    let Some(now) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
    else {
        return (None, None);
    };

    if let Some((code, cached_expires_at)) = &entry.totp_code_cache
        && *cached_expires_at > now
    {
        return (
            Some(code.to_string()),
            Some((cached_expires_at - now).to_string()),
        );
    }

    let Some(totp) = &entry.totp_cache else {
        return (None, None);
    };
    // otpauth:// URIs may carry their own period; only fall back to the
    // common 30s grid for raw base32 secrets.
    let step = if totp.step > 0 {
        totp.step
    } else {
        TOTP_STEP_SECS
    };
    let expires_at = now - (now % step) + step;
    let Ok(code) = totp.generate_current() else {
        return (None, None);
    };
    entry.totp_code_cache = Some((zeroize::Zeroizing::new(code.clone()), expires_at));
    (Some(code), Some((expires_at - now).to_string()))
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
    hide_user: bool,
    invert_copy_controls: bool,
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
            if hide_user {
                "********"
            } else {
                entry.username.as_str()
            },
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
        let copy_password_button: imgui::MouseButton = if invert_copy_controls {
            imgui::MouseButton::Right
        } else {
            imgui::MouseButton::Left
        };

        let copy_username_button: imgui::MouseButton = if invert_copy_controls {
            imgui::MouseButton::Left
        } else {
            imgui::MouseButton::Right
        };

        if ui.is_item_clicked_with_button(copy_password_button) {
            response.copy = Some((entry.password.to_string(), "password"));
        } else if ui.is_item_clicked_with_button(copy_username_button) {
            response.copy = Some((entry.username.clone(), "username"));
        } else if ui.is_item_clicked_with_button(imgui::MouseButton::Middle)
            && let Some(code) = totp_code
        {
            response.copy = Some((code.to_string(), "TOTP code"));
        }

        if ui.is_item_hovered() {
            ui.tooltip(|| {
                if invert_copy_controls {
                    ui.text("Left click to copy the username.");
                    ui.separator();
                    ui.text("Middle click to copy the TOTP.");
                    ui.separator();
                    ui.text("Right click to copy the password.");
                } else {
                    ui.text("Right click to copy the username.");
                    ui.separator();
                    ui.text("Middle click to copy the TOTP.");
                    ui.separator();
                    ui.text("Left click to copy the password.");
                }
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
    let visible_indices = if state
        .search_cache
        .as_ref()
        .is_some_and(|(query, _)| query == &search_query)
    {
        state
            .search_cache
            .as_ref()
            .map(|(_, indices)| indices.clone())
            .unwrap_or_default()
    } else {
        let indices: Vec<usize> = state
            .vault
            .store
            .as_ref()
            .map(|store| {
                store
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| !is_trashed(entry))
                    .filter_map(|(index, entry)| {
                        entry_matches_search(entry, &search_query).then_some(index)
                    })
                    .collect()
            })
            .unwrap_or_default();
        state.search_cache = Some((search_query.clone(), indices.clone()));
        indices
    };
    let mut pending_copy: Option<(String, &'static str)> = None;
    let mut pending_error: Option<String> = None;
    let hide_user = state.hide_user;
    let invert_copy_controls = state.invert_copy_controls;

    if let Some(store) = &mut state.vault.store {
        let visible_count = store
            .entries
            .iter()
            .filter(|entry| !is_trashed(entry))
            .count();
        ui.text(format!("Entry count: {visible_count}"));

        for index in visible_indices {
            let Some(entry) = store.entries.get_mut(index) else {
                continue;
            };

            let response = if entry.is_secure_note {
                render_secure_note(ui, entry)
            } else if entry.password_type == PasswordType::Card {
                render_card_entry(ui, entry)
            } else {
                ensure_totp_cache(entry);
                let (totp_code, totp_timeout) = current_totp(entry);
                render_normal_entry(
                    ui,
                    entry,
                    totp_code.as_deref(),
                    totp_timeout.as_deref(),
                    hide_user,
                    invert_copy_controls,
                )
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

#[cfg(test)]
mod tests {
    use super::*;

    const OTPAUTH_URI: &str =
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    #[test]
    fn build_totp_parses_otpauth_uri() {
        let totp = build_totp(OTPAUTH_URI).expect("otpauth URI should parse");
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.step, 30);

        let code = totp.generate_current().expect("code should generate");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn build_totp_normalizes_raw_base32() {
        let totp = build_totp("jbsw y3dp").expect("raw base32 should build");
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.step, 30);
    }

    #[test]
    fn build_totp_rejects_invalid_and_empty_secrets() {
        assert!(build_totp("").is_none());
        assert!(build_totp("   ").is_none());
        assert!(build_totp("not base32!!").is_none());
    }

    #[test]
    fn entry_matches_search_matches_url() {
        let entry = PasswordEntry {
            label: "Example".to_string(),
            url: "https://github.com/alice".to_string(),
            ..Default::default()
        };

        assert!(entry_matches_search(&entry, "github"));
        assert!(entry_matches_search(&entry, "/alice"));
        assert!(entry_matches_search(&entry, ""));
        assert!(!entry_matches_search(&entry, "gitlab"));
    }
}

use crate::models::AppState;
use crate::theme;
use totp_rs::{Algorithm, TOTP};

fn is_allowed_external_url(url: &str) -> bool {
    let lower = url.trim_start().to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
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
            if !search_query.is_empty()
                && !entry.label.to_lowercase().contains(&search_query)
                && !entry.username.to_lowercase().contains(&search_query)
                && !entry
                    .tags
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|t| t.to_lowercase().contains(&search_query))
            {
                continue;
            }

            if entry.is_secure_note {
                let masked = "*".repeat(entry.notes.len().min(64));
                ui.text(format!(
                    "{}[{}] | {}",
                    entry
                        .tags
                        .as_deref()
                        .map(|t| format!("[{}] ", t.join(", ")))
                        .unwrap_or_default(),
                    entry.label,
                    masked
                ));

                if ui.is_item_clicked() {
                    pending_copy = Some((entry.notes.to_string(), "note"));
                }

                if ui.is_item_hovered() {
                    ui.tooltip(|| {
                        ui.text("This is a secure note.");
                        ui.separator();
                        ui.text("Left click to copy the note.");
                    })
                }

                continue;
            }

            if entry.password_type == crate::models::PasswordType::Card {
                let masked_number = entry
                    .number
                    .as_ref()
                    .map(|n| {
                        let s = n.as_str();
                        if s.len() > 4 {
                            format!("**** **** **** {}", &s[s.len() - 4..])
                        } else {
                            s.to_string()
                        }
                    })
                    .unwrap_or_default();

                let expiry = entry
                    .expiration_date
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("");

                ui.text(format!("[CARD] {} | {}", masked_number, expiry));

                if ui.is_item_clicked()
                    && let Some(number) = &entry.number
                {
                    pending_copy = Some((number.to_string(), "card number"));
                }

                if ui.is_item_clicked_with_button(imgui::MouseButton::Right)
                    && let Some(cvc) = &entry.cvc
                {
                    pending_copy = Some((cvc.to_string(), "CVC"));
                }

                if ui.is_item_hovered() {
                    ui.tooltip(|| {
                        ui.text("Left click to copy the card number.");
                        ui.separator();
                        ui.text("Right click to copy the CVC.");
                        if !entry.custom_fields.is_empty() {
                            ui.separator();
                            for (name, value) in entry.custom_fields.iter() {
                                ui.text(format!("{}: {}", name, value));
                            }
                        }
                    });
                }

                continue;
            }

            let mut totp_code: Option<String> = None;
            let mut totp_timeout: Option<String> = None;
            if entry.totp_secret.is_some() && entry.totp_cache.is_none() {
                let clean_secret = entry
                    .totp_secret
                    .as_ref()
                    .unwrap()
                    .replace(" ", "")
                    .to_uppercase();
                if let Some(bytes) =
                    base32::decode(base32::Alphabet::RFC4648 { padding: false }, &clean_secret)
                {
                    match TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "".to_string()) {
                        Ok(totp) => entry.totp_cache = Some(totp),
                        Err(e) => log::error!("TOTP error for {}: {:?}", entry.label, e),
                    }
                } else {
                    log::error!("Failed to decode Base32 secret for {}", entry.label);
                }
            }

            if let Some(totp) = &entry.totp_cache
                && let Ok(code) = totp.generate_current()
            {
                totp_code = Some(code);
                use std::time::{SystemTime, UNIX_EPOCH};
                if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                    let step = 30;
                    let ttl = step - (now.as_secs() % step);
                    totp_timeout = Some(ttl.to_string());
                }
            }

            let url_clicked = std::cell::Cell::new(false);
            ui.group(|| {
                let totp_suffix = totp_code
                    .as_deref()
                    .map(|c| {
                        format!(
                            " | TOTP: {} ({}s)",
                            c,
                            totp_timeout.as_deref().unwrap_or("?")
                        )
                    })
                    .unwrap_or_default();

                let notes_part = if entry.notes.is_empty() {
                    String::new()
                } else {
                    format!(" ? {}", entry.notes.as_str())
                };

                let tags_part = entry
                    .tags
                    .as_deref()
                    .map(|t| format!("[{}] ", t.join(", ")))
                    .unwrap_or_default();

                ui.text(format!(
                    "{}[{}] | {}{}{}",
                    tags_part, entry.label, entry.username, notes_part, totp_suffix
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
                            pending_error = Some(
                                "Only http:// and https:// URLs can be opened from vault entries."
                                    .to_string(),
                            );
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
                    pending_copy = Some((entry.password.to_string(), "password"));
                } else if ui.is_item_clicked_with_button(imgui::MouseButton::Right) {
                    pending_copy = Some((entry.username.clone(), "username"));
                } else if ui.is_item_clicked_with_button(imgui::MouseButton::Middle)
                    && let Some(code) = totp_code
                {
                    pending_copy = Some((code, "TOTP code"));
                }

                if ui.is_item_hovered() {
                    ui.tooltip(|| {
                        ui.text("Left click to copy the password.");
                        ui.separator();
                        ui.text("Right click to copy the username.");
                        ui.separator();
                        ui.text("Middle click to copy the TOTP.");
                        if !entry.custom_fields.is_empty() {
                            ui.separator();
                            for (name, value) in entry.custom_fields.iter() {
                                ui.text(format!("{}: {}", name, value));
                            }
                        }
                    });
                }
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

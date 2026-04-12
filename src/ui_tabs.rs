use crate::models::{AppState};
use crate::theme;
use crate::strength::{haveibeenpwned, manual_strength};

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

    if let Some(store) = &state.vault.store {
        ui.text(format!("Entry count: {}", store.entries.len()));

        for entry in &store.entries {
            if !search_query.is_empty()
                && !entry.label.to_lowercase().contains(&search_query)
                && !entry.username.to_lowercase().contains(&search_query)
                && !entry.tags.as_deref().unwrap_or(&[]).iter().any(|t| t.to_lowercase().contains(&search_query))
            {
                continue;
            }

            let mut totp_code: Option<String> = None;
            let mut totp_timeout: Option<String> = None;
            if let Some(secret) = &entry.totp_secret {
                use totp_rs::{Algorithm, Secret, TOTP};
                if let Ok(bytes) = Secret::Encoded(secret.replace(" ", "").to_uppercase()).to_bytes()
                    && let Ok(totp) = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes)
                    && let Ok(code) = totp.generate_current()
                {
                    totp_code = Some(code);
                    totp_timeout = Some(totp.ttl().unwrap().to_string());
                }
            }

            let url_clicked = std::cell::Cell::new(false);
            ui.group(|| {
                let totp_suffix = totp_code.as_deref()
                    .map(|c| format!(" | TOTP: {} ({}s)", c, totp_timeout.as_deref().unwrap_or("?")))
                    .unwrap_or_default();

                let notes_part = if entry.notes.is_empty() {
                    String::new()
                } else {
                    format!(" ? {}", entry.notes)
                };

                let tags_part = entry.tags.as_deref()
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
                        let _ = open::that(&entry.url);
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
                    pending_copy = Some((entry.password.clone(), "password"));
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
                            for (name, value) in &entry.custom_fields {
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

    if let Some(field) = &state.clipboard.copied_field {
        ui.separator();
        ui.text(format!("The {} has been copied to the clipboard!", field));
    }
}

pub fn render_add_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Add passwords to your current password list.");

    if ui.button("Add new password") {
        state.modals.add_password = true;
    }
}

pub fn render_delete_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Delete passwords.");

    if let Some(store) = &state.vault.store {
        for (i, entry) in store.entries.iter().enumerate() {
            ui.text(format!("{} - {}", entry.label, entry.username));
            ui.same_line();
            if ui.button(format!("Remove##remove{}", i)) {
                state.modals.confirm_delete = true;
                state.delete_idx = Some(i);
            }
        }
    }
}

pub fn render_modify_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Modify passwords.");

    let mut clicked_idx = None;
    if let Some(store) = &state.vault.store {
        for (i, entry) in store.entries.iter().enumerate() {
            ui.text(format!("{} - {}", entry.label, entry.username));
            ui.same_line();
            if ui.button(format!("Modify##modify{}", i)) {
                clicked_idx = Some(i);
            }
        }
    }

    if let Some(idx) = clicked_idx
        && let Some(store) = &state.vault.store
        && idx < store.entries.len()
    {
        let entry = &store.entries[idx];
        state.form.label = entry.label.clone();
        state.form.username = entry.username.clone();
        state.form.password = entry.password.clone();
        state.form.notes = entry.notes.clone();
        state.form.totp = entry.totp_secret.clone().unwrap_or_default();
        state.form.url = entry.url.clone();
        state.form.tag = entry.tags.as_deref().map(|t| t.join(", ")).unwrap_or_default();
        state.form.custom_fields = entry.custom_fields.clone();
        state.edit_index = Some(idx);
    }
}

pub fn render_health_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    if let Some(store) = &state.vault.store {
        ui.text("Weak passwords:");
        for entry in &store.entries {
            let (score, _label, _) = manual_strength(&entry.password);
            if score < 3 {
                ui.text(format!("{} - {}", entry.label, entry.username));
            }
        }
        ui.separator();

        use std::collections::HashMap;
        let mut seen: HashMap<&str, Vec<&str>> = HashMap::new();

        ui.text("Reused passwords:");
        for entry in &store.entries {
            seen.entry(entry.password.as_str()).or_default().push(entry.username.as_str());
        }

        for labels in seen.values() {
            if labels.len() > 1 {
                ui.text(format!("Reused by: {}", labels.join(", ")));
            }
        }

        ui.separator();

        ui.text("Pwned passwords:");
        for i in 0..store.entries.len() {
            let password = store.entries[i].password.clone();
            if !state.hibp_cache.contains_key(&password) {
                let result = haveibeenpwned(&password);
                state.hibp_cache.insert(password.clone(), result);
            }
            if state.hibp_cache[&password] {
                ui.text(format!("The password \"{}\" has been pwned! Click the button to modify the password.", password));
                ui.same_line();
                if ui.button("Modify password") {
                    state.modals.gen_password = true;
                }
            }
        }
    }
}


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


            if entry.is_secure_note {
                ui.text(format!("{}[{}] | {}", entry.tags.as_deref()
                    .map(|t| format!("[{}] ", t.join(", ")))
                    .unwrap_or_default(), entry.label, entry.notes));

                if ui.is_item_clicked() {
                    pending_copy = Some((entry.notes.clone(), "note"));
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


            let mut totp_code: Option<String> = None;
            let mut totp_timeout: Option<String> = None;
            if let Some(secret) = &entry.totp_secret {
                use totp_rs::{Algorithm, TOTP};


                let clean_secret = secret.replace(" ", "").to_uppercase();
                if let Some(bytes) = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &clean_secret) {

                    match TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "".to_string()) {
                        Ok(totp) => {
                            if let Ok(code) = totp.generate_current() {
                                totp_code = Some(code);


                                use std::time::{SystemTime, UNIX_EPOCH};
                                if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                                    let step = 30;
                                    let ttl = step - (now.as_secs() % step);
                                    totp_timeout = Some(ttl.to_string());
                                }
                            }
                        }
                        Err(e) => log::error!("TOTP error for {}: {:?}", entry.label, e),
                    }
                } else {
                    log::error!("Failed to decode Base32 secret for {}", entry.label);
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

fn mask_password(s: &str) -> String {
    if s.len() <= 4 {
        return "*".repeat(s.len());
    }
    let prefix = &s[..2];
    let suffix = &s[s.len()-2..];
    let stars = "*".repeat(s.len().saturating_sub(4));
    format!("{prefix}{stars}{suffix}")
}

pub fn render_health_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    if let Some(store) = &state.vault.store {
        let mut weak_titles: Vec<String> = Vec::new();

        for entry in &store.entries {
            let (score, _label, _) = manual_strength(&entry.password);
            if score < 3 {
                weak_titles.push(format!("{} - {}", entry.label, mask_password(&entry.password)));
            }
        }

        if !weak_titles.is_empty() {
            ui.text("Weak passwords: ");
            for title in &weak_titles {
                ui.text(title);
            }
            ui.separator();
        }

        use std::collections::HashMap;
        let mut seen: HashMap<&str, Vec<&str>> = HashMap::new();

        for entry in &store.entries {
            seen.entry(entry.password.as_str()).or_default().push(entry.username.as_str());
        }

        let reused_groups: Vec<_> = seen.values().filter(|labels| labels.len() > 1).collect();
        if !reused_groups.is_empty() {
            ui.text("Reused passwords:");
            for labels in &reused_groups {
                ui.text(format!("Reused by: {}", labels.join(", ")));
            }
            ui.separator();
        }

        let mut pwned_indices: Vec<usize> = Vec::new();
        let mut checked_any = false;
        for (i, entry) in store.entries.iter().enumerate() {
            let password: &str = &entry.password;
            if !checked_any && !state.hibp_cache.contains_key(password) {
                checked_any = true;
                match haveibeenpwned(password) {
                    Ok(result) => { state.hibp_cache.insert(password.to_string(), result); }
                    Err(e) => { log::error!("HIBP error for {}: {e}", entry.label); }
                }
            }
            if state.hibp_cache.get(password) == Some(&true) {
                pwned_indices.push(i);
            }
        }

        if !pwned_indices.is_empty() {
            ui.text("Pwned passwords:");
            for &idx in &pwned_indices {
                if let Some(entry) = store.entries.get(idx) {
                    ui.text(format!("{} - {} has been pwned!", entry.label, mask_password(&entry.password)));
                    ui.same_line();
                    if ui.button(format!("Modify##pwned{}", idx)) {
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
            }
            ui.separator();
        }

        let thirty_days = 30 * 24 * 60 * 60;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        let mut old_titles: Vec<String> = Vec::new();

        for entry in &store.entries {
            if let Some(created_at) = entry.created_at
                && now > created_at
                && now - created_at > thirty_days
            {
                old_titles.push(format!("{} - {} is old! You should update it!", entry.label, mask_password(&entry.password)));
            }
        }

        for title in &old_titles {
            ui.text(title);
        }

        if weak_titles.is_empty() && reused_groups.is_empty() && pwned_indices.is_empty() && old_titles.is_empty() {
            ui.text("Good job! Every password is safe!");
        }
    }
}

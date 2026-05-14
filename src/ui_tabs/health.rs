use crate::models::{AppState, PasswordType};
use crate::strength::{haveibeenpwned, manual_strength};

pub fn mask_password(s: &str) -> String {
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

            if entry.password_type != PasswordType::Normal {
                continue
            }

            if entry.is_secure_note {
                continue
            }

            let (score, _label, _) = manual_strength(entry.password.as_str());
            if score < 2 {
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
        let mut seen: HashMap<u64, Vec<&str>> = HashMap::new();

        for entry in &store.entries {

            if entry.password_type != PasswordType::Normal {
                continue
            }

            let hash = crate::app::hash_password(entry.password.as_str());
            seen.entry(hash).or_default().push(entry.username.as_str());
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
            if entry.password_type != PasswordType::Normal {
                continue;
            }

            if entry.is_secure_note {
                continue;
            }

            let password: &str = &entry.password;
            let pw_hash = crate::app::hash_password(password);
            if !checked_any && !state.hibp_cache.contains_key(&pw_hash) {
                checked_any = true;
                match haveibeenpwned(password) {
                    Ok(result) => { state.hibp_cache.insert(pw_hash, result); }
                    Err(e) => {
                        state.custom_error_message = Some(format!("Failed to check HIBP for {}: {e}", entry.label));
                        log::error!("HIBP error for {}: {e}", entry.label);
                    }
                }
            }
            if state.hibp_cache.get(&pw_hash) == Some(&true) {
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

        const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        let mut old_titles: Vec<String> = Vec::new();

        for entry in &store.entries {
            if let Some(created_at) = entry.created_at
                && now > created_at
                && now - created_at > THIRTY_DAYS
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

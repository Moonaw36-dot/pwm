use crate::models::{AppState, PasswordType};
use crate::strength::{haveibeenpwned, manual_strength};
use std::sync::mpsc::TryRecvError;
use zeroize::Zeroizing;

pub fn mask_password(s: &str) -> String {
    if s.len() <= 4 {
        return "*".repeat(s.len());
    }
    let prefix = &s[..2];
    let suffix = &s[s.len() - 2..];
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
                continue;
            }

            if entry.is_secure_note {
                continue;
            }

            let (score, _label, _) = manual_strength(entry.password.as_str());
            if score < 2 {
                weak_titles.push(format!(
                    "{} - {}",
                    entry.label,
                    mask_password(&entry.password)
                ));
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
                continue;
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

        if let Some((pw_hash, receiver, label)) = state.hibp_pending.take() {
            match receiver.try_recv() {
                Ok(Ok(result)) => {
                    state.hibp_cache.insert(pw_hash, result);
                }
                Ok(Err(e)) => {
                    state.custom_error_message =
                        Some(format!("Failed to check HIBP for {label}: {e}"));
                    log::error!("HIBP error for {label}: {e}");
                }
                Err(TryRecvError::Empty) => {
                    state.hibp_pending = Some((pw_hash, receiver, label));
                }
                Err(TryRecvError::Disconnected) => {
                    state.custom_error_message = Some(format!(
                        "Failed to check HIBP for {label}: background worker stopped"
                    ));
                    log::error!("HIBP worker stopped for {label}");
                }
            }
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
            if !checked_any
                && state.hibp_pending.is_none()
                && !state.hibp_cache.contains_key(&pw_hash)
            {
                checked_any = true;
                let password = Zeroizing::new(entry.password.to_string());
                let label = entry.label.clone();
                let label_for_worker = label.clone();
                let (sender, receiver) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let result = haveibeenpwned(password.as_str());
                    if sender.send(result).is_err() {
                        log::error!("HIBP result receiver dropped for {label_for_worker}");
                    }
                });
                state.hibp_pending = Some((pw_hash, receiver, label));
            }
            if state.hibp_cache.get(&pw_hash) == Some(&true) {
                pwned_indices.push(i);
            }
        }

        if let Some((_, _, label)) = &state.hibp_pending {
            ui.text(format!("Checking HIBP for {label}..."));
            ui.separator();
        }

        if !pwned_indices.is_empty() {
            ui.text("Pwned passwords:");
            for &idx in &pwned_indices {
                if let Some(entry) = store.entries.get(idx) {
                    ui.text(format!(
                        "{} - {} has been pwned!",
                        entry.label,
                        mask_password(&entry.password)
                    ));
                    ui.same_line();
                    if ui.button(format!("Modify##pwned{}", idx)) {
                        crate::modals::copy_entry_to_form(
                            &mut state.form,
                            entry.password_type,
                            entry,
                        );
                        state.edit_index = Some(idx);
                    }
                }
            }
            ui.separator();
        }

        const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut old_titles: Vec<String> = Vec::new();

        for entry in &store.entries {
            if let Some(created_at) = entry.created_at
                && now > created_at
                && now - created_at > THIRTY_DAYS
            {
                old_titles.push(format!(
                    "{} - {} is old! You should update it!",
                    entry.label,
                    mask_password(&entry.password)
                ));
            }
        }

        for title in &old_titles {
            ui.text(title);
        }

        if weak_titles.is_empty()
            && reused_groups.is_empty()
            && pwned_indices.is_empty()
            && old_titles.is_empty()
        {
            ui.text("Good job! Every password is safe!");
        }
    }
}

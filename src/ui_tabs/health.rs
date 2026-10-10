use crate::models::{AppState, HealthSummary, PasswordList, PasswordType, is_trashed};
use crate::strength::{haveibeenpwned, manual_strength};
use std::sync::atomic::Ordering;
use std::sync::mpsc::TryRecvError;
use zeroize::Zeroizing;

const MAX_HIBP_IN_FLIGHT: usize = 4;

pub fn mask_password(s: &str) -> String {
    "*".repeat(s.chars().count().min(32))
}

fn build_health_summary(store: &PasswordList) -> HealthSummary {
    let mut weak_titles = Vec::new();
    let mut seen: std::collections::HashMap<[u8; 32], Vec<String>> =
        std::collections::HashMap::new();
    let mut old_titles = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;

    for entry in &store.entries {
        if is_trashed(entry) || entry.is_secure_note {
            continue;
        }
        if entry.password_type == PasswordType::Normal || entry.password_type == PasswordType::WiFi
        {
            let (score, _label, _) = manual_strength(entry.password.as_str());
            if score < 2 {
                weak_titles.push(format!(
                    "{} - {}",
                    entry.label,
                    mask_password(&entry.password)
                ));
            }
            seen.entry(crate::app::hash_password(entry.password.as_str()))
                .or_default()
                .push(entry.username.clone());
        }
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

    let reused_groups = seen
        .into_values()
        .filter(|labels| labels.len() > 1)
        .collect();

    HealthSummary {
        weak_titles,
        reused_groups,
        old_titles,
    }
}

pub fn render_health_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    if state.health_cache.is_none()
        && let Some(store) = &state.vault.store
    {
        state.health_cache = Some(build_health_summary(store));
    }

    let Some(summary) = state.health_cache.clone() else {
        return;
    };

    if let Some(store) = &state.vault.store {
        let weak_titles = summary.weak_titles;
        let reused_groups = summary.reused_groups;
        let old_titles = summary.old_titles;

        if !weak_titles.is_empty() {
            ui.text("Weak passwords: ");
            for title in &weak_titles {
                ui.text(title);
            }
            ui.separator();
        }

        if !reused_groups.is_empty() {
            ui.text("Reused passwords:");
            for labels in &reused_groups {
                ui.text(format!("Reused by: {}", labels.join(", ")));
            }
            ui.separator();
        }

        let pending = std::mem::take(&mut state.hibp_pending);
        for (pw_hash, receiver, label) in pending {
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
                    state.hibp_pending.push((pw_hash, receiver, label));
                }
                Err(TryRecvError::Disconnected) => {
                    state.custom_error_message = Some(format!(
                        "Failed to check HIBP for {label}: background worker stopped"
                    ));
                    log::error!("HIBP worker stopped for {label}");
                }
            }
        }
        if state.hibp_pending.is_empty() {
            state.hibp_cancel = None;
        }

        let mut pwned_indices: Vec<usize> = Vec::new();
        let mut pending_hashes: std::collections::HashSet<[u8; 32]> = state
            .hibp_pending
            .iter()
            .map(|(hash, _, _)| *hash)
            .collect();
        for (i, entry) in store.entries.iter().enumerate() {
            if entry.password_type != PasswordType::Normal {
                continue;
            }

            if is_trashed(entry) || entry.is_secure_note {
                continue;
            }

            let password: &str = &entry.password;
            let pw_hash = crate::app::hash_password(password);
            if state.hibp_pending.len() < MAX_HIBP_IN_FLIGHT
                && !state.hibp_cache.contains_key(&pw_hash)
                && !pending_hashes.contains(&pw_hash)
            {
                let password = Zeroizing::new(entry.password.to_string());
                let label = entry.label.clone();
                let label_for_worker = label.clone();
                let cancel = state
                    .hibp_cancel
                    .get_or_insert_with(|| {
                        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
                    })
                    .clone();
                let (sender, receiver) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let result = haveibeenpwned(password.as_str());
                    if !cancel.load(Ordering::Acquire) && sender.send(result).is_err() {
                        log::error!("HIBP result receiver dropped for {label_for_worker}");
                    }
                });
                pending_hashes.insert(pw_hash);
                state.hibp_pending.push((pw_hash, receiver, label));
            }
            if state.hibp_cache.get(&pw_hash) == Some(&true) {
                pwned_indices.push(i);
            }
        }

        if let Some((_, _, label)) = state.hibp_pending.first() {
            let extra = state.hibp_pending.len() - 1;
            if extra > 0 {
                ui.text(format!("Checking HIBP for {label} (+{extra} more)..."));
            } else {
                ui.text(format!("Checking HIBP for {label}..."));
            }
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

#[cfg(test)]
mod tests {
    use super::mask_password;

    #[test]
    fn mask_password_handles_unicode_boundaries() {
        assert_eq!(mask_password("pässwörd"), "********");
        assert_eq!(mask_password("秘密"), "**");
    }
}

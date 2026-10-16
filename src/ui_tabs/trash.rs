use crate::app::{AppState, hash_password};
use crate::models::{PasswordEntry, PasswordType, is_trashed, now_unix};

const SECS_PER_DAY: u64 = 24 * 60 * 60;

fn type_indicator(entry: &PasswordEntry) -> &'static str {
    if entry.is_secure_note {
        return "[Note]";
    }
    match entry.password_type {
        PasswordType::Card => "[CARD]",
        PasswordType::WiFi => "[Wi-Fi]",
        PasswordType::Normal => "",
    }
}

fn days_ago_label(trashed_at: u64, now: u64) -> String {
    let days = now.saturating_sub(trashed_at) / SECS_PER_DAY;
    match days {
        0 => "today".to_string(),
        1 => "1 day ago".to_string(),
        days => format!("{days} days ago"),
    }
}

pub fn render_trash_tab(ui: &imgui::Ui, state: &mut AppState) {
    if state.vault.store.is_none() {
        ui.text("Open a file to get started.");
        return;
    }

    ui.text("Deleted entries stay in the trash until restored or deleted forever.");
    ui.separator();

    drop_stale_pending(state);

    let trashed_indices: Vec<usize> = state
        .vault
        .store
        .as_ref()
        .map(|store| {
            store
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| is_trashed(entry))
                .map(|(index, _)| index)
                .collect()
        })
        .unwrap_or_default();

    if trashed_indices.is_empty() {
        state.trash_purge_pending = None;
        state.trash_empty_pending = false;
        ui.text("The trash is empty.");
        return;
    }

    let mut restore_idx = None;
    let mut purge_idx = None;
    let mut empty_trash = false;
    let now = now_unix();

    let empty_label = if state.trash_empty_pending {
        "Confirm empty trash?"
    } else {
        "Empty trash"
    };
    if ui.button(empty_label) {
        if state.trash_empty_pending {
            empty_trash = true;
        } else {
            state.trash_empty_pending = true;
            state.trash_purge_pending = None;
        }
    }
    if state.trash_empty_pending {
        ui.same_line();
        if ui.button("Cancel##empty_trash") {
            state.trash_empty_pending = false;
        }
    }
    ui.separator();

    for index in trashed_indices {
        let Some(entry) = state
            .vault
            .store
            .as_ref()
            .and_then(|store| store.entries.get(index))
        else {
            continue;
        };

        let indicator = type_indicator(entry);
        let label = if entry.label.is_empty() {
            "(no label)"
        } else {
            entry.label.as_str()
        };
        let age = days_ago_label(entry.trashed_at.unwrap_or(now), now);
        let id_suffix = format!("##trash{index}");

        ui.text(format!("{indicator} {label} — trashed {age}"));
        ui.same_line();

        let cursor = ui.cursor_pos();
        let text_height = ui.text_line_height();
        let button_height = ui.frame_height();
        let offset = (button_height - text_height) * -0.5;
        ui.set_cursor_pos([cursor[0], cursor[1] + offset]);

        if ui.button(format!("Restore{id_suffix}")) {
            restore_idx = Some(index);
        }
        ui.same_line();

        if state.trash_purge_pending == Some(index) {
            if ui.button(format!("Confirm?{id_suffix}")) {
                purge_idx = Some(index);
            }
            ui.same_line();
            if ui.button(format!("Cancel{id_suffix}")) {
                state.trash_purge_pending = None;
            }
        } else if ui.button(format!("Delete forever{id_suffix}")) {
            state.trash_purge_pending = Some(index);
            state.trash_empty_pending = false;
        }
    }

    if let Some(index) = restore_idx
        && let Some(entry) = state
            .vault
            .store
            .as_mut()
            .and_then(|store| store.entries.get_mut(index))
    {
        entry.trashed_at = None;
        state.trash_purge_pending = None;
        state.trash_empty_pending = false;
        state.invalidate_vault_caches();
        state.save();
    }

    if purge_idx.is_some() || empty_trash {
        let mut purged_hashes = Vec::new();
        if let Some(store) = state.vault.store.as_mut() {
            if let Some(index) = purge_idx
                && let Some(entry) = store.entries.get(index)
                && is_trashed(entry)
            {
                purged_hashes.push(hash_password(entry.password.as_str()));
                store.entries.remove(index);
            }
            if empty_trash {
                store.entries.retain(|entry| {
                    if is_trashed(entry) {
                        purged_hashes.push(hash_password(entry.password.as_str()));
                        false
                    } else {
                        true
                    }
                });
            }
        }
        for hash in purged_hashes {
            state.hibp_cache.remove(&hash);
        }
        state.trash_purge_pending = None;
        state.trash_empty_pending = false;
        state.invalidate_vault_caches();
        state.save();
    }
}

fn drop_stale_pending(state: &mut AppState) {
    if let Some(index) = state.trash_purge_pending
        && state
            .vault
            .store
            .as_ref()
            .and_then(|store| store.entries.get(index))
            .is_none_or(|entry| !is_trashed(entry))
    {
        state.trash_purge_pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::{SECS_PER_DAY, days_ago_label, type_indicator};
    use crate::models::{PasswordEntry, PasswordType};

    #[test]
    fn type_indicator_covers_entry_kinds() {
        let mut entry = PasswordEntry::default();
        assert_eq!(type_indicator(&entry), "");

        entry.password_type = PasswordType::Card;
        assert_eq!(type_indicator(&entry), "[CARD]");

        entry.password_type = PasswordType::WiFi;
        assert_eq!(type_indicator(&entry), "[Wi-Fi]");

        entry.password_type = PasswordType::Normal;
        entry.is_secure_note = true;
        assert_eq!(type_indicator(&entry), "[Note]");
    }

    #[test]
    fn days_ago_label_formats_days() {
        let now = 40 * SECS_PER_DAY;
        assert_eq!(days_ago_label(now, now), "today");
        assert_eq!(days_ago_label(now - 1, now), "today");
        assert_eq!(days_ago_label(now - SECS_PER_DAY, now), "1 day ago");
        assert_eq!(days_ago_label(now - 5 * SECS_PER_DAY, now), "5 days ago");
        assert_eq!(days_ago_label(now + SECS_PER_DAY, now), "today");
    }

    #[test]
    fn days_ago_label_ignores_partial_days() {
        let now = 10 * SECS_PER_DAY + 60;
        assert_eq!(days_ago_label(now - SECS_PER_DAY + 1, now), "today");
        assert_eq!(days_ago_label(now - SECS_PER_DAY, now), "1 day ago");
        assert_eq!(days_ago_label(0, now), "10 days ago");
    }
}

use crate::models::{AppState, HealthSummary, PasswordType, is_trashed};
use crate::strength::{haveibeenpwned, live_strength};
use crate::theme;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_HIBP_IN_FLIGHT: usize = 4;
const HIBP_RETRY_AFTER: Duration = Duration::from_secs(60);

pub fn mask_password(s: &str) -> String {
    "*".repeat(s.chars().count().min(32))
}

type EntryHashes = Vec<(usize, [u8; 32])>;

/// Health-tab state that is not part of the vault, kept for the session.
#[derive(Default)]
struct HealthUi {
    /// Off until the user opts in to the Have I Been Pwned lookups.
    hibp_enabled: bool,
    /// Password hashes whose lookup failed, and when to try them again.
    failed: HashMap<[u8; 32], Instant>,
    last_error: Option<String>,
    /// Hashes of checkable entries, valid for (vault generation, entry count).
    hashes: Option<(u64, usize, EntryHashes)>,
    summary_cancel: Option<Arc<AtomicBool>>,
}

thread_local! {
    static HEALTH: RefCell<HealthUi> = RefCell::new(HealthUi::default());
}

/// What the summary worker needs from an entry, and nothing more.
struct HealthInput {
    label: String,
    password: Zeroizing<String>,
    created_at: Option<u64>,
    has_password: bool,
}

fn health_inputs(state: &AppState) -> Vec<HealthInput> {
    let Some(store) = &state.vault.store else {
        return Vec::new();
    };
    store
        .entries
        .iter()
        .filter(|entry| !is_trashed(entry) && !entry.is_secure_note)
        .map(|entry| {
            let has_password = matches!(
                entry.password_type,
                PasswordType::Normal | PasswordType::WiFi
            );
            HealthInput {
                label: entry.label.clone(),
                password: if has_password {
                    Zeroizing::new(entry.password.to_string())
                } else {
                    Zeroizing::new(String::new())
                },
                created_at: entry.created_at,
                has_password,
            }
        })
        .collect()
}

fn build_health_summary(inputs: &[HealthInput], cancel: &AtomicBool) -> Option<HealthSummary> {
    let mut weak_titles = Vec::new();
    let mut seen: HashMap<[u8; 32], Vec<String>> = HashMap::new();
    let mut old_titles = Vec::new();
    let now = crate::models::now_unix();
    const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;

    for input in inputs {
        if cancel.load(Ordering::Acquire) {
            return None;
        }
        if !input.has_password {
            continue;
        }
        if !input.password.is_empty() {
            // live_strength caps how much of a long password zxcvbn sees.
            let (score, _label, _) = live_strength(input.password.as_str());
            if score < 2 {
                weak_titles.push(format!(
                    "{} - {}",
                    input.label,
                    mask_password(&input.password)
                ));
            }
            seen.entry(crate::app::hash_password(input.password.as_str()))
                .or_default()
                .push(input.label.clone());
        }
        if let Some(created_at) = input.created_at
            && now > created_at
            && now - created_at > THIRTY_DAYS
        {
            old_titles.push(format!(
                "{} - {} is old! You should update it!",
                input.label,
                mask_password(&input.password)
            ));
        }
    }

    let mut reused_groups: Vec<Vec<String>> = seen
        .into_values()
        .filter(|labels| labels.len() > 1)
        .collect();
    reused_groups.sort();

    Some(HealthSummary {
        weak_titles,
        reused_groups,
        old_titles,
    })
}

fn poll_summary_worker(state: &mut AppState) {
    let Some(receiver) = &state.health_worker else {
        return;
    };
    match receiver.try_recv() {
        Ok((generation, summary)) => {
            state.health_worker = None;
            if generation == state.health_generation {
                state.health_cache = Some(summary);
            }
        }
        Err(TryRecvError::Empty) => {}
        Err(TryRecvError::Disconnected) => state.health_worker = None,
    }
}

pub fn render_health_tab(ui: &imgui::Ui, state: &mut AppState) {
    let mut health = HEALTH.take();
    render_health(ui, state, &mut health);
    HEALTH.set(health);
}

fn render_health(ui: &imgui::Ui, state: &mut AppState, health: &mut HealthUi) {
    if state.vault.store.is_none() {
        if let Some(cancel) = health.summary_cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        *health = HealthUi::default();
        ui.text("Open a file to get started.");
        return;
    }

    // zxcvbn over every entry is slow, so build the summary off the UI
    // thread; results are discarded when the vault changed in the meantime.
    if state.health_cache.is_none() && state.health_worker.is_none() {
        if let Some(old) = health.summary_cancel.take() {
            old.store(true, Ordering::Release);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        health.summary_cancel = Some(cancel.clone());
        let inputs = health_inputs(state);
        let generation = state.health_generation;
        let (sender, receiver) = std::sync::mpsc::channel();
        state.health_worker = Some(receiver);
        std::thread::spawn(move || {
            if let Some(summary) = build_health_summary(&inputs, &cancel)
                && sender.send((generation, summary)).is_err()
            {
                log::debug!("Health summary receiver dropped; discarding result");
            }
        });
    }

    poll_summary_worker(state);

    if state.health_cache.is_none() {
        ui.text("Analyzing the vault...");
        return;
    }

    if ui.checkbox("Check against Have I Been Pwned", &mut health.hibp_enabled)
        && !health.hibp_enabled
    {
        stop_hibp(state);
    }
    ui.text_disabled(
        "Sends only the first 5 characters of each password's SHA-1 hash to api.pwnedpasswords.com.",
    );
    ui.separator();

    let pwned_indices = if health.hibp_enabled {
        drive_hibp(state, health)
    } else {
        Vec::new()
    };

    if let Some(error) = &health.last_error {
        ui.text_colored(theme::ERROR_COLOR, error);
        ui.same_line();
        if ui.button("Retry##hibp") {
            health.failed.clear();
            health.last_error = None;
        }
        ui.separator();
    }

    let mut modify_idx = None;
    if let Some(summary) = &state.health_cache
        && let Some(store) = &state.vault.store
    {
        if !summary.weak_titles.is_empty() {
            let _bold = crate::ui::push_bold(ui, state);
            ui.text("Weak passwords: ");
            drop(_bold);
            for title in &summary.weak_titles {
                ui.text(title);
            }
            ui.separator();
        }

        if !summary.reused_groups.is_empty() {
            ui.text("Reused passwords:");
            for labels in &summary.reused_groups {
                ui.text(format!("Reused by: {}", labels.join(", ")));
            }
            ui.separator();
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
                        modify_idx = Some(idx);
                    }
                }
            }
            ui.separator();
        }

        for title in &summary.old_titles {
            ui.text(title);
        }

        if summary.weak_titles.is_empty()
            && summary.reused_groups.is_empty()
            && pwned_indices.is_empty()
            && summary.old_titles.is_empty()
        {
            ui.text("Good job! Every password is safe!");
        }
    }

    if let Some(idx) = modify_idx
        && let Some(entry) = state
            .vault
            .store
            .as_ref()
            .and_then(|store| store.entries.get(idx))
    {
        crate::modals::copy_entry_to_form(&mut state.form, entry.password_type, entry);
        state.edit_index = Some(idx);
        state.modals.modify_entry = true;
    }
}

fn stop_hibp(state: &mut AppState) {
    if let Some(cancel) = state.hibp_cancel.take() {
        cancel.store(true, Ordering::Release);
    }
    state.hibp_pending.clear();
}

/// Collect finished lookups, start new ones, and return the indices of
/// entries known to be pwned.
fn drive_hibp(state: &mut AppState, health: &mut HealthUi) -> Vec<usize> {
    let now = Instant::now();
    health.failed.retain(|_, until| now < *until);
    if health.failed.is_empty() {
        health.last_error = None;
    }

    for (pw_hash, receiver, label) in std::mem::take(&mut state.hibp_pending) {
        let failure = match receiver.try_recv() {
            Ok(Ok(result)) => {
                state.hibp_cache.insert(pw_hash, result);
                continue;
            }
            Ok(Err(e)) => e,
            Err(TryRecvError::Empty) => {
                state.hibp_pending.push((pw_hash, receiver, label));
                continue;
            }
            Err(TryRecvError::Disconnected) => "background worker stopped".to_string(),
        };
        log::warn!("HIBP check failed for {label}: {failure}");
        health.failed.insert(pw_hash, now + HIBP_RETRY_AFTER);
        health.last_error = Some(format!("HIBP check failed for {label}: {failure}"));
    }
    if state.hibp_pending.is_empty() {
        state.hibp_cancel = None;
    }

    let stale = !matches!(
        &health.hashes,
        Some((generation, len, _))
            if *generation == state.health_generation
                && Some(*len) == state.vault.store.as_ref().map(|s| s.entries.len())
    );
    if stale && let Some(store) = &state.vault.store {
        let hashes = store
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.password_type == PasswordType::Normal
                    && !is_trashed(entry)
                    && !entry.is_secure_note
                    && !entry.password.is_empty()
            })
            .map(|(i, entry)| (i, crate::app::hash_password(entry.password.as_str())))
            .collect();
        health.hashes = Some((state.health_generation, store.entries.len(), hashes));
    }

    let mut pwned = Vec::new();
    let mut in_flight: HashSet<[u8; 32]> = state
        .hibp_pending
        .iter()
        .map(|(hash, _, _)| *hash)
        .collect();
    let Some((_, _, hashes)) = &health.hashes else {
        return pwned;
    };
    for &(i, pw_hash) in hashes {
        if state.hibp_pending.len() < MAX_HIBP_IN_FLIGHT
            && !state.hibp_cache.contains_key(&pw_hash)
            && !in_flight.contains(&pw_hash)
            && !health.failed.contains_key(&pw_hash)
            && let Some(entry) = state.vault.store.as_ref().and_then(|s| s.entries.get(i))
        {
            let password = Zeroizing::new(entry.password.to_string());
            let label = entry.label.clone();
            let label_for_worker = label.clone();
            let cancel = state
                .hibp_cancel
                .get_or_insert_with(|| Arc::new(AtomicBool::new(false)))
                .clone();
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                if cancel.load(Ordering::Acquire) {
                    return;
                }
                let result = haveibeenpwned(password.as_str());
                if !cancel.load(Ordering::Acquire) && sender.send(result).is_err() {
                    log::error!("HIBP result receiver dropped for {label_for_worker}");
                }
            });
            in_flight.insert(pw_hash);
            state.hibp_pending.push((pw_hash, receiver, label));
        }
        if state.hibp_cache.get(&pw_hash) == Some(&true) {
            pwned.push(i);
        }
    }
    pwned
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

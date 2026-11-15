use crate::app::{AppState, PasswordEntry};
use crate::modals::render_strength_bar;
use crate::models::{now_unix, record_password_change};
use crate::theme;
use zeroize::Zeroizing;

pub fn render(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_STANDARD, 0.0]);
    ui.text("Modify the fields you want to change:");
    ui.separator();

    ui.checkbox("Secure note", &mut state.form.is_secure_note);

    ui.input_text("Label", &mut state.form.label).build();
    ui.input_text("Tag", &mut state.form.tag).build();
    ui.input_text("URL / Website", &mut state.form.url).build();

    if !state.form.is_secure_note {
        ui.input_text("Username", &mut state.form.username).build();
        ui.input_text("Password", &mut state.form.password)
            .password(true)
            .build();

        let pw = state.form.password.clone();
        let strength = state.cached_strength(&pw);
        if ui.button("Generate password") {
            state.modals.gen_password = true;
            state.modals.gen_into_form = true;
        }
        render_strength_bar(ui, strength);
        render_password_history(ui, state);
    }

    ui.input_text("Notes", &mut state.form.notes).build();
    ui.input_text("TOTP###MODIFY", &mut state.form.totp)
        .password(true)
        .build();
    ui.separator();

    crate::modals::render_custom_fields_editor(ui, &mut state.form.custom_fields, "modify");

    if ui.button("Save")
        && let Some(idx) = state.edit_index
        && let Some(store) = &mut state.vault.store
    {
        if let Err(error) = crate::modals::modify_entry::validate_normal_fields(
            &state.form.label,
            &state.form.username,
            &state.form.password,
            &state.form.notes,
            state.form.is_secure_note,
        ) {
            state.custom_error_message = Some(error.to_string());
            return;
        }
        // Only require a strong password when the password itself changes;
        // otherwise a weak stored password would block every other edit.
        let password_changed = !state.form.is_secure_note
            && state.form.password.as_str() != store.entries[idx].password.as_str();
        if password_changed && !crate::strength::verify_password(&state.form.password).is_empty() {
            state.custom_error_message =
                Some("Choose a stronger password before saving this entry.".to_string());
            return;
        }
        state.hibp_cache.remove(&crate::app::hash_password(
            store.entries[idx].password.as_str(),
        ));
        // Archiving to history happens on every password change, including
        // converting an entry into a secure note, so nothing is lost silently.
        // An empty stored password has nothing worth archiving.
        if !store.entries[idx].password.is_empty() {
            let replacement = if state.form.is_secure_note {
                ""
            } else {
                state.form.password.as_str()
            };
            record_password_change(&mut store.entries[idx], replacement, now_unix());
        }
        let trashed_at = store.entries[idx].trashed_at;
        let password_history = std::mem::take(&mut store.entries[idx].password_history);
        let passkeys = std::mem::take(&mut store.entries[idx].passkeys);
        let created_at = store.entries[idx].created_at;
        let password_type = store.entries[idx].password_type;
        store.entries[idx] = PasswordEntry {
            label: state.form.label.clone(),
            username: if state.form.is_secure_note {
                String::new()
            } else {
                state.form.username.clone()
            },
            password: if state.form.is_secure_note {
                Zeroizing::new(String::new())
            } else {
                state.form.password.clone()
            },
            notes: state.form.notes.clone(),
            url: state.form.url.clone(),
            totp_secret: {
                let totp = std::mem::replace(&mut state.form.totp, Zeroizing::new(String::new()));
                if state.form.is_secure_note {
                    None
                } else {
                    crate::modals::modify_entry::sanitize_totp(totp)
                }
            }
            .into(),
            tags: crate::modals::modify_entry::parse_tags(std::mem::take(&mut state.form.tag)),
            custom_fields: Zeroizing::new(crate::modals::take_custom_fields(
                &mut state.form.custom_fields,
            )),
            is_secure_note: state.form.is_secure_note,
            created_at,
            trashed_at,
            password_history,
            passkeys,
            totp_cache: None,
            password_type,
            number: store.entries[idx].number.clone(),
            expiration_date: store.entries[idx].expiration_date.clone(),
            cvc: store.entries[idx].cvc.clone(),
            favorite: store.entries[idx].favorite,
            totp_code_cache: None,
        };
        state.invalidate_vault_caches();
        state.save();
        state.edit_index = None;
        state.clear_inputs();
        ui.close_current_popup();
    }

    ui.same_line();
    if ui.button("Cancel") {
        state.edit_index = None;
        state.clear_inputs();
        ui.close_current_popup();
    }
}

/// Stored password history for the edited entry, newest last. Shown masked;
/// the per-item Copy button reveals it via the clipboard only.
fn render_password_history(ui: &imgui::Ui, state: &mut AppState) {
    let Some(entry) = state
        .edit_index
        .and_then(|idx| state.vault.store.as_ref()?.entries.get(idx))
    else {
        return;
    };
    if entry.password_history.is_empty() {
        return;
    }

    if !ui.collapsing_header(
        format!("Password history ({})", entry.password_history.len()),
        imgui::TreeNodeFlags::empty(),
    ) {
        return;
    }

    let mut copied = None;
    for (i, item) in entry.password_history.iter().enumerate().rev() {
        ui.text(crate::ui_tabs::health::mask_password(
            item.password.as_str(),
        ));
        ui.same_line();
        if ui.button(format!("Copy##pw_history_{i}")) {
            copied = Some(item.password.clone());
        }
        ui.same_line();
        if ui.button(format!("Restore##pw_history_{i}")) {
            state.form.password = item.password.clone();
        }
    }
    if let Some(password) = copied {
        state.copy_to_clipboard(&password, "previous password");
    }
}

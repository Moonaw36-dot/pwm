use crate::app::AppState;
use crate::modals::modify_entry_normal::render;
use crate::models::PasswordType;

pub fn parse_tags(s: String) -> Option<Vec<String>> {
    let v: Vec<String> = s
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if v.is_empty() { None } else { Some(v) }
}

pub fn sanitize_totp(s: impl AsRef<str>) -> Option<String> {
    let s = s.as_ref().trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with("otpauth://") {
        return Some(s.to_string());
    }
    Some(s.replace(' ', "").to_uppercase())
}

pub(crate) fn validate_normal_fields(
    label: &str,
    username: &str,
    password: &str,
    notes: &str,
    is_secure_note: bool,
) -> Result<(), &'static str> {
    if label.trim().is_empty() {
        return Err("A label is required");
    }
    if is_secure_note {
        if notes.trim().is_empty() {
            return Err("Secure notes cannot be empty");
        }
    } else if username.trim().is_empty() || password.is_empty() {
        return Err("Username and password are required");
    }
    Ok(())
}

pub fn modify_entry_modal(ui: &imgui::Ui, state: &mut AppState) {
    let Some(entry_type) = state
        .edit_index
        .and_then(|idx| state.vault.store.as_ref()?.entries.get(idx))
        .map(|entry| entry.password_type)
    else {
        state.edit_index = None;
        ui.close_current_popup();
        return;
    };

    match entry_type {
        PasswordType::Normal | PasswordType::WiFi => render(ui, state),
        PasswordType::Card => crate::modals::modify_entry_card::render(ui, state),
    }
}

#[cfg(test)]
mod tests {
    use super::{sanitize_totp, validate_normal_fields};

    #[test]
    fn normal_entries_require_label_username_and_password() {
        assert!(validate_normal_fields("label", "user", "password", "", false).is_ok());
        assert!(validate_normal_fields("", "user", "password", "", false).is_err());
        assert!(validate_normal_fields("label", "", "password", "", false).is_err());
        assert!(validate_normal_fields("label", "user", "", "", false).is_err());
    }

    #[test]
    fn secure_notes_require_label_and_notes() {
        assert!(validate_normal_fields("label", "", "", "note", true).is_ok());
        assert!(validate_normal_fields("label", "", "", "", true).is_err());
    }

    #[test]
    fn sanitize_totp_preserves_otpauth_uri_verbatim() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        assert_eq!(sanitize_totp(uri).as_deref(), Some(uri));
        assert_eq!(
            sanitize_totp(format!("  {uri} ")).as_deref(),
            Some(uri),
            "surrounding whitespace is trimmed, URI kept verbatim"
        );
    }

    #[test]
    fn sanitize_totp_normalizes_raw_base32() {
        assert_eq!(sanitize_totp("jbsw y3dp").as_deref(), Some("JBSWY3DP"));
        assert_eq!(sanitize_totp("  jbsw y3dp  ").as_deref(), Some("JBSWY3DP"));
        assert_eq!(sanitize_totp("").as_deref(), None);
        assert_eq!(sanitize_totp("   ").as_deref(), None);
    }
}

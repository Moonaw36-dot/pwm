//! TOTP codes from either a bare base32 secret or an `otpauth://` URL.

use totp_rs::{Algorithm, TOTP};

/// Parse a stored TOTP secret the same way the desktop app does.
pub fn build_totp(secret: &str) -> Option<TOTP> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }

    if secret.starts_with("otpauth://") {
        return TOTP::<Vec<u8>>::from_url(secret).ok();
    }

    let clean_secret = secret.replace(' ', "").to_uppercase();
    let bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &clean_secret)?;
    TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "".to_string()).ok()
}

/// Current code and the seconds left before it rotates.
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
}

pub fn code_at(secret: &str, unix_time: u64) -> Option<TotpCode> {
    let totp = build_totp(secret)?;
    let period = totp.step;
    Some(TotpCode {
        code: totp.generate(unix_time),
        seconds_remaining: period - (unix_time % period),
        period,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_style_vector() {
        // "12345678901234567890" in base32, SHA1, 6 digits, t=59 -> 287082
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = code_at(secret, 59).unwrap();
        assert_eq!(code.code, "287082");
        assert_eq!(code.seconds_remaining, 1);
    }

    #[test]
    fn empty_and_garbage_secrets_are_rejected() {
        assert!(code_at("", 0).is_none());
        assert!(code_at("!!!", 0).is_none());
    }
}

use sha1::{Digest, Sha1};
use std::time::Duration;

static WORDLIST: &str = include_str!("../assets/wordlist.txt");

const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGIT_CHARS: &[u8] = b"0123456789";
const SPECIAL_CHARS: &[u8] = b"!@#$%^&*-_=?";
const AMBIGUOUS_CHARS: &[u8] = b"0OIl1B8S5Z2";

const MIN_PASSWORD_LENGTH: usize = 15;
const MIN_PASSPHRASE_WORDS: usize = 4;

#[derive(PartialEq, Clone, Copy)]
pub enum GenMode {
    Password,
    Passphrase,
}

#[derive(PartialEq)]
pub enum PasswordSafety {
    TooShort,
    MissingNumbers,
    MissingSpecialChars,
    NoLowerCase,
    NoUpperCase,
    TooFewWords,
}

pub fn get_card_issuer(card: &str) -> String {
    if card.starts_with("4") {
        return "Visa".into();
    }
    if card.starts_with("51")
        || card.starts_with("52")
        || card.starts_with("53")
        || card.starts_with("54")
        || card.starts_with("55")
    {
        return "Mastercard".into();
    }
    if card.starts_with("34") || card.starts_with("37") {
        return "American Express".into();
    }
    "Unknown".into()
}

pub type StrengthResult = (u8, &'static str, [f32; 4]);

pub fn haveibeenpwned(password: &str) -> Result<bool, String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut digest = zeroize::Zeroizing::new([0u8; 20]);
    digest.copy_from_slice(&Sha1::digest(password.as_bytes()));
    let mut hash = zeroize::Zeroizing::new(String::with_capacity(40));
    for b in digest.iter() {
        hash.push(HEX[usize::from(b >> 4)] as char);
        hash.push(HEX[usize::from(b & 15)] as char);
    }
    let (prefix, suffix) = hash.split_at(5);

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_per_call(Some(Duration::from_secs(10)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let body = agent
        .get(&url)
        .header("Add-Padding", "true")
        .call()
        .map_err(|e| format!("HIBP request failed: {e}"))?
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_string()
        .map_err(|e| format!("HIBP response read failed: {e}"))?;
    // Padded responses carry fake rows with a zero count.
    Ok(body.lines().any(|line: &str| {
        let mut parts = line.trim().split(':');
        parts
            .next()
            .is_some_and(|s: &str| s.eq_ignore_ascii_case(suffix))
            && parts.next().is_some_and(|count| count.trim() != "0")
    }))
}

fn password_words(password: &str) -> Vec<&str> {
    password
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|s| !s.is_empty())
        .collect()
}

fn looks_like_passphrase(words: &[&str]) -> bool {
    words.len() >= 2
        && words
            .iter()
            .all(|word| word.chars().all(|c| c.is_ascii_lowercase()))
}

pub fn verify_password(password: &str) -> Vec<PasswordSafety> {
    let words = password_words(password);
    if looks_like_passphrase(&words) {
        if words.len() < MIN_PASSPHRASE_WORDS {
            return vec![PasswordSafety::TooFewWords];
        }
        return vec![];
    }

    let mut issues = Vec::new();

    if password.chars().count() < MIN_PASSWORD_LENGTH {
        issues.push(PasswordSafety::TooShort);
    }
    if !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        issues.push(PasswordSafety::MissingSpecialChars);
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        issues.push(PasswordSafety::MissingNumbers);
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        issues.push(PasswordSafety::NoLowerCase);
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        issues.push(PasswordSafety::NoUpperCase);
    }

    issues
}

pub fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    special: bool,
    ambiguous: bool,
) -> String {
    use rand::seq::IndexedRandom;

    let mut charset: Vec<u8> = Vec::new();
    if uppercase {
        charset.extend_from_slice(UPPERCASE_CHARS);
    }
    if lowercase {
        charset.extend_from_slice(LOWERCASE_CHARS);
    }
    if numbers {
        charset.extend_from_slice(DIGIT_CHARS);
    }
    if special {
        charset.extend_from_slice(SPECIAL_CHARS);
    }
    if !ambiguous {
        charset.retain(|c| !AMBIGUOUS_CHARS.contains(c));
    }

    if charset.is_empty() {
        return String::new();
    }

    let mut rng = rand::rng();
    (0..length)
        .map(|_| *charset.choose(&mut rng).expect("charset is non-empty") as char)
        .collect()
}

pub fn generate_passphrase(word_count: usize, separator: &str) -> String {
    use rand::seq::IndexedRandom;
    let words: Vec<&str> = WORDLIST.lines().filter(|l| !l.is_empty()).collect();
    let mut rng = rand::rng();
    (0..word_count)
        .map(|_| *words.choose(&mut rng).expect("wordlist is non-empty"))
        .collect::<Vec<_>>()
        .join(separator)
}

fn score_to_strength(score: u8) -> StrengthResult {
    match score {
        0 => (0, "Very Weak", [0.85, 0.15, 0.15, 1.0]),
        1 => (1, "Weak", [0.90, 0.50, 0.10, 1.0]),
        2 => (2, "Fair", [0.85, 0.75, 0.10, 1.0]),
        3 => (3, "Strong", [0.35, 0.75, 0.20, 1.0]),
        _ => (4, "Very Strong", [0.10, 0.70, 0.20, 1.0]),
    }
}

/// Longest prefix, in characters, that the live strength meter scores.
/// zxcvbn's cost grows steeply and unevenly with length (a single 100-char
/// password can take hundreds of milliseconds in a debug build), and the meter
/// re-scores on every keystroke. A prefix never scores higher than the whole
/// password, and 64 random characters already rate "Very Strong".
const LIVE_STRENGTH_MAX_CHARS: usize = 64;

/// `manual_strength` for interactive use: bounds the work done per keystroke.
pub fn live_strength(password: &str) -> StrengthResult {
    match password.char_indices().nth(LIVE_STRENGTH_MAX_CHARS) {
        Some((end, _)) => manual_strength(&password[..end]),
        None => manual_strength(password),
    }
}

pub fn manual_strength(password: &str) -> StrengthResult {
    if password.is_empty() {
        return (0, "—", [0.45, 0.45, 0.45, 1.0]);
    }

    score_to_strength(u8::from(zxcvbn::zxcvbn(password, &[]).score()))
}

pub fn master_password_issue(password: &str) -> Option<&'static str> {
    let score = u8::from(zxcvbn::zxcvbn(password, &[]).score());
    let length = password.chars().count();

    if (length >= 12 && score >= 3) || (length >= 15 && score >= 2) {
        return None;
    }

    let words = password_words(password);
    if looks_like_passphrase(&words) && words.len() >= MIN_PASSPHRASE_WORDS && score >= 2 {
        return None;
    }

    Some(
        "Master password is too weak: use at least 12 unpredictable characters, 15+ mixed characters, or a 4+ word passphrase.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- verify_password ----

    #[test]
    fn test_verify_short_password() {
        let issues = verify_password("abc");
        assert!(issues.contains(&PasswordSafety::TooShort));
    }

    #[test]
    fn test_verify_no_special() {
        let issues = verify_password("Abcdefg1hijklmn");
        assert!(issues.contains(&PasswordSafety::MissingSpecialChars));
        assert!(!issues.contains(&PasswordSafety::TooShort));
    }

    #[test]
    fn test_verify_no_digits() {
        let issues = verify_password("Abcdefg!hijklmn");
        assert!(issues.contains(&PasswordSafety::MissingNumbers));
    }

    #[test]
    fn test_verify_no_lowercase() {
        let issues = verify_password("ABCDEFG!HIJKLMN1");
        assert!(issues.contains(&PasswordSafety::NoLowerCase));
    }

    #[test]
    fn test_verify_no_uppercase_plain_string() {
        // Must not look like a passphrase (need >=2 all-lowercase alpha words)
        let issues = verify_password("abcdefghijklmnop!");
        assert!(issues.contains(&PasswordSafety::NoUpperCase));
    }

    #[test]
    fn test_verify_valid_password() {
        let issues = verify_password("Abcdefg1!hijklmn");
        assert!(issues.is_empty());
    }

    #[test]
    fn test_verify_passphrase_too_few_words() {
        // 2 lowercase words triggers passphrase mode, but < 4 words = TooFewWords
        let issues = verify_password("foo bar");
        assert!(issues.contains(&PasswordSafety::TooFewWords));
    }

    #[test]
    fn test_verify_valid_passphrase() {
        let issues = verify_password("correct horse battery staple");
        assert!(issues.is_empty());
    }

    #[test]
    fn test_verify_mixed_passphrase_with_caps_is_treated_as_password() {
        let issues = verify_password("Correct horse battery staple");
        assert!(!issues.contains(&PasswordSafety::TooFewWords));
    }

    // ---- live_strength ----

    #[test]
    fn test_live_strength_matches_manual_for_normal_lengths() {
        for pw in [
            "",
            "abc",
            "password",
            "qW7#mZx2$vLp9&nR4!kDf8",
            &"x9$".repeat(21),
        ] {
            assert_eq!(live_strength(pw).0, manual_strength(pw).0, "{pw}");
        }
    }

    #[test]
    fn test_live_strength_only_scores_a_bounded_prefix() {
        // Everything past the cap is ignored, so a weak prefix stays weak.
        let weak_prefix = format!(
            "{}{}",
            "a".repeat(LIVE_STRENGTH_MAX_CHARS),
            "qW7#mZx2$vLp9&nR4!kDf8"
        );
        assert_eq!(
            live_strength(&weak_prefix),
            live_strength(&"a".repeat(LIVE_STRENGTH_MAX_CHARS))
        );
        assert_eq!(live_strength(&weak_prefix).0, 0);
    }

    #[test]
    fn test_live_strength_cuts_on_char_boundaries() {
        let unicode = "é".repeat(LIVE_STRENGTH_MAX_CHARS * 2);
        let _ = live_strength(&unicode); // must not panic mid-codepoint
    }

    // ---- manual_strength ----

    #[test]
    fn test_manual_strength_empty() {
        let (score, label, _) = manual_strength("");
        assert_eq!(score, 0);
        assert_eq!(label, "—");
    }

    #[test]
    fn test_manual_strength_common_password_is_weak() {
        let (score, label, _) = manual_strength("password");
        assert!(score <= 1);
        assert_eq!(label, if score == 0 { "Very Weak" } else { "Weak" });
    }

    #[test]
    fn test_manual_strength_l33t_password_is_weak() {
        let (score, _, _) = manual_strength("P@ssw0rd123");
        assert!(score <= 1, "P@ssw0rd123 scored {score}");
    }

    #[test]
    fn test_manual_strength_random_password_is_strong() {
        let (score, _, _) = manual_strength("qW7#mZx2$vLp9&nR4!kDf8");
        assert!(score >= 3, "random password scored {score}");
    }

    #[test]
    fn test_manual_strength_passphrase() {
        let (score, _, _) = manual_strength("correct horse battery staple");
        assert!(score >= 2, "passphrase scored {score}");
    }

    #[test]
    fn test_manual_strength_strong_passphrase() {
        let (score, _, _) = manual_strength("correct horse battery staple gun pack");
        assert!(score >= 3, "long passphrase scored {score}");
    }

    #[test]
    fn test_manual_strength_short_password() {
        let (score, _, _) = manual_strength("aB1!");
        assert!(score < 3);
    }

    // ---- master_password_issue ----

    #[test]
    fn test_master_password_accepts_passphrase() {
        assert_eq!(master_password_issue("correct horse battery staple"), None);
    }

    #[test]
    fn test_master_password_accepts_long_random() {
        assert_eq!(master_password_issue("qW7#mZx2$vLp9&nR4!kDf8"), None);
    }

    #[test]
    fn test_master_password_rejects_weak_password() {
        assert!(master_password_issue("password123").is_some());
    }

    #[test]
    fn test_master_password_rejects_short_password() {
        assert!(master_password_issue("short1!").is_some());
    }

    // ---- generate_password ----

    #[test]
    fn test_generate_all_options_off_returns_empty() {
        let pw = generate_password(16, false, false, false, false, true);
        assert!(pw.is_empty());
    }

    #[test]
    fn test_generate_zero_length() {
        let pw = generate_password(0, true, true, true, true, true);
        assert!(pw.is_empty());
    }

    #[test]
    fn test_generate_uppercase_only() {
        let pw = generate_password(100, true, false, false, false, true);
        assert_eq!(pw.len(), 100);
        assert!(pw.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn test_generate_lowercase_only() {
        let pw = generate_password(100, false, true, false, false, true);
        assert_eq!(pw.len(), 100);
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn test_generate_digits_only() {
        let pw = generate_password(100, false, false, true, false, true);
        assert_eq!(pw.len(), 100);
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_excludes_ambiguous_chars() {
        let ambiguous = "0OIl1B8S5Z2";
        for _ in 0..20 {
            let pw = generate_password(100, true, true, true, true, false);
            assert!(pw.chars().all(|c| !ambiguous.contains(c)));
        }
    }

    #[test]
    fn test_generate_correct_length() {
        for len in [1, 8, 16, 32, 64] {
            let pw = generate_password(len, true, true, true, true, true);
            assert_eq!(pw.len(), len);
        }
    }

    // ---- generate_passphrase ----

    #[test]
    fn test_passphrase_correct_word_count() {
        let pw = generate_passphrase(4, "-");
        assert_eq!(pw.matches('-').count(), 3);
    }

    #[test]
    fn test_passphrase_no_words() {
        let pw = generate_passphrase(0, "-");
        assert!(pw.is_empty());
    }

    #[test]
    fn test_passphrase_custom_separator() {
        let pw = generate_passphrase(3, ".");
        assert_eq!(pw.matches('.').count(), 2);
    }
}

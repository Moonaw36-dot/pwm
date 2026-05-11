use sha1::{Digest, Sha1};
use std::time::Duration;

static WORDLIST: &str = include_str!("../assets/wordlist.txt");

const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGIT_CHARS:     &[u8] = b"0123456789";
const SPECIAL_CHARS:   &[u8] = b"!@#$%^&*-_=?";
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

pub type StrengthResult = (u8, &'static str, [f32; 4]);

pub fn haveibeenpwned(password: &str) -> Result<bool, String> {
    let hash: String = Sha1::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    let (prefix, suffix) = hash.split_at(5);

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_per_call(Some(Duration::from_secs(10)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let body = agent.get(&url).call()
        .map_err(|e| format!("HIBP request failed: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("HIBP response read failed: {e}"))?;
    Ok(body.lines().any(|line: &str| {
        line.split(':').next().is_some_and(|s: &str| s.eq_ignore_ascii_case(suffix))
    }))
}

pub fn verify_password(password: &str) -> Vec<PasswordSafety> {
    let words: Vec<&str> = password
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|s| !s.is_empty())
        .collect();
    let is_passphrase = words.len() >= 2
        && words.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase()));

    if is_passphrase {
        if words.len() < MIN_PASSPHRASE_WORDS {
            return vec![PasswordSafety::TooFewWords];
        }
        return vec![];
    }

    let mut issues = Vec::new();

    if password.len() < MIN_PASSWORD_LENGTH {
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
    if uppercase { charset.extend_from_slice(UPPERCASE_CHARS); }
    if lowercase { charset.extend_from_slice(LOWERCASE_CHARS); }
    if numbers   { charset.extend_from_slice(DIGIT_CHARS); }
    if special   { charset.extend_from_slice(SPECIAL_CHARS); }
    if !ambiguous { charset.retain(|c| !AMBIGUOUS_CHARS.contains(c)); }

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

pub fn bits_to_strength(bits: f64) -> StrengthResult {
    match bits as u32 {
        0..=29  => (0, "Very Weak",   [0.85, 0.15, 0.15, 1.0]),
        30..=49 => (1, "Weak",        [0.90, 0.50, 0.10, 1.0]),
        50..=65 => (2, "Fair",        [0.85, 0.75, 0.10, 1.0]),
        66..=94 => (3, "Strong",      [0.35, 0.75, 0.20, 1.0]),
        _       => (4, "Very Strong", [0.10, 0.70, 0.20, 1.0]),
    }
}

pub fn manual_strength(password: &str) -> StrengthResult {
    if password.is_empty() {
        return (0, "—", [0.45, 0.45, 0.45, 1.0]);
    }

    let words: Vec<&str> = password
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|s| !s.is_empty())
        .collect();
    let looks_like_passphrase = words.len() >= 2
        && words.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase()));

    if looks_like_passphrase {
        let wordlist_size = WORDLIST.lines().filter(|l| !l.is_empty()).count() as f64;
        return bits_to_strength(words.len() as f64 * wordlist_size.log2());
    }

    let mut pool = 0.0f64;
    if password.chars().any(|c| c.is_ascii_lowercase()) { pool += 26.0; }
    if password.chars().any(|c| c.is_ascii_uppercase()) { pool += 26.0; }
    if password.chars().any(|c| c.is_ascii_digit())     { pool += 10.0; }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) { pool += 32.0; }
    if pool == 0.0 { pool = 26.0; }
    bits_to_strength(password.len() as f64 * pool.log2())
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

    // ---- bits_to_strength ----

    #[test]
    fn test_bits_very_weak() {
        assert_eq!(bits_to_strength(0.0).0, 0);
        assert_eq!(bits_to_strength(29.9).0, 0);
    }

    #[test]
    fn test_bits_weak() {
        assert_eq!(bits_to_strength(30.0).0, 1);
        assert_eq!(bits_to_strength(49.9).0, 1);
    }

    #[test]
    fn test_bits_fair() {
        assert_eq!(bits_to_strength(50.0).0, 2);
        assert_eq!(bits_to_strength(65.9).0, 2);
    }

    #[test]
    fn test_bits_strong() {
        assert_eq!(bits_to_strength(66.0).0, 3);
        assert_eq!(bits_to_strength(94.9).0, 3);
    }

    #[test]
    fn test_bits_very_strong() {
        assert_eq!(bits_to_strength(95.0).0, 4);
        assert_eq!(bits_to_strength(200.0).0, 4);
    }

    // ---- manual_strength ----

    #[test]
    fn test_manual_strength_empty() {
        let (score, label, _) = manual_strength("");
        assert_eq!(score, 0);
        assert_eq!(label, "—");
    }

    #[test]
    fn test_manual_strength_passphrase() {
        let (score, _, _) = manual_strength("correct horse battery staple");
        // ~52 bits → "Fair" (score 2)
        assert_eq!(score, 2);
    }

    #[test]
    fn test_manual_strength_strong_passphrase() {
        let (score, _, _) = manual_strength("correct horse battery staple gun pack");
        // ~77 bits → "Strong" (score 3)
        assert_eq!(score, 3);
    }

    #[test]
    fn test_manual_strength_short_password() {
        let (score, _, _) = manual_strength("aB1!");
        assert!(score < 3);
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

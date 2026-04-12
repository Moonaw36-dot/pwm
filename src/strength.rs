use sha1::{Digest, Sha1};

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

pub fn haveibeenpwned(password: &str) -> bool {
    let hash: String = Sha1::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    let (prefix, suffix) = hash.split_at(5);

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let body = match ureq::get(&url).call() {
        Ok(mut response) => response.body_mut().read_to_string().unwrap_or_default(),
        Err(_) => return false,
    };
    body.lines().any(|line: &str| {
        line.split(':').next().is_some_and(|s: &str| s.eq_ignore_ascii_case(suffix))
    })
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
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        issues.push(PasswordSafety::MissingSpecialChars);
    }
    if !password.chars().any(|c| c.is_numeric()) {
        issues.push(PasswordSafety::MissingNumbers);
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        issues.push(PasswordSafety::NoLowerCase);
    }
    if !password.chars().any(|c| c.is_uppercase()) {
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
    if password.chars().any(|c| !c.is_alphanumeric())   { pool += 32.0; }
    if pool == 0.0 { pool = 26.0; }
    bits_to_strength(password.len() as f64 * pool.log2())
}

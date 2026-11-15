//! Password and passphrase generation.

use rand::seq::IndexedRandom;

static WORDLIST: &str = include_str!("../../assets/wordlist.txt");

const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGIT_CHARS: &[u8] = b"0123456789";
const SPECIAL_CHARS: &[u8] = b"!@#$%^&*-_=?";
const AMBIGUOUS_CHARS: &[u8] = b"0OIl1B8S5Z2";

pub fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    special: bool,
    ambiguous: bool,
) -> String {
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
    let words: Vec<&str> = WORDLIST.lines().filter(|l| !l.is_empty()).collect();
    let mut rng = rand::rng();
    (0..word_count)
        .map(|_| *words.choose(&mut rng).expect("wordlist is non-empty"))
        .collect::<Vec<_>>()
        .join(separator)
}

//! Contents of the decoy vault a duress password opens. Same shape as the
//! desktop app's, so a coerced unlock looks the same on every device: a
//! believable set of logins, a card and a note, all with random secrets.

use rand::RngExt;
use zeroize::Zeroizing;

use crate::generator::{generate_passphrase, generate_password};
use crate::model::{PasswordEntry, PasswordList, PasswordType, now_unix};

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const LOGINS: &[(&str, &str, &str, bool)] = &[
    (
        "GitHub",
        "morgan.reid@proton.me",
        "https://github.com/login",
        false,
    ),
    (
        "Gmail",
        "morgan.reid@gmail.com",
        "https://mail.google.com",
        true,
    ),
    (
        "Chase Bank",
        "morgan.reid92",
        "https://secure.chase.com",
        false,
    ),
    (
        "Amazon",
        "morgan.reid@gmail.com",
        "https://www.amazon.com",
        true,
    ),
    (
        "Netflix",
        "morgan.reid@gmail.com",
        "https://www.netflix.com",
        false,
    ),
    ("Work VPN", "m.reid", "https://vpn.northwind-corp.com", true),
    (
        "Microsoft 365",
        "m.reid@northwind-corp.com",
        "https://login.microsoftonline.com",
        false,
    ),
    (
        "AWS Console",
        "mreid-deploy",
        "https://console.aws.amazon.com",
        true,
    ),
    (
        "Dropbox",
        "morgan.reid@gmail.com",
        "https://www.dropbox.com",
        false,
    ),
    ("Steam", "reidplays", "https://store.steampowered.com", true),
];

fn random_totp_secret() -> String {
    let mut rng = rand::rng();
    (0..16)
        .map(|_| BASE32_ALPHABET[rng.random_range(..BASE32_ALPHABET.len())] as char)
        .collect()
}

fn luhn_card_number() -> String {
    let mut digits: Vec<u8> = (0..15).map(|_| rand::rng().random_range(0..10)).collect();
    let mut sum = 0u32;
    for (index, digit) in digits.iter().rev().enumerate() {
        if index % 2 == 0 {
            let doubled = u32::from(*digit) * 2;
            sum += doubled / 10 + doubled % 10;
        } else {
            sum += u32::from(*digit);
        }
    }
    digits.push(((10 - sum % 10) % 10) as u8);
    digits.iter().map(|d| (b'0' + d) as char).collect()
}

fn random_card_expiry() -> String {
    let month = rand::rng().random_range(1..=12u32);
    let year = 27 + rand::rng().random_range(0..=5u32);
    format!("{month:02}/{year}")
}

fn login(label: &str, username: &str, url: &str, passphrase: bool, now: u64) -> PasswordEntry {
    let password = if passphrase {
        generate_passphrase(5, "-")
    } else {
        generate_password(20, true, true, true, true, false)
    };
    PasswordEntry {
        label: label.to_string(),
        username: username.to_string(),
        password: Zeroizing::new(password),
        url: url.to_string(),
        created_at: Some(now),
        ..Default::default()
    }
}

pub fn decoy_list() -> PasswordList {
    let now = now_unix();
    let mut entries: Vec<PasswordEntry> = LOGINS
        .iter()
        .map(|&(label, username, url, passphrase)| login(label, username, url, passphrase, now))
        .collect();
    for entry in entries.iter_mut().take(2) {
        entry.totp_secret = Zeroizing::new(Some(random_totp_secret()));
    }

    let mut card = login("Visa Debit", "Morgan Reid", "", false, now);
    card.password_type = PasswordType::Card;
    card.password = Zeroizing::new(String::new());
    card.number = Some(Zeroizing::new(luhn_card_number()));
    card.expiration_date = Some(Zeroizing::new(random_card_expiry()));
    card.cvc = Some(Zeroizing::new(generate_password(
        3, false, false, true, false, false,
    )));
    entries.push(card);

    let mut note = login("Recovery codes", "", "", false, now);
    note.is_secure_note = true;
    note.password = Zeroizing::new(String::new());
    note.notes = Zeroizing::new(
        "GitHub: 8412 3390 5567\nGmail: 7712 0045 9932\nWork VPN: 55810 2201 4477".to_string(),
    );
    entries.push(note);

    PasswordList {
        entries,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_looks_like_a_real_vault() {
        let list = decoy_list();
        assert_eq!(list.entries.len(), LOGINS.len() + 2);
        assert!(list.entries.iter().all(|e| e.created_at.is_some()));
        let card = list
            .entries
            .iter()
            .find(|e| e.password_type == PasswordType::Card)
            .unwrap();
        assert_eq!(card.number.as_ref().unwrap().len(), 16);
        assert!(list.entries[0].totp_secret.is_some());
        assert_ne!(*list.entries[0].password, *decoy_list().entries[0].password);
    }
}

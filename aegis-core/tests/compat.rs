//! Vault files written by Aegis 1.7.2 (before the core split) must keep
//! opening, and must round-trip without losing any field.

use aegis_core::format;
use aegis_core::{KdfParams, PasswordList, PasswordType, UnlockedVault};

const PLAIN: &[u8] = include_bytes!("fixtures/v2_plain.aegis");
const WITH_KEYFILE: &[u8] = include_bytes!("fixtures/v2_keyfile.aegis");
const KEYFILE: &[u8] = include_bytes!("fixtures/keyfile.bin");
const EXPECTED: &str = include_str!("fixtures/expected.json");
const PASSWORD: &str = "fixture-master";

fn as_value(list: &PasswordList) -> serde_json::Value {
    serde_json::to_value(list).unwrap()
}

#[test]
fn opens_desktop_vault() {
    let vault = UnlockedVault::open(PLAIN, PASSWORD, None).unwrap();
    let expected: serde_json::Value = serde_json::from_str(EXPECTED).unwrap();
    assert_eq!(as_value(&vault.list), expected);
    assert_eq!(vault.list.entries[1].password_type, PasswordType::Card);
    assert!(vault.list.entries[1].is_trashed());
    assert_eq!(
        vault.params(),
        KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1
        }
    );
}

#[test]
fn opens_desktop_vault_with_keyfile() {
    let vault = UnlockedVault::open(WITH_KEYFILE, PASSWORD, Some(KEYFILE)).unwrap();
    let expected: serde_json::Value = serde_json::from_str(EXPECTED).unwrap();
    assert_eq!(as_value(&vault.list), expected);
    assert!(UnlockedVault::open(WITH_KEYFILE, PASSWORD, None).is_err());
    assert!(UnlockedVault::open(WITH_KEYFILE, PASSWORD, Some(b"wrong")).is_err());
}

#[test]
fn wrong_password_fails() {
    assert!(UnlockedVault::open(PLAIN, "nope", None).is_err());
}

#[test]
fn seal_roundtrip_keeps_salt_params_and_contents() {
    let vault = UnlockedVault::open(PLAIN, PASSWORD, None).unwrap();
    let resealed = vault.seal().unwrap();
    assert_eq!(
        &resealed[..33],
        &PLAIN[..33],
        "magic, version, salt, params unchanged"
    );
    assert_ne!(&resealed[33..45], &PLAIN[33..45], "fresh nonce");
    let reopened = UnlockedVault::open(&resealed, PASSWORD, None).unwrap();
    assert_eq!(as_value(&reopened.list), as_value(&vault.list));
}

#[test]
fn unknown_fields_survive_roundtrip() {
    let json = br#"{"entries":[{"label":"x","future_field":{"a":1}}],"vault_meta":"keep"}"#;
    let list = PasswordList::from_json(json).unwrap();
    let out: serde_json::Value = serde_json::from_slice(&list.to_json().unwrap()).unwrap();
    assert_eq!(out["entries"][0]["future_field"]["a"], 1);
    assert_eq!(out["vault_meta"], "keep");
}

#[test]
fn tampered_header_is_rejected() {
    let mut data = PLAIN.to_vec();
    data[25] ^= 1; // t_cost byte
    assert!(format::open(&data, PASSWORD, None).is_err());
}

#[test]
fn create_and_change_password() {
    let params = KdfParams {
        m_cost: 1024,
        t_cost: 1,
        p_cost: 1,
    };
    let mut vault = UnlockedVault::create("first", params, None).unwrap();
    vault.list.entries.push(Default::default());
    let data = vault.seal().unwrap();
    assert_eq!(
        UnlockedVault::open(&data, "first", None)
            .unwrap()
            .list
            .entries
            .len(),
        1
    );

    vault.change_password("second", None).unwrap();
    let data = vault.seal().unwrap();
    assert!(UnlockedVault::open(&data, "first", None).is_err());
    assert!(UnlockedVault::open(&data, "second", None).is_ok());
}

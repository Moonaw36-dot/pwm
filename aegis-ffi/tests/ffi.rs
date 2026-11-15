use aegis_core::{PasswordList, UnlockedVault};
use aegis_ffi::{AegisError, CustomField, Entry, EntryType, Vault};

const PLAIN: &[u8] = include_bytes!("../../aegis-core/tests/fixtures/v2_plain.aegis");
const WITH_KEYFILE: &[u8] = include_bytes!("../../aegis-core/tests/fixtures/v2_keyfile.aegis");
const KEYFILE: &[u8] = include_bytes!("../../aegis-core/tests/fixtures/keyfile.bin");
const PASSWORD: &str = "fixture-master";

fn as_value(list: &PasswordList) -> serde_json::Value {
    serde_json::to_value(list).unwrap()
}

fn open_fixture() -> std::sync::Arc<Vault> {
    Vault::open(PLAIN.to_vec(), PASSWORD.into(), None).unwrap()
}

fn reopen(data: &[u8]) -> UnlockedVault {
    UnlockedVault::open(data, PASSWORD, None).unwrap()
}

fn blank(label: &str) -> Entry {
    Entry {
        id: 999,
        label: label.into(),
        username: String::new(),
        password: String::new(),
        notes: String::new(),
        url: String::new(),
        totp_secret: None,
        tags: vec![],
        entry_type: EntryType::Normal,
        is_secure_note: false,
        favorite: false,
        card_number: None,
        card_expiration: None,
        card_cvc: None,
        custom_fields: vec![],
        created_at: None,
        trashed: false,
    }
}

fn message(err: AegisError) -> String {
    match err {
        AegisError::Failed { message } => message,
    }
}

#[test]
fn unchanged_update_is_lossless() {
    let original = reopen(PLAIN);
    let vault = open_fixture();
    let entries = vault.entries();
    assert_eq!(entries.len(), original.list.entries.len());
    for e in entries {
        vault.update_entry(e).unwrap();
    }
    let resealed = reopen(&vault.seal().unwrap());
    assert_eq!(as_value(&resealed.list), as_value(&original.list));
}

#[test]
fn maps_fixture_fields() {
    let entries = open_fixture().entries();
    let gh = &entries[0];
    assert_eq!(gh.label, "GitHub");
    assert_eq!(gh.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert_eq!(gh.tags, vec!["dev".to_string()]);
    assert!(gh.favorite);
    assert_eq!(
        gh.custom_fields,
        vec![CustomField {
            name: "recovery".into(),
            value: "abcd-efgh".into()
        }]
    );
    let visa = &entries[1];
    assert_eq!(visa.entry_type, EntryType::Card);
    assert_eq!(visa.card_number.as_deref(), Some("4111111111111111"));
    assert_eq!(visa.card_expiration.as_deref(), Some("12/30"));
    assert_eq!(visa.card_cvc.as_deref(), Some("123"));
    assert!(visa.trashed);
    assert_eq!(entries[2].entry_type, EntryType::WiFi);
}

#[test]
fn crud_with_stable_ids() {
    let vault = open_fixture();
    let before: Vec<u64> = vault.entries().iter().map(|e| e.id).collect();

    let id_a = vault.add_entry(blank("A")).unwrap();
    let id_b = vault.add_entry(blank("B")).unwrap();
    assert!(!before.contains(&id_a) && id_a != id_b && id_a != 999);
    let a = vault.entries().into_iter().find(|e| e.id == id_a).unwrap();
    assert!(a.created_at.is_some());

    // Delete the first entry and A; remaining ids must be unchanged.
    vault.delete_entry(before[0]).unwrap();
    vault.delete_entry(id_a).unwrap();
    let ids: Vec<u64> = vault.entries().iter().map(|e| e.id).collect();
    let mut expected = before[1..].to_vec();
    expected.push(id_b);
    assert_eq!(ids, expected);
    assert!(vault.delete_entry(id_a).is_err());

    // New ids are never reused.
    let id_c = vault.add_entry(blank("C")).unwrap();
    assert!(id_c > id_b);

    let mut b = vault.entries().into_iter().find(|e| e.id == id_b).unwrap();
    b.username = "bob".into();
    b.tags = vec!["x".into()];
    b.favorite = true;
    vault.update_entry(b).unwrap();

    vault.trash_entry(id_b).unwrap();
    assert!(
        vault
            .entries()
            .iter()
            .find(|e| e.id == id_b)
            .unwrap()
            .trashed
    );
    let sealed = reopen(&vault.seal().unwrap());
    let raw = sealed.list.entries.iter().find(|e| e.label == "B").unwrap();
    assert!(raw.trashed_at.is_some());
    assert_eq!(raw.username, "bob");
    assert_eq!(raw.tags.as_deref(), Some(&["x".to_string()][..]));
    assert_eq!(raw.favorite, Some(true));

    vault.restore_entry(id_b).unwrap();
    assert!(
        !vault
            .entries()
            .iter()
            .find(|e| e.id == id_b)
            .unwrap()
            .trashed
    );
    let sealed = reopen(&vault.seal().unwrap());
    assert_eq!(sealed.list.entries.len(), before.len() + 1);
    assert!(sealed.list.entries.iter().all(|e| e.label != "A"));
}

#[test]
fn password_change_records_history_and_keeps_extra() {
    let vault = open_fixture();
    let mut gh = vault.entries().remove(0);
    gh.password = "brand-new".into();
    gh.card_number = None;
    vault.update_entry(gh).unwrap();
    let list = reopen(&vault.seal().unwrap()).list;
    let raw = &list.entries[0];
    assert_eq!(raw.password.as_str(), "brand-new");
    assert_eq!(raw.password_history.len(), 2);
    assert_eq!(raw.password_history[0].password.as_str(), "old-pass");
    assert_eq!(
        raw.password_history[1].password.as_str(),
        "hunter2-correct-horse"
    );
    assert_eq!(raw.created_at, Some(1700000000));
}

#[test]
fn totp_secret_empty_becomes_none() {
    let vault = open_fixture();
    let mut gh = vault.entries().remove(0);
    gh.totp_secret = Some("  ".into());
    vault.update_entry(gh).unwrap();
    let list = reopen(&vault.seal().unwrap()).list;
    assert!(list.entries[0].totp_secret.is_none());
}

#[test]
fn master_password_change() {
    let vault = open_fixture();
    vault.change_password("other".into(), None).unwrap();
    let data = vault.seal().unwrap();
    assert!(Vault::open(data.clone(), PASSWORD.into(), None).is_err());
    assert!(Vault::open(data, "other".into(), None).is_ok());
}

#[test]
fn locked_vault_errors() {
    let vault = open_fixture();
    let id = vault.entries()[0].id;
    vault.lock();
    assert!(vault.entries().is_empty());
    assert_eq!(message(vault.seal().unwrap_err()), "Vault is locked");
    assert_eq!(
        message(vault.trash_entry(id).unwrap_err()),
        "Vault is locked"
    );
    assert_eq!(
        message(vault.add_entry(blank("x")).unwrap_err()),
        "Vault is locked"
    );
    assert_eq!(
        message(vault.change_password("x".into(), None).unwrap_err()),
        "Vault is locked"
    );
}

#[test]
fn wrong_password_fails() {
    assert!(Vault::open(PLAIN.to_vec(), "nope".into(), None).is_err());
}

#[test]
fn keyfile_fixture_opens() {
    let vault = Vault::open(
        WITH_KEYFILE.to_vec(),
        PASSWORD.into(),
        Some(KEYFILE.to_vec()),
    )
    .unwrap();
    assert_eq!(vault.entries()[0].label, "GitHub");
    assert!(Vault::open(WITH_KEYFILE.to_vec(), PASSWORD.into(), None).is_err());
}

#[test]
fn create_new_vault_roundtrip() {
    let vault = Vault::create("fresh".into(), None).unwrap();
    assert!(vault.entries().is_empty());
    vault.add_entry(blank("only")).unwrap();
    let data = vault.seal().unwrap();
    let reopened = Vault::open(data, "fresh".into(), None).unwrap();
    assert_eq!(reopened.entries()[0].label, "only");
}

#[test]
fn free_functions() {
    let code = aegis_ffi::totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(), 59).unwrap();
    assert_eq!(code.code, "287082");
    assert_eq!(code.seconds_remaining, 1);
    assert_eq!(code.period, 30);
    assert!(aegis_ffi::totp_code(String::new(), 0).is_none());
    assert_eq!(
        aegis_ffi::generate_password(24, true, true, true, true, false).len(),
        24
    );
    let phrase = aegis_ffi::generate_passphrase(4, "-".into());
    assert_eq!(phrase.split('-').count(), 4);
}

#[test]
fn refuses_to_save_over_a_rekeyed_file() {
    let vault = open_fixture();
    assert!(vault.can_save_over(PLAIN.to_vec()));
    assert!(vault.can_save_over(vault.seal().unwrap()));

    // Another device changed the master password: same file, new key.
    let other = open_fixture();
    other.change_password("someone-else".into(), None).unwrap();
    assert!(!vault.can_save_over(other.seal().unwrap()));
    assert!(!vault.can_save_over(WITH_KEYFILE.to_vec()));
    assert!(!vault.can_save_over(b"not a vault".to_vec()));

    vault.lock();
    assert!(!vault.can_save_over(PLAIN.to_vec()));
}

#[test]
fn decoy_vault_round_trips() {
    let decoy = Vault::create_decoy("duress-pass".into()).unwrap();
    let sealed = decoy.seal().unwrap();
    let reopened = Vault::open(sealed, "duress-pass".into(), None).unwrap();
    let entries = reopened.entries();
    assert!(entries.len() > 5);
    assert!(entries.iter().any(|e| e.entry_type == EntryType::Card));
}

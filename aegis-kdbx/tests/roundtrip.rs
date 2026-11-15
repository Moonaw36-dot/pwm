use aegis_core::model::{PasswordEntry, PasswordHistory, PasswordList, PasswordType};
use aegis_kdbx::{ExportCipher, ExportOptions, KdbxCredentials, export_kdbx_with, import_kdbx};
use serde_json::json;
use zeroize::Zeroizing;

const PW: &str = "correct horse battery staple";

fn fast(cipher: ExportCipher) -> ExportOptions {
    ExportOptions {
        kdf_memory_bytes: 64 * 1024,
        kdf_iterations: 1,
        kdf_parallelism: 1,
        cipher,
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

fn base(label: &str) -> PasswordEntry {
    PasswordEntry {
        label: label.to_string(),
        created_at: Some(1_600_000_000),
        ..Default::default()
    }
}

fn rich_list() -> PasswordList {
    let mut list = PasswordList::default();
    list.extra
        .insert("vault_setting".into(), json!({"theme": "dark"}));

    // Normal entry, bare base32 TOTP, tags, custom fields, group, history.
    let mut normal = base("Mail / Work");
    normal.username = "alice@example.com".into();
    *normal.password = "n3w-p4ss".into();
    *normal.notes = "multi\nline notes; with, separators".into();
    *normal.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
    normal.url = "https://mail.example.com".into();
    normal.tags = Some(vec![
        "email".into(),
        "work".into(),
        "group:Work/Servers".into(),
    ]);
    *normal.custom_fields = vec![
        ("Zeta".into(), "last-alpha-first".into()),
        ("Alpha".into(), "second".into()),
        ("Recovery codes".into(), "1111 2222\n3333".into()),
    ];
    normal.password_history = vec![
        PasswordHistory {
            password: z("oldest"),
            changed_at: 1_600_000_100,
        },
        PasswordHistory {
            password: z("older"),
            changed_at: 1_600_000_200,
        },
        PasswordHistory {
            password: z("oldest"),
            changed_at: 1_600_000_300,
        },
    ];
    normal.extra.insert("future_field".into(), json!([1, 2, 3]));
    list.entries.push(normal);

    // otpauth URL TOTP with issuer: kept verbatim.
    let mut otp = base("GitHub");
    otp.username = "alice".into();
    *otp.password = "gh-pass".into();
    *otp.totp_secret = Some(
        "otpauth://totp/GitHub:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=8&period=60&algorithm=SHA256"
            .into(),
    );
    list.entries.push(otp);

    let mut card = base("Visa");
    card.password_type = PasswordType::Card;
    card.number = Some(z("4111111111111111"));
    card.expiration_date = Some(z("12/30"));
    card.cvc = Some(z("123"));
    card.tags = Some(vec!["finance".into()]);
    *card.custom_fields = vec![("Bank".into(), "ACME".into())];
    list.entries.push(card);

    let mut wifi = base("Home WiFi");
    wifi.password_type = PasswordType::WiFi;
    *wifi.password = "wifi-secret".into();
    list.entries.push(wifi);

    let mut note = base("Safe combination");
    note.is_secure_note = true;
    *note.notes = "12-34-56".into();
    list.entries.push(note);

    let mut fav = base("Bank");
    fav.favorite = Some(true);
    *fav.password = "bank".into();
    fav.tags = Some(vec!["group:Finance".into()]);
    list.entries.push(fav);

    let mut trashed = base("Old forum");
    trashed.trashed_at = Some(1_700_000_000);
    *trashed.password = "forum".into();
    trashed.tags = Some(vec!["misc".into(), "group:Archive/2019".into()]);
    list.entries.push(trashed);

    let mut trashed_root = base("Old shop");
    trashed_root.trashed_at = Some(1_700_000_500);
    list.entries.push(trashed_root);

    list
}

fn sorted(v: &[PasswordEntry]) -> Vec<&PasswordEntry> {
    let mut v: Vec<&PasswordEntry> = v.iter().collect();
    v.sort_by(|a, b| a.label.cmp(&b.label));
    v
}

fn assert_entry_eq(a: &PasswordEntry, b: &PasswordEntry) {
    let l = &a.label;
    assert_eq!(a.label, b.label);
    assert_eq!(a.username, b.username, "{l}: username");
    assert_eq!(*a.password, *b.password, "{l}: password");
    assert_eq!(*a.notes, *b.notes, "{l}: notes");
    assert_eq!(*a.totp_secret, *b.totp_secret, "{l}: totp");
    assert_eq!(a.url, b.url, "{l}: url");
    assert_eq!(a.tags, b.tags, "{l}: tags");
    assert_eq!(*a.custom_fields, *b.custom_fields, "{l}: custom fields");
    assert_eq!(a.is_secure_note, b.is_secure_note, "{l}: secure note");
    assert_eq!(a.created_at, b.created_at, "{l}: created_at");
    assert_eq!(a.password_type, b.password_type, "{l}: type");
    assert_eq!(a.number, b.number, "{l}: number");
    assert_eq!(a.expiration_date, b.expiration_date, "{l}: expiration");
    assert_eq!(a.cvc, b.cvc, "{l}: cvc");
    assert_eq!(a.favorite, b.favorite, "{l}: favorite");
    assert_eq!(a.trashed_at, b.trashed_at, "{l}: trashed_at");
    assert_eq!(
        a.password_history.len(),
        b.password_history.len(),
        "{l}: history len"
    );
    for (x, y) in a.password_history.iter().zip(&b.password_history) {
        assert_eq!(*x.password, *y.password, "{l}: history password");
        assert_eq!(x.changed_at, y.changed_at, "{l}: history time");
    }
    assert_eq!(a.extra, b.extra, "{l}: extra");
}

fn round_trip(creds: KdbxCredentials, cipher: ExportCipher) {
    let original = rich_list();
    let bytes = export_kdbx_with(&original, creds, fast(cipher)).unwrap();
    let (imported, report) = import_kdbx(&bytes, creds).unwrap();

    assert_eq!(report.imported, original.entries.len());
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert_eq!(imported.extra, original.extra);
    assert_eq!(imported.entries.len(), original.entries.len());
    for (a, b) in sorted(&original.entries)
        .into_iter()
        .zip(sorted(&imported.entries))
    {
        assert_entry_eq(a, b);
    }

    // Exporting the import again is stable.
    let again = export_kdbx_with(&imported, creds, fast(cipher)).unwrap();
    let (imported2, _) = import_kdbx(&again, creds).unwrap();
    for (a, b) in sorted(&imported.entries)
        .into_iter()
        .zip(sorted(&imported2.entries))
    {
        assert_entry_eq(a, b);
    }
}

#[test]
fn password_round_trip_is_lossless() {
    round_trip(
        KdbxCredentials {
            password: Some(PW),
            keyfile: None,
        },
        ExportCipher::Aes256,
    );
}

#[test]
fn chacha20_round_trip() {
    round_trip(
        KdbxCredentials {
            password: Some(PW),
            keyfile: None,
        },
        ExportCipher::ChaCha20,
    );
}

#[test]
fn keyfile_round_trip() {
    let keyfile = b"some arbitrary keyfile contents, hashed by KeePass".to_vec();
    let creds = KdbxCredentials {
        password: Some(PW),
        keyfile: Some(&keyfile),
    };
    round_trip(creds, ExportCipher::Aes256);

    let bytes = export_kdbx_with(&rich_list(), creds, fast(ExportCipher::Aes256)).unwrap();
    // Password alone is not enough.
    let err = import_kdbx(
        &bytes,
        KdbxCredentials {
            password: Some(PW),
            keyfile: None,
        },
    )
    .unwrap_err();
    assert!(err.contains("Wrong password or keyfile"), "{err}");
    // Wrong keyfile fails.
    let other = b"another keyfile".to_vec();
    assert!(
        import_kdbx(
            &bytes,
            KdbxCredentials {
                password: Some(PW),
                keyfile: Some(&other)
            }
        )
        .is_err()
    );
}

#[test]
fn keyfile_only_round_trip() {
    let keyfile = [7u8; 32];
    round_trip(
        KdbxCredentials {
            password: None,
            keyfile: Some(&keyfile),
        },
        ExportCipher::Aes256,
    );
}

#[test]
fn wrong_password_fails() {
    let bytes = export_kdbx_with(
        &rich_list(),
        KdbxCredentials {
            password: Some(PW),
            keyfile: None,
        },
        fast(ExportCipher::Aes256),
    )
    .unwrap();
    let err = import_kdbx(
        &bytes,
        KdbxCredentials {
            password: Some("wrong"),
            keyfile: None,
        },
    )
    .unwrap_err();
    assert!(err.contains("Wrong password or keyfile"), "{err}");
}

#[test]
fn missing_credentials_rejected() {
    let none = KdbxCredentials::default();
    assert!(export_kdbx_with(&rich_list(), none, fast(ExportCipher::Aes256)).is_err());
    assert!(import_kdbx(b"garbage", none).is_err());
}

#[test]
fn garbage_input_is_an_error() {
    let creds = KdbxCredentials {
        password: Some(PW),
        keyfile: None,
    };
    assert!(import_kdbx(b"", creds).is_err());
    assert!(import_kdbx(&[0u8; 300], creds).is_err());
}

#[test]
fn colliding_custom_field_names_are_renamed() {
    let mut e = base("Collide");
    *e.custom_fields = vec![
        ("Password".into(), "not the password".into()),
        ("dup".into(), "1".into()),
        ("dup".into(), "2".into()),
    ];
    let list = PasswordList {
        entries: vec![e],
        ..Default::default()
    };
    let creds = KdbxCredentials {
        password: Some(PW),
        keyfile: None,
    };
    let bytes = export_kdbx_with(&list, creds, fast(ExportCipher::Aes256)).unwrap();
    let (back, _) = import_kdbx(&bytes, creds).unwrap();
    assert_eq!(
        *back.entries[0].custom_fields,
        vec![
            ("Password (2)".to_string(), "not the password".to_string()),
            ("dup".to_string(), "1".to_string()),
            ("dup (2)".to_string(), "2".to_string()),
        ]
    );
}

#[test]
fn default_options_are_strong() {
    let d = ExportOptions::default();
    assert!(d.kdf_memory_bytes >= 64 * 1024 * 1024);
    assert!(d.kdf_iterations >= 10);
    assert!(d.kdf_parallelism >= 1);
}

#[test]
fn export_is_kdbx4_with_argon2id() {
    // Header check: KDBX signature, major version 4, Argon2id KDF UUID.
    let list = PasswordList {
        entries: vec![base("x")],
        ..Default::default()
    };
    let creds = KdbxCredentials {
        password: Some(PW),
        keyfile: None,
    };
    let bytes = export_kdbx_with(&list, creds, fast(ExportCipher::Aes256)).unwrap();
    assert_eq!(
        &bytes[..8],
        &[0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]
    );
    assert_eq!(
        u16::from_le_bytes([bytes[10], bytes[11]]),
        4,
        "major version"
    );
    // Argon2id KDF UUID 9e298b19-56db-4773-b23d-fc3ec6f0a1e6
    let argon2id = [
        0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1,
        0xe6,
    ];
    assert!(bytes.windows(16).any(|w| w == argon2id));
}

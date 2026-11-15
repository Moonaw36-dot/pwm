//! Import a KDBX4 file produced by an independent implementation
//! (pykeepass, see tests/fixtures/gen.py).

use aegis_kdbx::{KdbxCredentials, import_kdbx};

const FIXTURE: &[u8] = include_bytes!("fixtures/pykeepass.kdbx");
const CREDS: KdbxCredentials = KdbxCredentials {
    password: Some("fixture-password"),
    keyfile: None,
};

#[test]
fn imports_pykeepass_fixture() {
    let (list, report) = import_kdbx(FIXTURE, CREDS).unwrap();
    assert_eq!(report.imported, 3);
    assert_eq!(list.entries.len(), 3);
    assert_eq!(
        report.skipped,
        vec!["Entry \"Build server\": 1 attachment(s) not imported".to_string()]
    );

    let find = |label: &str| list.entries.iter().find(|e| e.label == label).unwrap();

    let build = find("Build server");
    assert_eq!(build.username, "deploy");
    assert_eq!(build.password.as_str(), "s3cr3t-Pa55");
    assert_eq!(build.url, "https://ci.example.com");
    assert_eq!(build.notes.as_str(), "Line one\nLine two");
    assert_eq!(
        build.totp_secret.as_deref(),
        Some(
            "otpauth://totp/Example:deploy?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=Example"
        )
    );
    assert!(aegis_core::totp::build_totp(build.totp_secret.as_deref().unwrap()).is_some());
    assert_eq!(
        build.tags,
        Some(vec![
            "infra".to_string(),
            "ci".to_string(),
            "group:Work/Servers".to_string()
        ])
    );
    assert_eq!(
        *build.custom_fields,
        vec![
            ("PIN".to_string(), "4321".to_string()),
            ("Region".to_string(), "eu-west-3".to_string()),
        ]
    );
    // 2024-01-02T03:04:05Z
    assert_eq!(build.created_at, Some(1_704_164_645));
    assert!(build.trashed_at.is_none());
    assert!(build.password_history.is_empty());

    let root = find("Root entry");
    assert_eq!(root.username, "root");
    assert_eq!(root.password.as_str(), "toor");
    assert_eq!(root.tags, None);
    assert!(root.trashed_at.is_none());

    let old = find("Old account");
    assert_eq!(old.password.as_str(), "gone");
    assert!(old.trashed_at.is_some());
    assert_eq!(old.tags, None, "recycle bin must not become a group tag");
}

#[test]
fn fixture_wrong_password_fails() {
    let creds = KdbxCredentials {
        password: Some("nope"),
        keyfile: None,
    };
    assert!(import_kdbx(FIXTURE, creds).is_err());
}

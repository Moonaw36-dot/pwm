use super::*;
use crate::file_ops::write_new_vault_file;
use p256::EncodedPoint;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand::RngExt;
use std::io::Cursor;

const MASTER: &str = "correct horse battery staple 42";
const ORIGIN: &str = "https://login.example.com/signin";

fn params() -> VaultKdfParams {
    VaultKdfParams {
        m_cost: 2048,
        t_cost: 2,
        p_cost: 1,
    }
}

fn temp_vault(entries: Vec<PasswordEntry>) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "aegis-host-{:016x}.aegis",
        rand::rng().random::<u64>()
    ));
    write_new_vault_file(&path, &PasswordList { entries }, MASTER, params(), None).unwrap();
    path
}

fn login(label: &str, username: &str, url: &str, password: &str) -> PasswordEntry {
    PasswordEntry {
        label: label.into(),
        username: username.into(),
        password: Zeroizing::new(password.into()),
        url: url.into(),
        ..Default::default()
    }
}

fn unlocked_host(entries: Vec<PasswordEntry>) -> (Host, PathBuf) {
    let path = temp_vault(entries);
    let mut host = Host::default();
    let reply = host.handle(json!({
        "id": 1, "cmd": "unlock", "path": path, "password": MASTER
    }));
    assert_eq!(reply["ok"], true, "{reply}");
    (host, path)
}

/// authenticatorData-shaped input for `passkey_sign`.
fn signed_input(rp_id: &str, tail: &[u8]) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.extend_from_slice(&[0x05, 0, 0, 0, 0]);
    data.extend_from_slice(tail);
    data
}

fn ok(host: &mut Host, request: Value) -> Value {
    let reply = host.handle(request);
    assert_eq!(reply["ok"], true, "{reply}");
    reply
}

fn err_code(host: &mut Host, request: Value) -> String {
    let reply = host.handle(request);
    assert_eq!(reply["ok"], false, "{reply}");
    reply["code"].as_str().unwrap().to_string()
}

#[test]
fn messages_round_trip_through_the_wire_format() {
    let mut wire = Vec::new();
    write_message(&mut wire, &json!({"cmd": "status", "id": 7})).unwrap();
    assert_eq!(
        u32::from_ne_bytes(wire[..4].try_into().unwrap()) as usize,
        wire.len() - 4
    );
    let mut reader = Cursor::new(wire);
    assert_eq!(read_message(&mut reader).unwrap().unwrap()["id"], 7);
    assert!(read_message(&mut reader).unwrap().is_none());
}

#[test]
fn oversized_messages_are_skipped() {
    // Truncated body: a real protocol error.
    let mut huge = Cursor::new((MAX_INCOMING_BYTES + 1).to_ne_bytes().to_vec());
    assert!(read_message(&mut huge).is_err());

    // Full body: dropped, and the next message still gets through.
    let mut wire = (MAX_INCOMING_BYTES + 1).to_ne_bytes().to_vec();
    wire.resize(wire.len() + MAX_INCOMING_BYTES as usize + 1, b' ');
    write_message(&mut wire, &json!({"cmd": "lock", "id": 3})).unwrap();
    let mut output = Vec::new();
    serve(&mut Cursor::new(wire), &mut output, &mut Host::default()).unwrap();
    let mut reader = Cursor::new(output);
    let first = read_message(&mut reader).unwrap().unwrap();
    assert_eq!(first["code"], "too_large");
    assert_eq!(read_message(&mut reader).unwrap().unwrap()["id"], 3);
}

#[test]
fn serve_answers_each_request_in_order() {
    let mut input = Vec::new();
    write_message(&mut input, &json!({"cmd": "lock", "id": 1})).unwrap();
    write_message(&mut input, &json!({"cmd": "bogus", "id": 2})).unwrap();
    let mut output = Vec::new();
    serve(&mut Cursor::new(input), &mut output, &mut Host::default()).unwrap();

    let mut reader = Cursor::new(output);
    let first = read_message(&mut reader).unwrap().unwrap();
    let second = read_message(&mut reader).unwrap().unwrap();
    assert_eq!(
        (first["id"].clone(), first["ok"].clone()),
        (json!(1), json!(true))
    );
    assert_eq!(second["id"], 2);
    assert_eq!(second["code"], "bad_request");
}

#[test]
fn vault_commands_require_unlock() {
    let mut host = Host::default();
    for request in [
        json!({"cmd": "search", "url": "https://example.com"}),
        json!({"cmd": "get_login", "url": "https://example.com", "entry": 0}),
        json!({"cmd": "passkey_list", "rp_id": "example.com", "origin": ORIGIN}),
    ] {
        assert_eq!(err_code(&mut host, request), "locked");
    }
}

#[test]
fn wrong_password_fails_and_right_one_unlocks() {
    let path = temp_vault(vec![]);
    let mut host = Host::default();
    let code = err_code(
        &mut host,
        json!({"cmd": "unlock", "path": path, "password": "nope"}),
    );
    assert_eq!(code, "unlock_failed");
    assert!(host.session.is_none());

    let reply = ok(
        &mut host,
        json!({"cmd": "unlock", "path": path, "password": MASTER}),
    );
    assert_eq!(reply["unlocked"], true);
    assert_eq!(ok(&mut host, json!({"cmd": "status"}))["unlocked"], true);
    ok(&mut host, json!({"cmd": "lock"}));
    assert_eq!(ok(&mut host, json!({"cmd": "status"}))["unlocked"], false);
}

#[test]
fn repeated_failures_trigger_the_backoff() {
    let path = temp_vault(vec![]);
    let mut host = Host::default();
    for _ in 0..3 {
        err_code(
            &mut host,
            json!({"cmd": "unlock", "path": path, "password": "x"}),
        );
    }
    let code = err_code(
        &mut host,
        json!({"cmd": "unlock", "path": path, "password": MASTER}),
    );
    assert_eq!(code, "rate_limited");
}

#[test]
fn search_and_get_login_only_serve_matching_https_pages() {
    let mut trashed = login("Old", "bob", "https://example.com", "old-pw");
    trashed.trashed_at = Some(1);
    let mut with_totp = login("Mail", "carol", "https://mail.example.com", "mail-pw");
    with_totp.totp_secret = Zeroizing::new(Some("JBSWY3DPEHPK3PXP".into()));
    let (mut host, _) = unlocked_host(vec![
        login("Example", "alice", "https://example.com/login", "s3cret"),
        trashed,
        with_totp,
        login("Other", "dave", "https://other.org", "other-pw"),
    ]);

    let found = ok(
        &mut host,
        json!({"cmd": "search", "url": "https://www.example.com/a"}),
    );
    let ids: Vec<u64> = found["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![0], "trashed and unrelated entries stay hidden");
    assert!(found["matches"][0].get("password").is_none());
    assert_eq!(found["matches"][0]["exact"], true);

    let sub = ok(
        &mut host,
        json!({"cmd": "search", "url": "https://accounts.example.com/"}),
    );
    assert_eq!(sub["matches"][0]["exact"], false);

    let creds = ok(
        &mut host,
        json!({"cmd": "get_login", "entry": 0, "url": "https://example.com/"}),
    );
    assert_eq!(creds["username"], "alice");
    assert_eq!(creds["password"], "s3cret");

    // Replies must echo the request id, never an entry index.
    let tagged = ok(
        &mut host,
        json!({"id": 77, "cmd": "get_login", "entry": 0, "url": "https://example.com/"}),
    );
    assert_eq!(tagged["id"], 77);
    assert!(creds["totp"].is_null());

    let totp = ok(
        &mut host,
        json!({"cmd": "get_login", "entry": 2, "url": "https://mail.example.com/"}),
    );
    assert_eq!(totp["totp"].as_str().unwrap().len(), 6);

    for request in [
        json!({"cmd": "get_login", "entry": 0, "url": "https://evil.net/"}),
        json!({"cmd": "get_login", "entry": 0, "url": "https://sub.example.com/", "exact": true}),
        json!({"cmd": "get_login", "entry": 0, "url": "https://example.com/", "label": "Other"}),
        json!({"cmd": "get_login", "entry": 0, "url": "https://example.com/", "username": "bob"}),
        json!({"cmd": "get_login", "entry": 0, "url": "http://example.com/"}),
        json!({"cmd": "get_login", "entry": 1, "url": "https://example.com/"}),
        json!({"cmd": "get_login", "entry": 99, "url": "https://example.com/"}),
    ] {
        assert_eq!(err_code(&mut host, request), "not_found");
    }
    let none = ok(
        &mut host,
        json!({"cmd": "search", "url": "http://example.com/"}),
    );
    assert!(none["matches"].as_array().unwrap().is_empty());
}

#[test]
fn passkey_only_entries_are_not_offered_as_logins() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, _) = unlocked_host(vec![login("Pk", "alice", "https://example.com", "")]);
    let found = ok(
        &mut host,
        json!({"cmd": "search", "url": "https://example.com/"}),
    );
    assert!(found["matches"].as_array().unwrap().is_empty());
    assert_eq!(
        err_code(
            &mut host,
            json!({"cmd": "get_login", "entry": 0, "url": "https://example.com/"})
        ),
        "not_found"
    );
}

#[test]
fn save_login_creates_updates_and_persists() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, path) = unlocked_host(vec![]);
    let created = ok(
        &mut host,
        json!({
            "cmd": "save_login", "url": "https://shop.example.org/login?next=/",
            "username": "erin", "password": "pw-1", "title": "Shop"
        }),
    );
    assert_eq!(created["action"], "created");
    assert_eq!(created["entry"], 0);

    let same = ok(
        &mut host,
        json!({"cmd": "save_login", "url": "https://shop.example.org/", "username": "ERIN", "password": "pw-1"}),
    );
    assert_eq!(same["action"], "unchanged");

    let updated = ok(
        &mut host,
        json!({"cmd": "save_login", "url": "https://shop.example.org/", "username": "erin", "password": "pw-2"}),
    );
    assert_eq!(updated["action"], "updated");

    let (store, _, _) = load_store(&path, MASTER, None).unwrap();
    assert_eq!(store.entries.len(), 1);
    let entry = &store.entries[0];
    assert_eq!(entry.label, "Shop");
    assert_eq!(entry.url, "https://shop.example.org");
    assert_eq!(entry.password.as_str(), "pw-2");
    assert_eq!(entry.password_history.len(), 1);
    assert_eq!(entry.password_history[0].password.as_str(), "pw-1");

    assert_eq!(
        err_code(
            &mut host,
            json!({"cmd": "save_login", "url": "http://insecure.example.org/", "username": "e", "password": "p"})
        ),
        "bad_request"
    );
}

#[test]
fn save_login_from_a_subdomain_leaves_the_parent_entry_alone() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, path) = unlocked_host(vec![login("Ex", "alice", "https://example.com", "pw")]);
    let saved = ok(
        &mut host,
        json!({"id": 9, "cmd": "save_login", "url": "https://evil.example.com/", "username": "alice", "password": "other"}),
    );
    assert_eq!(saved["action"], "created");
    assert_eq!(saved["id"], 9);
    assert_eq!(saved["entry"], 1);
    let (store, _, _) = load_store(&path, MASTER, None).unwrap();
    assert_eq!(store.entries[0].password.as_str(), "pw");
    assert_eq!(store.entries[1].url, "https://evil.example.com");
}

#[test]
fn save_login_keeps_the_loopback_port() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, path) = unlocked_host(vec![]);
    ok(
        &mut host,
        json!({"cmd": "save_login", "url": "http://localhost:3000/login", "username": "u", "password": "p"}),
    );
    let (store, _, _) = load_store(&path, MASTER, None).unwrap();
    assert_eq!(store.entries[0].url, "http://localhost:3000");
}

#[test]
fn passkey_lifecycle_signs_verifiably_and_survives_a_reload() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, path) =
        unlocked_host(vec![login("Example", "alice", "https://example.com", "pw")]);

    let created = ok(
        &mut host,
        json!({
            "cmd": "passkey_create", "rp_id": "example.com", "origin": ORIGIN,
            "rp_name": "Example", "user_id": "dXNlci0x",
            "user_name": "alice", "user_display_name": "Alice A."
        }),
    );
    let credential_id = created["credential_id"].as_str().unwrap().to_string();

    // Attached to the existing login instead of creating a duplicate entry.
    let (store, _, _) = load_store(&path, MASTER, None).unwrap();
    assert_eq!(store.entries.len(), 1);
    assert_eq!(store.entries[0].passkeys.len(), 1);
    assert_eq!(store.entries[0].password.as_str(), "pw");

    let listed = ok(
        &mut host,
        json!({"cmd": "passkey_list", "rp_id": "example.com", "origin": ORIGIN}),
    );
    assert_eq!(listed["credentials"][0]["credential_id"], credential_id);
    assert_eq!(listed["credentials"][0]["user_name"], "alice");

    let data = signed_input("example.com", b"client-data-hash-and-more-bytes");
    let data = data.as_slice();
    let signed = ok(
        &mut host,
        json!({
            "cmd": "passkey_sign", "rp_id": "example.com", "origin": ORIGIN,
            "credential_id": credential_id, "data": passkey::b64_encode(data)
        }),
    );
    assert_eq!(signed["user_id"], "dXNlci0x");
    let point = EncodedPoint::from_affine_coordinates(
        passkey::b64_decode(created["x"].as_str().unwrap())
            .unwrap()
            .as_slice()
            .into(),
        passkey::b64_decode(created["y"].as_str().unwrap())
            .unwrap()
            .as_slice()
            .into(),
        false,
    );
    let signature =
        Signature::from_der(&passkey::b64_decode(signed["signature"].as_str().unwrap()).unwrap())
            .unwrap();
    VerifyingKey::from_encoded_point(&point)
        .unwrap()
        .verify(data, &signature)
        .unwrap();

    // Anything that isn't authenticator data for this rp is refused.
    for bad in [
        passkey::b64_encode(b"short"),
        passkey::b64_encode(&signed_input("evil.com", b"x")),
    ] {
        assert_eq!(
            err_code(
                &mut host,
                json!({
                    "cmd": "passkey_sign", "rp_id": "example.com", "origin": ORIGIN,
                    "credential_id": credential_id, "data": bad
                })
            ),
            "bad_request"
        );
    }

    // A fresh host (new browser session) still finds and uses the passkey.
    let mut second = Host::default();
    ok(
        &mut second,
        json!({"cmd": "unlock", "path": path, "password": MASTER}),
    );
    ok(
        &mut second,
        json!({
            "cmd": "passkey_sign", "rp_id": "example.com", "origin": ORIGIN,
            "credential_id": credential_id, "data": passkey::b64_encode(data)
        }),
    );
}

#[test]
fn passkey_requests_are_scoped_to_their_relying_party() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, _) = unlocked_host(vec![]);
    let created = ok(
        &mut host,
        json!({
            "cmd": "passkey_create", "rp_id": "example.com", "origin": ORIGIN,
            "user_id": "dTE", "user_name": "alice"
        }),
    );
    let credential_id = created["credential_id"].as_str().unwrap();

    // Creating a second passkey for the same account is refused when the site
    // lists the existing one in excludeCredentials.
    assert_eq!(
        err_code(
            &mut host,
            json!({
                "cmd": "passkey_create", "rp_id": "example.com", "origin": ORIGIN,
                "user_id": "dTE", "user_name": "alice", "exclude": [credential_id]
            })
        ),
        "excluded"
    );

    // Other sites never see it, and an rp id the origin cannot claim is rejected.
    let other = ok(
        &mut host,
        json!({"cmd": "passkey_list", "rp_id": "evil.com", "origin": "https://evil.com/"}),
    );
    assert!(other["credentials"].as_array().unwrap().is_empty());
    assert_eq!(
        err_code(
            &mut host,
            json!({
                "cmd": "passkey_sign", "rp_id": "evil.com", "origin": "https://evil.com/",
                "credential_id": credential_id,
                "data": passkey::b64_encode(&signed_input("evil.com", b"x"))
            })
        ),
        "not_found"
    );
    assert_eq!(
        err_code(
            &mut host,
            json!({"cmd": "passkey_list", "rp_id": "example.com", "origin": "https://evil.com/"})
        ),
        "bad_request"
    );
}

#[test]
fn recreating_a_passkey_for_the_same_user_replaces_it() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, _) = unlocked_host(vec![]);
    let request = json!({
        "cmd": "passkey_create", "rp_id": "example.com", "origin": ORIGIN,
        "user_id": "dTE", "user_name": "alice"
    });
    let check = json!({
        "cmd": "passkey_check", "rp_id": "example.com", "origin": ORIGIN, "user_id": "dTE"
    });
    assert_eq!(ok(&mut host, check.clone())["replaces"], false);
    let first = ok(&mut host, request.clone());
    assert_eq!(ok(&mut host, check)["replaces"], true);
    let second = ok(&mut host, request);
    assert_ne!(first["credential_id"], second["credential_id"]);

    let listed = ok(
        &mut host,
        json!({"cmd": "passkey_list", "rp_id": "example.com", "origin": ORIGIN}),
    );
    assert_eq!(listed["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(
        listed["credentials"][0]["credential_id"],
        second["credential_id"]
    );
}

#[test]
fn writes_made_by_another_process_are_picked_up() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, path) = unlocked_host(vec![login("A", "a", "https://a.example", "pw-a")]);

    // Simulate the GUI saving a new entry to the same vault file.
    let session = host.session.as_ref().unwrap();
    let mut store = session.store.clone();
    store
        .entries
        .push(login("B", "b", "https://b.example", "pw-b"));
    std::thread::sleep(Duration::from_millis(20));
    save_store(&Some(path), &store, &session.key, session.params).unwrap();

    let found = ok(
        &mut host,
        json!({"cmd": "search", "url": "https://b.example/"}),
    );
    assert_eq!(found["matches"].as_array().unwrap().len(), 1);
}

#[test]
fn an_unreadable_reload_locks_the_session() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, path) = unlocked_host(vec![login("A", "a", "https://a.example", "pw-a")]);
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&path, b"garbage").unwrap();
    assert_eq!(
        err_code(
            &mut host,
            json!({"cmd": "search", "url": "https://a.example/"})
        ),
        "vault_changed"
    );
    assert!(host.session.is_none());
}

#[test]
fn saves_are_refused_when_the_file_changed_since_load() {
    let _env = crate::file_ops::config_env_guard();
    let (mut host, _) = unlocked_host(vec![]);
    host.session.as_mut().unwrap().mtime = Some(SystemTime::UNIX_EPOCH);
    let session = host.session.as_mut().unwrap();
    let next = session.store.clone();
    assert_eq!(session.commit(next).unwrap_err().code, "vault_changed");
}

#[test]
fn passive_requests_do_not_extend_the_idle_timer() {
    let (mut host, _) = unlocked_host(vec![]);
    let stale = Instant::now() - Duration::from_secs(50);
    {
        let session = host.session.as_mut().unwrap();
        session.timeout_secs = 60;
        session.last_activity = stale;
    }
    ok(
        &mut host,
        json!({"cmd": "search", "url": "https://example.com", "passive": true}),
    );
    assert_eq!(host.session.as_ref().unwrap().last_activity, stale);
    ok(
        &mut host,
        json!({"cmd": "search", "url": "https://example.com"}),
    );
    assert!(host.session.as_ref().unwrap().last_activity > stale);
}

#[test]
fn idle_sessions_lock_themselves() {
    let (mut host, _) = unlocked_host(vec![]);
    {
        let session = host.session.as_mut().unwrap();
        session.timeout_secs = 60;
        session.last_activity = Instant::now() - Duration::from_secs(120);
    }
    assert_eq!(
        err_code(
            &mut host,
            json!({"cmd": "search", "url": "https://example.com"})
        ),
        "locked"
    );
}

#[test]
fn zero_timeout_never_auto_locks() {
    let (mut host, _) = unlocked_host(vec![]);
    {
        let session = host.session.as_mut().unwrap();
        session.timeout_secs = 0;
        session.last_activity = Instant::now() - Duration::from_secs(100_000);
    }
    ok(
        &mut host,
        json!({"cmd": "search", "url": "https://example.com"}),
    );
}

/// Writes the vault `extension/test/host.e2e.test.js` drives through the real
/// binary. Run: `AEGIS_FIXTURE_VAULT=/tmp/v.aegis cargo test fixture -- --ignored`.
#[test]
#[ignore = "fixture generator for the extension's Node end-to-end test"]
fn write_extension_fixture_vault() {
    let Ok(path) = std::env::var("AEGIS_FIXTURE_VAULT") else {
        return;
    };
    let entries = vec![
        login("Example", "alice", "https://example.com", "s3cret"),
        login("Local", "tester", "http://localhost", "hunter2-local"),
    ];
    write_new_vault_file(
        Path::new(&path),
        &PasswordList { entries },
        MASTER,
        params(),
        None,
    )
    .unwrap();
}

#[test]
fn malformed_json_gets_an_error_and_the_host_keeps_going() {
    let mut wire = Vec::new();
    wire.extend_from_slice(&5u32.to_ne_bytes());
    wire.extend_from_slice(b"{nope");
    write_message(&mut wire, &json!({"cmd": "status", "id": 4})).unwrap();
    let mut output = Vec::new();
    serve(&mut Cursor::new(wire), &mut output, &mut Host::default()).unwrap();
    let mut reader = Cursor::new(output);
    assert_eq!(
        read_message(&mut reader).unwrap().unwrap()["code"],
        "bad_request"
    );
    assert_eq!(read_message(&mut reader).unwrap().unwrap()["id"], 4);
}

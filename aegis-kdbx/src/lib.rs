//! Conversion between KeePass KDBX databases and Aegis vault contents
//! ([`aegis_core::model::PasswordList`]).
//!
//! This lives in its own crate so `aegis-core`, which ships inside the iOS
//! app, does not pull in a KDBX parser.
//!
//! * [`import_kdbx`] reads KDBX 3.1 / 4.x (and legacy KDB) files.
//! * [`export_kdbx`] writes KDBX 4 with Argon2id, AES-256 (or ChaCha20) and
//!   ChaCha20 inner-stream protection. [`export_kdbx_with`] lets callers
//!   tune the KDF (tests use it to stay fast).
//!
//! # Field mapping
//!
//! | Aegis                                | KeePass                                                        |
//! |--------------------------------------|----------------------------------------------------------------|
//! | `label`                              | `Title`                                                        |
//! | `username`                           | `UserName`                                                     |
//! | `password`                           | `Password` (protected)                                         |
//! | `url`                                | `URL`                                                          |
//! | `notes`                              | `Notes` (protected)                                            |
//! | `totp_secret`                        | `otp` (protected) as an `otpauth://` URL; on import also the legacy `TOTP Seed`/`TOTP Settings`, `TimeOtp-*` and KeeOtp `key=...` forms |
//! | `tags`                               | entry `Tags`                                                   |
//! | tag `group:A/B`                      | entry placed in group `A/B` (tag removed from KeePass `Tags`)  |
//! | `custom_fields`                      | other string fields (protected); order kept in entry CustomData `aegis:field_order` |
//! | `password_type == Card`              | tag `aegis:card` + `card_number` (protected), `card_expiration`, `card_cvc` (protected) |
//! | `password_type == WiFi`              | tag `aegis:wifi`                                               |
//! | `is_secure_note`                     | tag `aegis:note`                                               |
//! | `favorite == Some(true)`             | tag `aegis:favorite`                                           |
//! | `password_history`                   | entry history: one version per item, `Password` + `LastModificationTime = changed_at` |
//! | `created_at`                         | `Times/CreationTime`                                           |
//! | `trashed_at`                         | entry in the recycle bin group, `Times/LocationChanged = trashed_at` |
//! | `extra` (unknown fields)             | entry CustomData `aegis:extra` (JSON); list-level `extra` in Meta CustomData `aegis:extra` |
//!
//! Attachments, icons, colours, auto-type and expiry dates have no Aegis
//! equivalent: they are dropped on import and listed in
//! [`ImportReport::skipped`] where they carry user data (attachments, expiry).

use std::collections::HashSet;

use aegis_core::model::{
    PASSWORD_HISTORY_CAP, PasswordEntry, PasswordHistory, PasswordList, PasswordType, now_unix,
};
use chrono::NaiveDateTime;
use keepass::config::{
    CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig,
};
use keepass::db::{
    CustomDataItem, CustomDataValue, Entry, EntryRef, GroupId, GroupRef, History, fields,
};
use keepass::{Database, DatabaseKey};
use serde_json::{Map, Value as JsonValue};
use zeroize::Zeroizing;

/// Credentials protecting a KDBX file. At least one must be set. An empty
/// password (`Some("")`) is a valid KeePass key component, distinct from `None`.
#[derive(Clone, Copy, Debug, Default)]
pub struct KdbxCredentials<'a> {
    pub password: Option<&'a str>,
    /// Raw keyfile contents (KeePass XML v1/v2, 32-byte binary, 64-char hex,
    /// or any other file, which is hashed).
    pub keyfile: Option<&'a [u8]>,
}

/// What an import did. `skipped` holds human-readable reasons for data that
/// could not be carried over.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub imported: usize,
    pub skipped: Vec<String>,
}

/// Outer cipher for exported databases.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExportCipher {
    #[default]
    Aes256,
    ChaCha20,
}

/// Tunables for [`export_kdbx_with`]. The KDF is always Argon2id (v1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportOptions {
    /// Argon2 memory in bytes.
    pub kdf_memory_bytes: u64,
    pub kdf_iterations: u64,
    pub kdf_parallelism: u32,
    pub cipher: ExportCipher,
}

impl Default for ExportOptions {
    /// Argon2id, 64 MiB, 10 passes, 2 lanes; AES-256.
    fn default() -> Self {
        Self {
            kdf_memory_bytes: 64 * 1024 * 1024,
            kdf_iterations: 10,
            kdf_parallelism: 2,
            cipher: ExportCipher::Aes256,
        }
    }
}

pub const TAG_CARD: &str = "aegis:card";
pub const TAG_WIFI: &str = "aegis:wifi";
pub const TAG_NOTE: &str = "aegis:note";
pub const TAG_FAVORITE: &str = "aegis:favorite";
pub const GROUP_TAG_PREFIX: &str = "group:";
pub const FIELD_CARD_NUMBER: &str = "card_number";
pub const FIELD_CARD_EXPIRATION: &str = "card_expiration";
pub const FIELD_CARD_CVC: &str = "card_cvc";
/// Entry CustomData key holding the JSON array of custom field names in order.
pub const CD_FIELD_ORDER: &str = "aegis:field_order";
/// Entry/Meta CustomData key holding unknown Aegis fields as a JSON object.
pub const CD_EXTRA: &str = "aegis:extra";
pub const RECYCLE_BIN_NAME: &str = "Recycle Bin";

const MARKER_TAGS: [&str; 4] = [TAG_CARD, TAG_WIFI, TAG_NOTE, TAG_FAVORITE];
const STANDARD_FIELDS: [&str; 6] = [
    fields::TITLE,
    fields::USERNAME,
    fields::PASSWORD,
    fields::URL,
    fields::NOTES,
    fields::OTP,
];

fn database_key(creds: &KdbxCredentials) -> Result<DatabaseKey, String> {
    if creds.password.is_none() && creds.keyfile.is_none() {
        return Err("A password or a keyfile is required".to_string());
    }
    let mut key = DatabaseKey::new();
    if let Some(p) = creds.password {
        key = key.with_password(p);
    }
    if let Some(mut kf) = creds.keyfile {
        key = key
            .with_keyfile(&mut kf)
            .map_err(|e| format!("Could not read keyfile: {e}"))?;
    }
    Ok(key)
}

fn ts_to_naive(ts: u64) -> Option<NaiveDateTime> {
    chrono::DateTime::from_timestamp(i64::try_from(ts).ok()?, 0).map(|d| d.naive_utc())
}

fn naive_to_ts(t: NaiveDateTime) -> Option<u64> {
    u64::try_from(t.and_utc().timestamp()).ok()
}

// ---------------------------------------------------------------------------
// TOTP helpers
// ---------------------------------------------------------------------------

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn normalize_base32(secret: &str) -> Zeroizing<String> {
    Zeroizing::new(
        secret
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    )
}

/// The URL [`export_kdbx`] writes for a bare base32 secret.
fn canonical_otpauth(label: &str, secret: &str) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "otpauth://totp/{}?secret={secret}&period=30&digits=6&algorithm=SHA1",
        percent_encode(label)
    ))
}

/// Aegis secret (bare base32 or otpauth URL) -> KeePass `otp` value.
fn totp_to_kdbx(label: &str, secret: &str) -> Option<Zeroizing<String>> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    if secret.starts_with("otpauth://") {
        return Some(Zeroizing::new(secret.to_string()));
    }
    Some(canonical_otpauth(label, &normalize_base32(secret)))
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

/// Build an Aegis secret from parts: bare base32 when the parameters are the
/// Aegis defaults (SHA1/6/30), otherwise an otpauth URL.
fn totp_from_parts(
    label: &str,
    secret: &str,
    period: u64,
    digits: u32,
    algorithm: &str,
) -> Zeroizing<String> {
    let secret = normalize_base32(secret);
    if period == 30 && digits == 6 && algorithm == "SHA1" {
        return secret;
    }
    Zeroizing::new(format!(
        "otpauth://totp/{}?secret={}&period={period}&digits={digits}&algorithm={algorithm}",
        percent_encode(label),
        secret.as_str()
    ))
}

/// KeePass `otp` value -> Aegis secret.
fn totp_from_otp_field(label: &str, value: &str) -> Option<Zeroizing<String>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.starts_with("otpauth://") {
        // Collapse exactly what we export for a bare secret back to it, so a
        // round trip is lossless; anything else (issuer, other params) is
        // kept verbatim.
        if let Some((_, query)) = value.split_once('?')
            && let Some(secret) = query_param(query, "secret")
            && canonical_otpauth(label, secret).as_str() == value
        {
            return Some(Zeroizing::new(secret.to_string()));
        }
        return Some(Zeroizing::new(value.to_string()));
    }
    // KeeOtp style: key=SECRET&step=30&size=6&otpHashMode=Sha256
    if let Some(key) = query_param(value, "key") {
        let period = query_param(value, "step")
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let digits = query_param(value, "size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(6);
        let algorithm = match query_param(value, "otpHashMode")
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("sha256") => "SHA256",
            Some("sha512") => "SHA512",
            _ => "SHA1",
        };
        return Some(totp_from_parts(label, key, period, digits, algorithm));
    }
    Some(normalize_base32(value))
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Export with strong defaults ([`ExportOptions::default`]).
pub fn export_kdbx(list: &PasswordList, creds: KdbxCredentials) -> Result<Vec<u8>, String> {
    export_kdbx_with(list, creds, ExportOptions::default())
}

/// Export to KDBX 4 with explicit KDF/cipher settings.
pub fn export_kdbx_with(
    list: &PasswordList,
    creds: KdbxCredentials,
    opts: ExportOptions,
) -> Result<Vec<u8>, String> {
    let key = database_key(&creds)?;
    if opts.kdf_iterations == 0
        || opts.kdf_parallelism == 0
        || opts.kdf_memory_bytes < 8 * 1024 * u64::from(opts.kdf_parallelism)
    {
        return Err("Invalid KDF parameters".to_string());
    }

    let mut config = DatabaseConfig::default();
    // The Argon2 version type comes from keepass' own argon2 dependency; take
    // it from the default config instead of depending on that crate.
    let version = match &config.kdf_config {
        KdfConfig::Argon2 { version, .. } | KdfConfig::Argon2id { version, .. } => *version,
        _ => return Err("Unexpected default KDF in keepass crate".to_string()),
    };
    config.kdf_config = KdfConfig::Argon2id {
        iterations: opts.kdf_iterations,
        memory: opts.kdf_memory_bytes,
        parallelism: opts.kdf_parallelism,
        version,
    };
    config.outer_cipher_config = match opts.cipher {
        ExportCipher::Aes256 => OuterCipherConfig::AES256,
        ExportCipher::ChaCha20 => OuterCipherConfig::ChaCha20,
    };
    config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    config.compression_config = CompressionConfig::GZip;

    let mut db = Database::with_config(config);
    db.meta.generator = Some("Aegis".to_string());
    db.meta.recyclebin_enabled = Some(true);
    if !list.extra.is_empty() {
        let json = serde_json::to_string(&list.extra).map_err(|e| e.to_string())?;
        db.meta
            .custom_data
            .insert(CD_EXTRA.to_string(), custom_data_string(json));
    }

    let root = db.root().id();
    let mut recycle_bin: Option<GroupId> = None;

    for entry in &list.entries {
        let mut tags: Vec<String> = Vec::new();
        let mut group_path: Option<Vec<String>> = None;
        for tag in entry.tags.iter().flatten() {
            let tag = tag.trim();
            if tag.is_empty() || MARKER_TAGS.contains(&tag) {
                continue;
            }
            if group_path.is_none()
                && let Some(path) = tag.strip_prefix(GROUP_TAG_PREFIX)
            {
                group_path = Some(split_group_path(path));
                continue;
            }
            tags.push(tag.to_string());
        }

        let base = if entry.is_trashed() {
            *recycle_bin.get_or_insert_with(|| {
                let mut root_group = db.root_mut();
                let mut bin = root_group.add_group();
                bin.name = RECYCLE_BIN_NAME.to_string();
                bin.set_icon_builtin(43);
                bin.id()
            })
        } else {
            root
        };
        let gid = match &group_path {
            Some(path) => ensure_group(&mut db, base, path),
            None => base,
        };
        write_entry(&mut db, gid, entry, tags)?;
    }
    if let Some(bin) = recycle_bin {
        db.meta.recyclebin_uuid = Some(bin.uuid());
        db.meta.recyclebin_changed = Some(keepass::db::Times::now());
    }

    let mut out = Vec::new();
    db.save(&mut out, key)
        .map_err(|e| format!("Could not write KDBX: {e}"))?;
    Ok(out)
}

fn split_group_path(path: &str) -> Vec<String> {
    path.split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn ensure_group(db: &mut Database, base: GroupId, path: &[String]) -> GroupId {
    let mut current = base;
    for part in path {
        let Some(mut group) = db.group_mut(current) else {
            return current;
        };
        let existing = group
            .as_ref()
            .groups()
            .find(|g| g.name == *part)
            .map(|g| g.id());
        current = match existing {
            Some(id) => id,
            None => {
                let mut child = group.add_group();
                child.name = part.clone();
                child.id()
            }
        };
    }
    current
}

fn custom_data_string(value: String) -> CustomDataItem {
    CustomDataItem {
        value: Some(CustomDataValue::String(value)),
        last_modification_time: Some(keepass::db::Times::now()),
    }
}

fn write_entry(
    db: &mut Database,
    gid: GroupId,
    e: &PasswordEntry,
    mut tags: Vec<String>,
) -> Result<(), String> {
    let mut group = db
        .group_mut(gid)
        .ok_or_else(|| "internal error: group vanished".to_string())?;
    let mut ke = group.add_entry();

    ke.set_unprotected(fields::TITLE, e.label.as_str());
    ke.set_unprotected(fields::USERNAME, e.username.as_str());
    ke.set_protected(fields::PASSWORD, e.password.as_str());
    ke.set_unprotected(fields::URL, e.url.as_str());
    ke.set_protected(fields::NOTES, e.notes.as_str());
    if let Some(secret) = e.totp_secret.as_deref()
        && let Some(otp) = totp_to_kdbx(&e.label, secret)
    {
        ke.set_protected(fields::OTP, otp.as_str());
    }

    let mut used: HashSet<String> = STANDARD_FIELDS.iter().map(|s| s.to_string()).collect();
    match e.password_type {
        PasswordType::Card => {
            tags.push(TAG_CARD.to_string());
            if let Some(n) = &e.number {
                ke.set_protected(FIELD_CARD_NUMBER, n.as_str());
            }
            if let Some(x) = &e.expiration_date {
                ke.set_unprotected(FIELD_CARD_EXPIRATION, x.as_str());
            }
            if let Some(c) = &e.cvc {
                ke.set_protected(FIELD_CARD_CVC, c.as_str());
            }
            for f in [FIELD_CARD_NUMBER, FIELD_CARD_EXPIRATION, FIELD_CARD_CVC] {
                used.insert(f.to_string());
            }
        }
        PasswordType::WiFi => tags.push(TAG_WIFI.to_string()),
        PasswordType::Normal => {}
    }
    if e.is_secure_note {
        tags.push(TAG_NOTE.to_string());
    }
    if e.favorite == Some(true) {
        tags.push(TAG_FAVORITE.to_string());
    }

    let mut order = Vec::with_capacity(e.custom_fields.len());
    for (name, value) in e.custom_fields.iter() {
        let base = if name.is_empty() {
            "(unnamed)"
        } else {
            name.as_str()
        };
        let mut unique = base.to_string();
        let mut n = 2;
        while used.contains(&unique) {
            unique = format!("{base} ({n})");
            n += 1;
        }
        used.insert(unique.clone());
        ke.set_protected(unique.as_str(), value.as_str());
        order.push(unique);
    }
    if !order.is_empty() {
        let json = serde_json::to_string(&order).map_err(|e| e.to_string())?;
        ke.custom_data
            .insert(CD_FIELD_ORDER.to_string(), custom_data_string(json));
    }
    if !e.extra.is_empty() {
        let json = serde_json::to_string(&e.extra).map_err(|e| e.to_string())?;
        ke.custom_data
            .insert(CD_EXTRA.to_string(), custom_data_string(json));
    }

    ke.tags = tags;
    let now = keepass::db::Times::now();
    if let Some(created) = e.created_at.and_then(ts_to_naive) {
        ke.times.creation = Some(created);
    }
    ke.times.last_modification = Some(now);
    if let Some(trashed) = e.trashed_at.and_then(ts_to_naive) {
        ke.times.location_changed = Some(trashed);
    }

    if !e.password_history.is_empty() {
        let base: Entry = Entry::clone(&ke);
        let mut history = History::default();
        // History::add_entry prepends; KeePass stores versions oldest first.
        for h in e.password_history.iter().rev() {
            let mut version = base.clone();
            version.history = None;
            version.set_protected(fields::PASSWORD, h.password.as_str());
            version.times.last_modification = ts_to_naive(h.changed_at);
            history.add_entry(version);
        }
        ke.history = Some(history);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Import a KDBX (or KDB) database.
pub fn import_kdbx(
    data: &[u8],
    creds: KdbxCredentials,
) -> Result<(PasswordList, ImportReport), String> {
    let key = database_key(&creds)?;
    let db = Database::parse(data, key).map_err(|e| match e {
        keepass::db::DatabaseOpenError::Key(keepass_key_err) => {
            format!("Wrong password or keyfile ({keepass_key_err})")
        }
        other => format!("Could not open KDBX: {other}"),
    })?;

    let mut list = PasswordList::default();
    if let Some(extra) = db
        .meta
        .custom_data
        .get(CD_EXTRA)
        .and_then(parse_json_object)
    {
        list.extra = extra;
    }

    let mut ctx = ImportCtx {
        bin: db
            .meta
            .recyclebin_uuid
            .map(GroupId::from_uuid)
            .filter(|id| db.group(*id).is_some()),
        now: now_unix(),
        entries: Vec::with_capacity(db.num_entries()),
        report: ImportReport::default(),
    };
    let mut path = Vec::new();
    walk(&db.root(), &mut path, false, &mut ctx);

    ctx.report.imported = ctx.entries.len();
    list.entries = ctx.entries;
    Ok((list, ctx.report))
}

struct ImportCtx {
    bin: Option<GroupId>,
    now: u64,
    entries: Vec<PasswordEntry>,
    report: ImportReport,
}

fn walk(group: &GroupRef<'_>, path: &mut Vec<String>, trashed: bool, ctx: &mut ImportCtx) {
    for entry in group.entries() {
        let converted = convert_entry(&entry, path, trashed, ctx);
        ctx.entries.push(converted);
    }
    for child in group.groups() {
        if Some(child.id()) == ctx.bin {
            // Paths inside the bin are relative to the bin itself.
            walk(&child, &mut Vec::new(), true, ctx);
        } else {
            path.push(child.name.clone());
            walk(&child, path, trashed, ctx);
            path.pop();
        }
    }
}

fn parse_json_object(item: &CustomDataItem) -> Option<Map<String, JsonValue>> {
    match &item.value {
        Some(CustomDataValue::String(s)) => serde_json::from_str(s).ok(),
        _ => None,
    }
}

fn parse_field_order(item: &CustomDataItem) -> Option<Vec<String>> {
    match &item.value {
        Some(CustomDataValue::String(s)) => serde_json::from_str(s).ok(),
        _ => None,
    }
}

fn convert_entry(
    entry: &EntryRef<'_>,
    path: &[String],
    trashed: bool,
    ctx: &mut ImportCtx,
) -> PasswordEntry {
    let get = |k: &str| entry.get(k).unwrap_or("");
    let label = get(fields::TITLE).to_string();
    let display = if label.is_empty() {
        "(untitled)".to_string()
    } else {
        label.clone()
    };

    let field_order = entry
        .custom_data
        .get(CD_FIELD_ORDER)
        .and_then(parse_field_order);
    let extra = entry.custom_data.get(CD_EXTRA).and_then(parse_json_object);
    let written_by_aegis = field_order.is_some() || extra.is_some();

    let raw_tags: Vec<&str> = entry
        .tags
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect();
    let has = |t: &str| raw_tags.contains(&t);
    let is_card = has(TAG_CARD);
    let is_wifi = has(TAG_WIFI);

    let mut consumed: HashSet<&str> = STANDARD_FIELDS.into_iter().collect();

    // TOTP
    let mut totp: Option<Zeroizing<String>> = entry
        .get(fields::OTP)
        .and_then(|v| totp_from_otp_field(&label, v));
    if totp.is_none() && !written_by_aegis {
        totp = legacy_totp(entry, &label, &display, &mut consumed, &mut ctx.report);
    }

    let mut out = PasswordEntry {
        label,
        username: get(fields::USERNAME).to_string(),
        password: Zeroizing::new(get(fields::PASSWORD).to_string()),
        notes: Zeroizing::new(get(fields::NOTES).to_string()),
        url: get(fields::URL).to_string(),
        ..Default::default()
    };
    *out.totp_secret = totp.map(|s| s.as_str().to_string());

    if is_card {
        out.password_type = PasswordType::Card;
        let take = |name: &str| entry.get(name).map(|v| Zeroizing::new(v.to_string()));
        out.number = take(FIELD_CARD_NUMBER);
        out.expiration_date = take(FIELD_CARD_EXPIRATION);
        out.cvc = take(FIELD_CARD_CVC);
        consumed.extend([FIELD_CARD_NUMBER, FIELD_CARD_EXPIRATION, FIELD_CARD_CVC]);
    } else if is_wifi {
        out.password_type = PasswordType::WiFi;
    }
    out.is_secure_note = has(TAG_NOTE);
    out.favorite = has(TAG_FAVORITE).then_some(true);

    // Custom fields: Aegis' recorded order first, then the rest by name.
    let mut remaining: Vec<&str> = entry
        .fields
        .keys()
        .map(String::as_str)
        .filter(|k| !consumed.contains(k))
        .collect();
    remaining.sort_unstable();
    let mut ordered: Vec<&str> = Vec::with_capacity(remaining.len());
    if let Some(order) = &field_order {
        for name in order {
            if let Some(pos) = remaining.iter().position(|k| k == name) {
                ordered.push(remaining.remove(pos));
            }
        }
    }
    ordered.extend(remaining);
    out.custom_fields.reserve_exact(ordered.len());
    for name in ordered {
        out.custom_fields
            .push((name.to_string(), get(name).to_string()));
    }

    // Tags: plain tags in order, then the group tag (placed before any other
    // literal group: tag so it keeps deciding placement on re-export).
    let mut tags: Vec<String> = raw_tags
        .iter()
        .filter(|t| !MARKER_TAGS.contains(t))
        .map(|t| t.to_string())
        .collect();
    if !path.is_empty() {
        let group_tag = format!("{GROUP_TAG_PREFIX}{}", path.join("/"));
        let pos = tags
            .iter()
            .position(|t| t.starts_with(GROUP_TAG_PREFIX))
            .unwrap_or(tags.len());
        tags.insert(pos, group_tag);
    }
    out.tags = (!tags.is_empty()).then_some(tags);

    out.created_at = entry.times.creation.and_then(naive_to_ts);
    if trashed {
        out.trashed_at = Some(
            entry
                .times
                .location_changed
                .or(entry.times.last_modification)
                .and_then(naive_to_ts)
                .unwrap_or(ctx.now),
        );
    }

    out.password_history = import_history(entry);
    if let Some(extra) = extra {
        out.extra = extra;
    }

    let attachments = entry.attachments().count();
    if attachments > 0 {
        ctx.report.skipped.push(format!(
            "Entry \"{display}\": {attachments} attachment(s) not imported"
        ));
    }
    if entry.times.expires == Some(true) {
        ctx.report
            .skipped
            .push(format!("Entry \"{display}\": expiry date not imported"));
    }
    out
}

/// Legacy KeePassXC (`TOTP Seed`/`TOTP Settings`) and KeePass 2.47+
/// (`TimeOtp-*`) TOTP fields.
fn legacy_totp<'e>(
    entry: &'e EntryRef<'_>,
    label: &str,
    display: &str,
    consumed: &mut HashSet<&'e str>,
    report: &mut ImportReport,
) -> Option<Zeroizing<String>> {
    if let Some(seed) = entry.get("TOTP Seed").filter(|s| !s.trim().is_empty()) {
        let settings = entry.get("TOTP Settings").unwrap_or("30;6");
        let (period, digits) = settings.split_once(';').unwrap_or((settings, "6"));
        if digits.trim().eq_ignore_ascii_case("S") {
            report.skipped.push(format!(
                "Entry \"{display}\": Steam TOTP is not supported; kept as custom fields"
            ));
            return None;
        }
        consumed.insert("TOTP Seed");
        consumed.insert("TOTP Settings");
        let period = period.trim().parse().unwrap_or(30);
        let digits = digits.trim().parse().unwrap_or(6);
        return Some(totp_from_parts(label, seed, period, digits, "SHA1"));
    }
    if let Some(seed) = entry
        .get("TimeOtp-Secret-Base32")
        .filter(|s| !s.trim().is_empty())
    {
        let algorithm = match entry.get("TimeOtp-Algorithm") {
            None | Some("HMAC-SHA-1") => "SHA1",
            Some("HMAC-SHA-256") => "SHA256",
            Some("HMAC-SHA-512") => "SHA512",
            Some(other) => {
                report.skipped.push(format!(
                    "Entry \"{display}\": TOTP algorithm {other} is not supported; kept as custom fields"
                ));
                return None;
            }
        };
        for f in [
            "TimeOtp-Secret-Base32",
            "TimeOtp-Period",
            "TimeOtp-Length",
            "TimeOtp-Algorithm",
        ] {
            consumed.insert(f);
        }
        let period = entry
            .get("TimeOtp-Period")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(30);
        let digits = entry
            .get("TimeOtp-Length")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(6);
        return Some(totp_from_parts(label, seed, period, digits, algorithm));
    }
    None
}

/// KeePass history versions (oldest first) -> Aegis password history.
/// Consecutive versions with the same password collapse into one (keeping
/// the later timestamp); trailing versions whose password is still the
/// current one are not history.
fn import_history(entry: &EntryRef<'_>) -> Vec<PasswordHistory> {
    let Some(history) = &entry.history else {
        return Vec::new();
    };
    let mut out: Vec<PasswordHistory> = Vec::new();
    for version in history.get_entries() {
        let password = version.get(fields::PASSWORD).unwrap_or("");
        let changed_at = version
            .times
            .last_modification
            .and_then(naive_to_ts)
            .unwrap_or(0);
        match out.last_mut() {
            Some(last) if last.password.as_str() == password => last.changed_at = changed_at,
            _ => out.push(PasswordHistory {
                password: Zeroizing::new(password.to_string()),
                changed_at,
            }),
        }
    }
    let current = entry.get(fields::PASSWORD).unwrap_or("");
    if out.last().is_some_and(|h| h.password.as_str() == current) {
        out.pop();
    }
    if out.len() > PASSWORD_HISTORY_CAP {
        out.drain(..out.len() - PASSWORD_HISTORY_CAP);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otpauth_canonical_round_trip() {
        let url = totp_to_kdbx("My Site/é", "jbsw y3dp ehpk3pxp").unwrap();
        assert_eq!(
            url.as_str(),
            "otpauth://totp/My%20Site%2F%C3%A9?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&algorithm=SHA1"
        );
        assert_eq!(
            totp_from_otp_field("My Site/é", &url).unwrap().as_str(),
            "JBSWY3DPEHPK3PXP"
        );
        // A URL for a different label is kept verbatim.
        assert_eq!(
            totp_from_otp_field("Other", &url).unwrap().as_str(),
            url.as_str()
        );
    }

    #[test]
    fn keeotp_format() {
        assert_eq!(
            totp_from_otp_field("x", "key=JBSWY3DPEHPK3PXP&step=30&size=6")
                .unwrap()
                .as_str(),
            "JBSWY3DPEHPK3PXP"
        );
        assert_eq!(
            totp_from_otp_field("x", "key=JBSWY3DPEHPK3PXP&size=8&otpHashMode=Sha256")
                .unwrap()
                .as_str(),
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=30&digits=8&algorithm=SHA256"
        );
    }
}

//! Native-messaging host for the Firefox extension (`aegis --native-host`).
//!
//! Firefox spawns this process, speaks length-prefixed JSON over stdio, and
//! kills it when the extension disconnects. The host unlocks the vault itself
//! (the extension only ever forwards the master password), keeps the derived
//! key in locked memory, and re-reads the vault file whenever the GUI has
//! written to it.

mod matching;
pub(crate) mod passkey;

use crate::file_ops::{
    KEYFILE_MAX_BYTES, VaultKdfParams, load_store, reload_store_with_key, save_store,
};
use crate::locked_buf::LockedKey;
use crate::models::{
    PasswordEntry, PasswordList, PasswordType, is_trashed, now_unix, record_password_change,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use zeroize::{Zeroize, Zeroizing};

/// Browsers cap host-to-browser messages at 1 MiB and never send more than a
/// few KiB to us; anything larger is read, dropped and answered with an error.
const MAX_INCOMING_BYTES: u32 = 4 * 1024 * 1024;

pub fn run() -> i32 {
    let stdin = io::stdin();
    let stdout = io::stdout();
    match serve(&mut stdin.lock(), &mut stdout.lock(), &mut Host::default()) {
        Ok(()) => 0,
        Err(error) => {
            log::error!("native host stopped: {error}");
            1
        }
    }
}

fn serve(input: &mut impl Read, output: &mut impl Write, host: &mut Host) -> io::Result<()> {
    while let Some(request) = read_message(input)? {
        let reply = if request.is_null() {
            // read_message yields null for a body it had to throw away.
            json!({"ok": false, "code": "too_large", "error": "message too large", "id": null})
        } else {
            host.handle(request)
        };
        write_message(output, &reply)?;
    }
    Ok(())
}

fn read_message(input: &mut impl Read) -> io::Result<Option<Value>> {
    let mut len_bytes = [0u8; 4];
    match input.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let len = u32::from_ne_bytes(len_bytes);
    if len > MAX_INCOMING_BYTES {
        let skipped = io::copy(&mut input.by_ref().take(u64::from(len)), &mut io::sink())?;
        if skipped < u64::from(len) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        return Ok(Some(Value::Null));
    }
    let mut body = Zeroizing::new(vec![0u8; len as usize]);
    input.read_exact(&mut body)?;
    // Garbage in the body shouldn't end the session; handle() answers a
    // non-object with bad_request.
    Ok(Some(
        serde_json::from_slice(&body).unwrap_or_else(|_| json!([])),
    ))
}

fn write_message(output: &mut impl Write, message: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(message)?;
    output.write_all(&(body.len() as u32).to_ne_bytes())?;
    output.write_all(&body)?;
    output.flush()
}

struct HostError {
    code: &'static str,
    message: String,
}

impl HostError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new("bad_request", message)
    }
}

type HostResult = Result<Map<String, Value>, HostError>;

struct Session {
    path: PathBuf,
    store: PasswordList,
    key: LockedKey,
    params: VaultKdfParams,
    mtime: Option<SystemTime>,
    last_activity: Instant,
    timeout_secs: u64,
}

fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

impl Session {
    /// Pick up writes made by the GUI since we last looked.
    fn refresh(&mut self) -> Result<(), String> {
        let current = mtime_of(&self.path);
        if current == self.mtime {
            return Ok(());
        }
        let store = reload_store_with_key(&self.path, &self.key)?;
        self.store = store;
        self.mtime = current;
        Ok(())
    }

    /// Write `next` and make it the live store, but only if the file is still
    /// the one we loaded and the save worked.
    fn commit(&mut self, next: PasswordList) -> Result<(), HostError> {
        if mtime_of(&self.path) != self.mtime {
            return Err(HostError::new(
                "vault_changed",
                "The vault changed on disk. Try again.",
            ));
        }
        save_store(&Some(self.path.clone()), &next, &self.key, self.params)
            .map_err(|error| HostError::new("io", error))?;
        self.store = next;
        self.mtime = mtime_of(&self.path);
        Ok(())
    }
}

#[derive(Default)]
struct Host {
    session: Option<Session>,
    failed_unlocks: u32,
    penalty_until: Option<Instant>,
}

fn field<'a>(request: &'a Value, key: &str) -> Result<&'a str, HostError> {
    request
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| HostError::bad_request(format!("missing field `{key}`")))
}

fn optional_field<'a>(request: &'a Value, key: &str) -> Option<&'a str> {
    request
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}

fn matchable(entry: &PasswordEntry) -> bool {
    !is_trashed(entry) && entry.password_type == PasswordType::Normal && !entry.is_secure_note
}

/// Entries that can fill a login form: passkey-only ones have no password.
fn loginable(entry: &PasswordEntry) -> bool {
    matchable(entry) && !entry.password.is_empty()
}

impl Host {
    fn handle(&mut self, mut request: Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let command = request
            .get("cmd")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let outcome = self.dispatch(&command, &mut request);

        let mut reply = match outcome {
            Ok(map) => {
                let mut map = map;
                map.insert("ok".into(), Value::Bool(true));
                map
            }
            Err(error) => object(json!({
                "ok": false,
                "code": error.code,
                "error": error.message,
            })),
        };
        reply.insert("id".into(), id);
        Value::Object(reply)
    }

    fn dispatch(&mut self, command: &str, request: &mut Value) -> HostResult {
        self.expire_if_idle();
        // Page-load autofill is passive: it must not keep the vault unlocked.
        let passive = request.get("passive").and_then(Value::as_bool) == Some(true);
        if command != "status" && !passive {
            self.touch();
        }
        match command {
            "status" => Ok(self.status()),
            "unlock" => self.unlock(request),
            "lock" => {
                self.session = None;
                Ok(Map::new())
            }
            "search" => self.search(request),
            "get_login" => self.get_login(request),
            "save_login" => self.save_login(request),
            "passkey_check" => self.passkey_check(request),
            "passkey_create" => self.passkey_create(request),
            "passkey_list" => self.passkey_list(request),
            "passkey_sign" => self.passkey_sign(request),
            _ => Err(HostError::bad_request(format!(
                "unknown command `{command}`"
            ))),
        }
    }

    fn touch(&mut self) {
        if let Some(session) = &mut self.session {
            session.last_activity = Instant::now();
        }
    }

    fn expire_if_idle(&mut self) {
        let idle = self.session.as_ref().is_some_and(|session| {
            session.timeout_secs != 0
                && session.last_activity.elapsed() >= Duration::from_secs(session.timeout_secs)
        });
        if idle {
            self.session = None;
        }
    }

    fn session(&mut self) -> Result<&mut Session, HostError> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| HostError::new("locked", "Aegis is locked"))?;
        if let Err(error) = session.refresh() {
            log::warn!("could not refresh vault: {error}");
            // Stale data is worse than a lock: make the user unlock again.
            self.session = None;
            return Err(HostError::new(
                "vault_changed",
                "The vault changed on disk and could not be reloaded. Unlock again.",
            ));
        }
        self.session
            .as_mut()
            .ok_or_else(|| HostError::new("locked", "Aegis is locked"))
    }

    fn status(&self) -> Map<String, Value> {
        let config = crate::config::load();
        let configured = &config.last_used_file;
        let path = self
            .session
            .as_ref()
            .map_or(configured.clone(), |s| s.path.clone());
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        object(json!({
            "unlocked": self.session.is_some(),
            "version": env!("CARGO_PKG_VERSION"),
            "vault_path": path.to_string_lossy(),
            "vault_name": name,
            "vault_exists": !path.as_os_str().is_empty() && path.exists(),
            "needs_keyfile": config.keyfile_hashes.contains_key(&path),
            "lock_timeout_secs": config.lock_timeout_secs,
        }))
    }

    fn unlock(&mut self, request: &mut Value) -> HostResult {
        if let Some(until) = self.penalty_until {
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining > Duration::ZERO {
                return Err(HostError::new(
                    "rate_limited",
                    format!(
                        "Too many failed attempts. Try again in {} s.",
                        remaining.as_secs().max(1)
                    ),
                ));
            }
            self.penalty_until = None;
        }

        let config = crate::config::load();
        let path = match optional_field(request, "path") {
            Some(path) => expand_home(path),
            None => config.last_used_file.clone(),
        };
        if path.as_os_str().is_empty() {
            return Err(HostError::new(
                "no_vault",
                "No vault known yet: open one in Aegis once or enter its path.",
            ));
        }
        if !path.is_file() {
            return Err(HostError::new(
                "no_vault",
                format!("Vault file not found: {}", path.display()),
            ));
        }

        let keyfile = optional_field(request, "keyfile")
            .map(|p| read_keyfile(&expand_home(p)))
            .transpose()?;
        if keyfile.is_none() && config.keyfile_hashes.contains_key(&path) {
            return Err(HostError::new(
                "keyfile_required",
                "This vault requires a keyfile.",
            ));
        }

        let password = Zeroizing::new(field(request, "password")?.to_string());
        // The request still holds a copy of the password; wipe it now.
        if let Some(Value::String(copy)) = request.get_mut("password") {
            copy.zeroize();
        }

        let loaded = match config.duress_by_vault.get(&path) {
            Some(duress) if duress.matches(&password) => {
                crate::modals::enter_master_password::load_or_create_decoy(&path, &password)
                    .map(|(store, key, params, decoy)| (decoy, store, key, params))
            }
            _ => load_store(&path, &password, keyfile.as_ref().map(|k| k.as_slice()))
                .map(|(store, key, params)| (path.clone(), store, key, params)),
        };

        match loaded {
            Ok((path, store, key, params)) => {
                self.failed_unlocks = 0;
                self.penalty_until = None;
                self.session = Some(Session {
                    mtime: mtime_of(&path),
                    path,
                    store,
                    key,
                    params,
                    last_activity: Instant::now(),
                    timeout_secs: config.lock_timeout_secs,
                });
                Ok(self.status())
            }
            Err(error) => {
                self.failed_unlocks = self.failed_unlocks.saturating_add(1);
                let secs = crate::app::unlock_penalty_secs(self.failed_unlocks);
                if secs > 0 {
                    self.penalty_until = Some(Instant::now() + Duration::from_secs(secs));
                }
                Err(HostError::new("unlock_failed", error))
            }
        }
    }

    fn search(&mut self, request: &Value) -> HostResult {
        let url = field(request, "url")?;
        let session = self.session()?;
        let matches: Vec<Value> = session
            .store
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| loginable(entry) && matching::url_matches(&entry.url, url))
            .map(|(index, entry)| {
                json!({
                    "id": index,
                    "label": entry.label,
                    "username": entry.username,
                    "url": entry.url,
                    "exact": matching::url_matches_exact(&entry.url, url),
                    "has_totp": entry.totp_secret.is_some(),
                    "has_password": true,
                    "has_passkey": !entry.passkeys.is_empty(),
                })
            })
            .collect();
        Ok(object(json!({ "matches": matches })))
    }

    fn get_login(&mut self, request: &Value) -> HostResult {
        let url = field(request, "url")?;
        // Not `id`: that key carries the request id the reply echoes back.
        let index = request
            .get("entry")
            .and_then(Value::as_u64)
            .ok_or_else(|| HostError::bad_request("missing field `entry`"))?
            as usize;
        let exact = request.get("exact").and_then(Value::as_bool) == Some(true);
        // Indexes shift when the vault is reordered; these pin the entry.
        let label = optional_field(request, "label");
        let username = request.get("username").and_then(Value::as_str);
        let session = self.session()?;
        let entry = session
            .store
            .entries
            .get(index)
            .filter(|entry| {
                loginable(entry)
                    && if exact {
                        matching::url_matches_exact(&entry.url, url)
                    } else {
                        matching::url_matches(&entry.url, url)
                    }
                    && label.is_none_or(|label| entry.label == label)
                    && username.is_none_or(|username| entry.username == username)
            })
            .ok_or_else(|| HostError::new("not_found", "No matching login for this page"))?;

        let totp = entry
            .totp_secret
            .as_deref()
            .and_then(crate::ui_tabs::view::build_totp)
            .and_then(|totp| totp.generate_current().ok());
        Ok(object(json!({
            "username": entry.username,
            "password": entry.password.as_str(),
            "totp": totp,
        })))
    }

    fn save_login(&mut self, request: &mut Value) -> HostResult {
        let url = field(request, "url")?.to_string();
        let username = field(request, "username")?.to_string();
        let password = Zeroizing::new(field(request, "password")?.to_string());
        if let Some(Value::String(copy)) = request.get_mut("password") {
            copy.zeroize();
        }
        let title = optional_field(request, "title").map(str::to_string);
        if password.is_empty() {
            return Err(HostError::bad_request("password is empty"));
        }
        if !matching::is_secure_page(&url) {
            return Err(HostError::bad_request(
                "logins are only saved from HTTPS pages",
            ));
        }
        let host =
            matching::host_of(&url).ok_or_else(|| HostError::bad_request("page has no host"))?;
        if matching::is_public_suffix(&host) {
            return Err(HostError::bad_request("not a site that can hold logins"));
        }
        let scheme = url.split_once("://").map_or("https", |(scheme, _)| scheme);
        // Loopback entries keep their port so they only match that server.
        let origin = match matching::port_of(&url) {
            Some(port)
                if host == "localhost"
                    || host.starts_with('[')
                    || host.ends_with(".localhost")
                    || host == "127.0.0.1" =>
            {
                format!("{scheme}://{host}:{port}")
            }
            _ => format!("{scheme}://{host}"),
        };

        let session = self.session()?;
        let mut next = session.store.clone();
        // Only the same host is updated: a subdomain page must not rewrite a
        // parent-domain entry.
        let existing = next.entries.iter().position(|entry| {
            matchable(entry)
                && entry.username.eq_ignore_ascii_case(&username)
                && matching::url_matches_exact(&entry.url, &url)
        });

        let (action, index) = match existing {
            Some(index) => {
                let entry = &mut next.entries[index];
                if entry.password.as_str() == password.as_str() {
                    ("unchanged", index)
                } else {
                    record_password_change(entry, &password, now_unix());
                    entry.password = password;
                    ("updated", index)
                }
            }
            None => {
                next.entries.push(PasswordEntry {
                    label: title.unwrap_or_else(|| host.clone()),
                    username,
                    password,
                    url: origin,
                    created_at: Some(now_unix()),
                    ..Default::default()
                });
                ("created", next.entries.len() - 1)
            }
        };
        if action != "unchanged" {
            session.commit(next)?;
        }
        // `entry`, not `id`: the reply's `id` is the request id.
        Ok(object(json!({ "action": action, "entry": index })))
    }

    /// Validated, canonical (trimmed, lower-case) rp id plus the origin.
    fn passkey_context(request: &Value) -> Result<(String, &str), HostError> {
        let rp_id = field(request, "rp_id")?.trim().to_ascii_lowercase();
        let origin = field(request, "origin")?;
        if !matching::rp_id_valid_for_origin(&rp_id, origin) {
            return Err(HostError::bad_request(
                "relying party id is not valid for this origin",
            ));
        }
        Ok((rp_id, origin))
    }

    fn excluded_ids(request: &Value) -> Vec<&str> {
        request
            .get("exclude")
            .and_then(Value::as_array)
            .map(|ids| ids.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    /// What creating a passkey would do, so the prompt can say so up front.
    fn passkey_check(&mut self, request: &Value) -> HostResult {
        let (rp_id, _) = Self::passkey_context(request)?;
        let user_handle = field(request, "user_id")?;
        let excluded = Self::excluded_ids(request);
        let session = self.session()?;
        let live = session.store.entries.iter().filter(|e| !is_trashed(e));
        let mut replaces = false;
        let mut already = false;
        for pk in live.flat_map(|entry| entry.passkeys.iter()) {
            if pk.rp_id != rp_id {
                continue;
            }
            replaces |= pk.user_handle == user_handle;
            already |= excluded.contains(&pk.credential_id.as_str());
        }
        Ok(object(json!({ "replaces": replaces, "excluded": already })))
    }

    fn passkey_create(&mut self, request: &Value) -> HostResult {
        let (rp_id, _) = Self::passkey_context(request)?;
        let user_handle = field(request, "user_id")?;
        let user_name = field(request, "user_name")?;
        let display_name = optional_field(request, "user_display_name").unwrap_or(user_name);
        let rp_name = optional_field(request, "rp_name")
            .unwrap_or(&rp_id)
            .to_string();
        let excluded = Self::excluded_ids(request);

        let session = self.session()?;
        let already_registered = session.store.entries.iter().any(|entry| {
            !is_trashed(entry)
                && entry
                    .passkeys
                    .iter()
                    .any(|pk| pk.rp_id == rp_id && excluded.contains(&pk.credential_id.as_str()))
        });
        if already_registered {
            return Err(HostError::new(
                "excluded",
                "A passkey for this account already exists",
            ));
        }

        let created = passkey::create(
            &rp_id,
            passkey::UserInfo {
                handle: user_handle,
                name: user_name,
                display_name,
            },
        );

        // Work on a copy: the old passkey only goes once the new one is saved.
        let mut next = session.store.clone();
        for entry in next.entries.iter_mut() {
            entry
                .passkeys
                .retain(|pk| !(pk.rp_id == rp_id && pk.user_handle == user_handle));
        }

        let origin_url = format!("https://{rp_id}");
        let target = next.entries.iter().position(|entry| {
            matchable(entry)
                && entry.username.eq_ignore_ascii_case(user_name)
                && matching::url_matches_exact(&entry.url, &origin_url)
        });
        match target {
            Some(index) => next.entries[index].passkeys.push(created.passkey.clone()),
            None => next.entries.push(PasswordEntry {
                label: rp_name,
                username: user_name.to_string(),
                url: origin_url,
                created_at: Some(now_unix()),
                passkeys: vec![created.passkey.clone()],
                ..Default::default()
            }),
        }
        session.commit(next)?;

        Ok(object(json!({
            "credential_id": created.passkey.credential_id,
            "x": created.x,
            "y": created.y,
        })))
    }

    fn passkey_list(&mut self, request: &Value) -> HostResult {
        let (rp_id, _) = Self::passkey_context(request)?;
        let allowed: Vec<&str> = request
            .get("allow")
            .and_then(Value::as_array)
            .map(|ids| ids.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        let session = self.session()?;
        let credentials: Vec<Value> = session
            .store
            .entries
            .iter()
            .filter(|entry| !is_trashed(entry))
            .flat_map(|entry| entry.passkeys.iter())
            .filter(|pk| {
                pk.rp_id == rp_id
                    && (allowed.is_empty() || allowed.contains(&pk.credential_id.as_str()))
            })
            .map(|pk| {
                json!({
                    "credential_id": pk.credential_id,
                    "user_id": pk.user_handle,
                    "user_name": pk.user_name,
                    "user_display_name": pk.user_display_name,
                    "created_at": pk.created_at,
                })
            })
            .collect();
        Ok(object(json!({ "credentials": credentials })))
    }

    fn passkey_sign(&mut self, request: &Value) -> HostResult {
        let (rp_id, _) = Self::passkey_context(request)?;
        let credential_id = field(request, "credential_id")?;
        let data = passkey::b64_decode(field(request, "data")?).map_err(HostError::bad_request)?;
        // authenticatorData (rp id hash, flags, counter) || clientDataHash.
        if data.len() < 37 || data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
            return Err(HostError::bad_request(
                "data is not authenticator data for this relying party",
            ));
        }

        let session = self.session()?;
        let found = session
            .store
            .entries
            .iter()
            .filter(|entry| !is_trashed(entry))
            .flat_map(|entry| entry.passkeys.iter())
            .find(|pk| pk.rp_id == rp_id && pk.credential_id == credential_id)
            .ok_or_else(|| HostError::new("not_found", "No such passkey"))?;
        let signature = passkey::sign(found, &data).map_err(|e| HostError::new("io", e))?;
        Ok(object(json!({
            "signature": passkey::b64_encode(&signature),
            "user_id": found.user_handle,
        })))
    }
}

fn read_keyfile(path: &Path) -> Result<Zeroizing<Vec<u8>>, HostError> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| HostError::new("keyfile_invalid", format!("Keyfile unreadable: {e}")))?;
    if metadata.len() > KEYFILE_MAX_BYTES {
        return Err(HostError::new("keyfile_invalid", "Keyfile is too large"));
    }
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| HostError::new("keyfile_invalid", format!("Keyfile unreadable: {e}")))
}

#[cfg(test)]
mod tests;

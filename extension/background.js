"use strict";
// Background page: owns the native-messaging port to `aegis --native-host`,
// decides what content scripts and extension pages may ask for, and runs the
// passkey flows. The vault, its key and all signing stay in the host process.

const HOST_NAME = "aegis";
const W = self.AegisWebAuthn;
const PENDING_SAVE_TTL_MS = 2 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 10 * 1000;

// ---------------------------------------------------------------- native host

let port = null;
let nextRequestId = 1;
const HOST_TIMEOUT_MS = 30 * 1000;
const inflight = new Map();

function failAll(error) {
  for (const { reject, timer } of inflight.values()) {
    clearTimeout(timer);
    reject(error);
  }
  inflight.clear();
}

function hostError(code, message) {
  return Object.assign(new Error(message), { code });
}

function connect() {
  if (port) return port;
  try {
    port = browser.runtime.connectNative(HOST_NAME);
  } catch (error) {
    throw hostError("host_unavailable", String(error));
  }
  port.onMessage.addListener((reply) => {
    const call = inflight.get(reply.id);
    if (!call) return;
    inflight.delete(reply.id);
    clearTimeout(call.timer);
    if (reply.ok) call.resolve(reply);
    else call.reject(hostError(reply.code || "error", reply.error || "Request failed"));
  });
  port.onDisconnect.addListener((p) => {
    const detail = p.error ? p.error.message : browser.runtime.lastError?.message;
    port = null;
    failAll(hostError("host_unavailable", detail || "Native host disconnected"));
  });
  return port;
}

function host(cmd, payload = {}) {
  return new Promise((resolve, reject) => {
    let p;
    try {
      p = connect();
    } catch (error) {
      reject(error);
      return;
    }
    const id = nextRequestId++;
    const timer = setTimeout(() => {
      inflight.delete(id);
      reject(hostError("host_timeout", "Aegis did not answer in time"));
    }, HOST_TIMEOUT_MS);
    inflight.set(id, { resolve, reject, timer });
    try {
      // Payload first: it must never be able to override the request id.
      p.postMessage({ ...payload, id, cmd });
    } catch (error) {
      clearTimeout(timer);
      inflight.delete(id);
      reject(hostError("host_unavailable", String(error)));
    }
  });
}

// ------------------------------------------------------------------- settings

const DEFAULT_SETTINGS = { autofill: true };

async function getSettings() {
  const stored = await browser.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(stored.settings || {}) };
}

// ----------------------------------------------------------- pending save/badge

const pendingSaves = new Map(); // tabId -> { url, username, password, at, timer }

function setBadge(tabId, text) {
  browser.action.setBadgeText({ tabId, text }).catch(() => {});
  if (text) browser.action.setBadgeBackgroundColor({ tabId, color: "#2f6df6" }).catch(() => {});
}

function dropPending(tabId) {
  clearTimeout(pendingSaves.get(tabId)?.timer);
  pendingSaves.delete(tabId);
  setBadge(tabId, "");
}

function livePending(tabId) {
  const pending = pendingSaves.get(tabId);
  if (pending && Date.now() - pending.at > PENDING_SAVE_TTL_MS) {
    dropPending(tabId);
    return null;
  }
  return pending || null;
}

browser.tabs.onRemoved.addListener((tabId) => dropPending(tabId));

async function noteSubmittedLogin(tabId, url, username, password) {
  if (!password) return;
  dropPending(tabId);
  const timer = setTimeout(() => dropPending(tabId), PENDING_SAVE_TTL_MS);
  pendingSaves.set(tabId, { url, username, password, at: Date.now(), timer });
  setBadge(tabId, "+");
}

// ------------------------------------------------------------------- autofill

function isSecureUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1"].includes(u.hostname));
  } catch {
    return false;
  }
}

// `match` is a search result; label and username pin the entry in case the
// vault was reordered between the search and this call.
async function credentialsFor(url, match, extra = {}) {
  const reply = await host("get_login", {
    url,
    entry: match.id,
    label: match.label,
    username: match.username,
    ...extra,
  });
  return { username: reply.username, password: reply.password, totp: reply.totp };
}

// Content script asks on page load. Only an exact host match with a single
// candidate is filled; subdomain matches wait for a click in the popup.
// Passive requests don't count as activity, so background pages can't keep
// the vault unlocked.
async function autofillQuery(tab, frameId, url) {
  if (frameId !== 0 || !isSecureUrl(url)) return { status: "none" };
  if (!(await getSettings()).autofill) return { status: "disabled" };
  try {
    const { matches } = await host("search", { url, passive: true });
    const exact = matches.filter((m) => m.exact);
    if (exact.length !== 1) return { status: exact.length ? "ambiguous" : "none" };
    return { status: "fill", ...(await credentialsFor(url, exact[0], { exact: true, passive: true })) };
  } catch (error) {
    return { status: error.code === "locked" ? "locked" : "error" };
  }
}

async function fillTab(tabId, id) {
  const tab = await browser.tabs.get(tabId);
  const url = tab.url;
  if (!isSecureUrl(url)) throw hostError("insecure", "Logins are only filled on HTTPS pages");
  const { matches } = await host("search", { url });
  let match;
  if (id === undefined) {
    if (matches.length === 0) throw hostError("not_found", "No saved login for this site");
    if (matches.length > 1) throw hostError("ambiguous", "Several logins match this site");
    match = matches[0];
  } else {
    match = matches.find((m) => m.id === id);
    if (!match) throw hostError("not_found", "That login is no longer available");
  }
  const creds = await credentialsFor(url, match);
  // The content script checks the URL again so a navigation can't redirect the fill.
  const result = await browser.tabs.sendMessage(tabId, { type: "fill", url, ...creds }, { frameId: 0 });
  return result || { filled: false };
}

browser.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  try {
    await fillTab(tab.id);
  } catch (error) {
    if (error.code === "ambiguous" || error.code === "locked") {
      browser.action.openPopup().catch(() => {});
    }
  }
});

// ------------------------------------------------------------------- passkeys

let nextPromptId = 1;
const prompts = new Map(); // id -> { details, resolve, windowId }

function openPrompt(details) {
  return new Promise(async (resolve) => {
    const id = nextPromptId++;
    const entry = { details, resolve, windowId: null };
    prompts.set(id, entry);
    try {
      const win = await browser.windows.create({
        url: browser.runtime.getURL(`prompt.html?id=${id}`),
        type: "popup",
        width: 460,
        height: 620,
      });
      entry.windowId = win.id;
    } catch {
      prompts.delete(id);
      resolve({ decision: "fallback" });
    }
  });
}

function settlePrompt(id, result) {
  const entry = prompts.get(id);
  if (!entry) return;
  prompts.delete(id);
  entry.resolve(result);
  if (entry.windowId !== null) browser.windows.remove(entry.windowId).catch(() => {});
}

browser.windows.onRemoved.addListener((windowId) => {
  for (const [id, entry] of prompts) {
    if (entry.windowId === windowId) {
      prompts.delete(id);
      entry.resolve({ decision: "cancel" });
    }
  }
});

function validatePasskeyRequest(origin, request) {
  const rpId = String(request.rpId || "").trim().toLowerCase();
  return W.rpIdValidFor(new URL(origin).hostname, rpId) ? rpId : null;
}

// The page controls these, so keep them bounded even if the page script is bypassed.
const MAX_DESCRIPTORS = 64;
const MAX_ID_CHARS = 1400;
const MAX_TEXT = 256;

function idList(list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > MAX_DESCRIPTORS) return null;
  const ids = [];
  for (const item of list) {
    const id = typeof item === "string" ? item : item && item.id;
    if (typeof id !== "string" || id.length > MAX_ID_CHARS) return null;
    ids.push(id);
  }
  return ids;
}

function boundedText(value, max = MAX_TEXT) {
  return typeof value === "string" && value.length <= max;
}

// One approval window per tab at a time; a page can't stack prompts.
const busyTabs = new Set();

async function exclusivePerTab(tabId, work) {
  if (busyTabs.has(tabId)) return { error: "NotAllowedError" };
  busyTabs.add(tabId);
  try {
    return await work();
  } finally {
    busyTabs.delete(tabId);
  }
}

function passkeyCreate(tab, frameId, url, request, activation) {
  if (frameId !== 0 || !isSecureUrl(url) || !activation) return { fallback: true };
  return exclusivePerTab(tab.id, () => doPasskeyCreate(url, request));
}

function passkeyGet(tab, frameId, url, request, activation) {
  if (frameId !== 0 || !isSecureUrl(url) || !activation) return { fallback: true };
  return exclusivePerTab(tab.id, () => doPasskeyGet(url, request));
}

async function doPasskeyCreate(url, request) {
  const origin = new URL(url).origin;
  const exclude = idList(request.excludeCredentials);
  const user = request.user;
  if (
    !exclude || !user || !boundedText(user.id, 86) || !boundedText(user.name) || !boundedText(user.displayName) ||
    !boundedText(request.challenge, MAX_ID_CHARS) || !boundedText(request.rpName || "")
  ) {
    return { fallback: true };
  }
  const rpId = validatePasskeyRequest(origin, request);
  if (!rpId) return { error: "SecurityError" };

  const algs = request.pubKeyCredParams || [];
  if (algs.length && !algs.some((p) => p.alg === -7)) return { fallback: true };
  if (request.authenticatorAttachment === "cross-platform") return { fallback: true };
  try {
    await host("status");
  } catch {
    return { fallback: true };
  }

  const outcome = await openPrompt({
    kind: "create",
    origin,
    rpId,
    rpName: request.rpName || rpId,
    user: { id: user.id, name: user.name, displayName: user.displayName },
    excludeCredentials: exclude,
  });
  if (outcome.decision === "fallback") return { fallback: true };
  if (outcome.decision !== "approve") return { error: "NotAllowedError" };

  let created;
  try {
    created = await host("passkey_create", {
      rp_id: rpId,
      origin,
      rp_name: request.rpName,
      user_id: user.id,
      user_name: user.name,
      user_display_name: user.displayName,
      exclude,
    });
  } catch (error) {
    return { error: error.code === "excluded" ? "InvalidStateError" : "NotAllowedError" };
  }

  const credentialId = W.b64urlDecode(created.credential_id);
  const x = W.b64urlDecode(created.x);
  const y = W.b64urlDecode(created.y);
  const authData = await W.buildAuthData({ rpId, credentialId, coseKey: W.coseKeyEs256(x, y) });
  const clientData = W.clientDataJson({ type: "webauthn.create", challenge: request.challenge, origin });
  return {
    result: {
      id: created.credential_id,
      clientDataJSON: W.b64urlEncode(clientData),
      attestationObject: W.b64urlEncode(W.attestationObjectNone(authData)),
      authenticatorData: W.b64urlEncode(authData),
      publicKey: W.b64urlEncode(W.spkiEs256(x, y)),
      publicKeyAlgorithm: -7,
    },
  };
}

async function listPasskeys(origin, rpId, allow) {
  const reply = await host("passkey_list", { rp_id: rpId, origin, allow });
  return reply.credentials;
}

async function doPasskeyGet(url, request) {
  const origin = new URL(url).origin;
  const allow = idList(request.allowCredentials);
  if (!allow || !boundedText(request.challenge, MAX_ID_CHARS)) return { fallback: true };
  const rpId = validatePasskeyRequest(origin, { rpId: request.rpId || new URL(origin).hostname });
  if (!rpId) return { error: "SecurityError" };

  let locked = false;
  let candidates = [];
  try {
    candidates = await listPasskeys(origin, rpId, allow);
  } catch (error) {
    if (error.code === "locked") locked = true;
    else return { fallback: true };
  }
  // Nothing of ours could answer this request: let the browser handle it.
  if (!locked && candidates.length === 0) return { fallback: true };

  const outcome = await openPrompt({ kind: "get", origin, rpId, allow, candidates, locked });
  if (outcome.decision === "fallback") return { fallback: true };
  if (outcome.decision !== "approve") return { error: "NotAllowedError" };

  const authData = await W.buildAuthData({ rpId });
  const clientData = W.clientDataJson({ type: "webauthn.get", challenge: request.challenge, origin });
  const clientDataHash = await W.sha256(clientData);
  let signed;
  try {
    signed = await host("passkey_sign", {
      rp_id: rpId,
      origin,
      credential_id: outcome.credentialId,
      data: W.b64urlEncode(W.concat(authData, clientDataHash)),
    });
  } catch {
    return { error: "NotAllowedError" };
  }
  return {
    result: {
      id: outcome.credentialId,
      clientDataJSON: W.b64urlEncode(clientData),
      authenticatorData: W.b64urlEncode(authData),
      signature: signed.signature,
      userHandle: signed.user_id,
    },
  };
}

// ------------------------------------------------------------------- messages

const EXTENSION_ORIGIN = browser.runtime.getURL("");

function fromExtensionPage(sender) {
  return sender.id === browser.runtime.id && typeof sender.url === "string" && sender.url.startsWith(EXTENSION_ORIGIN);
}

function describeError(error) {
  return { ok: false, code: error.code || "error", error: error.message || String(error) };
}

// Requests from web-page content scripts: a deliberately small surface.
async function handleContentMessage(message, sender) {
  const tabId = sender.tab.id;
  switch (message.type) {
    case "autofill-query":
      return autofillQuery(sender.tab, sender.frameId, sender.url);
    case "login-submitted":
      if (sender.frameId === 0 && isSecureUrl(sender.url)) {
        await noteSubmittedLogin(tabId, sender.url, String(message.username || ""), String(message.password || ""));
      }
      return { ok: true };
    case "passkey-create":
      return passkeyCreate(sender.tab, sender.frameId, sender.url, message.request || {}, message.userActivation === true);
    case "passkey-get":
      return passkeyGet(sender.tab, sender.frameId, sender.url, message.request || {}, message.userActivation === true);
    default:
      return { ok: false, error: "unsupported" };
  }
}

// Requests from the popup and the passkey prompt window.
async function handleExtensionMessage(message) {
  switch (message.type) {
    case "status": {
      const status = await host("status");
      return { ok: true, status, settings: await getSettings() };
    }
    case "unlock": {
      const status = await host("unlock", {
        password: message.password,
        path: message.path,
        keyfile: message.keyfile,
      });
      if ((await getSettings()).autofill && message.tabId !== undefined) {
        fillTab(message.tabId).catch(() => {});
      }
      return { ok: true, status };
    }
    case "lock":
      await host("lock");
      return { ok: true };
    case "search": {
      const { matches } = await host("search", { url: message.url });
      return { ok: true, matches, pending: livePendingFor(message.tabId) };
    }
    case "fill":
      return { ok: true, ...(await fillTab(message.tabId, message.id)) };
    case "totp": {
      const tab = await browser.tabs.get(message.tabId);
      const creds = await credentialsFor(tab.url, { id: message.id, label: message.label, username: message.username });
      return { ok: true, totp: creds.totp };
    }
    case "clear-clipboard-later":
      clearClipboardLater(String(message.text || ""));
      return { ok: true };
    case "save-pending": {
      const pending = livePending(message.tabId);
      if (!pending) return { ok: false, code: "not_found", error: "Nothing to save" };
      const reply = await host("save_login", {
        url: pending.url,
        username: pending.username,
        password: pending.password,
        title: message.title,
      });
      dropPending(message.tabId);
      return { ok: true, action: reply.action, entry: reply.entry };
    }
    case "dismiss-pending":
      dropPending(message.tabId);
      return { ok: true };
    case "set-settings": {
      const next = { ...(await getSettings()), ...message.settings };
      await browser.storage.local.set({ settings: next });
      return { ok: true, settings: next };
    }
    case "prompt-info": {
      const entry = prompts.get(message.id);
      if (!entry) return { ok: false, code: "gone", error: "This request is no longer active" };
      const { details } = entry;
      let status;
      try {
        status = await host("status");
      } catch (error) {
        return describeError(error);
      }
      let candidates = details.candidates;
      let locked = !status.unlocked;
      let replaces = false;
      if (details.kind === "create" && status.unlocked) {
        try {
          const check = await host("passkey_check", {
            rp_id: details.rpId,
            origin: details.origin,
            user_id: details.user.id,
            exclude: details.excludeCredentials,
          });
          replaces = check.replaces;
        } catch (error) {
          locked = error.code === "locked";
        }
      }
      if (details.kind === "get" && status.unlocked) {
        try {
          candidates = await listPasskeys(details.origin, details.rpId, details.allow);
        } catch (error) {
          locked = error.code === "locked";
        }
      }
      return { ok: true, details: { ...details, candidates, replaces }, status, locked };
    }
    case "prompt-decision":
      settlePrompt(message.id, {
        decision: message.decision,
        credentialId: message.credentialId,
      });
      return { ok: true };
    default:
      return { ok: false, error: "unsupported" };
  }
}

// Copied one-time codes shouldn't linger: wipe the clipboard if it still holds the code.
function clearClipboardLater(text) {
  if (!text) return;
  setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText("");
    } catch {}
  }, CLIPBOARD_CLEAR_MS);
}

function livePendingFor(tabId) {
  const pending = livePending(tabId);
  return pending ? { url: pending.url, username: pending.username } : null;
}

browser.runtime.onMessage.addListener((message, sender) => {
  if (!message || typeof message.type !== "string") return undefined;
  if (fromExtensionPage(sender)) {
    return handleExtensionMessage(message).catch(describeError);
  }
  if (sender.tab && sender.id === browser.runtime.id) {
    return handleContentMessage(message, sender).catch((error) => ({ status: "error", ...describeError(error) }));
  }
  return undefined;
});

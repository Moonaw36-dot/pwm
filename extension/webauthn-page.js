"use strict";
// Runs in the page's own JavaScript world (manifest `world: "MAIN"`), before
// the page's scripts. It wraps navigator.credentials.create/get for WebAuthn
// requests and forwards them to content.js through DOM events. Anything it
// cannot or should not handle goes straight to the browser's own
// implementation, so security keys and other authenticators keep working.
//
// The page can see and tamper with this script; that is fine, because it only
// forwards requests the page could make anyway. Origin checks, the approval
// prompt and all signing happen outside the page.

(() => {
  if (window.__aegisWebAuthn) return;
  const proto = window.CredentialsContainer && window.CredentialsContainer.prototype;
  if (!proto || typeof proto.create !== "function" || typeof proto.get !== "function") return;
  Object.defineProperty(window, "__aegisWebAuthn", { value: true });

  const nativeCreate = proto.create;
  const nativeGet = proto.get;
  const pending = new Map();
  let sequence = 0;

  window.addEventListener("aegis:res", (event) => {
    let reply;
    try {
      reply = JSON.parse(event.detail);
    } catch {
      return;
    }
    const resolve = pending.get(reply && reply.id);
    if (resolve) {
      pending.delete(reply.id);
      resolve(reply);
    }
  });

  function bridgeAlive() {
    const root = document.documentElement;
    return !!root && root.getAttribute("data-aegis-bridge") === "1";
  }

  function ask(type, payload) {
    return new Promise((resolve) => {
      const id = ++sequence;
      pending.set(id, resolve);
      window.dispatchEvent(new CustomEvent("aegis:req", { detail: JSON.stringify({ id, type, payload }) }));
    });
  }

  function bytesOf(source) {
    if (source instanceof ArrayBuffer) return new Uint8Array(source);
    if (ArrayBuffer.isView(source)) return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    return null;
  }

  function encode(source) {
    const bytes = bytesOf(source);
    if (!bytes) return null;
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decode(text) {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function define(target, name, value) {
    Object.defineProperty(target, name, { value, enumerable: false, configurable: true, writable: false });
  }

  // Beyond these the browser's own implementation gets the request.
  const MAX_DESCRIPTORS = 64;
  const MAX_ID_BYTES = 1024;
  const MAX_CHALLENGE_BYTES = 1024;
  const MAX_TEXT = 256;

  // null when the list is too big to relay.
  function credentialDescriptors(list) {
    if (list === undefined || list === null) return [];
    if (!Array.isArray(list) || list.length > MAX_DESCRIPTORS) return null;
    const ids = [];
    for (const c of list) {
      if (!c || c.type !== "public-key") continue;
      const bytes = bytesOf(c.id);
      if (!bytes || bytes.length > MAX_ID_BYTES) return null;
      ids.push(encode(c.id));
    }
    return ids;
  }

  function smallBytes(source, max) {
    const bytes = bytesOf(source);
    return bytes && bytes.length > 0 && bytes.length <= max ? encode(source) : null;
  }

  function activeNow() {
    return !!(navigator.userActivation && navigator.userActivation.isActive);
  }

  function raise(reply) {
    const messages = {
      NotAllowedError: "The operation either timed out or was not allowed.",
      InvalidStateError: "The user attempted to register an authenticator that contains one of the credentials already registered.",
      SecurityError: "The relying party ID is not a registrable domain suffix of, nor equal to the current domain.",
    };
    return new DOMException(messages[reply.error] || "The operation failed.", reply.error || "NotAllowedError");
  }

  function makeResponse(prototype, fields) {
    const response = Object.create(prototype || Object.prototype);
    for (const [name, value] of Object.entries(fields)) define(response, name, value);
    return response;
  }

  function makeCredential(result, response, json) {
    const credential = Object.create(window.PublicKeyCredential ? window.PublicKeyCredential.prototype : Object.prototype);
    define(credential, "id", result.id);
    define(credential, "rawId", decode(result.id));
    define(credential, "type", "public-key");
    define(credential, "authenticatorAttachment", "platform");
    define(credential, "response", response);
    define(credential, "getClientExtensionResults", () => ({}));
    define(credential, "toJSON", () => ({
      id: result.id,
      rawId: result.id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: json,
    }));
    return credential;
  }

  function registrationCredential(result) {
    const clientDataJSON = decode(result.clientDataJSON);
    const attestationObject = decode(result.attestationObject);
    const authenticatorData = decode(result.authenticatorData);
    const publicKey = decode(result.publicKey);
    const response = makeResponse(window.AuthenticatorAttestationResponse && window.AuthenticatorAttestationResponse.prototype, {
      clientDataJSON,
      attestationObject,
      getTransports: () => ["internal"],
      getAuthenticatorData: () => authenticatorData,
      getPublicKey: () => publicKey,
      getPublicKeyAlgorithm: () => result.publicKeyAlgorithm,
    });
    return makeCredential(result, response, {
      clientDataJSON: result.clientDataJSON,
      attestationObject: result.attestationObject,
      authenticatorData: result.authenticatorData,
      transports: ["internal"],
      publicKey: result.publicKey,
      publicKeyAlgorithm: result.publicKeyAlgorithm,
    });
  }

  function assertionCredential(result) {
    const response = makeResponse(window.AuthenticatorAssertionResponse && window.AuthenticatorAssertionResponse.prototype, {
      clientDataJSON: decode(result.clientDataJSON),
      authenticatorData: decode(result.authenticatorData),
      signature: decode(result.signature),
      userHandle: result.userHandle ? decode(result.userHandle) : null,
    });
    return makeCredential(result, response, {
      clientDataJSON: result.clientDataJSON,
      authenticatorData: result.authenticatorData,
      signature: result.signature,
      userHandle: result.userHandle,
    });
  }

  function wrapped(name, native, handler) {
    const wrapper = {
      [name](options) {
        const args = arguments;
        const fallback = () => Reflect.apply(native, this, args);
        if (!options || !options.publicKey || !bridgeAlive()) return fallback();
        if (options.signal && options.signal.aborted) return fallback();
        return handler(options, fallback);
      },
    }[name];
    Object.defineProperty(proto, name, { value: wrapper, writable: true, configurable: true, enumerable: true });
  }

  wrapped("create", nativeCreate, async (options, fallback) => {
    const pk = options.publicKey;
    const challenge = smallBytes(pk.challenge, MAX_CHALLENGE_BYTES);
    const userId = pk.user && smallBytes(pk.user.id, 64);
    if (!challenge || !userId || !pk.user.name) return fallback();
    const name = String(pk.user.name);
    const displayName = String(pk.user.displayName || name);
    if (name.length > MAX_TEXT || displayName.length > MAX_TEXT) return fallback();
    const exclude = credentialDescriptors(pk.excludeCredentials);
    if (!exclude) return fallback();
    const rpName = String((pk.rp && pk.rp.name) || "");
    if (rpName.length > MAX_TEXT) return fallback();
    if (!activeNow()) return fallback();

    const reply = await ask("create", {
      rpId: (pk.rp && pk.rp.id) || location.hostname,
      rpName,
      challenge,
      user: { id: userId, name, displayName },
      pubKeyCredParams: (pk.pubKeyCredParams || []).map((p) => ({ type: p.type, alg: p.alg })),
      excludeCredentials: exclude,
      authenticatorAttachment: pk.authenticatorSelection && pk.authenticatorSelection.authenticatorAttachment,
    });
    if (reply.fallback) return fallback();
    if (reply.error || !reply.result) throw raise(reply);
    return registrationCredential(reply.result);
  });

  wrapped("get", nativeGet, async (options, fallback) => {
    const pk = options.publicKey;
    if (options.mediation === "conditional") return fallback();
    const challenge = smallBytes(pk.challenge, MAX_CHALLENGE_BYTES);
    if (!challenge) return fallback();
    const allow = credentialDescriptors(pk.allowCredentials);
    if (!allow) return fallback();
    if (!activeNow()) return fallback();

    const reply = await ask("get", {
      rpId: pk.rpId || location.hostname,
      challenge,
      allowCredentials: allow.map((id) => ({ id })),
    });
    if (reply.fallback) return fallback();
    if (reply.error || !reply.result) throw raise(reply);
    return assertionCredential(reply.result);
  });
})();

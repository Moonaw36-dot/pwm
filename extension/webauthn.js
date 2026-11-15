// Pure WebAuthn helpers shared by the background page and the Node tests.
// Nothing here touches the vault: key generation and signing happen in the
// native host, this file only assembles the structures the browser expects.
(function (root) {
  "use strict";

  const textEncoder = new TextEncoder();

  function b64urlEncode(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64urlDecode(text) {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  function cborHead(major, n) {
    if (n < 24) return Uint8Array.of((major << 5) | n);
    if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
    if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
    return Uint8Array.of((major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }

  // Minimal CBOR encoder: integers, text, byte strings, arrays and Maps
  // (Map keeps insertion order, which COSE keys and attestation objects need).
  function cborEncode(value) {
    if (typeof value === "number") {
      if (!Number.isInteger(value)) throw new TypeError("only integers are supported");
      return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
    }
    if (typeof value === "string") {
      const bytes = textEncoder.encode(value);
      return concat(cborHead(3, bytes.length), bytes);
    }
    if (value instanceof Uint8Array) return concat(cborHead(2, value.length), value);
    if (Array.isArray(value)) return concat(cborHead(4, value.length), ...value.map(cborEncode));
    if (value instanceof Map) {
      const parts = [cborHead(5, value.size)];
      for (const [k, v] of value) parts.push(cborEncode(k), cborEncode(v));
      return concat(...parts);
    }
    throw new TypeError("unsupported CBOR value");
  }

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }

  const FLAG_UP = 0x01;
  const FLAG_UV = 0x04;
  const FLAG_AT = 0x40;

  // COSE_Key for an ES256 public key (kty EC2, alg -7, crv P-256).
  function coseKeyEs256(x, y) {
    return cborEncode(
      new Map([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, x],
        [-3, y],
      ]),
    );
  }

  // SubjectPublicKeyInfo DER for an uncompressed P-256 point.
  const SPKI_P256_PREFIX = Uint8Array.of(
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
  );
  function spkiEs256(x, y) {
    return concat(SPKI_P256_PREFIX, x, y);
  }

  // Authenticator data. Counters are always 0: the vault is not a hardware
  // token, and sites must treat 0 as "counter not supported".
  async function buildAuthData({ rpId, credentialId, coseKey }) {
    const rpIdHash = await sha256(textEncoder.encode(rpId));
    let flags = FLAG_UP | FLAG_UV;
    const parts = [rpIdHash, null, Uint8Array.of(0, 0, 0, 0)];
    if (coseKey) {
      flags |= FLAG_AT;
      parts.push(
        new Uint8Array(16), // AAGUID: none
        Uint8Array.of(credentialId.length >> 8, credentialId.length & 0xff),
        credentialId,
        coseKey,
      );
    }
    parts[1] = Uint8Array.of(flags);
    return concat(...parts);
  }

  // "none" attestation: the credential is software-backed and unattested.
  function attestationObjectNone(authData) {
    return cborEncode(
      new Map([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", authData],
      ]),
    );
  }

  function clientDataJson({ type, challenge, origin }) {
    return textEncoder.encode(
      JSON.stringify({ type, challenge, origin, crossOrigin: false }),
    );
  }

  // Hosts nobody should be able to claim as a whole. Keep in sync with
  // PUBLIC_SUFFIXES in src/native_host/matching.rs.
  const PUBLIC_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz",
    "co.jp", "or.jp", "ne.jp", "co.in", "net.in", "org.in", "co.za",
    "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk", "com.tw",
    "co.kr", "co.il", "github.io", "gitlab.io", "herokuapp.com", "pages.dev",
    "workers.dev", "vercel.app", "netlify.app", "web.app", "firebaseapp.com",
    "appspot.com", "blogspot.com", "azurewebsites.net", "cloudfront.net",
    "onrender.com", "fly.dev", "glitch.me", "repl.co", "surge.sh",
    "s3.amazonaws.com", "amazonaws.com", "myshopify.com", "wordpress.com",
    "000webhostapp.com", "ngrok.io", "ngrok-free.app",
  ]);

  function isPublicSuffix(host) {
    host = String(host || "").toLowerCase().replace(/\.+$/, "");
    if (!host || host === "localhost" || host.startsWith("[") || /^[0-9.]+$/.test(host)) return false;
    return !host.includes(".") || PUBLIC_SUFFIXES.has(host);
  }

  // May a page on `host` use `rpId` as its WebAuthn relying party id?
  function rpIdValidFor(host, rpId) {
    host = String(host || "").toLowerCase();
    rpId = String(rpId || "").trim().toLowerCase();
    if (!rpId || rpId !== rpId.replace(/^\.+|\.+$/g, "") || host.startsWith("[") || /^[0-9.]+$/.test(rpId)) return false;
    if (isPublicSuffix(rpId)) return false;
    return host === rpId || host.endsWith("." + rpId);
  }

  const api = {
    isPublicSuffix,
    rpIdValidFor,
    b64urlEncode,
    b64urlDecode,
    concat,
    sha256,
    cborEncode,
    coseKeyEs256,
    spkiEs256,
    buildAuthData,
    attestationObjectNone,
    clientDataJson,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.AegisWebAuthn = api;
})(typeof self !== "undefined" ? self : globalThis);

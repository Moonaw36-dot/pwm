"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const W = require("../webauthn.js");

const hex = (bytes) => Buffer.from(bytes).toString("hex");

// Tiny CBOR decoder, just enough to read back what the encoder produced.
function cborDecode(bytes) {
  let pos = 0;
  function read() {
    const initial = bytes[pos++];
    const major = initial >> 5;
    let n = initial & 31;
    if (n === 24) n = bytes[pos++];
    else if (n === 25) { n = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2; }
    else if (n === 26) { n = bytes.readUInt32BE(pos); pos += 4; }
    else if (n > 26) throw new Error("unsupported length");
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { const out = bytes.subarray(pos, pos + n); pos += n; return Buffer.from(out); }
      case 3: { const out = bytes.subarray(pos, pos + n).toString("utf8"); pos += n; return out; }
      case 4: return Array.from({ length: n }, read);
      case 5: { const map = new Map(); for (let i = 0; i < n; i++) { const k = read(); map.set(k, read()); } return map; }
      default: throw new Error("unsupported major type " + major);
    }
  }
  const value = read();
  return { value, rest: bytes.subarray(pos) };
}

test("base64url round-trips and is URL safe", () => {
  const bytes = Uint8Array.of(0xfb, 0xff, 0xfe, 0x01, 0x02);
  const text = W.b64urlEncode(bytes);
  assert.doesNotMatch(text, /[+/=]/);
  assert.deepEqual(W.b64urlDecode(text), bytes);
  assert.deepEqual(W.b64urlDecode(""), new Uint8Array());
});

test("CBOR encoder matches RFC 8949 vectors", () => {
  assert.equal(hex(W.cborEncode(0)), "00");
  assert.equal(hex(W.cborEncode(23)), "17");
  assert.equal(hex(W.cborEncode(24)), "1818");
  assert.equal(hex(W.cborEncode(1000)), "1903e8");
  assert.equal(hex(W.cborEncode(100000)), "1a000186a0");
  assert.equal(hex(W.cborEncode(-1)), "20");
  assert.equal(hex(W.cborEncode(-7)), "26");
  assert.equal(hex(W.cborEncode("IETF")), "6449455446");
  assert.equal(hex(W.cborEncode(Uint8Array.of(1, 2, 3, 4))), "4401020304");
  assert.equal(hex(W.cborEncode([1, 2, 3])), "83010203");
  assert.equal(hex(W.cborEncode(new Map([[1, 2], [3, -7], [-1, 1]]))), "a30102032620" + "01");
  assert.throws(() => W.cborEncode(1.5));
  assert.throws(() => W.cborEncode({}));
});

test("COSE key is a canonical ES256 key and its SPKI imports into WebCrypto", async () => {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const x = W.b64urlDecode(jwk.x), y = W.b64urlDecode(jwk.y);

  const cose = cborDecode(Buffer.from(W.coseKeyEs256(x, y))).value;
  assert.deepEqual([...cose.keys()], [1, 3, -1, -2, -3]);
  assert.equal(cose.get(1), 2);
  assert.equal(cose.get(3), -7);
  assert.equal(cose.get(-1), 1);
  assert.deepEqual(cose.get(-2), Buffer.from(x));
  assert.deepEqual(cose.get(-3), Buffer.from(y));

  const spki = W.spkiEs256(x, y);
  assert.equal(spki.length, 91);
  const imported = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const roundTrip = await crypto.subtle.exportKey("jwk", imported);
  assert.equal(roundTrip.x, jwk.x);
  assert.equal(roundTrip.y, jwk.y);
});

test("registration authenticator data has the layout RPs parse", async () => {
  const credentialId = Uint8Array.from({ length: 32 }, (_, i) => i);
  const x = new Uint8Array(32).fill(7), y = new Uint8Array(32).fill(9);
  const coseKey = W.coseKeyEs256(x, y);
  const authData = Buffer.from(await W.buildAuthData({ rpId: "example.com", credentialId, coseKey }));

  const expectedHash = Buffer.from(await W.sha256(new TextEncoder().encode("example.com")));
  assert.deepEqual(authData.subarray(0, 32), expectedHash);
  assert.equal(authData[32], 0x45, "UP | UV | AT");
  assert.equal(authData.readUInt32BE(33), 0, "signature counter");
  assert.deepEqual(authData.subarray(37, 53), Buffer.alloc(16), "AAGUID");
  assert.equal(authData.readUInt16BE(53), 32);
  assert.deepEqual(authData.subarray(55, 87), Buffer.from(credentialId));
  assert.deepEqual(authData.subarray(87), Buffer.from(coseKey));
});

test("assertion authenticator data omits attested credential data", async () => {
  const authData = Buffer.from(await W.buildAuthData({ rpId: "example.com" }));
  assert.equal(authData.length, 37);
  assert.equal(authData[32], 0x05, "UP | UV");
});

test("attestation object is a 'none' statement wrapping the authenticator data", async () => {
  const authData = await W.buildAuthData({ rpId: "example.com" });
  const decoded = cborDecode(Buffer.from(W.attestationObjectNone(authData)));
  assert.equal(decoded.rest.length, 0);
  assert.equal(decoded.value.get("fmt"), "none");
  assert.equal(decoded.value.get("attStmt").size, 0);
  assert.deepEqual(decoded.value.get("authData"), Buffer.from(authData));
});

test("client data JSON carries the checked origin and challenge", () => {
  const json = JSON.parse(
    new TextDecoder().decode(W.clientDataJson({ type: "webauthn.get", challenge: "abc_-", origin: "https://example.com" })),
  );
  assert.deepEqual(json, { type: "webauthn.get", challenge: "abc_-", origin: "https://example.com", crossOrigin: false });
});

test("public suffixes cannot be relying party ids", () => {
  for (const host of ["com", "co.uk", "github.io", "herokuapp.com", "intranet"]) {
    assert.equal(W.isPublicSuffix(host), true, host);
  }
  for (const host of ["example.com", "alice.github.io", "localhost", "127.0.0.1"]) {
    assert.equal(W.isPublicSuffix(host), false, host);
  }
  assert.equal(W.rpIdValidFor("login.example.com", "example.com"), true);
  assert.equal(W.rpIdValidFor("example.com", "login.example.com"), false);
  assert.equal(W.rpIdValidFor("alice.github.io", "github.io"), false);
  assert.equal(W.rpIdValidFor("shop.co.uk", "co.uk"), false);
  assert.equal(W.rpIdValidFor("localhost", "localhost"), true);
  assert.equal(W.rpIdValidFor("example.com", "ample.com"), false);
});

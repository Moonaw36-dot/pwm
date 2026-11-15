"use strict";
// End-to-end check of the native host against the extension's own WebAuthn
// code: registers a passkey through the real `aegis --native-host` process,
// then verifies an assertion signature with WebCrypto. Skipped unless
//   AEGIS_E2E_BIN=<path to aegis binary>  AEGIS_E2E_VAULT=<fixture vault>
// are set (see write_extension_fixture_vault in src/native_host/tests.rs).
const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const W = require("../webauthn.js");

const BIN = process.env.AEGIS_E2E_BIN;
const VAULT = process.env.AEGIS_E2E_VAULT;
const MASTER = "correct horse battery staple 42";
const ORIGIN = "https://login.example.com/signin";
const skip = !BIN || !VAULT;

class Host {
  constructor() {
    this.child = spawn(BIN, ["--native-host"], { stdio: ["pipe", "pipe", "inherit"] });
    this.buffer = Buffer.alloc(0);
    this.waiting = new Map();
    this.nextId = 1;
    this.child.stdout.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      while (this.buffer.length >= 4) {
        const length = this.buffer.readUInt32LE(0);
        if (this.buffer.length < 4 + length) break;
        const message = JSON.parse(this.buffer.subarray(4, 4 + length).toString("utf8"));
        this.buffer = this.buffer.subarray(4 + length);
        this.waiting.get(message.id)?.(message);
        this.waiting.delete(message.id);
      }
    });
  }
  call(cmd, payload = {}) {
    return new Promise((resolve) => {
      const id = this.nextId++;
      this.waiting.set(id, resolve);
      const body = Buffer.from(JSON.stringify({ id, cmd, ...payload }));
      const head = Buffer.alloc(4);
      head.writeUInt32LE(body.length, 0);
      this.child.stdin.write(Buffer.concat([head, body]));
    });
  }
  close() {
    this.child.stdin.end();
  }
}

function derToRaw(der) {
  assert.equal(der[0], 0x30);
  let pos = 2;
  const ints = [];
  for (let i = 0; i < 2; i++) {
    assert.equal(der[pos++], 0x02);
    const len = der[pos++];
    let int = der.subarray(pos, pos + len);
    pos += len;
    while (int.length > 32 && int[0] === 0) int = int.subarray(1);
    ints.push(Buffer.concat([Buffer.alloc(32 - int.length), int]));
  }
  return Buffer.concat(ints);
}

test("host drives a full passkey registration and sign-in", { skip }, async () => {
  const host = new Host();
  try {
    assert.equal((await host.call("search", { url: "https://example.com" })).code, "locked");
    assert.equal((await host.call("unlock", { path: VAULT, password: "wrong" })).code, "unlock_failed");
    assert.equal((await host.call("unlock", { path: VAULT, password: MASTER })).ok, true);

    const found = await host.call("search", { url: "https://example.com/login" });
    assert.equal(found.matches.length, 1);
    const login = await host.call("get_login", { entry: found.matches[0].id, url: "https://example.com/login" });
    assert.equal(login.password, "s3cret");

    // Registration, assembled exactly as background.js does.
    const userId = W.b64urlEncode(Buffer.from("user-1"));
    const created = await host.call("passkey_create", {
      rp_id: "example.com", origin: ORIGIN, rp_name: "Example",
      user_id: userId, user_name: "alice", user_display_name: "Alice",
    });
    assert.equal(created.ok, true, JSON.stringify(created));
    const x = W.b64urlDecode(created.x), y = W.b64urlDecode(created.y);
    const credentialId = W.b64urlDecode(created.credential_id);
    const regAuthData = await W.buildAuthData({ rpId: "example.com", credentialId, coseKey: W.coseKeyEs256(x, y) });
    assert.ok(W.attestationObjectNone(regAuthData).length > regAuthData.length);

    // Sign-in: the host signs authData || SHA-256(clientDataJSON).
    const authData = await W.buildAuthData({ rpId: "example.com" });
    const clientData = W.clientDataJson({ type: "webauthn.get", challenge: "Y2hhbGxlbmdl", origin: "https://login.example.com" });
    const signedData = W.concat(authData, await W.sha256(clientData));
    const signed = await host.call("passkey_sign", {
      rp_id: "example.com", origin: ORIGIN,
      credential_id: created.credential_id, data: W.b64urlEncode(signedData),
    });
    assert.equal(signed.ok, true, JSON.stringify(signed));
    assert.equal(signed.user_id, userId);

    const publicKey = await crypto.subtle.importKey("spki", W.spkiEs256(x, y), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const rawSignature = derToRaw(Buffer.from(W.b64urlDecode(signed.signature)));
    assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, rawSignature, signedData), true);
    assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, rawSignature, W.concat(signedData, Uint8Array.of(1))), false);

    // Attached to the existing example.com login rather than a new entry.
    const listed = await host.call("passkey_list", { rp_id: "example.com", origin: ORIGIN });
    assert.equal(listed.credentials.length, 1);
    assert.equal((await host.call("search", { url: "https://example.com/" })).matches[0].has_passkey, true);
  } finally {
    host.close();
  }
});

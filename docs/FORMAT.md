# Aegis vault file format

This document describes the vault file format exactly as implemented in
[`aegis-core/src/format.rs`](../aegis-core/src/format.rs) (bytes and crypto)
and [`aegis-core/src/model.rs`](../aegis-core/src/model.rs) (plaintext JSON).
The code is the authority; if the two disagree, the code wins and this file is
out of date.

All multi-byte integers are **unsigned 32-bit little-endian**. Sizes are in
bytes unless stated otherwise.

## 1. Current layout: format v2

| Offset | Size | Field        | Notes                                                  |
|-------:|-----:|--------------|--------------------------------------------------------|
| 0      | 4    | `magic`      | ASCII `AEGS` (`41 45 47 53`)                           |
| 4      | 1    | `version`    | Must be `0x02` (`FORMAT_VERSION`)                       |
| 5      | 16   | `salt`       | Argon2id salt (`SALT_LEN`)                             |
| 21     | 4    | `m_cost`     | Argon2 memory cost in KiB, u32 LE                      |
| 25     | 4    | `t_cost`     | Argon2 iterations, u32 LE                              |
| 29     | 4    | `p_cost`     | Argon2 lanes (parallelism), u32 LE                     |
| 33     | 12   | `nonce`      | AES-GCM nonce (`NONCE_LEN`)                            |
| 45     | n+16 | `ciphertext` | AES-256-GCM ciphertext of the n-byte plaintext, followed by the 16-byte GCM tag |

The header is bytes `0..45` (`HEADER_LEN_V2 = 45`). There is no length field;
the ciphertext runs to the end of the file. There is no padding.

### Parsing rules (`parse_header_v2` / `open_v2`)

Applied in this order; the first failure is returned:

1. `open` first rejects any input shorter than 16 bytes ("File is too short to
   be a valid store"), whatever its prefix.
2. If the file starts with `AEGS` it is treated as v2, with no fallback to the
   legacy layouts.
3. The file must be **longer** than 45 bytes (at least one ciphertext byte),
   otherwise "Vault file is truncated or corrupted". In practice a valid file
   is at least 61 bytes (45 header + 16 tag), and anything shorter than that
   fails GCM authentication.
4. `version` must equal 2. Other values get a "Vault version N is not
   supported" error, so that a future v3 file gives a clear message instead of
   a decryption failure.
5. KDF parameters must be within the bounds in section 2. Out-of-range values
   are rejected **before** any key derivation runs ("Vault file is
   corrupted").

`parse_header_v2` does all of this without key derivation. It is public so it
can be fuzzed on its own.

## 2. Key derivation

### Argon2id

```
argon_key = Argon2id(version = 0x13,
                     password = UTF-8 bytes of the master password,
                     salt     = header salt (16 bytes),
                     m = m_cost KiB, t = t_cost, p = p_cost,
                     output length = 32)
```

No secret ("pepper") and no associated data are passed to Argon2. The
implementation is the RustCrypto `argon2` crate 0.5, with default features
(single-threaded, so `p_cost` lanes are computed one after another).

| Parameter | Default (`KdfParams::default`) | Accepted range (`validate_kdf_params`) |
|-----------|-------------------------------:|-----------------------------------------|
| `m_cost`  | 65536 KiB (64 MiB)             | 8 ..= 1 048 576 KiB (1 GiB)             |
| `t_cost`  | 3                              | 1 ..= 20                                |
| `p_cost`  | 1                              | 1 ..= 8                                 |

On top of these bounds the `argon2` crate requires `m_cost >= 8 * p_cost`.
Headers that break this rule fail with an "Argon2 params" error (not a
panic) after validation passes.

The bounds exist because the header is untrusted input. They put a ceiling on
the cost of opening a hostile file. The ceiling is still high: one Argon2 run
using up to 1 GiB of memory and 20 passes. Nothing enforces a *minimum*
strength on open beyond `m_cost >= 8`, `t_cost >= 1`; see 7.3.

### Keyfile combination (current)

If a keyfile is used, its raw bytes (any length, including empty) are mixed in
after Argon2:

```
PRK = HMAC-SHA256(key = argon_key, msg = keyfile)
key = HMAC-SHA256(key = PRK,       msg = "aegis keyfile" || 0x01)
```

This is exactly RFC 5869 HKDF-SHA256 with `salt = argon_key`,
`IKM = keyfile`, `info = "aegis keyfile"` (13 ASCII bytes, no terminator) and
`L = 32` (a single expand block, `T(1)`). `hmac_sha256` is a local RFC 2104
implementation with a 64-byte block; keys longer than 64 bytes are hashed
first. Here the HMAC key is always 32 bytes, so that branch never runs.

Without a keyfile, `key = argon_key`.

### Keyfile combination (legacy)

Vaults written before the HKDF combiner used:

```
key = SHA-256(argon_key || keyfile)
```

When a keyfile is supplied, `open` tries both combiners in that order (HKDF
first). New files are always sealed with whatever key the caller passes in;
`UnlockedVault::create`/`change_password` use `derive_key`, which uses the HKDF
combiner. A vault that opened through the legacy combiner keeps that key
(`Opened.key`) and is re-sealed with it until the password is changed.

## 3. Encryption

* Cipher: AES-256-GCM (RustCrypto `aes-gcm` 0.10), 32-byte key from section 2,
  16-byte tag.
* Nonce: 96 bits from the OS CSPRNG (`Aes256Gcm::generate_nonce(&mut OsRng)`),
  freshly generated on **every** `seal`.
* AAD: the complete 45-byte header (magic, version, salt, the three costs and
  the nonce itself), byte for byte as written to the file.

`seal` always writes v2 with header AAD. Nothing writes the older forms any
more.

### Decryption order and the no-AAD fallback

For a v2 file, `open_v2` derives `argon_key` once, then tries each candidate
key in order and returns the first success:

| # | Key                                         | AAD          |
|---|---------------------------------------------|--------------|
| 1 | HKDF combiner (or `argon_key` if no keyfile) | 45-byte header |
| 2 | same                                        | none (empty) |
| 3 | legacy SHA-256 combiner (keyfile only)      | 45-byte header |
| 4 | same                                        | none (empty) |

The no-AAD attempts exist for v2 files written by earlier desktop versions,
before the header was authenticated as AAD. Such a file is upgraded to AAD
form the next time it is saved, because `seal` always uses AAD.

All failures return the same "Decryption failed: wrong master password or
corrupted file" error. There is no way to tell a wrong password from a
corrupted ciphertext.

#### Is the no-AAD fallback exploitable?

**Conclusion: no.** For v2 the AAD is defence in depth. What actually binds the
header to the ciphertext is the key derivation. Field by field:

* `salt`, `m_cost`, `t_cost`, `p_cost` are all Argon2id inputs (they are
  hashed into Argon2's initial block H0). Changing any of them gives an
  unrelated key, so the GCM tag fails under both the AAD and the no-AAD
  attempts. An attacker cannot lower the costs of an existing file, with or
  without AAD, unless they already know the password (and keyfile).
* `nonce` is the GCM nonce. Changing it breaks the tag.
* `magic` is a constant. Changing it sends the file down the legacy path,
  which uses different key-derivation inputs and offsets and therefore fails.
* `version` must equal 2. Any other value is rejected before decryption.

So every header byte is either a fixed constant or bound through the key or
nonce, whether or not AAD was used. For a file sealed **with** AAD, the
fallback also cannot be used to strip the header binding: a GCM tag computed
over AAD `A` verifies with empty AAD only with probability about 2^-128,
because GHASH covers the AAD blocks and the length block.

What the fallback does cost:

* Up to 4 tag checks per open instead of 1 or 2. Each forged ciphertext
  therefore has about 4 x 2^-128 chance to pass, which is negligible.
* Weaker *intended* semantics: v2 files written by pre-AAD versions are
  authenticated only implicitly, through the key, as explained above.

The fallback (and the legacy combiner) could be removed once no pre-AAD
vaults remain. Doing so would not change the security of current files.

## 4. Plaintext: vault JSON

The plaintext is UTF-8 JSON written by `serde_json::to_vec_pretty`
(pretty-printed, two-space indent). Its shape is `PasswordList`:

```jsonc
{
  "entries": [ PasswordEntry, ... ],   // required
  "...": ...                          // any other keys: preserved (see below)
}
```

`PasswordEntry`: every field is optional on input (`#[serde(default)]`) and
always written on output.

| Field              | JSON type                     | Default        |
|--------------------|-------------------------------|----------------|
| `label`            | string                        | `""`           |
| `username`         | string                        | `""`           |
| `password`         | string                        | `""`           |
| `notes`            | string                        | `""`           |
| `totp_secret`      | string or null                | null           |
| `tags`             | array of strings, or null     | null           |
| `url`              | string                        | `""`           |
| `custom_fields`    | array of `[name, value]` 2-element string arrays | `[]` |
| `is_secure_note`   | bool                          | false          |
| `created_at`       | u64 (Unix seconds) or null    | null           |
| `password_type`    | `"Normal"` \| `"Card"` \| `"WiFi"` | `"Normal"` |
| `number`           | string or null (card number)  | null           |
| `expiration_date`  | string or null (card)         | null           |
| `cvc`              | string or null (card)         | null           |
| `favorite`         | bool or null                  | null           |
| `trashed_at`       | u64 or null (set = in trash)  | null           |
| `password_history` | array of `PasswordHistory`    | `[]`           |

`PasswordHistory` is `{ "password": string, "changed_at": u64 }`. Both fields
are **required**, and this struct has no `extra` map. `set_password` caps the
history at 10 entries (`PASSWORD_HISTORY_CAP`), dropping the oldest. The cap
is not enforced when a file is parsed.

Parse errors:

* An unknown `password_type` variant gives "This vault was created by a newer
  version of Aegis".
* Any other mismatch gives "Corrupted vault contents: ...". This includes a
  known field with the wrong type, a missing `entries`, or a missing field in
  a history item.
* serde_json's recursion limit (128) rejects pathologically nested input.

### The `extra` preservation rule

Both `PasswordList` and `PasswordEntry` have a `#[serde(flatten)] extra` map.
Any key the current version does not know is captured there, with its full
JSON value, and written back on save. This way an older client never strips
data that a newer one added. Limits:

* It covers the top-level object and each entry object only. Unknown keys
  inside `password_history` items (or inside known fields generally) are
  **silently dropped** on the next save.
* Key order is not preserved (serde_json's default `Map` is sorted), and
  whitespace is not preserved either. The JSON *value* is preserved.
* Numbers round-trip exactly. `aegis-core` enables serde_json's
  `float_roundtrip` feature. Without it, float values in unknown fields
  drifted by one ULP per load/save cycle; the `vault_json` fuzz target found
  this.

## 5. Legacy (pre-v2) layouts

A file that does **not** start with `AEGS` is treated as headerless.
`legacy_attempts` (pure parsing, no key derivation) produces the guesses in
this order:

| Layout | Condition       | Bytes                                         | Params tried, in order (`p_cost = 1`) |
|--------|-----------------|-----------------------------------------------|----------------------------------------|
| A (oldest) | length > 28 | `salt[16] \| nonce[12] \| ciphertext`         | (19456 KiB, t=2), (65536 KiB, t=3)      |
| B      | length > 32     | `salt[16] \| t_cost u32 LE \| nonce[12] \| ciphertext` | (65536, t\*), (65536, 3), (19456, 2), (65536, 2) |

`t*` is the stored `t_cost` if it is in `1..=20`, otherwise 3. Some pairs can
repeat (for example `t* = 3`); nothing deduplicates them.

For each (layout, params) pair, `open` derives the Argon2id key with the
fixed params (the stored `t_cost` in B is the only header-chosen input). It
then tries the candidate keys (HKDF, then legacy combiner, when a keyfile is
given), always **without** AAD. Files of 16..=28 bytes without the magic
produce no attempts and fail with the generic decryption error, without any
key derivation.

Costs and quirks:

* Opening a hostile non-`AEGS` file can cost up to 6 Argon2 runs (2 for
  layout A, 4 for B), mostly at 64 MiB. That cost is fixed, not chosen by the
  attacker.
* A legacy file whose random salt happens to start with `AEGS` (probability
  2^-32) is routed to the v2 parser and cannot be opened.
* An opened legacy file reports the params that worked. The next save writes
  it as v2 with the same salt and those params.

## 6. Save behaviour (`UnlockedVault`)

* `seal` reuses the key, salt and KDF params the vault was opened or created
  with. Only the nonce changes between saves.
* `change_password` draws a fresh 16-byte salt from the OS RNG and re-derives
  the key with the existing params.
* `create` draws a fresh salt and uses the params the caller passes in.

## 7. Security considerations

### 7.1 Nonce reuse

Every save uses the same key (section 6) with a fresh random 96-bit nonce. The
chance that any two of `q` saves under one key share a nonce is about
`q^2 / 2^97`. That is about 2^-57 for a million saves and about 2^-33 at
`q = 2^32`, which is NIST SP 800-38D's limit for random nonces. A collision
would only matter if an attacker captured both colliding files. For a
password manager that saves at human speed this is negligible. Changing the
password resets the count, because it gives a new salt and so a new key.

### 7.2 Salt reuse across saves (by design)

The salt stays fixed across saves so the app can re-seal without running
Argon2 again (and without the password in memory). Consequences:

* Every saved version of the vault, including backups and sync history,
  shares one key. Recovering the key (or the password) from any copy opens
  all of them until the next password change.
* An offline guessing attack started on one copy applies unchanged to every
  copy. This is the same work as attacking one file, not extra work for the
  defender.
* Two different vaults still get independent random salts, so no
  precomputation carries over between users or vaults.

### 7.3 KDF downgrade resistance

* **Of an existing file:** not possible without the key. The costs are inputs
  to Argon2 (section 3, "Is the no-AAD fallback exploitable?"). An attacker
  who rewrites them gets a file nobody can open.
* **Substitution:** an attacker with write access can replace the whole file
  with one they made themselves, with weak params and their own password. It
  will not open with the user's password, so the user is not silently moved
  onto it. Nothing in the format authenticates *which* vault this is beyond
  "it decrypts with your password".
* **Weak params are accepted:** `open` accepts anything within bounds, down to
  `m_cost = 8 KiB, t_cost = 1`. A vault deliberately created with weak params
  (the API allows it; the desktop app uses the 64 MiB / t=3 defaults) stays
  weak. Nothing upgrades or warns.
* **Denial of service:** a hostile v2 header can request up to 1 GiB and 20
  passes for one open attempt. The bounds turn "unbounded" into "slow", not
  into "cheap".

### 7.4 What is not protected

* **Size and entry count.** There is no padding or compression. The file
  length is `45 + len(JSON) + 16`, and the pretty-printed JSON grows roughly
  linearly with the number of entries and their field lengths. A copy of the
  file therefore leaks approximate vault size. Comparing successive versions
  leaks when entries were added or removed and roughly how large they are.
* **Metadata in the clear:** the KDF params, the salt (and with it whether
  the password was changed between two copies) and the format version.
* **Keyfile presence:** not stored in the file. The same vault decrypts or
  fails, with no hint.
* **Decoy vault detectability (desktop app feature, outside this format).**
  The duress decoy is an ordinary v2 vault, stored next to the real one as
  `<stem>.decoy.aegis`. It is created the first time the duress password is
  used, filled with a fixed generated set of entries, and has no keyfile. The
  per-vault duress password hash sits in the app's `config.json`
  (`duress_by_vault`). This is not a hidden-volume scheme. Anyone who sees the
  directory and config can tell that a decoy exists, and may recognise the
  generated contents. It helps against someone who only ever sees what the
  app shows after unlock, not against forensic inspection.
* **Memory hygiene** is outside the format. Note anyway that `hmac_sha256`
  builds the key-XOR-pad blocks in temporary `Vec`s that are not zeroized.
  When a keyfile is used, those blocks are derived from the Argon2 output.

## 8. Fuzzing and robustness tests

Untrusted-input handling is covered in two places:

* `aegis-core/tests/robustness.rs` runs in normal `cargo test` on stable. It
  covers truncations, single-bit flips at every header offset, random
  mutations of the fixtures, random buffers, out-of-range costs and malformed
  JSON, all with header costs forced small.
* `fuzz/` holds cargo-fuzz targets (`vault_open`, `vault_json`,
  `seal_open_roundtrip`). See [`fuzz/README.md`](../fuzz/README.md) for how to
  run them.

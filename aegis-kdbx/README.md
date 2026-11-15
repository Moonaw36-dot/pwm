# aegis-kdbx

Import and export between KeePass databases (`.kdbx`) and Aegis vault
contents (`aegis_core::model::PasswordList`). It is a separate crate so that
`aegis-core`, which ships in the iOS app, stays small.

```rust
use aegis_kdbx::{export_kdbx, import_kdbx, KdbxCredentials};

let creds = KdbxCredentials { password: Some("master"), keyfile: None };
let (list, report) = import_kdbx(&bytes, creds)?;
for reason in &report.skipped { eprintln!("{reason}"); }
let kdbx: Vec<u8> = export_kdbx(&list, creds)?;
```

* **Import** reads KDBX 3.1 and 4.x files, plus legacy KDB files.
* **Export** writes KDBX 4 with Argon2id (64 MiB, 10 passes, 2 lanes by
  default), AES-256 for the file (ChaCha20 is optional) and ChaCha20 for
  protected fields. `export_kdbx_with(list, creds, ExportOptions { .. })`
  sets the KDF cost and the cipher.
* Credentials can be a password, a keyfile (KeePass XML v1/v2, 32-byte
  binary, 64-char hex, or any other file, which gets hashed), or both.
  An empty password `Some("")` is a valid key and is not the same as `None`.

Built on [`keepass`](https://crates.io/crates/keepass) 0.17 with the
`save_kdbx4` feature.

## Field mapping

| Aegis (`PasswordEntry`)       | KeePass                                                                 | Round trip |
|-------------------------------|-------------------------------------------------------------------------|------------|
| `label`                       | `Title`                                                                 | lossless |
| `username`                    | `UserName`                                                              | lossless |
| `password`                    | `Password` (protected)                                                  | lossless |
| `url`                         | `URL`                                                                   | lossless |
| `notes`                       | `Notes` (protected)                                                     | lossless |
| `totp_secret` (otpauth URL)   | `otp` (protected), copied unchanged                                     | lossless |
| `totp_secret` (bare base32)   | `otp` = `otpauth://totp/<label>?secret=<S>&period=30&digits=6&algorithm=SHA1` (label URL-encoded); turned back into the bare secret on import when the URL matches exactly | lossless after normalisation (spaces and `=` removed, uppercased) |
| `tags`                        | entry `Tags`                                                            | lossless, except tags containing `;` or `,`, which KeePass splits |
| tag `group:A/B`               | entry placed in group `A` → `B` (the tag is not written to `Tags`); on import, the group path (root excluded) becomes `group:A/B` again | placement kept; the tag moves after the plain tags. A `/` in a KeePass group name reads as nesting |
| `custom_fields`               | other string fields (protected). Order is stored as JSON in the entry's CustomData `aegis:field_order` | lossless; names that clash with a standard field or appear twice get ` (2)`, ` (3)`… appended |
| `password_type = Card`        | tag `aegis:card` plus fields `card_number` (protected), `card_expiration`, `card_cvc` (protected) | lossless |
| `password_type = WiFi`        | tag `aegis:wifi`                                                        | lossless |
| `is_secure_note`              | tag `aegis:note`                                                        | lossless |
| `favorite = Some(true)`       | tag `aegis:favorite` (KeePassXC has no favourites)                      | `Some(false)` comes back as `None` |
| `password_history`            | entry history: one version per item (a copy of the entry with the old `Password`, `LastModificationTime = changed_at`), oldest first | lossless |
| `created_at`                  | `Times/CreationTime`                                                    | lossless; `None` is exported as the export time |
| `trashed_at`                  | entry in the recycle bin group, named "Recycle Bin" and set as the recycle bin in Meta, with `Times/LocationChanged = trashed_at`. A trashed entry's `group:` tag becomes a subgroup of the bin | lossless |
| `extra` (unknown fields)      | entry CustomData `aegis:extra` (JSON); list-level `extra` goes in Meta CustomData `aegis:extra` | lossless |

### Importing files made by other KeePass apps

* **TOTP.** The order of precedence is: `otp` (an otpauth URL, KeeOtp
  `key=…&step=…&size=…&otpHashMode=…`, or a bare secret), then KeePassXC's
  legacy `TOTP Seed`/`TOTP Settings`, then KeePass 2.47+'s
  `TimeOtp-Secret-Base32`/`-Period`/`-Length`/`-Algorithm`. Non-default
  parameters become an otpauth URL. Steam TOTP and unsupported algorithms
  stay as custom fields and are listed in the report. Legacy fields are not
  read in entries Aegis exported, so they come back as custom fields.
* **History.** Versions in a row that share a password count as one; the
  later timestamp is kept. Versions whose password is still the current one
  are dropped. Only the newest `PASSWORD_HISTORY_CAP` (10) are kept.
  `changed_at` gets the version's `LastModificationTime`. That is
  approximate for files from other apps, because KeePass records when each
  version was made, not when its password was replaced.
* **Recycle bin.** Entries in the group named in Meta `RecycleBinUUID`
  (subgroups included) get `trashed_at` = `LocationChanged`, then
  `LastModificationTime`, then the current time, whichever is found first.
* **Not imported** (there is no Aegis equivalent):
  * listed in `ImportReport::skipped`: attachments (binaries) and expiry
    dates;
  * dropped without a report entry: icons, colours, auto-type settings,
    group notes, other apps' CustomData, and other metadata. The
    attachments of history versions are dropped too.

### Notes

* KeePass keeps fields in a map, so the order of custom fields comes from
  `aegis:field_order`. Fields that list does not name follow, sorted by
  name.
* Entries whose `<String>` elements are not next to each other (pykeepass
  writes them that way) fail to parse in keepass-rs 0.17 by default
  ("duplicate field `String`"). This crate turns on quick-xml's
  `overlapped-lists` feature to make them readable.
* Protected values are held in `Zeroizing` buffers on the Aegis side, and in
  keepass-rs as `SecretBox`es, which are zeroized on drop. `DatabaseKey`
  zeroizes itself too. Unprotected KeePass fields (title, username, URL)
  and keepass-rs's internal plaintext XML buffers are not zeroized.

## Tests

* `tests/roundtrip.rs`: exports a rich `PasswordList` and imports it again,
  then compares every field. It covers AES and ChaCha20, password plus
  keyfile, keyfile alone, wrong credentials, renamed fields, and the KDBX4
  header with Argon2id.
* `tests/external_fixture.rs`: imports `tests/fixtures/pykeepass.kdbx`,
  which an independent implementation wrote with
  `python3 -I tests/fixtures/gen.py tests/fixtures/pykeepass.kdbx`
  (pykeepass 4.2.0). The file has a nested group, an `otp` field, tags,
  custom fields, an attachment (which must show up as skipped) and a
  recycle-bin entry.

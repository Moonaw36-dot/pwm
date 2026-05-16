# Aegis

Aegis is a minimalist, local-first desktop password manager written in Rust. It stores your vault as a single encrypted `.aegis` file and unlocks it with a master password that is never stored.

Vault contents stay in files you control. Aegis does not provide cloud sync; the only network feature is the Health tab's Have I Been Pwned password check, which uses the k-anonymity API by sending only a SHA-1 hash prefix.

## Features

### Vault and security

- Local `.aegis` vault files encrypted with **AES-256-GCM**
- **Argon2id** master-password key derivation for new vaults
- Optional keyfile support for an additional unlock factor
- Fresh nonce on every save, with the vault salt preserved for unlocks
- Atomic saves via temporary files and rename
- Private file permissions on Unix-like systems where supported
- Sensitive in-memory fields use `zeroize` where practical
- Configurable idle auto-lock, including the option to disable it

### Entry management

- Add, edit, delete, and search entries
- Normal password entries with label, username, password, URL, notes, tags, custom fields, and optional TOTP secret
- Secure notes with masked display and click-to-copy note contents
- Payment card entries with masked card display, issuer hints, Luhn validation, expiry, and CVC fields
- URL opening for `http://` and `https://` entry links
- CSV import/export for backup and migration

### Password tooling

- Random password generator with configurable length and character sets
- Passphrase generator backed by the bundled wordlist
- Password strength meter and warnings before saving weak passwords
- Vault health report for weak, reused, old, and known-compromised passwords
- TOTP code generation with countdown display

### Clipboard behavior

- One-click copy for passwords, usernames, TOTP codes, secure notes, card numbers, and CVCs
- Clipboard auto-clear after 10 seconds
- Clipboard-history exclusion on Linux/Wayland and Windows where supported
- macOS falls back to normal clipboard writes followed by timed clear

## Requirements

- A Rust toolchain that supports edition 2024
- OpenGL-capable graphics drivers
- Native windowing dependencies for your platform

On Debian/Ubuntu-like Linux systems, the desktop stack may require packages such as:

```bash
sudo apt install libgl1-mesa-dev libglu1-mesa-dev libxkbcommon-dev libwayland-dev libx11-dev libxcb1-dev libxrandr-dev libxi-dev libxcursor-dev
```

## Building and running

```bash
cargo build --release
./target/release/aegis
```

For development checks:

```bash
cargo check
cargo test
cargo test -- --include-ignored
```

The ignored tests include slower Argon2-related checks.

## Basic usage

1. Start Aegis.
2. Use **Files → Create** to create a new vault, choose a filename, and set a strong master password.
3. Use **Files → Open** to open an existing `.aegis` vault. Legacy `.json` vaults are accepted by the file dialog.
4. Use the **Add**, **Modify**, and **Delete** tabs to manage entries.
5. Use the **View passwords** tab to search, copy values, and open saved URLs.
6. Use **Files → Settings** to adjust the auto-lock timeout.

### Keyfiles

After opening or creating a vault, use **Files → Add a key-file** to add an optional keyfile. The keyfile bytes are mixed into the derived encryption key, and a hash of the keyfile is stored in Aegis config for that vault.

If a vault has a keyfile, future unlocks require both the master password and the keyfile. Keep a backup of the keyfile; losing it can make the vault unrecoverable.

### CSV import/export

CSV export writes plaintext passwords after a confirmation dialog. Treat exported files as sensitive and delete or encrypt them after use.

The CSV format is intended for normal password entries and uses these columns:

```csv
label,username,password,url,notes,tags,totp_secret
```

Tags are exported as a semicolon-separated value. CSV import accepts common header aliases such as `name`, `title`, `login`, `email`, `website`, `site`, `note`, `comment`, `tag`, `totp`, and `otp`.

## Controls

| Action | Input |
|---|---|
| Copy normal-entry password | Left click the entry |
| Copy normal-entry username | Right click the entry |
| Copy TOTP code | Middle click the entry |
| Copy secure note contents | Left click the secure note |
| Copy card number | Left click the card entry |
| Copy card CVC | Right click the card entry |
| Open saved URL | Click the URL text |
| Focus search | Ctrl+F |

Copied values are cleared from the clipboard after 10 seconds.

## Vault format

An Aegis vault is a binary file with this layout:

```text
[16 bytes salt] [12 bytes nonce] [AES-256-GCM ciphertext]
```

The ciphertext decrypts to JSON containing the password entries. New vaults use Argon2id with 64 MiB of memory and 3 iterations. Older vaults created with legacy parameters can still be opened through a fallback path.

A fresh nonce is generated on every save. Saves are written to a temporary file and then renamed over the original vault to reduce the chance of partial writes.

## Configuration

Aegis stores non-vault configuration under your system config directory, for example:

```text
~/.config/aegis/config.json
```

The config currently stores the auto-lock timeout and known keyfile hashes by vault path. It does not store your master password or vault contents.

## Stack

| Crate | Role |
|---|---|
| `imgui` / `imgui-glow-renderer` | Immediate-mode UI |
| `glow` / `glutin` / `winit` | OpenGL windowing |
| `aes-gcm` + `argon2` | Encryption and key derivation |
| `zeroize` | Best-effort secure memory wiping |
| `arboard` | Clipboard access and timed clearing |
| `totp-rs` + `base32` | TOTP code generation |
| `csv` | CSV import/export |
| `ureq` + `sha1` | Have I Been Pwned range checks |
| `sha2` | Keyfile hashing and key mixing |
| `rfd` | Native file dialogs |
| `dirs` | Platform config directory lookup |
| `open` | Opening saved URLs in the browser |

## Limitations and security notes

- Aegis has not been formally security-audited.
- There is no master-password recovery. If you forget the master password, the vault cannot be decrypted.
- If you add a keyfile, losing the keyfile can make the vault unrecoverable.
- There is no built-in sync, browser extension, or autofill integration.
- CSV export is plaintext and does not fully round-trip every vault-only field such as card data or custom fields.
- Clipboard-history exclusion is best-effort and platform-dependent.
- Opening the Health tab may contact Have I Been Pwned using SHA-1 hash prefixes, not plaintext passwords.

## License

MIT License with Attribution Requirement — see [LICENSE](LICENSE).

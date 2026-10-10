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
- Automatic timestamped backups to a user-chosen folder, keeping the last 10 (best-effort)
- Private file permissions on Unix-like systems where supported
- Sensitive in-memory fields use `zeroize` where practical
- Configurable idle auto-lock, including the option to disable it

### Entry management

- Add, edit, delete, and search entries
- Normal password entries with label, username, password, URL, notes, tags, custom fields, and optional TOTP secret
- Secure notes with masked display and click-to-copy note contents
- Payment card entries with masked card display, issuer hints, Luhn validation, expiry, and CVC fields
- URL opening for `http://` and `https://` entry links
- CSV import/export for backup and migration, including card, Wi-Fi, secure-note, TOTP, favorite, and custom-field data
- Soft delete with a Trash tab: restore entries, purge individually or empty the trash (all behind confirmation)
- Per-entry password history (last 10 changes) with copy and restore from the Modify dialog

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
sudo apt install libgl1-mesa-dev libglu1-mesa-dev libxkbcommon-dev libwayland-dev libx11-dev libxcb1-dev libxrandr-dev libxi-dev libxcursor-dev libxext-dev libxfixes-dev libxrender-dev libxtst-dev
```

On NixOS, use the included traditional `shell.nix` and launcher. The shell supplies
the X11, Wayland, and OpenGL libraries, including the dynamic library path required
by winit and glutin:

```bash
cargo build --release
./aegis
```

Do not launch `target/release/aegis` directly on NixOS, because that bypasses the
library environment provided by the launcher. If you are already in the release
directory, use:

```bash
nix-shell ../../shell.nix --run ./aegis
```

A working X11 or Wayland session and graphics driver are still required.

To make it available in rofi's command mode, add the launcher to your local PATH:

```bash
mkdir -p ~/.local/bin
ln -sf "$PWD/aegis" ~/.local/bin/aegis
```

For rofi's desktop mode, install a desktop entry with the absolute launcher path:

```bash
mkdir -p ~/.local/share/applications
sed "s|^Exec=.*|Exec=$PWD/aegis|; s|^TryExec=.*|TryExec=$PWD/aegis|" \
  aegis.desktop > ~/.local/share/applications/aegis.desktop
```

## Building and running

```bash
cargo build --release
```

Then launch via the wrapper so the X11/Wayland/OpenGL libraries are present:

```bash
./aegis
```

On non-NixOS systems with the dependencies above installed system-wide,
`./target/release/aegis` also works directly. Inside `nix-shell shell.nix`,
`cargo run --release` works as well.

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

### Duress decoy vault

Each vault can have its own duress password, configured in **Files → Settings** while that vault is open. Entering the duress password at that vault's unlock prompt opens a generated decoy vault instead of the real one. The real vault file is never modified or deleted.

The decoy is stored next to the vault as `<name>.decoy.aegis`, is encrypted with the duress password, and comes pre-filled with plausible-looking entries so it passes casual inspection. It behaves like a normal vault and can be deleted at any time; it is regenerated on the next duress unlock if it is missing.

Older configs kept a single global duress password. On first load it is migrated to the most recently used vault; if no vault was recorded, it is dropped and should be re-set in Settings.

### CSV import/export

CSV export writes plaintext passwords after a confirmation dialog. Treat exported files as sensitive and delete or encrypt them after use.

The CSV format uses these columns:

```csv
label,username,password,url,notes,tags,totp_secret,type,number,expiration_date,cvc,secure_note,custom_fields,favorite
```

Tags are exported as a semicolon-separated value and custom fields as a JSON array. CSV import accepts common header aliases such as `name`, `title`, `login`, `email`, `website`, `site`, `note`, `comment`, `tag`, `totp`, and `otp`. CSV files contain plaintext secrets and should be deleted or encrypted after use.

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

An Aegis vault is a versioned binary file. Saves always write format version 2, which starts with a magic header followed by the Argon2id parameters used to derive the key:

```text
[4 bytes magic "AEGS"] [1 byte format version = 2] [16 bytes salt]
[4 bytes m_cost, little-endian] [4 bytes t_cost, little-endian] [4 bytes p_cost, little-endian]
[12 bytes nonce] [AES-256-GCM ciphertext]
```

Keys are derived with Argon2id (version 0x13, 32-byte output) using the parameters stored in the header, so opening a vault always performs exactly one key derivation. The ciphertext decrypts to JSON containing the password entries. Saving preserves the salt already stored in the vault file and generates a fresh nonce on every save.

Vaults created by older versions of Aegis have no magic header and use one of two layouts: `[16 bytes salt] [12 bytes nonce] [ciphertext]`, or `[16 bytes salt] [4 bytes little-endian Argon2id iterations] [12 bytes nonce] [ciphertext]`. Legacy vaults remain readable and are upgraded to format version 2 the next time the vault is saved.

Saves are written to a temporary file and then renamed over the original vault to reduce the chance of partial writes.

## Configuration

Aegis stores non-vault configuration under your system config directory, for example:

```text
~/.config/aegis/config.json
```

The config currently stores the auto-lock timeout, known keyfile hashes by vault path, and the backup folder (`backup_dir`) used for automatic vault backups. It does not store your master password or vault contents.

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
- There is no built-in sync or autofill integration.
- While unlocked, the derived key is kept in page-locked memory (`mlock`/`VirtualLock`) so it is not swapped to disk. Locking is best-effort: if the OS refuses (for example a low `RLIMIT_MEMLOCK`), the key still stays in ordinary memory and is still wiped on lock.
- After several failed unlock attempts, further attempts are delayed with an increasing backoff (up to one minute). This is an in-app speed bump: it resets when the app restarts and does not protect the vault file from offline attacks — Argon2id remains the real defense there.
- CSV export is plaintext. Treat exported files as sensitive and delete or encrypt them after use.
- Automatic backups are full encrypted vault copies; they unlock with the same master password (and keyfile, if used) as the original vault.
- Clipboard-history exclusion is best-effort and platform-dependent.
- Opening the Health tab may contact Have I Been Pwned using SHA-1 hash prefixes, not plaintext passwords.

## License

MIT License with Attribution Requirement — see [LICENSE](LICENSE).

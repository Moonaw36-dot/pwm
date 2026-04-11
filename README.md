# Aegis

A minimalist desktop password manager built in Rust. Passwords are stored in an encrypted local file — nothing leaves your machine.

## Features

- **AES-256-GCM** encryption with **Argon2** key derivation
- Master password is never stored — derived fresh on every unlock
- Add, edit, delete, and search password entries
- Entry tags for organization
- TOTP (two-factor) code generation per entry
- Built-in password generator with configurable length and charset
- Password strength warnings before saving weak entries
- One-click copy to clipboard (auto-clears after 10 seconds)
- Auto-lock on idle with configurable timeout
- Vault health report (weak and reused passwords)
- CSV export for backup or migration
- Dark, minimal UI

## Building

Requires Rust (edition 2024) and OpenGL drivers. The Inter font is bundled in the repo.

```bash
cargo build --release
./target/release/aegis
```

## How it works

Your vault is a single encrypted file with this layout:

```
[16 bytes salt] [12 bytes nonce] [AES-256-GCM ciphertext]
```

The ciphertext decrypts to a JSON array of password entries. A fresh nonce is generated on every save; the salt is preserved so the derived key stays consistent across the session.

## Controls

| Action | Input |
|---|---|
| Copy password | Left click an entry |
| Copy username | Right click an entry |
| Copy TOTP code | Middle click the TOTP |
| Focus search | Ctrl+F |

All copied values are automatically cleared from the clipboard after 10 seconds.

## Stack

| Crate | Role |
|---|---|
| `imgui` / `imgui-glow-renderer` | Immediate-mode UI |
| `glow` / `glutin` / `winit` | OpenGL windowing |
| `aes-gcm` + `argon2` | Encryption and key derivation |
| `arboard` | Clipboard with auto-clear |
| `totp-rs` | TOTP code generation |
| `rfd` | Native file dialogs |
| `zeroize` | Secure memory wiping |

## Limitations

- Clipboard auto-clear excludes copied values from clipboard history on Linux and Windows; macOS falls back to plain clear after 10 seconds
- Single local file — no cloud sync

## License

MIT — see [LICENSE](LICENSE).

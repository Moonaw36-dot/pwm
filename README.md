# pwm

A minimalist desktop password manager built in Rust. Passwords are stored in an encrypted local file — nothing leaves your machine.

## Features

- **AES-256-GCM** encryption with **Argon2** key derivation
- Master password is never stored — derived fresh on every unlock
- Add, edit, delete, and search password entries
- TOTP (two-factor) code generation per entry
- Built-in password generator with configurable length and charset
- Password strength warnings before saving weak entries
- One-click copy to clipboard (auto-clears after 10 seconds)
- Dark, minimal UI

## Building

Requires the Rust nightly toolchain (edition 2024), OpenGL drivers, and the [Inter](https://rsms.me/inter/) font.

```bash
cargo build --release
./target/release/pwm
```

> **Note:** The font path in `src/main.rs` is hardcoded. Update the `include_bytes!` path on line 126 to point to your local Inter font file before building.

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

## Limitations

- Linux only (clipboard auto-clear uses `arboard::SetExtLinux`)
- Single local file — no cloud sync
- No import/export

## License

This project is not yet licensed. All rights reserved.

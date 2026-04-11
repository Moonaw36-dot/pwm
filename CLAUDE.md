# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

Requires Rust (edition 2024) and OpenGL drivers. The Inter font is bundled in `assets/` and embedded at compile time — no manual font path setup needed.

```bash
cargo build --release
./target/release/pwm
```

There are no tests and no linter configuration beyond `cargo check`/`cargo clippy`.

## Architecture

The app is a single-window imgui desktop app with an immediate-mode UI loop.

**Data flow:**
1. `main.rs` — sets up the OpenGL/winit/glutin window, imgui context, font, and theme. Runs the event loop, forwarding keyboard input manually to imgui and calling `build_ui` each frame.
2. `app.rs` — defines `AppState` (all mutable UI + vault state in one struct), `PasswordEntry`, `PasswordList`, and `build_ui` which renders the main window with its tab bar and dispatches modal popups.
3. `modals.rs` — each modal is a standalone function taking `(&imgui::Ui, &mut AppState)`. Modals are triggered by boolean flags on `AppState`; the flag is set one frame, `open_popup` is called the next (imgui requires this two-frame pattern to nest popups correctly).
4. `file_ops.rs` — all disk I/O. Vault file format: `[16B salt][12B nonce][AES-256-GCM ciphertext]`. The salt is preserved across saves; the nonce is regenerated on every write. Key derivation uses Argon2 (default params). The master password is never stored.
5. `input.rs` — maps winit `Key` + `KeyLocation` to imgui keys. Exists because imgui-winit-support does not handle the keyboard correctly for this winit version.

**Key constraints:**
- Linux-only: clipboard auto-clear uses `arboard::SetExtLinux` (`.exclude_from_history()`).
- No cloud sync, no import/export — vault is a single local encrypted JSON file.
- `AppState` is the sole source of truth; it is passed by `&mut` through every render function each frame.

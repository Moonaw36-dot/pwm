# Code Review Fixes

## Security

- [X] **Keyfile is cryptographic placebo** — `file_ops.rs:333` `load_store` never feeds keyfile bytes to `derive_key`. The keyfile only gates the UI button. Combine keyfile bytes with password before Argon2 (e.g. HKDF or XOR).
- [X] **Vault JSON not zeroized after encrypt** — `file_ops.rs:143` wrap `serde_json::to_string_pretty` result in `Zeroizing::new(...)`.
- [X] **Keyfile bytes not zeroized after hashing** — `file_ops.rs:183` wrap `std::fs::read` result in `Zeroizing<Vec<u8>>`.
- [X] **Auto-lock doesn't clear EntryForm data** — `ui.rs:17-25` call `state.clear_inputs()` in the auto-lock branch so passwords/notes/TOTP don't survive in memory.

## Bugs

- [X] **`create_file` returns `Ok(())` on folder-picker cancel** — `file_ops.rs:155-157` change `return Ok(())` to `return Err("No folder selected")` or handle `None` in the caller at `modals.rs:252`.
- [X] **Empty filename creates hidden `.aegis` file** — `modals.rs:373` add emptiness check after trim: `if state.filename_input.is_empty() { return; }`.
- [X] **`EmptyClipboard()` before `GlobalAlloc`** — `clipboard.rs:48` move `GlobalAlloc` before `EmptyClipboard` so user's clipboard isn't destroyed on allocation failure.
- [ ] **Corrupt config silently resets to defaults** — `config.rs:34` at minimum log the error instead of silently unwrapping.
- [X] **Raw OS error on save if vault was deleted externally** — `file_ops.rs:359` map `std::fs::read` error to user-friendly message.
- [X] **Warning modal "Generate" button doesn't close popup** — `modals.rs:318-321` add `ui.close_current_popup()` or set `warning_password = false` after generating.
- [X] **Double-deref ICE risk (Rust 1.94)** — `ui_tabs.rs:260,293` use `.as_str()` instead of `&entry.password`.

## Code Quality

- [X] **TOTP instance recreated every frame** — `ui_tabs.rs:63-88` cache TOTP object or generated code for 1-2 seconds.
- [X] **`i32` for non-negative values** — `models.rs:54,60,97` switch `length`, `word_count`, `settings_timeout_mins` to `u32`.
- [X] **Unconditional `#![windows_subsystem = "windows"]`** — `main.rs:1` gate behind `#[cfg(target_os = "windows")]`.
- [X] **Magic number for 30-day password age** — `ui_tabs.rs:328` extract to a named constant.
- [X] **"Fair" passwords flagged as weak** — `ui_tabs.rs:261` consider `if score < 2` instead of `if score < 3`.
- [ ] **CSV import/export drops `custom_fields`** — `file_ops.rs:80,104-105` serialize/deserialize custom fields in round-trip.
- [X] **Plaintext passwords as HashMap keys** — `ui_tabs.rs:278` hash passwords before using as map keys.
- [X] **Double `.aegis` extension if user provides one** — `file_ops.rs:160` check if `file_name` already ends with `.aegis`.

---

# Future Features

## Security

- [ ] **Duress mode / self-destruct** — a second master password reveals a decoy vault; entering it during unlock pivots to a fake vault while the real one is destroyed.
- [ ] **Hardware token support** — YubiKey/Nitrokey PIV or HMAC-SHA1 challenge-response required alongside master password for vault unlock.
- [ ] **Argon2id parameter configuration** — make memory (MiB) and iterations user-configurable, or auto-scale to hardware on first unlock.

## Feature Gaps

- [ ] **Cloud sync (WebDAV / Nextcloud)** — sync the `.aegis` vault file to a remote WebDAV or Nextcloud endpoint so the vault stays available across machines without manual file copy.
- [ ] **Browser extension native messaging** — implement the native messaging host protocol so a companion browser extension can read entries and auto-fill credentials in the browser.
- [ ] **Recent files list** — File menu lists last 5 recently opened vaults with absolute paths for quick re-open.
- [ ] **Automatic timed backups** — on each save, copy the vault file to a configurable backup directory with a timestamp suffix.
- [ ] **Entry grouping / folders** — hierarchical folder tree alongside the flat list, with drag-and-drop to organize entries.
- [ ] **Favorites / pinning** — starred entries float to the top of the view list and appear in a separate "Favorites" section.

## Quality-of-Life

- [ ] **Undo delete / trash** — soft-delete entries into a trash folder; restore from trash or permanently delete on vault close.
- [ ] **Password history per entry** — store timestamped SHA-256 hashes of previous passwords; display change timeline in the modify modal.
- [ ] **Quick-open (Ctrl+P)** — fuzzy-finder overlay bar to search and jump to any entry by label, URL, or username without clicking tabs.
- [ ] **Entry templates** — preset forms for common types: credit card, identity, bank account, server/SSH key, Wi-Fi network.
- [ ] **Light theme toggle** — switchable light mode alongside the existing dark theme.
- [ ] **Offline HIBP corpus** — option to download the full HIBP password corpus so compromised-password checks work without internet access.
- [ ] **Emergency sheet export** — generate a printable PDF with all entries (label, username, password, URL, notes) for offline emergency access.
- [ ] **Vault compacting / cleanup** — remove orphaned data (deleted entries, stale custom fields) from vault JSON on save.

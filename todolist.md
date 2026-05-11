# Code Review Fixes

## Security

- [ ] **Keyfile is cryptographic placebo** — `file_ops.rs:333` `load_store` never feeds keyfile bytes to `derive_key`. The keyfile only gates the UI button. Combine keyfile bytes with password before Argon2 (e.g. HKDF or XOR).
- [X] **Vault JSON not zeroized after encrypt** — `file_ops.rs:143` wrap `serde_json::to_string_pretty` result in `Zeroizing::new(...)`.
- [ ] **Keyfile bytes not zeroized after hashing** — `file_ops.rs:183` wrap `std::fs::read` result in `Zeroizing<Vec<u8>>`.
- [X] **Auto-lock doesn't clear EntryForm data** — `ui.rs:17-25` call `state.clear_inputs()` in the auto-lock branch so passwords/notes/TOTP don't survive in memory.

## Bugs

- [ ] **`create_file` returns `Ok(())` on folder-picker cancel** — `file_ops.rs:155-157` change `return Ok(())` to `return Err("No folder selected")` or handle `None` in the caller at `modals.rs:252`.
- [ ] **Empty filename creates hidden `.aegis` file** — `modals.rs:373` add emptiness check after trim: `if state.filename_input.is_empty() { return; }`.
- [ ] **`EmptyClipboard()` before `GlobalAlloc`** — `clipboard.rs:48` move `GlobalAlloc` before `EmptyClipboard` so user's clipboard isn't destroyed on allocation failure.
- [ ] **Corrupt config silently resets to defaults** — `config.rs:34` at minimum log the error instead of silently unwrapping.
- [ ] **Raw OS error on save if vault was deleted externally** — `file_ops.rs:359` map `std::fs::read` error to user-friendly message.
- [ ] **Warning modal "Generate" button doesn't close popup** — `modals.rs:318-321` add `ui.close_current_popup()` or set `warning_password = false` after generating.
- [ ] **Double-deref ICE risk (Rust 1.94)** — `ui_tabs.rs:260,293` use `.as_str()` instead of `&entry.password`.

## Code Quality

- [ ] **Unnecessary `.clone()` in `add_entry_from_inputs`** — `modals.rs:351` use `std::mem::take(&mut state.form.tag)` like the other fields.
- [ ] **`modify_entry_modal` clones password instead of taking** — `modals.rs:519` use `std::mem::replace(..., Zeroizing::new(String::new()))`.
- [ ] **TOTP instance recreated every frame** — `ui_tabs.rs:63-88` cache TOTP object or generated code for 1-2 seconds.
- [ ] **`i32` for non-negative values** — `models.rs:54,60,97` switch `length`, `word_count`, `settings_timeout_mins` to `u32`.
- [ ] **Unconditional `#![windows_subsystem = "windows"]`** — `main.rs:1` gate behind `#[cfg(target_os = "windows")]`.
- [ ] **Magic number for 30-day password age** — `ui_tabs.rs:328` extract to a named constant.
- [ ] **"Fair" passwords flagged as weak** — `ui_tabs.rs:261` consider `if score < 2` instead of `if score < 3`.
- [ ] **CSV import/export drops `custom_fields`** — `file_ops.rs:80,104-105` serialize/deserialize custom fields in round-trip.
- [ ] **Plaintext passwords as HashMap keys** — `ui_tabs.rs:278` hash passwords before using as map keys.
- [ ] **Double `.aegis` extension if user provides one** — `file_ops.rs:160` check if `file_name` already ends with `.aegis`.

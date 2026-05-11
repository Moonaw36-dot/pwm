# Code Review Fixes

## High Priority
- [x] Zeroize password fields: Wrap PasswordEntry.password and strength_cache in Zeroizing<String>
- [x] Increase Argon2 default parameters (64 MiB, 3 iterations)
- [x] Fix NonZeroU32 panic on minimized window in main.rs
- [x] Make clipboard init non-panicking
- [x] Fix clipboard: add fallback for unknown OS targets
- [x] Fix HIBP blocking UI: defer to per-frame one-check or background thread

## Medium Priority
- [x] Fix modify_entry_modal: add secure note support (missing is_secure_note checkbox)
- [x] Fix pwned passwords 'Modify' button: should open modify modal, not generator
- [x] Fix generate_password: guard against empty charset
- [x] Fix save_store TOCTOU: use atomic write (write to temp + rename)
- [x] Improve error handling: replace .ok()? with Result returns in file_ops.rs
- [x] Zeroize intermediate JSON string in load_store
- [x] Add CSV export plaintext warning
- [x] Add unsaved-changes prompt on window close
- [x] Fix vault file extension (.aegis instead of .json)
- [x] Remove CString::new().unwrap() panic in main.rs

## Low Priority
- [x] Fix theme.rs: safe StyleColor indexing
- [x] Add structured logging (env_logger)

## Verify
- [x] Build and verify compilation

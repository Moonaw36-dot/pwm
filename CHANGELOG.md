# Changelog

All notable changes to Aegis are documented here.

## [Unreleased]

### Added

- Versioned vault format (magic `AEGS`, version 2) storing explicit Argon2id
  parameters (memory, iterations, parallelism) in the header, so unlocking
  derives the key exactly once; legacy vaults remain readable and are upgraded
  to the new format on the next save.
- Per-vault duress passwords that open a generated decoy vault instead of the
  real one; the real vault file is never modified or deleted. Legacy single
  duress configurations migrate automatically.
- Password strength estimation via zxcvbn and a NIST-flavored master-password
  policy; the Health tab no longer reveals any password characters.
- TOTP support for `otpauth://` URIs (algorithm, digits, and period respected)
  alongside raw base32 secrets.
- Soft delete with a Trash tab: restore entries, purge individually or empty
  the trash, all behind confirmation.
- Per-entry password history (last 10 changes) with copy and restore from the
  Modify dialog.
- Automatic timestamped vault backups to a user-chosen folder, keeping the
  last 10 (best-effort).
- Browser extension support via native messaging: a loopback IPC server with
  a per-session token, an extension allowlist, and explicit GUI approval for
  every password request; Chromium and Firefox manifest templates and a
  developer test script are included.
- Continuous integration workflow running fmt, clippy, tests, and
  cargo-audit on pushes and pull requests.
- Unlock throttling: after three failed attempts, each further attempt waits
  increasingly long (up to one minute) before running.
- The derived vault key now lives in page-locked memory (`mlock` on Unix,
  `VirtualLock` on Windows) so it cannot be swapped to disk, with core-dump
  exclusion where supported and zero-on-drop in all cases.

### Fixed

- Fixed per-frame configuration file reloads in the password list.
- Fixed the standalone password generator overwriting the Add-entry form and
  copying the wrong buffer.
- Fixed CSV export including trashed entries.

## [1.7.2] - 2026-09-12

### Added

- Added Wi-Fi entries across the add, modify, view, health, and CSV flows.
- Added CSV import and export support for cards, Wi-Fi entries, secure notes,
  TOTP secrets, favorites, and custom fields.
- Added automatic persistence of imported CSV entries.
- Added an option to reopen the last vault used when Aegis starts.
- Added a NixOS launcher, desktop entry, and platform release workflow.

### Security

- Hashed duress passwords with Argon2id and migrated legacy plaintext values
  automatically.
- Hardened vault locking and closing so sensitive form, clipboard, keyfile,
  cache, and in-memory vault data are cleared consistently.
- Made vault, configuration, keyfile, and CSV writes atomic and private where
  supported.
- Added safer vault loading with compatibility fallbacks for older formats and
  clearer errors for invalid or missing vault files.

### Fixed

- Fixed a Windows clipboard handle leak when excluded clipboard writes fail.
- Fixed stale vault state after failed unlocks, external vault changes, and
  lock or close operations.
- Fixed clipboard auto-clear notifications for copies made through the native
  backend.
- Improved handling of keyfile state and persistence errors.

## [1.7.1] - 2026-07-29

- Added card entry icons and the two-step entry-type flow.
- Added card texture support.
- Fixed entry-list button alignment and Wi-Fi option ordering.

[1.7.2]: https://github.com/Moonaw36-dot/pwm/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Moonaw36-dot/pwm/releases/tag/v1.7.1

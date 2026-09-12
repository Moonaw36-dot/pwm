# Changelog

All notable changes to Aegis are documented here.

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

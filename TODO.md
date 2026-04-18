# TODO

## High Priority
- [X] **CSV import** — import entries from a CSV file to migrate from other password managers
- [X] **HaveIBeenPwned breach check** — check passwords against the HIBP k-anonymity API in the Health tab (privacy-preserving: only the first 5 chars of the SHA1 hash are sent)
- [X] **Custom fields** — free-form key-value pairs per entry for API keys, license keys, security questions, etc.
- [X] **Exclude ambiguous characters** — option in the password generator to exclude 0/O, 1/l/I
- [X] **Key file support** — two-factor vault unlock using a key file + master password (like KeePass)

## Medium Priority
- [X] **Password expiry warnings** — optional expiry date per entry, Health tab flags expired/expiring passwords
- [ ] **Recent files list** — persist last N opened vault paths in config, show in the Files menu
- [X] **Secure notes** — entries with only a title and body, no username/password fields

## Development Roadmap (New Features)
- [ ] **Database compacting/cleanup** — Logic to optimize vault file size.
- [ ] **Search enhancements** — Fuzzy search and tag-based filtering.
- [ ] **Import from JSON/Bitwarden format** — Expand migration options beyond CSV.
- [ ] **CLI interface** — Add a CLI mode for querying/generating passwords.
- [ ] **Persistent password expiry** — Add a dedicated `expiry_date` field (persisted) to `PasswordEntry` to replace the current session-based logic.
- [ ] **Custom field persistence in CSV** — Update CSV import/export to handle key-value custom fields.

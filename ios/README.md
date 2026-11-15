# Aegis for iOS

A SwiftUI iPhone/iPad client for Aegis vaults. It reads and writes the same
`.aegis` file format as the desktop app, using the shared Rust core
(`aegis-core`) through UniFFI bindings (`aegis-ffi`).

## Layout

```
ios/
  project.yml            XcodeGen spec (target "Aegis", iOS 17+)
  Aegis/                 app: Swift sources, Info.plist, entitlements, assets
    VaultStore.swift     the app's only file that calls the Rust bindings
  AutoFill/              Password AutoFill extension (read-only)
  Shared/                code compiled into both: App Group, Face ID keychain
  Generated/             created at build time, not committed
    aegis_ffi.swift      UniFFI-generated Swift
    AegisFFI.xcframework static library + C header + module map (aegis_ffiFFI)
```

## How the build works

There is no Xcode project in the repository. CI on a macOS runner does this:

1. Build `aegis-ffi` as a static library for `aarch64-apple-ios` (device) and
   the simulator targets.
2. Run `uniffi-bindgen` to generate `Generated/aegis_ffi.swift`, the C header
   and the module map, then package everything as
   `Generated/AegisFFI.xcframework`.
3. Run `xcodegen` in `ios/` to create `Aegis.xcodeproj` from `project.yml`.
4. Build the `Aegis` scheme (app plus AutoFill extension) for
   `generic/platform=iOS` with code signing turned off.
5. Fake-sign both binaries with `ldid` to embed their entitlements (App Group,
   AutoFill), so SideStore/AltStore know which capabilities to request, then
   zip `Aegis.app` into `Payload/` to make an unsigned `Aegis.ipa`.

`ios/build.sh` and the CI workflow run these steps.

## Installing on an iPhone

The IPA from CI is unsigned. Install it with
[SideStore](https://sidestore.io) or [AltStore](https://altstore.io): they
sign it with your own (free) Apple ID on the device. With a free Apple ID the
signature lasts 7 days; SideStore/AltStore refresh it for you.

The app and its AutoFill extension use 2 of the 3 App IDs a free Apple ID may
have at once. If you install over the old 0.1 build and AutoFill or the
duress decoy misbehave, delete the app and install fresh.

## AutoFill

1. Install, open Aegis and unlock your vault once.
2. In the iOS Settings app, go to General › AutoFill & Passwords and turn on
   Aegis.
3. In Safari or any app, tap a password field, then the key icon or
   "Passwords" in the keyboard bar, and choose Aegis.

The extension can't open the file you picked in Files, so the app keeps an
encrypted copy of the vault (plus the keyfile, if you use one) in its App
Group container and refreshes it every time you unlock or save. The extension
only reads that copy; it never changes your vault. Turn AutoFill off in Aegis
Settings to delete the copy. Face ID works in the extension once it is on in
Aegis Settings; if your sideloader didn't grant keychain sharing, the
extension asks for the master password instead.

## Duress password

Settings › Duress sets a second password. Entering it on the unlock screen
(or in AutoFill) opens a decoy vault with believable fake logins instead of
your real one. The decoy lives in the app's private storage, is never synced
or backed up, and is separate from the desktop app's decoy. Inside the decoy,
Settings looks the same as in the real vault. Unlocking with the duress
password takes a moment longer than with the real one, since the real vault
is tried first.

## Syncing the vault with your computer

Aegis on iOS works directly on the vault file. Nothing is copied or uploaded
by the app.

1. On the computer, keep the vault in iCloud Drive (for example
   `iCloud Drive/Aegis/vault.aegis`). On Linux, use any tool that syncs that
   folder, or copy the file in through the Files app or a USB transfer.
2. On the iPhone, open Aegis, tap **Open Vault File…** and pick the file from
   iCloud Drive in the Files picker. If the vault uses a keyfile, pick that too.
3. Aegis keeps a security-scoped bookmark to the file, so next time it opens
   straight to the unlock screen. Every change is saved straight back to the
   same file, and iCloud syncs it.

Avoid editing the vault on two devices at the same time: the last save wins.

**Create New Vault** puts the file in the app's own folder (Files › On My
iPhone › Aegis). Move it to iCloud Drive in Files and open it again from there
to sync it.

## Security notes

- **Network.** The only connection the app ever makes is the optional
  Have I Been Pwned check in Settings › Password Health, and only when you tap
  the button. It sends the first 5 characters of each password's SHA-1 hash
  (k-anonymity, with response padding on). No analytics. Opening a website
  from an entry hands the URL to Safari.
- **Saving over a changed vault.** Before every save, Aegis checks that its
  key still opens the file on disk. If the master password was changed on
  another device and the file synced in, it refuses to save instead of
  writing a file neither password opens.
- **Master password.** It is used only to unlock the vault and is not kept
  after unlocking. Key derivation (Argon2id) and decryption happen in the Rust core.
- **Face ID quick unlock (optional, off by default).** When you turn it on in
  Settings, the master password is stored in the iOS Keychain as
  `WhenPasscodeSetThisDeviceOnly` with the `biometryCurrentSet` access
  control. That means:
  - it is never in iCloud Keychain or in backups, and never leaves this device;
  - it can only be read after Face ID (or Touch ID) succeeds;
  - it is erased if you remove the device passcode, and becomes unreadable if
    you enroll a new face or finger.
  Turning the option off, choosing another vault or forgetting the vault
  deletes it.
- **Clipboard.** Copied values expire after 30 seconds and are marked
  local-only, so Universal Clipboard never sends them to your other devices.
- **Auto-lock.** The vault locks when the app goes to the background (straight
  away by default, or after 30 s / 1 min / 5 min), and after a period with no
  screen touches while it is open (5 min by default). Locking drops all
  decrypted entries and the Rust-side key. While the app is inactive (app
  switcher, Control Center), a privacy screen hides its contents.
- **Limitations.** Swift `String`s cannot be reliably wiped from memory, so
  decrypted values shown in the UI can stay in process memory until iOS reuses
  it. iOS also takes the app switcher snapshot itself; the privacy screen is
  there to keep vault contents out of it.

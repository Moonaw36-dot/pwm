import Combine
import Foundation

// ---------------------------------------------------------------------------
// FFI boundary.
//
// Every reference to the UniFFI-generated bindings (Generated/aegis_ffi.swift:
// Vault, Entry, EntryType, CustomField, TotpCode, AegisError, totpCode,
// generatePassword, generatePassphrase) lives in THIS file. If the generated
// API differs, only this file needs to change.
// ---------------------------------------------------------------------------

/// Carries the non-Sendable UniFFI `Vault` object into detached tasks. The
/// Rust object is internally synchronised; the app only uses it from one task
/// at a time (the store is busy while a detached task holds it).
fileprivate final class VaultHandle: @unchecked Sendable {
    let vault: Vault

    init(_ vault: Vault) {
        self.vault = vault
    }
}

// MARK: - Entry conversion

extension VaultEntry {
    fileprivate init(ffi entry: Entry) {
        let kind: EntryKind
        switch entry.entryType {
        case .normal: kind = .normal
        case .card: kind = .card
        case .wiFi: kind = .wifi
        }
        self.init(
            id: entry.id,
            label: entry.label,
            username: entry.username,
            password: entry.password,
            notes: entry.notes,
            url: entry.url,
            totpSecret: entry.totpSecret ?? "",
            tags: entry.tags,
            kind: kind,
            isSecureNote: entry.isSecureNote,
            favorite: entry.favorite,
            cardNumber: entry.cardNumber ?? "",
            cardExpiration: entry.cardExpiration ?? "",
            cardCvc: entry.cardCvc ?? "",
            customFields: entry.customFields.map { CustomFieldItem(name: $0.name, value: $0.value) },
            createdAt: entry.createdAt,
            trashed: entry.trashed
        )
    }

    fileprivate var ffiEntry: Entry {
        let entryType: EntryType
        switch kind {
        case .normal: entryType = .normal
        case .card: entryType = .card
        case .wifi: entryType = .wiFi
        }
        let isCard = kind == .card
        return Entry(
            id: id,
            label: label,
            username: username,
            password: password,
            notes: notes,
            url: url,
            totpSecret: VaultEntry.nonEmpty(totpSecret.trimmingCharacters(in: .whitespacesAndNewlines)),
            tags: tags,
            entryType: entryType,
            isSecureNote: isSecureNote,
            favorite: favorite,
            cardNumber: isCard ? VaultEntry.nonEmpty(cardNumber) : nil,
            cardExpiration: isCard ? VaultEntry.nonEmpty(cardExpiration) : nil,
            cardCvc: isCard ? VaultEntry.nonEmpty(cardCvc) : nil,
            customFields: customFields
                .filter { !$0.name.isEmpty || !$0.value.isEmpty }
                .map { CustomField(name: $0.name, value: $0.value) },
            createdAt: createdAt,
            trashed: trashed
        )
    }

    private static func nonEmpty(_ value: String) -> String? {
        value.isEmpty ? nil : value
    }
}

// MARK: - Stateless core helpers (TOTP, generators)

enum AegisCore {
    static func totp(secret: String, at date: Date) -> TotpDisplay? {
        let trimmed = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let seconds = date.timeIntervalSince1970
        guard seconds > 0 else { return nil }
        guard let code = totpCode(secret: trimmed, unixTime: UInt64(seconds)) else { return nil }
        return TotpDisplay(
            code: code.code,
            secondsRemaining: Int(clamping: code.secondsRemaining),
            period: max(Int(clamping: code.period), 1)
        )
    }

    static func password(length: Int, uppercase: Bool, lowercase: Bool,
                         numbers: Bool, special: Bool, ambiguous: Bool) -> String {
        generatePassword(
            length: UInt32(clamping: length),
            uppercase: uppercase,
            lowercase: lowercase,
            numbers: numbers,
            special: special,
            ambiguous: ambiguous
        )
    }

    static func passphrase(wordCount: Int, separator: String) -> String {
        generatePassphrase(wordCount: UInt32(clamping: wordCount), separator: separator)
    }

    /// Human-readable message for any error thrown by the bindings. Reads the
    /// associated message by reflection so it does not depend on the exact
    /// case name UniFFI generates (`Failed` vs `failed`).
    static func describe(_ error: Error) -> String {
        if error is AegisError {
            let mirror = Mirror(reflecting: error)
            for child in mirror.children {
                if let message = child.value as? String {
                    return message
                }
                for inner in Mirror(reflecting: child.value).children {
                    if let message = inner.value as? String {
                        return message
                    }
                }
            }
            return String(describing: error)
        }
        if error is BiometricKeychain.KeychainError || error is VaultFile.FileError {
            return error.localizedDescription
        }
        let nsError = error as NSError
        if nsError.domain == NSCocoaErrorDomain {
            return nsError.localizedDescription
        }
        return error.localizedDescription
    }
}

// MARK: - Store

@MainActor
final class VaultStore: ObservableObject {
    @Published private(set) var vaultURL: URL?
    @Published private(set) var keyfileURL: URL?
    @Published private(set) var entries: [VaultEntry] = []
    @Published private(set) var isUnlocked = false
    @Published private(set) var isBusy = false
    @Published private(set) var busyMessage = ""
    @Published private(set) var biometricUnlockEnabled = false
    @Published var errorMessage: String?

    /// Last user interaction; deliberately not @Published (updated on every touch).
    private(set) var lastActivity = Date()

    private var handle: VaultHandle?
    /// Bumped by every lock(); an unlock that finishes after a lock is discarded.
    private var lockGeneration = 0
    private let defaults = UserDefaults.standard

    private enum Keys {
        static let vaultBookmark = "vaultBookmark"
        static let keyfileBookmark = "keyfileBookmark"
        static let biometric = "biometricUnlockEnabled"
    }

    init() {
        biometricUnlockEnabled = defaults.bool(forKey: Keys.biometric)
        vaultURL = Self.restoreBookmark(forKey: Keys.vaultBookmark)
        keyfileURL = Self.restoreBookmark(forKey: Keys.keyfileBookmark)
        if vaultURL == nil {
            setBiometricFlag(false)
            BiometricKeychain.delete()
        }
    }

    private static func restoreBookmark(forKey key: String) -> URL? {
        let defaults = UserDefaults.standard
        guard let data = defaults.data(forKey: key),
              let resolved = VaultFile.resolveBookmark(data)
        else { return nil }
        if let refreshed = resolved.refreshed {
            defaults.set(refreshed, forKey: key)
        }
        return resolved.url
    }

    // MARK: Derived state

    var vaultName: String {
        vaultURL?.lastPathComponent ?? "No vault"
    }

    var keyfileName: String? {
        keyfileURL?.lastPathComponent
    }

    var activeEntries: [VaultEntry] {
        entries.filter { !$0.trashed }
    }

    var trashedEntries: [VaultEntry] {
        entries
            .filter { $0.trashed }
            .sorted { $0.displayLabel.localizedCaseInsensitiveCompare($1.displayLabel) == .orderedAscending }
    }

    func entry(id: UInt64) -> VaultEntry? {
        entries.first { $0.id == id }
    }

    func noteActivity() {
        lastActivity = Date()
    }

    // MARK: Vault and keyfile selection

    /// Remembers a vault file picked in the Files picker (or opened from Files).
    func openVault(at url: URL) {
        if let current = vaultURL, current.standardizedFileURL == url.standardizedFileURL {
            return
        }
        do {
            let bookmark = try VaultFile.makeBookmark(for: url)
            lock()
            if vaultURL != nil {
                // Stored Face ID password belonged to the previous vault.
                disableBiometricUnlock()
            }
            defaults.set(bookmark, forKey: Keys.vaultBookmark)
            vaultURL = url
            errorMessage = nil
        } catch {
            errorMessage = "Could not keep access to \(url.lastPathComponent): \(AegisCore.describe(error))"
        }
    }

    func selectKeyfile(_ url: URL) {
        do {
            let bookmark = try VaultFile.makeBookmark(for: url)
            defaults.set(bookmark, forKey: Keys.keyfileBookmark)
            keyfileURL = url
            errorMessage = nil
        } catch {
            errorMessage = "Could not keep access to the keyfile: \(AegisCore.describe(error))"
        }
    }

    func clearKeyfile() {
        defaults.removeObject(forKey: Keys.keyfileBookmark)
        keyfileURL = nil
    }

    /// Locks and forgets the vault, keyfile and any stored Face ID password.
    func forgetVault() {
        lock()
        disableBiometricUnlock()
        defaults.removeObject(forKey: Keys.vaultBookmark)
        defaults.removeObject(forKey: Keys.keyfileBookmark)
        vaultURL = nil
        keyfileURL = nil
        errorMessage = nil
    }

    // MARK: Unlock / lock

    @discardableResult
    func unlock(password: String) async -> Bool {
        guard !isBusy else { return false }
        guard let url = vaultURL else {
            errorMessage = "No vault selected."
            return false
        }
        guard !password.isEmpty else {
            errorMessage = "Enter your master password."
            return false
        }
        beginBusy("Unlocking…")
        defer { endBusy() }

        let keyfileURL = self.keyfileURL
        let generation = lockGeneration
        do {
            let opened = try await Task.detached(priority: .userInitiated) { () throws -> VaultHandle in
                let data = try VaultFile.read(url)
                let keyfile: Data? = try keyfileURL.map { try VaultFile.read($0) }
                let vault = try Vault.open(data: data, password: password, keyfile: keyfile)
                return VaultHandle(vault)
            }.value
            guard generation == lockGeneration else {
                opened.vault.lock()
                return false
            }
            handle = opened
            reloadEntries()
            isUnlocked = true
            errorMessage = nil
            noteActivity()
            return true
        } catch {
            errorMessage = AegisCore.describe(error)
            return false
        }
    }

    func unlockWithBiometrics() async {
        guard biometricUnlockEnabled, !isBusy, !isUnlocked else { return }
        do {
            guard let password = try await BiometricKeychain.readPassword(reason: "Unlock your Aegis vault") else {
                disableBiometricUnlock()
                errorMessage = "\(BiometricKeychain.biometryName) unlock is no longer available. Enter your master password and turn it on again in Settings."
                return
            }
            await unlock(password: password)
        } catch BiometricKeychain.KeychainError.cancelled {
            // User chose to type the password instead.
        } catch {
            errorMessage = AegisCore.describe(error)
        }
    }

    /// Locks the vault and drops all decrypted data held by the app.
    func lock() {
        lockGeneration += 1
        handle?.vault.lock()
        handle = nil
        entries = []
        isUnlocked = false
    }

    // MARK: Create

    @discardableResult
    func createVault(name: String, password: String) async -> Bool {
        guard !isBusy else { return false }
        let url: URL
        do {
            url = try VaultFile.newVaultURL(named: name)
        } catch {
            errorMessage = AegisCore.describe(error)
            return false
        }
        beginBusy("Creating vault…")
        defer { endBusy() }

        let keyfileURL = self.keyfileURL
        do {
            let created = try await Task.detached(priority: .userInitiated) { () throws -> VaultHandle in
                let keyfile: Data? = try keyfileURL.map { try VaultFile.read($0) }
                let vault = try Vault.create(password: password, keyfile: keyfile)
                let sealed = try vault.seal()
                try VaultFile.write(sealed, to: url)
                return VaultHandle(vault)
            }.value

            let bookmark = try VaultFile.makeBookmark(for: url)
            lock()
            disableBiometricUnlock()
            defaults.set(bookmark, forKey: Keys.vaultBookmark)
            vaultURL = url
            handle = created
            reloadEntries()
            isUnlocked = true
            errorMessage = nil
            noteActivity()
            return true
        } catch {
            errorMessage = AegisCore.describe(error)
            return false
        }
    }

    // MARK: Entry mutations (each one saves and reloads)

    @discardableResult
    func add(_ entry: VaultEntry) -> Bool {
        var newEntry = entry
        newEntry.trashed = false
        let ffi = newEntry.ffiEntry
        return mutate { vault in
            _ = try vault.addEntry(entry: ffi)
        }
    }

    @discardableResult
    func update(_ entry: VaultEntry) -> Bool {
        let ffi = entry.ffiEntry
        return mutate { vault in
            try vault.updateEntry(entry: ffi)
        }
    }

    @discardableResult
    func toggleFavorite(_ entry: VaultEntry) -> Bool {
        var changed = entry
        changed.favorite.toggle()
        return update(changed)
    }

    @discardableResult
    func trash(id: UInt64) -> Bool {
        mutate { vault in
            try vault.trashEntry(id: id)
        }
    }

    @discardableResult
    func restore(id: UInt64) -> Bool {
        mutate { vault in
            try vault.restoreEntry(id: id)
        }
    }

    @discardableResult
    func deletePermanently(id: UInt64) -> Bool {
        mutate { vault in
            try vault.deleteEntry(id: id)
        }
    }

    @discardableResult
    func emptyTrash() -> Bool {
        let ids = entries.filter { $0.trashed }.map { $0.id }
        guard !ids.isEmpty else { return true }
        return mutate { vault in
            for id in ids {
                try vault.deleteEntry(id: id)
            }
        }
    }

    private func mutate(_ operation: (Vault) throws -> Void) -> Bool {
        guard !isBusy else { return false }
        guard let vault = handle?.vault, let url = vaultURL else {
            errorMessage = "The vault is locked."
            return false
        }
        noteActivity()
        do {
            try operation(vault)
            let sealed = try vault.seal()
            try VaultFile.write(sealed, to: url)
            reloadEntries()
            return true
        } catch {
            reloadEntries()
            errorMessage = AegisCore.describe(error)
            return false
        }
    }

    private func reloadEntries() {
        guard let vault = handle?.vault else {
            entries = []
            return
        }
        entries = vault.entries().map { VaultEntry(ffi: $0) }
    }

    // MARK: Master password

    @discardableResult
    func changePassword(current: String, new newPassword: String) async -> Bool {
        guard !isBusy else { return false }
        guard let handle, let url = vaultURL else {
            errorMessage = "The vault is locked."
            return false
        }
        beginBusy("Changing master password…")
        defer { endBusy() }

        guard await verify(password: current) else {
            errorMessage = "The current master password is incorrect."
            return false
        }

        let keyfileURL = self.keyfileURL
        do {
            let sealed = try await Task.detached(priority: .userInitiated) { () throws -> Data in
                let keyfile: Data? = try keyfileURL.map { try VaultFile.read($0) }
                try handle.vault.changePassword(newPassword: newPassword, keyfile: keyfile)
                return try handle.vault.seal()
            }.value
            try VaultFile.write(sealed, to: url)
        } catch {
            errorMessage = AegisCore.describe(error)
            return false
        }

        if biometricUnlockEnabled {
            do {
                try BiometricKeychain.save(password: newPassword)
            } catch {
                disableBiometricUnlock()
                errorMessage = "Password changed, but \(BiometricKeychain.biometryName) unlock was turned off: \(AegisCore.describe(error))"
            }
        }
        noteActivity()
        return true
    }

    /// Checks a password against the vault file on disk (slow: runs the KDF).
    private func verify(password: String) async -> Bool {
        guard let url = vaultURL, !password.isEmpty else { return false }
        let keyfileURL = self.keyfileURL
        let result = await Task.detached(priority: .userInitiated) { () -> Bool in
            do {
                let data = try VaultFile.read(url)
                let keyfile: Data? = try keyfileURL.map { try VaultFile.read($0) }
                let vault = try Vault.open(data: data, password: password, keyfile: keyfile)
                vault.lock()
                return true
            } catch {
                return false
            }
        }.value
        return result
    }

    // MARK: Biometric unlock

    @discardableResult
    func enableBiometricUnlock(password: String) async -> Bool {
        guard !isBusy else { return false }
        guard BiometricKeychain.isBiometryAvailable else {
            errorMessage = "Biometric authentication is not available on this device."
            return false
        }
        beginBusy("Checking password…")
        defer { endBusy() }

        guard await verify(password: password) else {
            errorMessage = "That master password is incorrect."
            return false
        }
        do {
            try BiometricKeychain.save(password: password)
            setBiometricFlag(true)
            return true
        } catch {
            errorMessage = AegisCore.describe(error)
            return false
        }
    }

    func disableBiometricUnlock() {
        BiometricKeychain.delete()
        setBiometricFlag(false)
    }

    private func setBiometricFlag(_ enabled: Bool) {
        defaults.set(enabled, forKey: Keys.biometric)
        biometricUnlockEnabled = enabled
    }

    // MARK: Busy state

    private func beginBusy(_ message: String) {
        busyMessage = message
        isBusy = true
    }

    private func endBusy() {
        isBusy = false
        busyMessage = ""
    }
}

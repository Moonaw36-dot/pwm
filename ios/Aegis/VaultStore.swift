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

fileprivate struct UnlockResult: @unchecked Sendable {
    let handle: VaultHandle
    let isDecoy: Bool
    let vaultData: Data
    let keyfile: Data?
}

enum StoreError: LocalizedError {
    case changedOnDisk
    case isMasterPassword

    var errorDescription: String? {
        switch self {
        case .changedOnDisk:
            return "The vault file was changed on another device (for example its master password). Nothing was saved. Lock and unlock to load the newer version."
        case .isMasterPassword:
            return "That is your master password. Choose a different duress password."
        }
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
        if error is BiometricKeychain.KeychainError || error is VaultFile.FileError
            || error is StoreError {
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
    /// True while a decoy exists for this vault. Also true inside the decoy
    /// itself, so its Settings look like the real vault's.
    @Published private(set) var duressEnabled = false
    @Published private(set) var autoFillEnabled = true
    @Published var errorMessage: String?

    /// Unlocked with the duress password: every read and write goes to the
    /// decoy, and nothing touches the real vault or the AutoFill copy.
    private var inDecoy = false

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
        static let vaultID = "vaultID"
        static let autoFillDisabled = "autoFillDisabled"
    }

    init() {
        biometricUnlockEnabled = defaults.bool(forKey: Keys.biometric)
        autoFillEnabled = !defaults.bool(forKey: Keys.autoFillDisabled)
        vaultURL = Self.restoreBookmark(forKey: Keys.vaultBookmark)
        keyfileURL = Self.restoreBookmark(forKey: Keys.keyfileBookmark)
        if vaultURL == nil {
            setBiometricFlag(false)
            BiometricKeychain.delete()
            AutoFillCache.clear()
        }
    }

    // MARK: Per-vault files

    /// Names this vault's decoy file. Replaced whenever another vault is picked.
    private var vaultID: String {
        if let id = defaults.string(forKey: Keys.vaultID) {
            return id
        }
        let id = UUID().uuidString
        defaults.set(id, forKey: Keys.vaultID)
        return id
    }

    /// Application Support is not shown in the Files app.
    private static var decoyDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Decoys", isDirectory: true)
    }

    private var decoyURL: URL {
        Self.decoyDirectory.appendingPathComponent(vaultID + ".aegis", isDirectory: false)
    }

    /// The file saves go to: the decoy inside a duress session, else the vault.
    private var activeURL: URL? {
        inDecoy ? decoyURL : vaultURL
    }

    private static func writeDecoy(_ data: Data, to url: URL) throws {
        try FileManager.default.createDirectory(at: decoyDirectory, withIntermediateDirectories: true)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        try? mutableURL.setResourceValues(values)
    }

    /// Drops everything tied to the current vault before another one replaces it.
    private func forgetVaultFiles() {
        try? FileManager.default.removeItem(at: decoyURL)
        defaults.removeObject(forKey: Keys.vaultID)
        AutoFillCache.clear()
        duressEnabled = false
    }

    private func readKeyfile() -> Data? {
        keyfileURL.flatMap { try? VaultFile.read($0) }
    }

    /// Gives the AutoFill extension a fresh encrypted copy of the real vault.
    private func refreshAutoFillCache(vault: Data, keyfile: Data?) {
        guard autoFillEnabled, !inDecoy else { return }
        let decoy = try? Data(contentsOf: decoyURL)
        try? AutoFillCache.store(vault: vault, keyfile: keyfile, decoy: decoy, vaultName: vaultName)
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
            forgetVaultFiles()
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
        forgetVaultFiles()
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
        let decoyURL = self.decoyURL
        let generation = lockGeneration
        do {
            let opened = try await Task.detached(priority: .userInitiated) { () throws -> UnlockResult in
                let data = try VaultFile.read(url)
                let keyfile: Data? = try keyfileURL.map { try VaultFile.read($0) }
                // The real vault first, so a duress password that happens to
                // equal the master password still opens the real vault.
                do {
                    let vault = try Vault.open(data: data, password: password, keyfile: keyfile)
                    return UnlockResult(handle: VaultHandle(vault), isDecoy: false, vaultData: data, keyfile: keyfile)
                } catch {
                    if let decoyData = try? Data(contentsOf: decoyURL),
                       let decoy = try? Vault.open(data: decoyData, password: password, keyfile: nil) {
                        return UnlockResult(handle: VaultHandle(decoy), isDecoy: true, vaultData: data, keyfile: nil)
                    }
                    throw error
                }
            }.value
            guard generation == lockGeneration else {
                opened.handle.vault.lock()
                return false
            }
            handle = opened.handle
            inDecoy = opened.isDecoy
            duressEnabled = inDecoy || FileManager.default.fileExists(atPath: decoyURL.path)
            if !inDecoy {
                refreshAutoFillCache(vault: opened.vaultData, keyfile: opened.keyfile)
            }
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
        inDecoy = false
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
            let created = try await Task.detached(priority: .userInitiated) { () throws -> UnlockResult in
                let keyfile: Data? = try keyfileURL.map { try VaultFile.read($0) }
                let vault = try Vault.create(password: password, keyfile: keyfile)
                let sealed = try vault.seal()
                try VaultFile.write(sealed, to: url)
                return UnlockResult(handle: VaultHandle(vault), isDecoy: false, vaultData: sealed, keyfile: keyfile)
            }.value

            let bookmark = try VaultFile.makeBookmark(for: url)
            lock()
            disableBiometricUnlock()
            forgetVaultFiles()
            defaults.set(bookmark, forKey: Keys.vaultBookmark)
            vaultURL = url
            handle = created.handle
            refreshAutoFillCache(vault: created.vaultData, keyfile: created.keyfile)
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
        guard let vault = handle?.vault, let url = activeURL else {
            errorMessage = "The vault is locked."
            return false
        }
        noteActivity()
        do {
            try ensureCanSave(vault, over: url)
            try operation(vault)
            let sealed = try vault.seal()
            try VaultFile.write(sealed, to: url)
            refreshAutoFillCache(vault: sealed, keyfile: readKeyfile())
            reloadEntries()
            return true
        } catch {
            reloadEntries()
            errorMessage = AegisCore.describe(error)
            return false
        }
    }

    /// Refuses to overwrite a file this vault's key can no longer open: the
    /// master password was changed elsewhere and the file synced here.
    private func ensureCanSave(_ vault: Vault, over url: URL) throws {
        let existing = try VaultFile.read(url)
        guard vault.canSaveOver(existing: existing) else {
            throw StoreError.changedOnDisk
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
        guard let handle, let url = activeURL else {
            errorMessage = "The vault is locked."
            return false
        }
        beginBusy("Changing master password…")
        defer { endBusy() }

        guard await verify(password: current) else {
            errorMessage = "The current master password is incorrect."
            return false
        }

        let keyfileURL = inDecoy ? nil : self.keyfileURL
        do {
            try ensureCanSave(handle.vault, over: url)
            let sealed = try await Task.detached(priority: .userInitiated) { () throws -> Data in
                let keyfile: Data? = try keyfileURL.map { try VaultFile.read($0) }
                try handle.vault.changePassword(newPassword: newPassword, keyfile: keyfile)
                return try handle.vault.seal()
            }.value
            try VaultFile.write(sealed, to: url)
            refreshAutoFillCache(vault: sealed, keyfile: readKeyfile())
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
        guard let url = activeURL, !password.isEmpty else { return false }
        let keyfileURL = inDecoy ? nil : self.keyfileURL
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

    // MARK: Duress password

    /// Creates (or replaces) this vault's decoy, opened by `password`.
    @discardableResult
    func setDuressPassword(_ password: String) async -> Bool {
        guard !isBusy else { return false }
        guard isUnlocked, !password.isEmpty else { return false }
        // Inside the decoy this must look like it worked, and change nothing.
        if inDecoy { return true }
        beginBusy("Creating decoy vault…")
        defer { endBusy() }

        if await verify(password: password) {
            errorMessage = AegisCore.describe(StoreError.isMasterPassword)
            return false
        }
        let decoyURL = self.decoyURL
        do {
            let sealed = try await Task.detached(priority: .userInitiated) { () throws -> Data in
                let decoy = try Vault.createDecoy(password: password)
                defer { decoy.lock() }
                return try decoy.seal()
            }.value
            try Self.writeDecoy(sealed, to: decoyURL)
            if autoFillEnabled {
                try? AutoFillCache.storeDecoy(sealed)
            }
            duressEnabled = true
            return true
        } catch {
            errorMessage = AegisCore.describe(error)
            return false
        }
    }

    func removeDuressPassword() {
        if inDecoy { return }
        try? FileManager.default.removeItem(at: decoyURL)
        try? AutoFillCache.storeDecoy(nil)
        duressEnabled = false
    }

    // MARK: AutoFill

    func setAutoFillEnabled(_ enabled: Bool) {
        defaults.set(!enabled, forKey: Keys.autoFillDisabled)
        autoFillEnabled = enabled
        guard enabled else {
            AutoFillCache.clear()
            return
        }
        if isUnlocked, !inDecoy, let url = vaultURL, let data = try? VaultFile.read(url) {
            refreshAutoFillCache(vault: data, keyfile: readKeyfile())
        }
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

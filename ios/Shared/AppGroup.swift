import Foundation

/// The App Group the app and its AutoFill extension share. SideStore and
/// AltStore rename App Groups when they re-sign with your Apple ID (they
/// append your team ID), so the real identifier is looked up at runtime.
enum AppGroup {
    static let defaultIdentifier = "group.com.moonaw.aegis"

    static let identifier: String? = {
        var candidates: [String] = []
        // AltStore/SideStore record the renamed groups here when they sign.
        if let groups = Bundle.main.object(forInfoDictionaryKey: "ALTAppGroups") as? [String] {
            candidates += groups
        }
        // They also rename bundle ids the same way (com.moonaw.aegis.TEAMID),
        // so "group." + the app's bundle id is the renamed group.
        if var bundleID = Bundle.main.bundleIdentifier {
            if bundleID.hasSuffix(".autofill") {
                bundleID = String(bundleID.dropLast(".autofill".count))
            }
            candidates.append("group." + bundleID)
        }
        candidates.append(defaultIdentifier)
        return candidates.first {
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: $0) != nil
        }
    }()

    static var containerURL: URL? {
        identifier.flatMap {
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: $0)
        }
    }
}

/// Encrypted copies of the vault (and keyfile, and decoy) for the AutoFill
/// extension, which can't open the file the app picked in Files. The app
/// refreshes them on every unlock and save; the extension only reads them.
enum AutoFillCache {
    struct Contents {
        let vault: Data
        let keyfile: Data?
        let decoy: Data?
        let vaultName: String
    }

    private static var directory: URL? {
        AppGroup.containerURL?.appendingPathComponent("AutoFill", isDirectory: true)
    }

    private static func file(_ name: String) -> URL? {
        directory?.appendingPathComponent(name, isDirectory: false)
    }

    static var isAvailable: Bool {
        directory != nil
    }

    static func store(vault: Data, keyfile: Data?, decoy: Data?, vaultName: String) throws {
        guard let directory else { return }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try write(vault, to: "vault.aegis")
        try write(keyfile, to: "keyfile.bin")
        try write(decoy, to: "decoy.aegis")
        try write(Data(vaultName.utf8), to: "name.txt")
    }

    /// Replaces only the decoy copy (after the duress password changes).
    static func storeDecoy(_ decoy: Data?) throws {
        guard directory != nil, read() != nil else { return }
        try write(decoy, to: "decoy.aegis")
    }

    static func read() -> Contents? {
        guard let vaultURL = file("vault.aegis"),
              let vault = try? Data(contentsOf: vaultURL)
        else { return nil }
        let keyfile = file("keyfile.bin").flatMap { try? Data(contentsOf: $0) }
        let decoy = file("decoy.aegis").flatMap { try? Data(contentsOf: $0) }
        let name = file("name.txt")
            .flatMap { try? Data(contentsOf: $0) }
            .flatMap { String(data: $0, encoding: .utf8) } ?? "Vault"
        return Contents(vault: vault, keyfile: keyfile, decoy: decoy, vaultName: name)
    }

    static func clear() {
        guard let directory else { return }
        try? FileManager.default.removeItem(at: directory)
    }

    private static func write(_ data: Data?, to name: String) throws {
        guard let url = file(name) else { return }
        guard let data else {
            try? FileManager.default.removeItem(at: url)
            return
        }
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        try? mutableURL.setResourceValues(values)
    }
}

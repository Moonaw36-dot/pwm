import Foundation

/// File access for the vault and keyfile: security-scoped access, coordinated
/// reads/writes (so iCloud Drive downloads/uploads correctly) and bookmarks.
/// Everything here is nonisolated and safe to call from detached tasks.
enum VaultFile {
    enum FileError: LocalizedError {
        case unreadable(String)
        case alreadyExists(String)

        var errorDescription: String? {
            switch self {
            case .unreadable(let name):
                return "Could not read \(name)."
            case .alreadyExists(let name):
                return "A file named \(name) already exists."
            }
        }
    }

    static func read(_ url: URL) throws -> Data {
        let accessing = url.startAccessingSecurityScopedResource()
        defer {
            if accessing { url.stopAccessingSecurityScopedResource() }
        }

        var coordinationError: NSError?
        var result: Result<Data, Error> = .failure(FileError.unreadable(url.lastPathComponent))
        let coordinator = NSFileCoordinator(filePresenter: nil)
        coordinator.coordinate(readingItemAt: url, options: [], error: &coordinationError) { readURL in
            do {
                result = .success(try Data(contentsOf: readURL))
            } catch {
                result = .failure(error)
            }
        }
        if let coordinationError {
            throw coordinationError
        }
        return try result.get()
    }

    static func write(_ data: Data, to url: URL) throws {
        let accessing = url.startAccessingSecurityScopedResource()
        defer {
            if accessing { url.stopAccessingSecurityScopedResource() }
        }

        var coordinationError: NSError?
        var writeError: Error?
        let coordinator = NSFileCoordinator(filePresenter: nil)
        coordinator.coordinate(writingItemAt: url, options: .forReplacing, error: &coordinationError) { writeURL in
            do {
                try data.write(to: writeURL, options: .atomic)
            } catch {
                // Some file providers grant access to the picked file only and
                // not to its folder, which an atomic replace needs. Fall back
                // to writing the file in place.
                do {
                    try data.write(to: writeURL, options: [])
                } catch let fallbackError {
                    writeError = fallbackError
                }
            }
        }
        if let coordinationError {
            throw coordinationError
        }
        if let writeError {
            throw writeError
        }
    }

    static func makeBookmark(for url: URL) throws -> Data {
        let accessing = url.startAccessingSecurityScopedResource()
        defer {
            if accessing { url.stopAccessingSecurityScopedResource() }
        }
        return try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
    }

    /// Resolves a bookmark. `refreshed` is non-nil when the bookmark was stale
    /// and has been recreated; the caller should store it.
    static func resolveBookmark(_ data: Data) -> (url: URL, refreshed: Data?)? {
        var isStale = false
        guard let url = try? URL(resolvingBookmarkData: data,
                                 options: [],
                                 relativeTo: nil,
                                 bookmarkDataIsStale: &isStale)
        else { return nil }
        if isStale {
            return (url, try? makeBookmark(for: url))
        }
        return (url, nil)
    }

    static var documentsDirectory: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    /// A file URL in the app's Documents folder (visible in the Files app).
    static func newVaultURL(named rawName: String) throws -> URL {
        var name = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        name = name.replacingOccurrences(of: "/", with: "-")
        name = name.replacingOccurrences(of: ":", with: "-")
        if name.hasPrefix(".") { name = String(name.dropFirst()) }
        if name.isEmpty { name = "Vault" }
        if !name.lowercased().hasSuffix(".aegis") { name += ".aegis" }
        let url = documentsDirectory.appendingPathComponent(name, isDirectory: false)
        if FileManager.default.fileExists(atPath: url.path) {
            throw FileError.alreadyExists(name)
        }
        return url
    }
}

import CryptoKit
import SwiftUI

/// Have I Been Pwned range lookups (k-anonymity): only the first five hex
/// characters of each password's SHA-1 are sent, with response padding on so
/// the reply size doesn't hint at the result either.
enum PwnedChecker {
    enum CheckError: LocalizedError {
        case http(Int)

        var errorDescription: String? {
            switch self {
            case .http(let code):
                return "Have I Been Pwned answered with HTTP \(code). Try again later."
            }
        }
    }

    static func sha1Hex(_ password: String) -> String {
        Insecure.SHA1.hash(data: Data(password.utf8))
            .map { String(format: "%02X", $0) }
            .joined()
    }

    /// Breach counts keyed by full SHA-1 hex; hashes not found are absent.
    static func counts(for hashes: Set<String>) async throws -> [String: Int] {
        let byPrefix = Dictionary(grouping: hashes) { String($0.prefix(5)) }
        var found: [String: Int] = [:]
        try await withThrowingTaskGroup(of: [String: Int].self) { group in
            var pending = Array(byPrefix)
            var running = 0
            // A few requests at a time is plenty and keeps the API happy.
            while !pending.isEmpty || running > 0 {
                while running < 4, let next = pending.popLast() {
                    let prefix = next.key
                    let wanted = Set(next.value)
                    group.addTask {
                        try await PwnedChecker.lookup(prefix: prefix, wanted: wanted)
                    }
                    running += 1
                }
                guard let result = try await group.next() else { break }
                running -= 1
                found.merge(result) { first, _ in first }
            }
        }
        return found
    }

    fileprivate static func lookup(prefix: String, wanted: Set<String>) async throws -> [String: Int] {
        guard let url = URL(string: "https://api.pwnedpasswords.com/range/\(prefix)") else { return [:] }
        var request = URLRequest(url: url, timeoutInterval: 15)
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        request.setValue("Aegis-iOS", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            throw CheckError.http(http.statusCode)
        }
        var result: [String: Int] = [:]
        let body = String(decoding: data, as: UTF8.self)
        for line in body.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":")
            guard parts.count == 2, let count = Int(parts[1].trimmingCharacters(in: .whitespaces)) else { continue }
            let hash = prefix + parts[0].uppercased()
            // Padding rows have a count of 0.
            if count > 0, wanted.contains(hash) {
                result[hash] = count
            }
        }
        return result
    }
}

struct BreachedItem: Identifiable {
    let entry: VaultEntry
    let count: Int

    var id: UInt64 { entry.id }
}

struct ReusedGroup: Identifiable {
    let entries: [VaultEntry]

    var id: UInt64 { entries[0].id }
}

@MainActor
struct HealthView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var breaches: [String: Int]?
    @State private var checking = false
    @State private var checkError: String?

    /// Logins and Wi-Fi entries that have a password.
    private var candidates: [VaultEntry] {
        store.activeEntries.filter { $0.kind != .card && !$0.isSecureNote && !$0.password.isEmpty }
    }

    private static func byLabel(_ a: VaultEntry, _ b: VaultEntry) -> Bool {
        a.displayLabel.localizedCaseInsensitiveCompare(b.displayLabel) == .orderedAscending
    }

    private var reusedGroups: [ReusedGroup] {
        let groups = Dictionary(grouping: candidates, by: { $0.password })
        return groups.values
            .filter { $0.count > 1 }
            .map { ReusedGroup(entries: $0.sorted(by: HealthView.byLabel)) }
            .sorted { HealthView.byLabel($0.entries[0], $1.entries[0]) }
    }

    private var breached: [BreachedItem] {
        guard let breaches else { return [] }
        var items: [BreachedItem] = []
        for entry in candidates {
            if let count = breaches[PwnedChecker.sha1Hex(entry.password)] {
                items.append(BreachedItem(entry: entry, count: count))
            }
        }
        return items.sorted { $0.count > $1.count }
    }

    var body: some View {
        Form {
            Section {
                if reusedGroups.isEmpty {
                    Label("No reused passwords", systemImage: "checkmark.circle")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(reusedGroups) { group in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(group.entries.map { $0.displayLabel }.joined(separator: ", "))
                            Text("Same password used \(group.entries.count) times")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Reused")
            }

            Section {
                if breaches != nil {
                    if breached.isEmpty {
                        Label("None of your passwords were found in known breaches", systemImage: "checkmark.shield")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(breached) { item in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.entry.displayLabel)
                                Text("Seen \(item.count.formatted()) times in breaches")
                                    .font(.footnote)
                                    .foregroundStyle(.red)
                            }
                        }
                    }
                }
                if let checkError {
                    Text(checkError)
                        .foregroundStyle(.red)
                }
                Button {
                    check()
                } label: {
                    HStack {
                        Text(breaches == nil ? "Check Against Have I Been Pwned" : "Check Again")
                        if checking {
                            Spacer()
                            ProgressView()
                        }
                    }
                }
                .disabled(checking || candidates.isEmpty)
            } header: {
                Text("Breached")
            } footer: {
                Text("Sends only the first 5 characters of each password's SHA-1 hash to api.pwnedpasswords.com. Your passwords never leave this device. This is the only time Aegis uses the network.")
            }
        }
        .navigationTitle("Password Health")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func check() {
        guard !checking else { return }
        let hashes = Set(candidates.map { PwnedChecker.sha1Hex($0.password) })
        checking = true
        checkError = nil
        Task {
            do {
                breaches = try await PwnedChecker.counts(for: hashes)
            } catch {
                checkError = AegisCore.describe(error)
            }
            checking = false
        }
    }
}

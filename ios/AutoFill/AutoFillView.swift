import LocalAuthentication
import SwiftUI

/// One login the extension can fill.
struct AutoFillLogin: Identifiable, Hashable {
    let id: UInt64
    let label: String
    let username: String
    let password: String
    let host: String?

    var title: String {
        label.isEmpty ? (host ?? "Untitled") : label
    }
}

@MainActor
final class AutoFillModel: ObservableObject {
    @Published private(set) var logins: [AutoFillLogin]?
    @Published private(set) var busy = false
    @Published var error: String?
    @Published var search = ""

    /// Hosts of the page or app asking, e.g. "accounts.example.com".
    @Published private(set) var serviceHosts: [String] = []

    var onCancel: () -> Void = {}
    var onPick: (String, String) -> Void = { _, _ in }

    let vaultName = AutoFillCache.read()?.vaultName ?? "Aegis"
    let hasCache = AutoFillCache.read() != nil

    func setServices(_ services: [(identifier: String, isURL: Bool)]) {
        serviceHosts = services.compactMap { service in
            let text = service.isURL ? URL(string: service.identifier)?.host : service.identifier
            return text.map(AutoFillModel.normalizedHost)
        }
    }

    nonisolated static func normalizedHost(_ host: String) -> String {
        var h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". "))
        if h.hasPrefix("www.") {
            h = String(h.dropFirst(4))
        }
        return h
    }

    nonisolated static func host(ofEntryURL text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let candidate = trimmed.contains("://") ? trimmed : "https://" + trimmed
        return URL(string: candidate)?.host.map(normalizedHost)
    }

    /// The page's host equals the entry's, or is a subdomain of it.
    func matches(_ login: AutoFillLogin) -> Bool {
        guard let entryHost = login.host, !entryHost.isEmpty else { return false }
        return serviceHosts.contains { $0 == entryHost || $0.hasSuffix("." + entryHost) }
    }

    var suggested: [AutoFillLogin] {
        (logins ?? []).filter(matches)
    }

    var others: [AutoFillLogin] {
        let q = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return (logins ?? []).filter { login in
            if q.isEmpty { return !matches(login) }
            return login.label.localizedCaseInsensitiveContains(q)
                || login.username.localizedCaseInsensitiveContains(q)
                || (login.host?.localizedCaseInsensitiveContains(q) ?? false)
        }
    }

    func unlock(password: String) async {
        guard !busy, !password.isEmpty else { return }
        guard let cache = AutoFillCache.read() else {
            error = "Open Aegis and unlock your vault once to set up AutoFill."
            return
        }
        busy = true
        defer { busy = false }
        do {
            logins = try await Task.detached(priority: .userInitiated) { () throws -> [AutoFillLogin] in
                let vault: Vault
                do {
                    vault = try Vault.open(data: cache.vault, password: password, keyfile: cache.keyfile)
                } catch {
                    guard let decoyData = cache.decoy,
                          let decoy = try? Vault.open(data: decoyData, password: password, keyfile: nil)
                    else { throw error }
                    vault = decoy
                }
                defer { vault.lock() }
                return vault.entries()
                    .filter { !$0.trashed && !$0.isSecureNote && $0.entryType != .card && !$0.password.isEmpty }
                    .map {
                        AutoFillLogin(
                            id: $0.id,
                            label: $0.label,
                            username: $0.username,
                            password: $0.password,
                            host: AutoFillModel.host(ofEntryURL: $0.url)
                        )
                    }
                    .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
            }.value
            error = nil
        } catch {
            self.error = AutoFillModel.describe(error)
        }
    }

    func unlockWithBiometrics() async {
        guard hasCache, BiometricKeychain.isBiometryAvailable else { return }
        do {
            guard let password = try await BiometricKeychain.readPassword(reason: "Unlock Aegis to fill a password") else {
                error = "Turn on \(BiometricKeychain.biometryName) unlock in Aegis Settings to use it here."
                return
            }
            await unlock(password: password)
        } catch BiometricKeychain.KeychainError.cancelled {
            // Typing the password instead.
        } catch {
            self.error = AutoFillModel.describe(error)
        }
    }

    /// Same idea as the app's AegisCore.describe: pull the message out of the
    /// UniFFI error without depending on the generated case name.
    nonisolated static func describe(_ error: Error) -> String {
        if error is AegisError {
            for child in Mirror(reflecting: error).children {
                if let message = child.value as? String {
                    return message
                }
                for inner in Mirror(reflecting: child.value).children {
                    if let message = inner.value as? String {
                        return message
                    }
                }
            }
        }
        return error.localizedDescription
    }
}

struct AutoFillView: View {
    @ObservedObject var model: AutoFillModel
    @State private var password = ""
    @FocusState private var passwordFocused: Bool

    var body: some View {
        NavigationStack {
            Group {
                if model.logins != nil {
                    list
                } else {
                    unlock
                }
            }
            .navigationTitle(model.vaultName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        model.onCancel()
                    }
                }
            }
        }
    }

    private var unlock: some View {
        Form {
            if !model.hasCache {
                Section {
                    Text("Open Aegis and unlock your vault once to set up AutoFill.")
                }
            } else {
                Section {
                    SecureField("Master password", text: $password, prompt: .hint("Master password"))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .focused($passwordFocused)
                        .onSubmit { submit() }
                    Button {
                        submit()
                    } label: {
                        HStack {
                            Text("Unlock")
                            if model.busy {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                    .disabled(password.isEmpty || model.busy)
                    if BiometricKeychain.isBiometryAvailable {
                        Button {
                            Task { await model.unlockWithBiometrics() }
                        } label: {
                            Label("Unlock with \(BiometricKeychain.biometryName)",
                                  systemImage: BiometricKeychain.biometrySymbol)
                        }
                        .disabled(model.busy)
                    }
                } footer: {
                    if !model.serviceHosts.isEmpty {
                        Text("Filling for \(model.serviceHosts.joined(separator: ", "))")
                    }
                }
            }
            if let error = model.error {
                Section {
                    Text(error)
                        .foregroundStyle(.red)
                }
            }
        }
        .task {
            if BiometricKeychain.isBiometryAvailable && model.hasCache {
                await model.unlockWithBiometrics()
            }
            if model.logins == nil {
                passwordFocused = true
            }
        }
    }

    private var list: some View {
        List {
            if model.search.isEmpty && !model.suggested.isEmpty {
                Section("Suggested") {
                    ForEach(model.suggested) { login in
                        row(login)
                    }
                }
            }
            Section(model.search.isEmpty ? "All Logins" : "Results") {
                if model.others.isEmpty {
                    Text(model.search.isEmpty ? "No other logins" : "No matches")
                        .foregroundStyle(.secondary)
                }
                ForEach(model.others) { login in
                    row(login)
                }
            }
        }
        .searchable(text: $model.search, placement: .navigationBarDrawer(displayMode: .always))
    }

    private func row(_ login: AutoFillLogin) -> some View {
        Button {
            model.onPick(login.username, login.password)
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text(login.title)
                    .foregroundStyle(.primary)
                if !login.username.isEmpty {
                    Text(login.username)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func submit() {
        let entered = password
        Task {
            await model.unlock(password: entered)
            if model.logins != nil {
                password = ""
            }
        }
    }
}

import SwiftUI
import UniformTypeIdentifiers

/// Content types offered when picking a vault file.
enum VaultFileTypes {
    static var vault: [UTType] {
        [UTType(filenameExtension: "aegis") ?? .data, .data]
    }

    static var keyfile: [UTType] {
        [.item]
    }
}

/// First-run screen: open an existing vault (e.g. synced through iCloud
/// Drive) or create a new one in the app's Documents folder.
@MainActor
struct VaultPickerView: View {
    private enum ImportTarget {
        case vault
        case keyfile
    }

    @EnvironmentObject private var store: VaultStore
    @State private var importTarget: ImportTarget = .vault
    @State private var showImporter = false
    @State private var newName = "Vault"
    @State private var newPassword = ""
    @State private var confirmPassword = ""

    private var createProblem: String? {
        if newPassword.isEmpty { return nil }
        if newPassword.count < 8 { return "Use at least 8 characters." }
        if !confirmPassword.isEmpty && newPassword != confirmPassword { return "Passwords do not match." }
        return nil
    }

    private var canCreate: Bool {
        newPassword.count >= 8 && newPassword == confirmPassword && !store.isBusy
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 44))
                            .foregroundStyle(.tint)
                        Text("Open the .aegis vault file you sync from your computer (for example through iCloud Drive), or create a new vault on this device.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }

                Section("Existing vault") {
                    Button {
                        importTarget = .vault
                        showImporter = true
                    } label: {
                        Label("Open Vault File…", systemImage: "folder")
                    }
                }

                Section {
                    if let keyfileName = store.keyfileName {
                        LabeledContent("Keyfile", value: keyfileName)
                        Button("Remove Keyfile", role: .destructive) {
                            store.clearKeyfile()
                        }
                    } else {
                        Button {
                            importTarget = .keyfile
                            showImporter = true
                        } label: {
                            Label("Choose Keyfile…", systemImage: "key")
                        }
                    }
                } header: {
                    Text("Keyfile (optional)")
                } footer: {
                    Text("Only needed if your vault was created with a keyfile.")
                }

                Section {
                    TextField("File name", text: $newName, prompt: .hint("File name"))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Master password", text: $newPassword, prompt: .hint("Master password"))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Confirm password", text: $confirmPassword, prompt: .hint("Confirm password"))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if let createProblem {
                        Text(createProblem)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                    Button {
                        create()
                    } label: {
                        Label("Create Vault", systemImage: "plus.circle")
                    }
                    .disabled(!canCreate)
                } header: {
                    Text("New vault")
                } footer: {
                    Text("The vault is saved in Aegis's folder in the Files app (On My iPhone › Aegis). Move it to iCloud Drive to share it with your computer, then open it from there.")
                }

                if let error = store.errorMessage {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Aegis")
            .fileImporter(
                isPresented: $showImporter,
                allowedContentTypes: importTarget == .vault ? VaultFileTypes.vault : VaultFileTypes.keyfile
            ) { result in
                handleImport(result)
            }
        }
    }

    private func handleImport(_ result: Result<URL, Error>) {
        switch result {
        case .success(let url):
            switch importTarget {
            case .vault:
                store.openVault(at: url)
            case .keyfile:
                store.selectKeyfile(url)
            }
        case .failure(let error):
            store.errorMessage = error.localizedDescription
        }
    }

    private func create() {
        let name = newName
        let password = newPassword
        Task {
            if await store.createVault(name: name, password: password) {
                newPassword = ""
                confirmPassword = ""
            }
        }
    }
}

import SwiftUI

@MainActor
struct UnlockView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.scenePhase) private var scenePhase
    @State private var password = ""
    @State private var showKeyfileImporter = false
    @State private var triedBiometric = false
    @State private var confirmChangeVault = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack(spacing: 12) {
                        Image(systemName: "lock.shield.fill")
                            .font(.largeTitle)
                            .foregroundStyle(.tint)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(store.vaultName)
                                .font(.headline)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text("Locked")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }

                Section {
                    SecureField("Master password", text: $password, prompt: .hint("Master password"))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .focused($passwordFocused)
                        .submitLabel(.go)
                        .onSubmit { unlock() }
                    Button {
                        unlock()
                    } label: {
                        Label("Unlock", systemImage: "lock.open")
                    }
                    .disabled(password.isEmpty || store.isBusy)

                    if store.biometricUnlockEnabled {
                        Button {
                            Task { await store.unlockWithBiometrics() }
                        } label: {
                            Label("Unlock with \(BiometricKeychain.biometryName)",
                                  systemImage: BiometricKeychain.biometrySymbol)
                        }
                        .disabled(store.isBusy)
                    }
                }

                if let error = store.errorMessage {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
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
                            showKeyfileImporter = true
                        } label: {
                            Label("Choose Keyfile…", systemImage: "key")
                        }
                    }
                } header: {
                    Text("Keyfile (optional)")
                }

                Section {
                    Button("Change Vault", role: .destructive) {
                        confirmChangeVault = true
                    }
                }
            }
            .navigationTitle("Unlock")
            .fileImporter(isPresented: $showKeyfileImporter, allowedContentTypes: VaultFileTypes.keyfile) { result in
                switch result {
                case .success(let url):
                    store.selectKeyfile(url)
                case .failure(let error):
                    store.errorMessage = error.localizedDescription
                }
            }
            .confirmationDialog("Change vault?", isPresented: $confirmChangeVault, titleVisibility: .visible) {
                Button("Forget This Vault", role: .destructive) {
                    store.forgetVault()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Aegis will forget this vault file and keyfile. The file itself is not deleted.")
            }
            .onAppear {
                attemptBiometricUnlock()
            }
            .onChange(of: scenePhase) { _, _ in
                attemptBiometricUnlock()
            }
        }
    }

    private func unlock() {
        guard !password.isEmpty, !store.isBusy else { return }
        let entered = password
        passwordFocused = false
        Task {
            if await store.unlock(password: entered) {
                password = ""
            }
        }
    }

    /// Offers Face ID once per lock, only while the app is in the foreground.
    private func attemptBiometricUnlock() {
        guard scenePhase == .active,
              !triedBiometric,
              store.biometricUnlockEnabled,
              !store.isBusy,
              !store.isUnlocked
        else { return }
        triedBiometric = true
        Task { await store.unlockWithBiometrics() }
    }
}

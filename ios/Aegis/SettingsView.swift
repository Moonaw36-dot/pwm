import SwiftUI

@MainActor
struct SettingsView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @AppStorage(Preferences.autoLockDelayKey) private var autoLockDelay: Int = Preferences.defaultAutoLockDelay
    @AppStorage(Preferences.inactivityTimeoutKey) private var inactivityTimeout: Int = Preferences.defaultInactivityTimeout
    @State private var showEnableBiometric = false
    @State private var showDuress = false
    @State private var confirmRemoveDuress = false
    @State private var confirmForget = false

    private var appVersion: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(version) (\(build))"
    }

    private var biometricBinding: Binding<Bool> {
        Binding(
            get: { store.biometricUnlockEnabled },
            set: { enabled in
                if enabled {
                    showEnableBiometric = true
                } else {
                    store.disableBiometricUnlock()
                }
            }
        )
    }

    private var autoFillBinding: Binding<Bool> {
        Binding(
            get: { store.autoFillEnabled },
            set: { store.setAutoFillEnabled($0) }
        )
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Vault") {
                    LabeledContent("File", value: store.vaultName)
                    LabeledContent("Keyfile", value: store.keyfileName ?? "None")
                    LabeledContent("Entries", value: String(store.activeEntries.count))
                    Button {
                        dismiss()
                        store.lock()
                    } label: {
                        Label("Lock Now", systemImage: "lock")
                    }
                }

                Section {
                    Toggle(isOn: biometricBinding) {
                        Label("Unlock with \(BiometricKeychain.biometryName)",
                              systemImage: BiometricKeychain.biometrySymbol)
                    }
                    .disabled(!BiometricKeychain.isBiometryAvailable && !store.biometricUnlockEnabled)

                    Picker("Lock when leaving app", selection: $autoLockDelay) {
                        ForEach(Preferences.autoLockDelayOptions) { option in
                            Text(option.title).tag(option.seconds)
                        }
                    }
                    Picker("Lock after inactivity", selection: $inactivityTimeout) {
                        ForEach(Preferences.inactivityOptions) { option in
                            Text(option.title).tag(option.seconds)
                        }
                    }
                    NavigationLink {
                        ChangePasswordView()
                    } label: {
                        Label("Change Master Password", systemImage: "key.horizontal")
                    }
                } header: {
                    Text("Security")
                } footer: {
                    Text("When enabled, your master password is stored in this device's Keychain and can only be read after \(BiometricKeychain.biometryName) succeeds. It never leaves this device. Copied values expire from the clipboard after 30 seconds and are not shared with your other devices.")
                }

                Section {
                    if store.duressEnabled {
                        Button {
                            showDuress = true
                        } label: {
                            Label("Change Duress Password", systemImage: "exclamationmark.shield")
                        }
                        Button("Remove Duress Password", role: .destructive) {
                            confirmRemoveDuress = true
                        }
                    } else {
                        Button {
                            showDuress = true
                        } label: {
                            Label("Set Duress Password", systemImage: "exclamationmark.shield")
                        }
                    }
                } header: {
                    Text("Duress")
                } footer: {
                    Text("A second password that opens a decoy vault with believable fake entries instead of your real one. Use it if you are ever forced to unlock Aegis. The decoy stays on this device and is never synced; your real vault is not touched.")
                }

                Section {
                    Toggle(isOn: autoFillBinding) {
                        Label("AutoFill Passwords", systemImage: "key.viewfinder")
                    }
                    .disabled(!AutoFillCache.isAvailable)
                } header: {
                    Text("AutoFill")
                } footer: {
                    if AutoFillCache.isAvailable {
                        Text("Lets you fill logins in Safari and other apps. Also turn on Aegis in the iOS Settings app under General › AutoFill & Passwords. AutoFill uses an encrypted copy of your vault (and keyfile, if any) kept on this device, refreshed whenever you unlock Aegis. It can't change the vault.")
                    } else {
                        Text("AutoFill isn't available in this install: the app was signed without an App Group. Reinstall it with SideStore or AltStore to enable it.")
                    }
                }

                Section {
                    NavigationLink {
                        HealthView()
                    } label: {
                        Label("Password Health", systemImage: "stethoscope")
                    }
                }

                Section {
                    Button("Forget Vault", role: .destructive) {
                        confirmForget = true
                    }
                } footer: {
                    Text("Locks Aegis and forgets the vault file, keyfile and stored \(BiometricKeychain.biometryName) password. The vault file itself is not deleted.")
                }

                Section("About") {
                    LabeledContent("Version", value: appVersion)
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
            .sheet(isPresented: $showEnableBiometric) {
                EnableBiometricView()
                    .environmentObject(store)
            }
            .sheet(isPresented: $showDuress) {
                DuressPasswordView()
                    .environmentObject(store)
            }
            .confirmationDialog("Remove the duress password?", isPresented: $confirmRemoveDuress, titleVisibility: .visible) {
                Button("Remove", role: .destructive) {
                    store.removeDuressPassword()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The decoy vault on this device is deleted.")
            }
            .confirmationDialog("Forget this vault?", isPresented: $confirmForget, titleVisibility: .visible) {
                Button("Forget Vault", role: .destructive) {
                    dismiss()
                    store.forgetVault()
                }
                Button("Cancel", role: .cancel) {}
            }
        }
    }
}

/// Sets or replaces the duress password.
@MainActor
struct DuressPasswordView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var confirm = ""
    @State private var error: String?

    private var canSubmit: Bool {
        password.count >= 8 && password == confirm && !store.isBusy
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Duress password", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Confirm duress password", text: $confirm)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onSubmit { save() }
                    if !password.isEmpty && password.count < 8 {
                        Text("Use at least 8 characters.")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    } else if !confirm.isEmpty && confirm != password {
                        Text("Passwords do not match.")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                } footer: {
                    Text("Entering this on the unlock screen opens a decoy vault. Pick something that is not your master password but that you would plausibly use. Setting a new one replaces the decoy with a fresh one.")
                }
                if let error {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                    }
                }
                if store.isBusy {
                    Section {
                        HStack {
                            ProgressView()
                            Text(store.busyMessage)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("Duress Password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        save()
                    }
                    .disabled(!canSubmit)
                }
            }
        }
        .interactiveDismissDisabled(store.isBusy)
    }

    private func save() {
        guard canSubmit else { return }
        let entered = password
        error = nil
        Task {
            if await store.setDuressPassword(entered) {
                password = ""
                confirm = ""
                dismiss()
            } else {
                error = store.errorMessage ?? "Could not set the duress password."
                store.errorMessage = nil
            }
        }
    }
}

/// Asks for the master password once, verifies it, then stores it for
/// biometric unlock.
@MainActor
struct EnableBiometricView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Master password", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onSubmit { enable() }
                } footer: {
                    Text("Enter your master password to store it in the Keychain, protected by \(BiometricKeychain.biometryName).")
                }
                if let error {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                    }
                }
                if store.isBusy {
                    Section {
                        HStack {
                            ProgressView()
                            Text(store.busyMessage)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle(BiometricKeychain.biometryName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Enable") {
                        enable()
                    }
                    .disabled(password.isEmpty || store.isBusy)
                }
            }
        }
        .interactiveDismissDisabled(store.isBusy)
    }

    private func enable() {
        guard !password.isEmpty, !store.isBusy else { return }
        let entered = password
        error = nil
        Task {
            if await store.enableBiometricUnlock(password: entered) {
                password = ""
                dismiss()
            } else {
                error = store.errorMessage ?? "Could not enable biometric unlock."
                store.errorMessage = nil
            }
        }
    }
}

@MainActor
struct ChangePasswordView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var newPassword = ""
    @State private var confirm = ""
    @State private var error: String?
    @State private var done = false

    private var problem: String? {
        if newPassword.isEmpty { return nil }
        if newPassword.count < 8 { return "Use at least 8 characters." }
        if !confirm.isEmpty && confirm != newPassword { return "New passwords do not match." }
        if !current.isEmpty && current == newPassword { return "The new password is the same as the current one." }
        return nil
    }

    private var canSubmit: Bool {
        !current.isEmpty && newPassword.count >= 8 && newPassword == confirm
            && current != newPassword && !store.isBusy
    }

    var body: some View {
        Form {
            Section {
                SecureField("Current password", text: $current)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            Section {
                SecureField("New password", text: $newPassword)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                SecureField("Confirm new password", text: $confirm)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if let problem {
                    Text(problem)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            } footer: {
                Text("The vault keeps its keyfile setting. Update the password on your other devices too: they will need the new one after the file syncs.")
            }
            if let error {
                Section {
                    Text(error)
                        .foregroundStyle(.red)
                }
            }
            Section {
                Button {
                    submit()
                } label: {
                    HStack {
                        Text("Change Password")
                        if store.isBusy {
                            Spacer()
                            ProgressView()
                        }
                    }
                }
                .disabled(!canSubmit)
            }
        }
        .navigationTitle("Master Password")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Password Changed", isPresented: $done) {
            Button("OK") {
                dismiss()
            }
        } message: {
            Text("Your vault is now protected by the new master password.")
        }
    }

    private func submit() {
        guard canSubmit else { return }
        let oldValue = current
        let newValue = newPassword
        error = nil
        Task {
            let ok = await store.changePassword(current: oldValue, new: newValue)
            if ok {
                current = ""
                newPassword = ""
                confirm = ""
                if let message = store.errorMessage {
                    // Password changed, but with a warning (e.g. Face ID turned off).
                    error = message
                    store.errorMessage = nil
                }
                done = true
            } else {
                error = store.errorMessage ?? "Could not change the password."
                store.errorMessage = nil
            }
        }
    }
}

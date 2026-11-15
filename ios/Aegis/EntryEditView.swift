import SwiftUI

/// Add (entry == nil) or edit an entry.
@MainActor
struct EntryEditView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss

    @State private var draft: VaultEntry
    @State private var tagsText: String
    @State private var revealPassword = false
    @State private var showGenerator = false
    @State private var localError: String?
    private let isNew: Bool

    init(entry: VaultEntry?) {
        let base = entry ?? VaultEntry.empty
        _draft = State(initialValue: base)
        _tagsText = State(initialValue: base.tags.joined(separator: ", "))
        isNew = entry == nil
    }

    private var canSave: Bool {
        let hasLabel = !draft.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        let hasCard = draft.kind == .card && !draft.cardNumber.isEmpty
        return hasLabel || hasCard
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Type", selection: $draft.kind) {
                        ForEach(EntryKind.allCases) { kind in
                            Text(kind.title).tag(kind)
                        }
                    }
                    .pickerStyle(.segmented)
                    Toggle("Secure note", isOn: $draft.isSecureNote)
                    Toggle("Favorite", isOn: $draft.favorite)
                }

                Section("Details") {
                    TextField("Label", text: $draft.label, prompt: .hint(draft.kind == .wifi ? "Network name (label)" : "Label"))
                    if !draft.isSecureNote {
                        TextField("Username", text: $draft.username, prompt: .hint("Username"))
                            .textContentType(.username)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        passwordField
                        if draft.kind != .wifi {
                            TextField("Website URL", text: $draft.url, prompt: .hint("Website URL"))
                                .keyboardType(.URL)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        }
                    }
                }

                if draft.kind == .card {
                    Section("Card") {
                        TextField("Card number", text: $draft.cardNumber, prompt: .hint("Card number"))
                            .keyboardType(.numbersAndPunctuation)
                            .textContentType(.creditCardNumber)
                            .font(.body.monospaced())
                        TextField("Expiration (MM/YY)", text: $draft.cardExpiration, prompt: .hint("Expiration (MM/YY)"))
                            .keyboardType(.numbersAndPunctuation)
                        TextField("CVC", text: $draft.cardCvc, prompt: .hint("CVC"))
                            .keyboardType(.numberPad)
                            .font(.body.monospaced())
                    }
                }

                if !draft.isSecureNote && draft.kind == .normal {
                    Section {
                        TextField("TOTP secret (Base32 or otpauth:// URI)", text: $draft.totpSecret, prompt: .hint("TOTP secret (Base32 or otpauth:// URI)"))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .font(.body.monospaced())
                        if draft.hasTotp && AegisCore.totp(secret: draft.totpSecret, at: Date()) == nil {
                            Text("This secret does not produce a valid code.")
                                .font(.footnote)
                                .foregroundStyle(.red)
                        }
                    } header: {
                        Text("Two-Factor (TOTP)")
                    }
                }

                Section("Notes") {
                    TextEditor(text: $draft.notes)
                        .frame(minHeight: 100)
                }

                Section {
                    TextField("work, email, bank", text: $tagsText, prompt: .hint("work, email, bank"))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } header: {
                    Text("Tags")
                } footer: {
                    Text("Separate tags with commas.")
                }

                Section("Custom Fields") {
                    ForEach($draft.customFields) { $field in
                        VStack(alignment: .leading, spacing: 6) {
                            TextField("Name", text: $field.name, prompt: .hint("Name"))
                                .font(.subheadline.weight(.medium))
                                .textInputAutocapitalization(.never)
                            TextField("Value", text: $field.value, prompt: .hint("Value"))
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        }
                        .padding(.vertical, 2)
                    }
                    .onDelete { offsets in
                        draft.customFields.remove(atOffsets: offsets)
                    }
                    Button {
                        draft.customFields.append(CustomFieldItem(name: "", value: ""))
                    } label: {
                        Label("Add Field", systemImage: "plus.circle")
                    }
                }
            }
            .navigationTitle(isNew ? "New Entry" : "Edit Entry")
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
                    .disabled(!canSave || store.isBusy)
                }
            }
            .sheet(isPresented: $showGenerator) {
                PasswordGeneratorView { generated in
                    draft.password = generated
                    revealPassword = true
                }
            }
            .errorAlert($localError)
        }
        .interactiveDismissDisabled()
    }

    private var passwordField: some View {
        HStack {
            Group {
                if revealPassword {
                    TextField("Password", text: $draft.password, prompt: .hint("Password"))
                } else {
                    SecureField("Password", text: $draft.password, prompt: .hint("Password"))
                }
            }
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .font(.body.monospaced())

            Button {
                revealPassword.toggle()
            } label: {
                Image(systemName: revealPassword ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)

            Button {
                showGenerator = true
            } label: {
                Image(systemName: "wand.and.stars")
            }
            .buttonStyle(.borderless)
        }
    }

    private func save() {
        var entry = draft
        entry.label = entry.label.trimmingCharacters(in: .whitespacesAndNewlines)
        entry.tags = VaultEntry.parseTags(tagsText)
        if entry.isSecureNote {
            entry.username = ""
            entry.password = ""
            entry.url = ""
            entry.totpSecret = ""
        }
        if entry.kind != .card {
            entry.cardNumber = ""
            entry.cardExpiration = ""
            entry.cardCvc = ""
        }

        let ok = isNew ? store.add(entry) : store.update(entry)
        if ok {
            dismiss()
        } else {
            localError = store.errorMessage ?? "Could not save the entry."
            store.errorMessage = nil
        }
    }
}

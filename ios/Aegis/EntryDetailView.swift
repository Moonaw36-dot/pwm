import SwiftUI

@MainActor
struct EntryDetailView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    let entryID: UInt64

    @State private var revealPassword = false
    @State private var revealCardNumber = false
    @State private var revealCvc = false
    @State private var editing = false
    @State private var confirmDelete = false
    @State private var toastText: String?
    @State private var toastTask: Task<Void, Never>?

    var body: some View {
        if let entry = store.entry(id: entryID) {
            content(for: entry)
        } else {
            ContentUnavailableView("Entry Not Found", systemImage: "questionmark.folder")
        }
    }

    private func content(for entry: VaultEntry) -> some View {
        List {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: entry.systemImage)
                        .font(.title)
                        .foregroundStyle(.tint)
                        .frame(width: 40)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.displayLabel)
                            .font(.title3.weight(.semibold))
                        Text(entry.isSecureNote ? "Secure Note" : entry.kind.title)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if entry.favorite {
                        Image(systemName: "star.fill")
                            .foregroundStyle(.yellow)
                    }
                }
                .padding(.vertical, 4)
            }

            if entry.trashed {
                Section {
                    Label("This entry is in the trash.", systemImage: "trash")
                        .foregroundStyle(.secondary)
                }
            }

            if !entry.isSecureNote {
                credentialsSection(for: entry)
            }

            if entry.kind == .card {
                cardSection(for: entry)
            }

            if entry.hasTotp {
                Section("One-Time Code") {
                    TotpRow(secret: entry.totpSecret) { code in
                        copy(code, label: "Code")
                    }
                }
            }

            if !entry.customFields.isEmpty {
                Section("Custom Fields") {
                    ForEach(entry.customFields) { field in
                        copyRow(title: field.name.isEmpty ? "Field" : field.name,
                                value: field.value,
                                copyLabel: field.name.isEmpty ? "Field" : field.name)
                    }
                }
            }

            if !entry.notes.isEmpty {
                Section("Notes") {
                    Text(entry.notes)
                        .textSelection(.enabled)
                }
            }

            if !entry.tags.isEmpty || entry.createdAt != nil {
                Section("Info") {
                    if !entry.tags.isEmpty {
                        LabeledContent("Tags", value: entry.tags.joined(separator: ", "))
                    }
                    if let createdAt = entry.createdAt {
                        LabeledContent(
                            "Created",
                            value: Date(timeIntervalSince1970: TimeInterval(createdAt))
                                .formatted(date: .abbreviated, time: .shortened)
                        )
                    }
                }
            }

            if entry.trashed {
                Section {
                    Button {
                        store.restore(id: entry.id)
                    } label: {
                        Label("Restore", systemImage: "arrow.uturn.backward")
                    }
                    Button(role: .destructive) {
                        confirmDelete = true
                    } label: {
                        Label("Delete Permanently", systemImage: "trash.slash")
                    }
                }
            }
        }
        .navigationTitle(entry.displayLabel)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if !entry.trashed {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button {
                        store.toggleFavorite(entry)
                    } label: {
                        Label(entry.favorite ? "Unfavorite" : "Favorite",
                              systemImage: entry.favorite ? "star.fill" : "star")
                    }
                    Button("Edit") {
                        editing = true
                    }
                    Menu {
                        Button(role: .destructive) {
                            if store.trash(id: entry.id) {
                                dismiss()
                            }
                        } label: {
                            Label("Move to Trash", systemImage: "trash")
                        }
                    } label: {
                        Label("More", systemImage: "ellipsis.circle")
                    }
                }
            }
        }
        .sheet(isPresented: $editing) {
            EntryEditView(entry: entry)
                .environmentObject(store)
        }
        .confirmationDialog("Delete permanently?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                if store.deletePermanently(id: entry.id) {
                    dismiss()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This cannot be undone.")
        }
        .overlay(alignment: .bottom) {
            if let toastText {
                CopiedToast(text: toastText)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: toastText)
        .onDisappear {
            toastTask?.cancel()
        }
    }

    // MARK: Sections

    @ViewBuilder
    private func credentialsSection(for entry: VaultEntry) -> some View {
        let showUsername = !entry.username.isEmpty
        let showPassword = !entry.password.isEmpty
        let link = VaultEntry.webURL(from: entry.url)
        if showUsername || showPassword || !entry.url.isEmpty {
            Section(entry.kind == .wifi ? "Network" : "Login") {
                if showUsername {
                    copyRow(title: "Username", value: entry.username, copyLabel: "Username")
                }
                if showPassword {
                    secretRow(title: "Password",
                              value: entry.password,
                              masked: "••••••••••••",
                              revealed: $revealPassword,
                              copyLabel: "Password")
                }
                if !entry.url.isEmpty {
                    if let link {
                        Link(destination: link) {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Website")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    Text(entry.url)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }
                                Spacer()
                                Image(systemName: "safari")
                            }
                        }
                        .contextMenu {
                            Button {
                                copy(entry.url, label: "URL")
                            } label: {
                                Label("Copy URL", systemImage: "doc.on.doc")
                            }
                        }
                    } else {
                        copyRow(title: "Website", value: entry.url, copyLabel: "URL")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func cardSection(for entry: VaultEntry) -> some View {
        if !entry.cardNumber.isEmpty || !entry.cardExpiration.isEmpty || !entry.cardCvc.isEmpty {
            Section("Card") {
                if !entry.cardNumber.isEmpty {
                    secretRow(title: "Card Number",
                              value: entry.cardNumber,
                              masked: VaultEntry.maskedCardNumber(entry.cardNumber),
                              revealed: $revealCardNumber,
                              copyLabel: "Card number")
                }
                if !entry.cardExpiration.isEmpty {
                    LabeledContent("Expiration", value: entry.cardExpiration)
                }
                if !entry.cardCvc.isEmpty {
                    secretRow(title: "CVC",
                              value: entry.cardCvc,
                              masked: "•••",
                              revealed: $revealCvc,
                              copyLabel: "CVC")
                }
            }
        }
    }

    // MARK: Rows

    private func copyRow(title: String, value: String, copyLabel: String) -> some View {
        Button {
            copy(value, label: copyLabel)
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(value)
                        .foregroundStyle(.primary)
                        .textSelection(.enabled)
                }
                Spacer()
                Image(systemName: "doc.on.doc")
                    .foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func secretRow(title: String, value: String, masked: String,
                           revealed: Binding<Bool>, copyLabel: String) -> some View {
        HStack {
            Button {
                copy(value, label: copyLabel)
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(revealed.wrappedValue ? value : masked)
                        .font(.body.monospaced())
                        .foregroundStyle(.primary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)

            Button {
                revealed.wrappedValue.toggle()
            } label: {
                Image(systemName: revealed.wrappedValue ? "eye.slash" : "eye")
                    .accessibilityLabel(revealed.wrappedValue ? "Hide" : "Show")
            }
            .buttonStyle(.borderless)
        }
    }

    private func copy(_ value: String, label: String) {
        Clipboard.copy(value)
        store.noteActivity()
        toastText = "\(label) copied · clears in 30 s"
        toastTask?.cancel()
        toastTask = Task {
            try? await Task.sleep(nanoseconds: 1_800_000_000)
            if !Task.isCancelled {
                toastText = nil
            }
        }
    }
}

/// Live TOTP code, refreshed every second.
struct TotpRow: View {
    let secret: String
    let onCopy: (String) -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            if let totp = AegisCore.totp(secret: secret, at: context.date) {
                Button {
                    onCopy(totp.code)
                } label: {
                    HStack {
                        Text(totp.formattedCode)
                            .font(.title2.monospacedDigit().weight(.semibold))
                            .foregroundStyle(.primary)
                        Spacer()
                        CountdownRing(remaining: totp.secondsRemaining, period: totp.period)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            } else {
                Label("Invalid TOTP secret", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct CountdownRing: View {
    let remaining: Int
    let period: Int

    private var fraction: Double {
        guard period > 0 else { return 0 }
        return min(max(Double(remaining) / Double(period), 0), 1)
    }

    var body: some View {
        ZStack {
            Circle()
                .stroke(Color.secondary.opacity(0.25), lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(remaining <= 5 ? Color.red : Color.accentColor,
                        style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(remaining)")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .frame(width: 30, height: 30)
        .accessibilityLabel("\(remaining) seconds remaining")
    }
}

import SwiftUI

enum Route: Hashable {
    case entry(UInt64)
    case trash
}

@MainActor
struct EntryListView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var searchText = ""
    @State private var showingAdd = false
    @State private var showingSettings = false

    private var filtered: [VaultEntry] {
        store.activeEntries
            .filter { $0.matches(searchText) }
            .sorted { $0.displayLabel.localizedCaseInsensitiveCompare($1.displayLabel) == .orderedAscending }
    }

    var body: some View {
        let visible = filtered
        let favorites = visible.filter { $0.favorite }
        let others = visible.filter { !$0.favorite }
        let othersTitle: String = favorites.isEmpty ? "Entries" : "All Entries"

        NavigationStack {
            List {
                if !favorites.isEmpty {
                    Section("Favorites") {
                        ForEach(favorites) { entry in
                            row(for: entry)
                        }
                    }
                }
                if !others.isEmpty {
                    Section(othersTitle) {
                        ForEach(others) { entry in
                            row(for: entry)
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .overlay {
                if visible.isEmpty {
                    if searchText.isEmpty {
                        ContentUnavailableView(
                            "No Entries",
                            systemImage: "key",
                            description: Text("Tap + to add your first entry.")
                        )
                    } else {
                        ContentUnavailableView(
                            "No Results",
                            systemImage: "magnifyingglass",
                            description: Text("No entries match your search.")
                        )
                    }
                }
            }
            .searchable(text: $searchText, prompt: "Label, username, URL or tag")
            .navigationTitle("Aegis")
            .navigationDestination(for: Route.self) { route in
                switch route {
                case .entry(let id):
                    EntryDetailView(entryID: id)
                case .trash:
                    TrashView()
                }
            }
            .toolbar {
                ToolbarItemGroup(placement: .topBarLeading) {
                    Button {
                        showingSettings = true
                    } label: {
                        Label("Settings", systemImage: "gearshape")
                    }
                    Button {
                        store.lock()
                    } label: {
                        Label("Lock", systemImage: "lock")
                    }
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    NavigationLink(value: Route.trash) {
                        Label("Trash", systemImage: "trash")
                    }
                    Button {
                        showingAdd = true
                    } label: {
                        Label("Add Entry", systemImage: "plus")
                    }
                }
            }
            .sheet(isPresented: $showingAdd) {
                EntryEditView(entry: nil)
                    .environmentObject(store)
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView()
                    .environmentObject(store)
            }
        }
        .errorAlert($store.errorMessage)
    }

    private func row(for entry: VaultEntry) -> some View {
        NavigationLink(value: Route.entry(entry.id)) {
            EntryRow(entry: entry)
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: true) {
            Button(role: .destructive) {
                store.trash(id: entry.id)
            } label: {
                Label("Trash", systemImage: "trash")
            }
        }
        .swipeActions(edge: .leading) {
            Button {
                store.toggleFavorite(entry)
            } label: {
                Label(entry.favorite ? "Unfavorite" : "Favorite",
                      systemImage: entry.favorite ? "star.slash" : "star")
            }
            .tint(.yellow)
        }
        .contextMenu {
            if !entry.username.isEmpty {
                Button {
                    Clipboard.copy(entry.username)
                } label: {
                    Label("Copy Username", systemImage: "person")
                }
            }
            if !entry.password.isEmpty {
                Button {
                    Clipboard.copy(entry.password)
                } label: {
                    Label("Copy Password", systemImage: "key")
                }
            }
        }
    }
}

struct EntryRow: View {
    let entry: VaultEntry

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: entry.systemImage)
                .font(.title3)
                .foregroundStyle(.tint)
                .frame(width: 32)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(entry.displayLabel)
                        .lineLimit(1)
                    if entry.favorite {
                        Image(systemName: "star.fill")
                            .font(.caption)
                            .foregroundStyle(.yellow)
                    }
                }
                let subtitle = entry.subtitle
                if !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
        }
        .padding(.vertical, 2)
    }
}

@MainActor
struct TrashView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var pendingDelete: VaultEntry?
    @State private var confirmEmpty = false

    var body: some View {
        let trashed = store.trashedEntries
        List {
            ForEach(trashed) { entry in
                NavigationLink(value: Route.entry(entry.id)) {
                    EntryRow(entry: entry)
                }
                .swipeActions(edge: .leading) {
                    Button {
                        store.restore(id: entry.id)
                    } label: {
                        Label("Restore", systemImage: "arrow.uturn.backward")
                    }
                    .tint(.green)
                }
                .swipeActions(edge: .trailing) {
                    Button {
                        pendingDelete = entry
                    } label: {
                        Label("Delete", systemImage: "trash.slash")
                    }
                    .tint(.red)
                }
            }
        }
        .overlay {
            if trashed.isEmpty {
                ContentUnavailableView(
                    "Trash Is Empty",
                    systemImage: "trash",
                    description: Text("Entries you move to the trash appear here.")
                )
            }
        }
        .navigationTitle("Trash")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Empty", role: .destructive) {
                    confirmEmpty = true
                }
                .disabled(trashed.isEmpty)
            }
        }
        .confirmationDialog(
            "Delete permanently?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { presented in
                    if !presented { pendingDelete = nil }
                }
            ),
            titleVisibility: .visible,
            presenting: pendingDelete
        ) { entry in
            Button("Delete \(entry.displayLabel)", role: .destructive) {
                store.deletePermanently(id: entry.id)
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("This cannot be undone.")
        }
        .confirmationDialog("Empty the trash?", isPresented: $confirmEmpty, titleVisibility: .visible) {
            Button("Delete All Permanently", role: .destructive) {
                store.emptyTrash()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("All entries in the trash will be deleted. This cannot be undone.")
        }
    }
}

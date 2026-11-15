import SwiftUI

@MainActor
struct RootView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(Preferences.autoLockDelayKey) private var autoLockDelay: Int = Preferences.defaultAutoLockDelay
    @AppStorage(Preferences.inactivityTimeoutKey) private var inactivityTimeout: Int = Preferences.defaultInactivityTimeout
    @State private var backgroundedAt: Date?

    var body: some View {
        content
            .background {
                ActivityMonitor {
                    store.noteActivity()
                }
            }
            .overlay {
                if store.isBusy {
                    BusyOverlay(message: store.busyMessage)
                }
            }
            .overlay {
                if scenePhase != .active {
                    PrivacyCover()
                }
            }
            .onChange(of: scenePhase) { _, newPhase in
                handleScenePhase(newPhase)
            }
            .task {
                // Inactivity check while the app is in the foreground.
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 5_000_000_000)
                    await checkInactivity()
                }
            }
            .onOpenURL { url in
                if url.isFileURL {
                    store.openVault(at: url)
                }
            }
    }

    @ViewBuilder
    private var content: some View {
        if store.vaultURL == nil {
            VaultPickerView()
        } else if store.isUnlocked {
            EntryListView()
        } else {
            UnlockView()
        }
    }

    private func handleScenePhase(_ phase: ScenePhase) {
        switch phase {
        case .background:
            if backgroundedAt == nil {
                backgroundedAt = Date()
            }
            if autoLockDelay <= 0 {
                store.lock()
            }
        case .active:
            if let since = backgroundedAt,
               Date().timeIntervalSince(since) >= TimeInterval(autoLockDelay) {
                store.lock()
            }
            backgroundedAt = nil
            store.noteActivity()
        case .inactive:
            // Covered by PrivacyCover. Not locking here: Face ID prompts and
            // Control Center also make the scene inactive.
            break
        @unknown default:
            break
        }
    }

    private func checkInactivity() {
        guard store.isUnlocked, inactivityTimeout > 0, scenePhase == .active else { return }
        if Date().timeIntervalSince(store.lastActivity) >= TimeInterval(inactivityTimeout) {
            store.lock()
        }
    }
}

import Foundation

/// UserDefaults keys and choices for non-secret app settings.
enum Preferences {
    static let autoLockDelayKey = "autoLockDelaySeconds"
    static let inactivityTimeoutKey = "inactivityTimeoutSeconds"

    static let defaultAutoLockDelay = 0
    static let defaultInactivityTimeout = 300

    struct Option: Identifiable, Hashable {
        let seconds: Int
        let title: String
        var id: Int { seconds }
    }

    /// Grace period after the app leaves the foreground.
    static let autoLockDelayOptions: [Option] = [
        Option(seconds: 0, title: "Immediately"),
        Option(seconds: 30, title: "After 30 seconds"),
        Option(seconds: 60, title: "After 1 minute"),
        Option(seconds: 300, title: "After 5 minutes"),
    ]

    /// Lock after this long without touching the screen while the app is open.
    static let inactivityOptions: [Option] = [
        Option(seconds: 60, title: "1 minute"),
        Option(seconds: 120, title: "2 minutes"),
        Option(seconds: 300, title: "5 minutes"),
        Option(seconds: 600, title: "10 minutes"),
        Option(seconds: 0, title: "Never"),
    ]
}

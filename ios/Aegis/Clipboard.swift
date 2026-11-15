import UIKit
import UniformTypeIdentifiers

enum Clipboard {
    static let expirySeconds: TimeInterval = 30

    /// Copies text that expires after 30 seconds and is never shared through
    /// Universal Clipboard (Handoff) with other devices.
    @MainActor
    static func copy(_ value: String) {
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: value]],
            options: [
                .expirationDate: Date().addingTimeInterval(expirySeconds),
                .localOnly: true,
            ]
        )
    }
}

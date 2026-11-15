import SwiftUI

extension Text {
    /// Placeholder for a text field: dimmer than typed text, so an empty field
    /// reads as "type here" and not as a disabled control.
    static func hint(_ text: String) -> Text {
        Text(text).foregroundStyle(.tertiary)
    }
}

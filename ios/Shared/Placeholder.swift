import SwiftUI
import UIKit

extension Text {
    /// Placeholder for a text field. In dark mode it is a lighter gray than
    /// iOS's default, so an empty field doesn't look disabled; light mode
    /// keeps the system placeholder color.
    static func hint(_ text: String) -> Text {
        Text(text).foregroundStyle(Color(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor(white: 1, alpha: 0.6)
                : .placeholderText
        }))
    }
}

import Foundation

/// App-side entry kind. Mapped to/from the FFI `EntryType` in VaultStore.swift only.
enum EntryKind: String, CaseIterable, Identifiable, Hashable {
    case normal
    case card
    case wifi

    var id: String { rawValue }

    var title: String {
        switch self {
        case .normal: return "Login"
        case .card: return "Card"
        case .wifi: return "Wi-Fi"
        }
    }
}

struct CustomFieldItem: Identifiable, Hashable {
    var id = UUID()
    var name: String
    var value: String
}

/// App-side copy of a vault entry. Views only ever see this type, never the
/// UniFFI-generated `Entry`, so binding changes stay confined to VaultStore.swift.
struct VaultEntry: Identifiable, Hashable {
    var id: UInt64
    var label: String = ""
    var username: String = ""
    var password: String = ""
    var notes: String = ""
    var url: String = ""
    /// Empty string means "no TOTP".
    var totpSecret: String = ""
    var tags: [String] = []
    var kind: EntryKind = .normal
    var isSecureNote: Bool = false
    var favorite: Bool = false
    var cardNumber: String = ""
    var cardExpiration: String = ""
    var cardCvc: String = ""
    var customFields: [CustomFieldItem] = []
    var createdAt: UInt64? = nil
    var trashed: Bool = false

    static var empty: VaultEntry { VaultEntry(id: 0) }

    var displayLabel: String {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty { return trimmed }
        switch kind {
        case .card: return "Card"
        case .wifi: return "Wi-Fi"
        case .normal: return isSecureNote ? "Secure Note" : "Untitled"
        }
    }

    var systemImage: String {
        if isSecureNote { return "note.text" }
        switch kind {
        case .normal: return "key.fill"
        case .card: return "creditcard.fill"
        case .wifi: return "wifi"
        }
    }

    var subtitle: String {
        if isSecureNote { return "Secure note" }
        switch kind {
        case .card:
            return VaultEntry.maskedCardNumber(cardNumber)
        case .wifi, .normal:
            return username
        }
    }

    var hasTotp: Bool {
        !totpSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func matches(_ query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if q.isEmpty { return true }
        if label.localizedCaseInsensitiveContains(q) { return true }
        if username.localizedCaseInsensitiveContains(q) { return true }
        if url.localizedCaseInsensitiveContains(q) { return true }
        return tags.contains { $0.localizedCaseInsensitiveContains(q) }
    }

    static func maskedCardNumber(_ number: String) -> String {
        let digits = number.filter { $0.isNumber }
        guard digits.count > 4 else { return digits.isEmpty ? "" : "••••" }
        return "•••• " + String(digits.suffix(4))
    }

    static func parseTags(_ text: String) -> [String] {
        text.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    /// Accepts "example.com" or a full http(s) URL; anything else is not opened.
    static func webURL(from text: String) -> URL? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let candidate = trimmed.contains("://") ? trimmed : "https://" + trimmed
        guard let url = URL(string: candidate),
              let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              url.host != nil
        else { return nil }
        return url
    }
}

/// A TOTP code ready for display.
struct TotpDisplay: Equatable {
    let code: String
    let secondsRemaining: Int
    let period: Int

    var formattedCode: String {
        guard code.count == 6 || code.count == 8 else { return code }
        let half = code.count / 2
        return String(code.prefix(half)) + " " + String(code.suffix(code.count - half))
    }
}

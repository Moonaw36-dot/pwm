import Foundation
import LocalAuthentication
import Security

/// Optional biometric quick-unlock: the master password is stored in the
/// Keychain, readable only on this device, only while a passcode is set, and
/// only after a successful biometric check with the currently enrolled
/// biometrics (re-enrolling Face ID invalidates the item).
enum BiometricKeychain {
    enum KeychainError: LocalizedError {
        case unavailable(String)
        case accessControl
        case status(OSStatus)
        case cancelled
        case badData

        var errorDescription: String? {
            switch self {
            case .unavailable(let reason):
                return reason
            case .accessControl:
                return "Could not create the Keychain access control."
            case .status(let status):
                var message = "OSStatus \(status)"
                if let cfMessage = SecCopyErrorMessageString(status, nil) {
                    message = cfMessage as String
                }
                return "Keychain error: \(message)"
            case .cancelled:
                return "Authentication was cancelled."
            case .badData:
                return "The stored password could not be decoded."
            }
        }
    }

    private static let service = "com.moonaw.aegis.master-password"
    private static let account = "vault"

    static var isBiometryAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    static var biometryName: String {
        let context = LAContext()
        var error: NSError?
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        switch context.biometryType {
        case .faceID:
            return "Face ID"
        case .touchID:
            return "Touch ID"
        default:
            return "Biometrics"
        }
    }

    static var biometrySymbol: String {
        let context = LAContext()
        var error: NSError?
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        return context.biometryType == .touchID ? "touchid" : "faceid"
    }

    private static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    /// Stores (or replaces) the master password. Does not prompt.
    static func save(password: String) throws {
        delete()

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            &accessError
        ) else {
            if let accessError {
                _ = accessError.takeRetainedValue()
            }
            throw KeychainError.accessControl
        }

        var query = baseQuery()
        query[kSecAttrAccessControl as String] = access
        query[kSecValueData as String] = Data(password.utf8)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.status(status)
        }
    }

    static func delete() {
        _ = SecItemDelete(baseQuery() as CFDictionary)
    }

    /// Asks for biometrics, then reads the password. Returns nil when no
    /// usable item exists (never saved, or invalidated by a biometry change).
    static func readPassword(reason: String) async throws -> String? {
        let context = LAContext()
        context.localizedCancelTitle = "Enter Password"

        do {
            let success = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                                           localizedReason: reason)
            if !success {
                throw KeychainError.cancelled
            }
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel, .userFallback:
                throw KeychainError.cancelled
            default:
                throw KeychainError.unavailable(error.localizedDescription)
            }
        }

        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        // Reuse the context that was just evaluated so the user is not asked twice.
        query[kSecUseAuthenticationContext as String] = context

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, let password = String(data: data, encoding: .utf8) else {
                throw KeychainError.badData
            }
            return password
        case errSecItemNotFound:
            return nil
        case errSecUserCanceled:
            throw KeychainError.cancelled
        default:
            throw KeychainError.status(status)
        }
    }
}

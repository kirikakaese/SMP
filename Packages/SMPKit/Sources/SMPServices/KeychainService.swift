import Foundation
import SMPCore
import Security

/// Identifies one generic-password item in the Keychain.
public struct KeychainItem: Hashable, Sendable {
    public enum Accessibility: Sendable {
        /// Readable only while the Mac is unlocked. The default for everything SMP stores.
        case whenUnlockedThisDeviceOnly
        /// Readable after the first unlock since boot (needed by the background agent helper).
        case afterFirstUnlockThisDeviceOnly

        var secValue: CFString {
            switch self {
            case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            }
        }
    }

    public var service: String
    public var account: String
    public var label: String?
    public var accessibility: Accessibility

    public init(
        service: String,
        account: String,
        label: String? = nil,
        accessibility: Accessibility = .whenUnlockedThisDeviceOnly
    ) {
        self.service = service
        self.account = account
        self.label = label
        self.accessibility = accessibility
    }

    /// Keychain service names used by SMP. Items are never synchronized to iCloud Keychain.
    public enum Service {
        public static let providerToken = "com.kirikakaese.smp.provider-token"
        public static let archiveKey = "com.kirikakaese.smp.archive-key"
    }

    public static func providerToken(accountID: String) -> KeychainItem {
        KeychainItem(service: Service.providerToken, account: accountID, label: "SMP provider token")
    }
}

/// Stores small secrets (provider tokens, archive keys) in the macOS Keychain.
///
/// Key passphrases are *not* stored here: OpenSSH's own `UseKeychain` integration handles those,
/// so `ssh` and `ssh-add` can find them without SMP running.
public protocol KeychainServicing: Sendable {
    /// Creates or replaces the secret for `item`.
    func setSecret(_ secret: SecureBytes, for item: KeychainItem) throws
    /// Returns the secret for `item`, or `nil` if there is none.
    func secret(for item: KeychainItem) throws -> SecureBytes?
    /// Deletes the secret for `item`. Deleting a missing item is not an error.
    func deleteSecret(for item: KeychainItem) throws
    /// Returns `true` if an item exists, without reading its secret.
    func containsSecret(for item: KeychainItem) throws -> Bool
}

/// `KeychainServicing` backed by Security.framework generic-password items.
public struct KeychainService: KeychainServicing {
    /// Whether to use the data-protection keychain. It requires a signed app with a
    /// `keychain-access-groups` entitlement, so it is off for unsigned builds and `swift test`.
    public let useDataProtectionKeychain: Bool

    public init(useDataProtectionKeychain: Bool = false) {
        self.useDataProtectionKeychain = useDataProtectionKeychain
    }

    public func setSecret(_ secret: SecureBytes, for item: KeychainItem) throws {
        try secret.withUnsafeBytes { bytes in
            // Point at the secure buffer instead of copying it; Security copies it internally.
            let value: Data
            if let base = bytes.baseAddress, !bytes.isEmpty {
                value = Data(
                    bytesNoCopy: UnsafeMutableRawPointer(mutating: base),
                    count: bytes.count,
                    deallocator: .none
                )
            } else {
                value = Data()
            }

            let update: [CFString: Any] = [
                kSecValueData: value,
                kSecAttrAccessible: item.accessibility.secValue,
            ]
            var status = SecItemUpdate(baseQuery(for: item) as CFDictionary, update as CFDictionary)
            if status == errSecItemNotFound {
                var add = baseQuery(for: item)
                add[kSecValueData] = value
                add[kSecAttrAccessible] = item.accessibility.secValue
                if let label = item.label {
                    add[kSecAttrLabel] = label
                }
                status = SecItemAdd(add as CFDictionary, nil)
            }
            try check(status, action: "save")
        }
    }

    public func secret(for item: KeychainItem) throws -> SecureBytes? {
        var query = baseQuery(for: item)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        try check(status, action: "read")
        guard var data = result as? Data else {
            throw SMPError(.keychain, whatHappened: "The Keychain returned an unexpected value.")
        }
        // Best effort: the CFData returned by Security may still hold a copy until released.
        return SecureBytes(consuming: &data)
    }

    public func deleteSecret(for item: KeychainItem) throws {
        let status = SecItemDelete(baseQuery(for: item) as CFDictionary)
        if status == errSecItemNotFound {
            return
        }
        try check(status, action: "delete")
    }

    public func containsSecret(for item: KeychainItem) throws -> Bool {
        var query = baseQuery(for: item)
        query[kSecReturnAttributes] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return false
        }
        try check(status, action: "look up")
        return true
    }

    private func baseQuery(for item: KeychainItem) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: item.service,
            kSecAttrAccount: item.account,
            kSecAttrSynchronizable: false,
        ]
        if useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain] = true
        }
        return query
    }

    private func check(_ status: OSStatus, action: String) throws {
        guard status != errSecSuccess else { return }
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        Log.keychain.error("Keychain \(action, privacy: .public) failed with status \(status)")
        throw SMPError(
            .keychain,
            whatHappened: "SMP could not \(action) an item in your Keychain.",
            howToFix: status == errSecInteractionNotAllowed
                ? "Unlock your Mac and try again."
                : "Open Keychain Access and check that your login keychain is unlocked, then try again.",
            details: message
        )
    }
}

/// An in-memory `KeychainServicing` for tests and SwiftUI previews.
public final class InMemoryKeychainService: KeychainServicing, @unchecked Sendable {
    // Safety: `items` is only touched while holding `lock`.
    private struct Key: Hashable {
        let service: String
        let account: String
    }

    private let lock = NSLock()
    private var items: [Key: SecureBytes] = [:]

    public init() {}

    public func setSecret(_ secret: SecureBytes, for item: KeychainItem) throws {
        let copy = secret.withUnsafeBytes { SecureBytes($0) }
        lock.withLock { items[Key(service: item.service, account: item.account)] = copy }
    }

    public func secret(for item: KeychainItem) throws -> SecureBytes? {
        guard let stored = lock.withLock({ items[Key(service: item.service, account: item.account)] }) else {
            return nil
        }
        return stored.withUnsafeBytes { SecureBytes($0) }
    }

    public func deleteSecret(for item: KeychainItem) throws {
        _ = lock.withLock { items.removeValue(forKey: Key(service: item.service, account: item.account)) }
    }

    public func containsSecret(for item: KeychainItem) throws -> Bool {
        lock.withLock { items[Key(service: item.service, account: item.account)] != nil }
    }
}

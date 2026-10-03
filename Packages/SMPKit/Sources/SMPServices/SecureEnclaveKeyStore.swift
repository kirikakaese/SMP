import CryptoKit
import Foundation
import LocalAuthentication
import SMPCore
import SMPSSH
import Security

/// Creates, lists, deletes and uses Secure Enclave keys.
public protocol SecureEnclaveKeyStoring: Sendable {
    /// `false` on Macs without a Secure Enclave (Intel Macs without T2, virtual machines).
    var isAvailable: Bool { get }
    func keys() throws -> [SecureEnclaveKeyInfo]
    func create(name: String, comment: String, policy: SigningPolicy) throws -> SecureEnclaveKeyInfo
    /// Updates name, comment and policy. The Touch ID requirement itself is fixed at creation.
    func update(_ key: SecureEnclaveKeyInfo) throws
    func delete(id: UUID) throws
    /// Signs `data` (SHA-256, ECDSA P-256) and returns the raw `r || s` signature.
    /// - Parameter context: an already evaluated `LAContext`, so the Secure Enclave does not prompt again.
    func sign(_ data: Data, with id: UUID, context: LAContext?) throws -> Data
}

extension SecureEnclaveKeyInfo {
    /// The SSH public key blob (`ecdsa-sha2-nistp256`).
    public var publicKeyBlob: Data { SSHAgentCodec.ecdsaP256PublicKeyBlob(x963: publicKeyX963) }

    /// The key as an `authorized_keys` line.
    public var openSSHLine: String {
        let base = SSHAgentCodec.ecdsaP256KeyType + " " + publicKeyBlob.base64EncodedString()
        return comment.isEmpty ? base : base + " " + comment
    }

    public func publicKey() throws -> SSHPublicKey {
        try SSHPublicKey(line: openSSHLine)
    }
}

/// Keeps Secure Enclave keys as Keychain items: the device-bound key reference is the item's
/// secret, `SecureEnclaveKeyInfo` (public data only) its generic attribute. Items use the data
/// protection keychain and, in signed builds, an access group shared with the agent helper.
public struct SecureEnclaveKeyStore: SecureEnclaveKeyStoring {
    public static let service = "com.kirikakaese.smp.secure-enclave"
    private let accessGroup: String?

    public init(accessGroup: String?) {
        self.accessGroup = accessGroup
    }

    /// Reads the shared access group from the running app's Info.plist (`SMPKeychainAccessGroup`).
    public static func bundleAccessGroup(_ bundle: Bundle = .main) -> String? {
        guard let value = bundle.object(forInfoDictionaryKey: "SMPKeychainAccessGroup") as? String,
              !value.isEmpty, !value.hasPrefix("$(")
        else { return nil }
        return value
    }

    public var isAvailable: Bool { SecureEnclave.isAvailable }

    public func keys() throws -> [SecureEnclaveKeyInfo] {
        var query = baseQuery()
        query[kSecMatchLimit] = kSecMatchLimitAll
        query[kSecReturnAttributes] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        try Self.check(status, action: "read Secure Enclave keys")
        let items = result as? [[CFString: Any]] ?? []
        let decoder = JSONDecoder()
        return items
            .compactMap { $0[kSecAttrGeneric] as? Data }
            .compactMap { try? decoder.decode(SecureEnclaveKeyInfo.self, from: $0) }
            .sorted { $0.createdAt < $1.createdAt }
    }

    public func create(name: String, comment: String, policy: SigningPolicy) throws -> SecureEnclaveKeyInfo {
        guard isAvailable else {
            throw SMPError(
                .keyOperationFailed,
                whatHappened: "This Mac has no Secure Enclave.",
                howToFix: "Secure Enclave keys need a Mac with Apple silicon or a T2 chip."
            )
        }
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if policy.requiresUserPresence {
            flags.insert(.userPresence)
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error
        ) else {
            throw SMPError(.keyOperationFailed, whatHappened: "SMP could not set up the key's access rules.")
        }
        let privateKey: SecureEnclave.P256.Signing.PrivateKey
        do {
            privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        } catch {
            throw SMPError(
                .keyOperationFailed,
                whatHappened: "The Secure Enclave could not create a key.",
                howToFix: "Secure Enclave keys need a signed copy of SMP. Builds you compile yourself "
                    + "without a development team cannot use the Secure Enclave.",
                details: error.localizedDescription
            )
        }
        let info = SecureEnclaveKeyInfo(
            name: name,
            comment: comment,
            policy: policy,
            publicKeyX963: privateKey.publicKey.x963Representation
        )
        var item = baseQuery()
        item[kSecAttrAccount] = info.id.uuidString
        item[kSecAttrLabel] = "SMP Secure Enclave key “\(name)”"
        item[kSecAttrGeneric] = try JSONEncoder().encode(info)
        // The reference is useless on any other device, but it still never leaves this Mac.
        item[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        item[kSecValueData] = privateKey.dataRepresentation
        try Self.check(SecItemAdd(item as CFDictionary, nil), action: "save the Secure Enclave key")
        return info
    }

    public func update(_ key: SecureEnclaveKeyInfo) throws {
        var query = baseQuery()
        query[kSecAttrAccount] = key.id.uuidString
        let changes: [CFString: Any] = [
            kSecAttrGeneric: try JSONEncoder().encode(key),
            kSecAttrLabel: "SMP Secure Enclave key “\(key.name)”",
        ]
        try Self.check(SecItemUpdate(query as CFDictionary, changes as CFDictionary), action: "update the key")
    }

    public func delete(id: UUID) throws {
        var query = baseQuery()
        query[kSecAttrAccount] = id.uuidString
        let status = SecItemDelete(query as CFDictionary)
        guard status != errSecItemNotFound else { return }
        try Self.check(status, action: "delete the Secure Enclave key")
    }

    public func sign(_ data: Data, with id: UUID, context: LAContext?) throws -> Data {
        var query = baseQuery()
        query[kSecAttrAccount] = id.uuidString
        query[kSecReturnData] = true
        var result: CFTypeRef?
        try Self.check(SecItemCopyMatching(query as CFDictionary, &result), action: "find the Secure Enclave key")
        guard let reference = result as? Data else {
            throw SMPError(.keychain, whatHappened: "The Secure Enclave key reference is missing.")
        }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: reference,
                authenticationContext: context
            )
            return try key.signature(for: data).rawRepresentation
        } catch {
            throw SMPError(
                .authenticationFailed,
                whatHappened: "The Secure Enclave did not sign the request.",
                howToFix: "Signing needs Touch ID or your password.",
                details: error.localizedDescription
            )
        }
    }

    private func baseQuery() -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecUseDataProtectionKeychain: true,
            kSecAttrSynchronizable: false,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        return query
    }

    private static func check(_ status: OSStatus, action: String) throws {
        guard status != errSecSuccess else { return }
        if status == errSecMissingEntitlement {
            throw SMPError(
                .keychain,
                whatHappened: "SMP could not \(action).",
                howToFix: "Secure Enclave keys need a signed copy of SMP (the shared Keychain group "
                    + "is only available to signed builds).",
                details: "OSStatus \(status)"
            )
        }
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        throw SMPError(.keychain, whatHappened: "SMP could not \(action).", details: message)
    }
}

/// A software stand-in with the same behavior (P-256 keys in memory). For tests and previews;
/// it never touches the Keychain or the Secure Enclave.
public final class InMemorySecureEnclaveKeyStore: SecureEnclaveKeyStoring, @unchecked Sendable {
    // Safety: all stored state is only accessed while holding `lock`.
    private let lock = NSLock()
    private var entries: [UUID: (info: SecureEnclaveKeyInfo, key: P256.Signing.PrivateKey)] = [:]
    private var signatureCount = 0
    private var shouldFail = false

    /// Set to make `sign` fail, as if the user cancelled Touch ID.
    public var failsSigning: Bool {
        get { lock.withLock { shouldFail } }
        set { lock.withLock { shouldFail = newValue } }
    }

    public init() {}

    public var isAvailable: Bool { true }

    public var signatures: Int { lock.withLock { signatureCount } }

    public func keys() throws -> [SecureEnclaveKeyInfo] {
        lock.withLock { entries.values.map(\.info).sorted { $0.createdAt < $1.createdAt } }
    }

    public func create(name: String, comment: String, policy: SigningPolicy) throws -> SecureEnclaveKeyInfo {
        let key = P256.Signing.PrivateKey()
        let info = SecureEnclaveKeyInfo(
            name: name, comment: comment, policy: policy, publicKeyX963: key.publicKey.x963Representation
        )
        lock.withLock { entries[info.id] = (info, key) }
        return info
    }

    public func update(_ key: SecureEnclaveKeyInfo) throws {
        try lock.withLock {
            guard let entry = entries[key.id] else { throw SMPError.invalidArgument("Unknown key.") }
            entries[key.id] = (key, entry.key)
        }
    }

    public func delete(id: UUID) throws {
        _ = lock.withLock { entries.removeValue(forKey: id) }
    }

    public func sign(_ data: Data, with id: UUID, context: LAContext?) throws -> Data {
        try lock.withLock {
            guard !shouldFail else {
                throw SMPError(.authenticationFailed, whatHappened: "Signing was cancelled.")
            }
            guard let entry = entries[id] else { throw SMPError.invalidArgument("Unknown key.") }
            signatureCount += 1
            return try entry.key.signature(for: data).rawRepresentation
        }
    }
}

import Foundation
import SMPCore
import SMPSSH

// MARK: - Requests and results

public struct SecurityKeyOptions: Sendable, Hashable {
    /// Store the key handle on the authenticator (`-O resident`), so it can be loaded on other machines.
    public var resident = false
    /// Require PIN or biometric verification on each use (`-O verify-required`).
    public var verifyRequired = false
    /// Optional application string, must start with `ssh:` (`-O application=`).
    public var application = ""
    /// Path to a FIDO middleware library (`-w`), needed by the OpenSSH that ships with macOS.
    public var providerPath = ""

    public init() {}
}

public struct KeyGenerationRequest: Sendable {
    public enum KeyType: Sendable, Hashable {
        case ed25519
        case ecdsa(bits: Int)
        case rsa(bits: Int)
        case ed25519SK
        case ecdsaSK

        public var isSecurityKey: Bool { self == .ed25519SK || self == .ecdsaSK }

        /// The conventional default file name for this type.
        public var defaultFileName: String {
            switch self {
            case .ed25519: "id_ed25519"
            case .ecdsa: "id_ecdsa"
            case .rsa: "id_rsa"
            case .ed25519SK: "id_ed25519_sk"
            case .ecdsaSK: "id_ecdsa_sk"
            }
        }
    }

    public var type: KeyType
    public var fileName: String
    public var directory: URL
    public var comment: String
    /// `nil` or empty creates a key without passphrase.
    public var passphrase: SecureBytes?
    public var kdfRounds: Int
    public var securityKey: SecurityKeyOptions
    /// PIN for the security key, if it asks for one.
    public var securityKeyPIN: SecureBytes?
    /// Archive an existing key with the same name instead of failing.
    public var replaceExisting: Bool

    public init(
        type: KeyType = .ed25519,
        fileName: String,
        directory: URL,
        comment: String,
        passphrase: SecureBytes? = nil,
        kdfRounds: Int = KeyService.defaultKDFRounds,
        securityKey: SecurityKeyOptions = SecurityKeyOptions(),
        securityKeyPIN: SecureBytes? = nil,
        replaceExisting: Bool = false
    ) {
        self.type = type
        self.fileName = fileName
        self.directory = directory
        self.comment = comment
        self.passphrase = passphrase
        self.kdfRounds = kdfRounds
        self.securityKey = securityKey
        self.securityKeyPIN = securityKeyPIN
        self.replaceExisting = replaceExisting
    }
}

public struct KeyImportRequest: Sendable {
    /// The key file's contents (private key in any supported format, or a public key line).
    public var contents: SecureBytes
    public var fileName: String
    public var directory: URL
    /// The key's current passphrase, if it has one.
    public var passphrase: SecureBytes?
    /// Comment for the public key file, when the source has none.
    public var comment: String?
    public var replaceExisting: Bool

    public init(
        contents: SecureBytes,
        fileName: String,
        directory: URL,
        passphrase: SecureBytes? = nil,
        comment: String? = nil,
        replaceExisting: Bool = false
    ) {
        self.contents = contents
        self.fileName = fileName
        self.directory = directory
        self.passphrase = passphrase
        self.comment = comment
        self.replaceExisting = replaceExisting
    }
}

public struct KeyOperationResult: Sendable {
    public let privateKeyURL: URL?
    public let publicKeyURL: URL
    public let publicKey: SSHPublicKey
    /// The key that was archived because it had the same name.
    public let replacedKey: ArchivedKey?
}

public struct RenameResult: Sendable {
    public let privateKeyURL: URL?
    public let publicKeyURL: URL?
    public let updatedConfigReferences: Int
}

public struct GitSigningReference: Sendable, Hashable {
    public let file: URL
    public let value: String
}

/// Everything that depends on a key, shown before it is archived or deleted.
public struct KeyImpactReport: Sendable {
    public let configReferences: [ConfigReference]
    public let isLoadedInAgent: Bool
    public let gitSigningReferences: [GitSigningReference]
    /// Things SMP cannot check yet, shown so the user can verify them by hand.
    public let notChecked: [String]

    public var isEmpty: Bool { configReferences.isEmpty && !isLoadedInAgent && gitSigningReferences.isEmpty }
}

// MARK: - Protocol

public protocol KeyManaging: Sendable {
    func generate(_ request: KeyGenerationRequest) async throws -> KeyOperationResult
    func importKey(_ request: KeyImportRequest) async throws -> KeyOperationResult
    func rename(_ key: DiscoveredKey, to newName: String, updateConfig: Bool) async throws -> RenameResult
    func changePassphrase(
        of key: DiscoveredKey,
        current: SecureBytes?,
        new: SecureBytes?,
        kdfRounds: Int
    ) async throws
    func changeComment(of key: DiscoveredKey, to comment: String, passphrase: SecureBytes?) async throws
    func upgradeFormat(of key: DiscoveredKey, passphrase: SecureBytes?) async throws
    func impactReport(for key: DiscoveredKey, isLoadedInAgent: Bool) async throws -> KeyImpactReport
    /// Removes the key from the agent and Keychain, applies `configEdits`, then securely deletes the files.
    func deletePermanently(_ key: DiscoveredKey, configEdits: [ConfigReferenceEdit]) async throws
    func exportPrivateKey(_ key: DiscoveredKey, to destination: URL) throws
    func exportPublicKey(_ key: DiscoveredKey, to destination: URL) throws
}

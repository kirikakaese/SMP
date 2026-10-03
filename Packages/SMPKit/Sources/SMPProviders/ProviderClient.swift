import Foundation
import SMPCore
import SMPSSH

/// Reads and changes the SSH keys of one provider account.
public protocol ProviderClient: Sendable {
    /// The login name the token belongs to.
    func currentUsername() async throws -> String
    /// All authentication and signing keys on the account.
    func listKeys() async throws -> [RemoteKey]
    /// Uploads a public key for the given usages. Returns the keys as the provider stored them.
    func addKey(title: String, publicKey: SSHPublicKey, usages: Set<RemoteKeyUsage>) async throws -> [RemoteKey]
    func deleteKey(_ key: RemoteKey) async throws
}

/// Creates clients. Inject a fake in tests.
public protocol ProviderClientMaking: Sendable {
    func client(for account: ProviderAccount, token: SecureBytes) throws -> any ProviderClient
}

public struct ProviderClientFactory: ProviderClientMaking {
    private let transport: any HTTPTransport

    public init(transport: any HTTPTransport = URLSessionTransport()) {
        self.transport = transport
    }

    public func client(for account: ProviderAccount, token: SecureBytes) throws -> any ProviderClient {
        let secret = token.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !secret.isEmpty, !secret.contains(where: { $0.isNewline || $0 == " " }) else {
            throw SMPError.invalidArgument(String(localized: "The token is empty or contains spaces."))
        }
        switch account.kind {
        case .github:
            return try GitHubClient(account: account, token: secret, transport: transport)
        case .gitlab:
            return try GitLabClient(account: account, token: secret, transport: transport)
        case .bitbucket:
            return try BitbucketClient(account: account, token: secret, transport: transport)
        case .gitea:
            return try GiteaClient(account: account, token: secret, transport: transport)
        }
    }
}

extension RemoteKey {
    /// Builds a key from provider data, computing the fingerprint locally.
    static func parsed(
        remoteID: String,
        account: ProviderAccount,
        title: String?,
        key: String,
        usages: Set<RemoteKeyUsage>,
        createdAt: String? = nil,
        lastUsedAt: String? = nil,
        expiresAt: String? = nil
    ) -> RemoteKey {
        let line = key.trimmingCharacters(in: .whitespacesAndNewlines)
        return RemoteKey(
            remoteID: remoteID,
            accountID: account.id,
            title: title ?? "",
            publicKeyLine: line,
            fingerprint: (try? SSHPublicKey(line: line))?.fingerprintSHA256,
            usages: usages,
            createdAt: ProviderDate.parse(createdAt),
            lastUsedAt: ProviderDate.parse(lastUsedAt),
            expiresAt: ProviderDate.parse(expiresAt)
        )
    }
}

extension SSHPublicKey {
    /// `type base64`, without the comment: providers do not need the local user and host name.
    var uploadLine: String { wireType + " " + blob.base64EncodedString() }
}

/// Checks a requested usage set against what the provider supports.
func requireSupported(_ usages: Set<RemoteKeyUsage>, by kind: ProviderKind) throws {
    guard !usages.isEmpty else { throw SMPError.invalidArgument(String(localized: """
        Choose at least one use for the key.
        """)) }
    if usages.contains(.signing), !kind.supportsSigningKeys {
        throw SMPError.invalidArgument(String(localized: "\(kind.displayName) does not store SSH signing keys."))
    }
}

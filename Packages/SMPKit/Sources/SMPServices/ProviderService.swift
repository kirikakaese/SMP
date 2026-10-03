import Foundation
import SMPCore
import SMPPersistence
import SMPProviders
import SMPSSH

/// Manages provider accounts and the SSH keys on them.
public protocol ProviderServicing: Sendable {
    func accounts() throws -> [ProviderAccount]
    /// The keys seen at the last refresh of each account (works offline).
    func cachedKeys() throws -> [RemoteKey]
    /// Checks the token with the provider, then saves the account (and the token, in the Keychain).
    func addAccount(
        kind: ProviderKind,
        serverURL: URL?,
        loginEmail: String?,
        token: SecureBytes
    ) async throws -> ProviderAccount
    /// Replaces an account's token after checking that it belongs to the same user.
    func updateToken(for account: ProviderAccount, token: SecureBytes) async throws
    /// Forgets the account locally: deletes its token and cached keys. Nothing changes on the provider.
    func removeAccount(_ account: ProviderAccount) throws
    func refresh(_ account: ProviderAccount) async throws -> [RemoteKey]
    func upload(
        _ key: SSHPublicKey,
        title: String,
        usages: Set<RemoteKeyUsage>,
        to account: ProviderAccount
    ) async throws -> [RemoteKey]
    func delete(_ key: RemoteKey, from account: ProviderAccount) async throws
}

public struct ProviderService: ProviderServicing {
    private let keychain: any KeychainServicing
    private let metadata: any MetadataStoring
    private let factory: any ProviderClientMaking

    public init(
        keychain: any KeychainServicing,
        metadata: any MetadataStoring,
        factory: any ProviderClientMaking = ProviderClientFactory()
    ) {
        self.keychain = keychain
        self.metadata = metadata
        self.factory = factory
    }

    public func accounts() throws -> [ProviderAccount] {
        try metadata.allProviderAccounts()
    }

    public func cachedKeys() throws -> [RemoteKey] {
        try metadata.providerKeys()
    }

    public func addAccount(
        kind: ProviderKind,
        serverURL: URL?,
        loginEmail: String?,
        token: SecureBytes
    ) async throws -> ProviderAccount {
        let server = try Self.normalizedServer(serverURL ?? kind.defaultServerURL)
        var account = ProviderAccount(kind: kind, serverURL: server, username: "", loginEmail: loginEmail)
        account.username = try await factory.client(for: account, token: token).currentUsername()
        let existing = try accounts().contains {
            $0.kind == kind && $0.serverURL == server && $0.username.lowercased() == account.username.lowercased()
        }
        if existing {
            throw SMPError.alreadyExists("\(account.displayName)")
        }
        try keychain.setSecret(token, for: .providerToken(accountID: account.id.uuidString))
        do {
            try metadata.saveProviderAccount(account)
        } catch {
            try? keychain.deleteSecret(for: .providerToken(accountID: account.id.uuidString))
            throw error
        }
        return account
    }

    public func updateToken(for account: ProviderAccount, token: SecureBytes) async throws {
        let username = try await factory.client(for: account, token: token).currentUsername()
        guard username.lowercased() == account.username.lowercased() else {
            throw SMPError.invalidArgument(
                "This token belongs to “\(username)”, not “\(account.username)”. Add it as a separate account."
            )
        }
        try keychain.setSecret(token, for: .providerToken(accountID: account.id.uuidString))
    }

    public func removeAccount(_ account: ProviderAccount) throws {
        try keychain.deleteSecret(for: .providerToken(accountID: account.id.uuidString))
        try metadata.deleteProviderAccount(id: account.id)
    }

    public func refresh(_ account: ProviderAccount) async throws -> [RemoteKey] {
        let keys = try await withClient(for: account) { try await $0.listKeys() }
        try metadata.replaceProviderKeys(keys, for: account.id)
        var synced = account
        synced.lastSyncedAt = Date()
        try metadata.saveProviderAccount(synced)
        return keys
    }

    public func upload(
        _ key: SSHPublicKey,
        title: String,
        usages: Set<RemoteKeyUsage>,
        to account: ProviderAccount
    ) async throws -> [RemoteKey] {
        let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 200, !trimmed.contains(where: \.isNewline) else {
            throw SMPError.invalidArgument("The title must be a single line of 1 to 200 characters.")
        }
        guard !key.isCertificate else {
            throw SMPError.invalidArgument("Upload the key itself, not its certificate.")
        }
        let added = try await withClient(for: account) {
            try await $0.addKey(title: trimmed, publicKey: key, usages: usages)
        }
        _ = try? await refresh(account)
        return added
    }

    public func delete(_ key: RemoteKey, from account: ProviderAccount) async throws {
        try await withClient(for: account) { try await $0.deleteKey(key) }
        _ = try? await refresh(account)
    }

    // MARK: Helpers

    /// Runs `body` with a client for `account`; the token is wiped from memory afterwards.
    private func withClient<T: Sendable>(
        for account: ProviderAccount,
        _ body: @Sendable (any ProviderClient) async throws -> T
    ) async throws -> T {
        guard let token = try keychain.secret(for: .providerToken(accountID: account.id.uuidString)) else {
            throw SMPError(
                .keychain,
                whatHappened: "The token for \(account.displayName) is missing from the Keychain.",
                howToFix: "Enter a new token for the account."
            )
        }
        defer { token.wipe() }
        return try await body(factory.client(for: account, token: token))
    }

    /// `https://host[:port][/path]` without a trailing slash, query or fragment.
    static func normalizedServer(_ url: URL?) throws -> URL {
        guard let url, url.scheme?.lowercased() == "https", let host = url.host(), !host.isEmpty else {
            throw SMPError.invalidArgument("Enter the server address, starting with https://.")
        }
        var components = URLComponents()
        components.scheme = "https"
        components.host = host.lowercased()
        components.port = url.port
        let path = url.path(percentEncoded: false)
        components.path = path.hasSuffix("/") ? String(path.dropLast()) : path
        guard let normalized = components.url else {
            throw SMPError.invalidArgument("The server address is not valid.")
        }
        return normalized
    }
}

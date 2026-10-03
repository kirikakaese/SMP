import Foundation

/// A code hosting service SMP can manage SSH keys on.
public enum ProviderKind: String, Sendable, Hashable, Codable, CaseIterable, Identifiable {
    case github
    case gitlab
    case bitbucket
    /// Gitea and Forgejo share the same API.
    case gitea

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .github: "GitHub"
        case .gitlab: "GitLab"
        case .bitbucket: "Bitbucket"
        case .gitea: "Gitea / Forgejo"
        }
    }

    /// The web address of the hosted service, or `nil` when the user must enter their server.
    public var defaultServerURL: URL? {
        switch self {
        case .github: URL(string: "https://github.com")
        case .gitlab: URL(string: "https://gitlab.com")
        case .bitbucket: URL(string: "https://bitbucket.org")
        case .gitea: nil
        }
    }

    /// Whether the provider stores SSH keys for commit signing separately.
    public var supportsSigningKeys: Bool {
        self == .github || self == .gitlab
    }

    /// Bitbucket API tokens authenticate together with the account's email address.
    public var needsUsername: Bool { self == .bitbucket }

    /// What the token needs, in the provider's own words.
    public var requiredScopes: String {
        switch self {
        case .github: String(localized: """
            admin:public_key and admin:ssh_signing_key (classic token), or “Git SSH keys” and \
            “SSH signing keys” read/write (fine-grained token)
            """)
        case .gitlab: "api (or read_user to only view keys)"
        case .bitbucket: "read:ssh-key:bitbucket, write:ssh-key:bitbucket and delete:ssh-key:bitbucket"
        case .gitea: "write:user (or read:user to only view keys)"
        }
    }

    /// Where the user creates a token, relative to the server URL.
    public func tokenSettingsURL(server: URL) -> URL? {
        switch self {
        case .github: URL(string: "https://github.com/settings/tokens")
        case .gitlab: server.appending(path: "-/user_settings/personal_access_tokens")
        case .bitbucket: URL(string: "https://id.atlassian.com/manage-profile/security/api-tokens")
        case .gitea: server.appending(path: "user/settings/applications")
        }
    }
}

/// What a key on a provider is used for.
public enum RemoteKeyUsage: String, Sendable, Hashable, Codable, CaseIterable {
    case authentication
    case signing

    public var title: String {
        switch self {
        case .authentication: String(localized: "Authentication")
        case .signing: String(localized: "Signing")
        }
    }
}

/// An account on a provider. The token lives only in the Keychain, keyed by `id`.
public struct ProviderAccount: Sendable, Hashable, Codable, Identifiable {
    public let id: UUID
    public var kind: ProviderKind
    /// The web address of the server, e.g. `https://github.com` or `https://git.example.com`.
    public var serverURL: URL
    /// The signed-in user's login name, as reported by the provider.
    public var username: String
    /// Bitbucket only: the email address used with the API token.
    public var loginEmail: String?
    public var lastSyncedAt: Date?

    public init(
        id: UUID = UUID(),
        kind: ProviderKind,
        serverURL: URL,
        username: String,
        loginEmail: String? = nil,
        lastSyncedAt: Date? = nil
    ) {
        self.id = id
        self.kind = kind
        self.serverURL = serverURL
        self.username = username
        self.loginEmail = loginEmail
        self.lastSyncedAt = lastSyncedAt
    }

    /// e.g. "GitHub · alice" or "git.example.com · alice".
    public var displayName: String {
        let host = serverURL.host() ?? serverURL.absoluteString
        let isDefault = kind.defaultServerURL?.host() == host
        return "\(isDefault ? kind.displayName : host) · \(username)"
    }
}

/// A public key stored on a provider account.
public struct RemoteKey: Sendable, Hashable, Codable, Identifiable {
    /// The provider's identifier for the key (unique per account and usage).
    public let remoteID: String
    public let accountID: UUID
    public var title: String
    /// The key as the provider returns it (`type base64 [comment]`).
    public var publicKeyLine: String
    /// SHA256 fingerprint, or `nil` if the provider returned a key SMP cannot parse.
    public var fingerprint: String?
    public var usages: Set<RemoteKeyUsage>
    public var createdAt: Date?
    public var lastUsedAt: Date?
    public var expiresAt: Date?

    public init(
        remoteID: String,
        accountID: UUID,
        title: String,
        publicKeyLine: String,
        fingerprint: String?,
        usages: Set<RemoteKeyUsage>,
        createdAt: Date? = nil,
        lastUsedAt: Date? = nil,
        expiresAt: Date? = nil
    ) {
        self.remoteID = remoteID
        self.accountID = accountID
        self.title = title
        self.publicKeyLine = publicKeyLine
        self.fingerprint = fingerprint
        self.usages = usages
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
        self.expiresAt = expiresAt
    }

    /// Unique across accounts and usages (GitHub keeps signing keys in a separate list).
    public var id: String {
        let usage = usages.map(\.rawValue).sorted().joined(separator: "+")
        return "\(accountID.uuidString)/\(usage)/\(remoteID)"
    }
}

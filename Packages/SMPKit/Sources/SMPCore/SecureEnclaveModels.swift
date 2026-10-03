import Foundation

/// When SMP's agent asks for Touch ID before signing with a key.
public enum SigningPolicy: Sendable, Hashable, Codable {
    /// Touch ID (or the login password) for every signature.
    case everyUse
    /// Touch ID once, then signatures are allowed for `seconds` without asking again.
    case reuse(seconds: Int)
    /// No prompt; SMP shows a notification for each signature. The key still never leaves the
    /// Secure Enclave and only works while the Mac is unlocked.
    case notifyOnly

    public static let reuseChoices = [60, 300, 900]

    /// Whether the key's Secure Enclave access control requires user presence. Fixed at creation.
    public var requiresUserPresence: Bool { self != .notifyOnly }

    public var title: String {
        switch self {
        case .everyUse: "Touch ID for every use"
        case .reuse(let seconds): "Touch ID, then allow for \(seconds / 60) min"
        case .notifyOnly: "No prompt, show a notification"
        }
    }
}

/// A P-256 signing key that lives in the Secure Enclave. Only an encrypted, device-bound
/// reference is stored (in the Keychain); the private key itself can never be exported.
public struct SecureEnclaveKeyInfo: Sendable, Hashable, Codable, Identifiable {
    public let id: UUID
    public var name: String
    public var comment: String
    public var policy: SigningPolicy
    public let createdAt: Date
    /// The uncompressed public point (`04 || X || Y`).
    public let publicKeyX963: Data

    public init(
        id: UUID = UUID(),
        name: String,
        comment: String,
        policy: SigningPolicy,
        createdAt: Date = Date(),
        publicKeyX963: Data
    ) {
        self.id = id
        self.name = name
        self.comment = comment
        self.policy = policy
        self.createdAt = createdAt
        self.publicKeyX963 = publicKeyX963
    }
}

/// Shared locations for the app and its agent helper.
public enum AgentPaths {
    /// The longest path a Unix domain socket address can hold on macOS (`sun_path`, minus NUL).
    public static let maxSocketPathLength = 103

    /// `~/Library/Application Support/com.kirikakaese.smp/agent.sock`.
    public static func socketURL() throws -> URL {
        try AppPaths.applicationSupportDirectory().appending(path: "agent.sock")
    }

    /// The `IdentityAgent` value for `~/.ssh/config`, quoted because the path contains a space.
    public static func identityAgentValue(for socket: URL, homeDirectory: URL) -> String {
        let path = socket.path
        let home = homeDirectory.path
        let display = path.hasPrefix(home + "/") ? "~" + String(path.dropFirst(home.count)) : path
        return "\"\(display)\""
    }

    /// Bundle identifier of the login-item helper inside SMP.app.
    public static let helperBundleIdentifier = "com.kirikakaese.smp.agent"
    /// The `UserDefaults` suite both processes read agent settings from.
    public static let sharedDefaultsSuite = "com.kirikakaese.smp.shared"
}

/// Agent settings shared between the app and the helper through `AgentPaths.sharedDefaultsSuite`.
public struct AgentSettings: Sendable, Hashable {
    /// Ask for Touch ID before forwarding a signature request for a key in the system agent.
    public var confirmForwardedSignatures: Bool
    /// After a forwarded signature was confirmed, allow more for this many seconds (0 = ask every time).
    public var forwardedReuseSeconds: Int

    public init(confirmForwardedSignatures: Bool = true, forwardedReuseSeconds: Int = 0) {
        self.confirmForwardedSignatures = confirmForwardedSignatures
        self.forwardedReuseSeconds = forwardedReuseSeconds
    }

    private enum Key {
        static let confirmForwarded = "agent.confirmForwardedSignatures"
        static let forwardedReuse = "agent.forwardedReuseSeconds"
    }

    public static func load(from defaults: UserDefaults) -> AgentSettings {
        AgentSettings(
            confirmForwardedSignatures: defaults.object(forKey: Key.confirmForwarded) as? Bool ?? true,
            forwardedReuseSeconds: max(0, defaults.integer(forKey: Key.forwardedReuse))
        )
    }

    public func save(to defaults: UserDefaults) {
        defaults.set(confirmForwardedSignatures, forKey: Key.confirmForwarded)
        defaults.set(forwardedReuseSeconds, forKey: Key.forwardedReuse)
    }
}

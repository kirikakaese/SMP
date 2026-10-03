import Foundation

/// Terminal apps SMP can open SSH sessions in.
public enum TerminalApp: String, Sendable, Codable, CaseIterable, Identifiable, Hashable {
    case terminal, iTerm2, ghostty, warp, wezTerm

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .terminal: "Terminal"
        case .iTerm2: "iTerm2"
        case .ghostty: "Ghostty"
        case .warp: "Warp"
        case .wezTerm: "WezTerm"
        }
    }

    public var bundleIdentifier: String {
        switch self {
        case .terminal: "com.apple.Terminal"
        case .iTerm2: "com.googlecode.iterm2"
        case .ghostty: "com.mitchellh.ghostty"
        case .warp: "dev.warp.Warp-Stable"
        case .wezTerm: "com.github.wez.wezterm"
        }
    }
}

/// User-managed metadata for a host alias from ~/.ssh/config. The config file stays the source of truth.
public struct HostMetadata: Sendable, Hashable, Codable {
    public var alias: String
    public var isFavorite: Bool
    public var notes: String
    public var lastConnectedAt: Date?

    public init(alias: String, isFavorite: Bool = false, notes: String = "", lastConnectedAt: Date? = nil) {
        self.alias = alias
        self.isFavorite = isFavorite
        self.notes = notes
        self.lastConnectedAt = lastConnectedAt
    }
}

/// One port forward of a tunnel.
public struct TunnelForward: Sendable, Hashable, Codable, Identifiable {
    public enum Kind: String, Sendable, Hashable, Codable, CaseIterable {
        /// `-L`: a local port reaches a host:port seen from the server.
        case local
        /// `-R`: a port on the server reaches a host:port seen from this Mac.
        case remote
        /// `-D`: a local SOCKS proxy.
        case dynamic
    }

    public var id: UUID
    public var kind: Kind
    public var bindAddress: String
    public var bindPort: Int
    public var targetHost: String
    public var targetPort: Int

    public init(
        id: UUID = UUID(),
        kind: Kind = .local,
        bindAddress: String = "127.0.0.1",
        bindPort: Int,
        targetHost: String = "localhost",
        targetPort: Int = 0
    ) {
        self.id = id
        self.kind = kind
        self.bindAddress = bindAddress
        self.bindPort = bindPort
        self.targetHost = targetHost
        self.targetPort = targetPort
    }

    /// The `ssh` arguments for this forward, e.g. `["-L", "127.0.0.1:8080:localhost:80"]`.
    public var arguments: [String] {
        switch kind {
        case .local: ["-L", "\(bindAddress):\(bindPort):\(targetHost):\(targetPort)"]
        case .remote: ["-R", "\(bindAddress):\(bindPort):\(targetHost):\(targetPort)"]
        case .dynamic: ["-D", "\(bindAddress):\(bindPort)"]
        }
    }

    /// Returns a problem description, or `nil` if the forward is valid.
    public var problem: String? {
        guard (1...65_535).contains(bindPort) else { return "Ports must be between 1 and 65535." }
        if kind != .dynamic {
            guard (1...65_535).contains(targetPort) else { return "Ports must be between 1 and 65535." }
            guard Self.isSafeHost(targetHost) else { return "The target host contains invalid characters." }
        }
        guard Self.isSafeHost(bindAddress) else { return "The bind address contains invalid characters." }
        return nil
    }

    static func isSafeHost(_ host: String) -> Bool {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_:[]*"))
        return !host.isEmpty && !host.hasPrefix("-") && host.unicodeScalars.allSatisfy(allowed.contains)
    }
}

/// A saved tunnel: an SSH host plus port forwards, started with `ssh -N`.
public struct TunnelProfile: Sendable, Hashable, Codable, Identifiable {
    public var id: UUID
    public var name: String
    public var hostAlias: String
    public var forwards: [TunnelForward]

    public init(id: UUID = UUID(), name: String, hostAlias: String, forwards: [TunnelForward]) {
        self.id = id
        self.name = name
        self.hostAlias = hostAlias
        self.forwards = forwards
    }
}

/// Validation for host aliases and names passed to `ssh` as arguments.
public enum HostAlias {
    /// Returns a problem description, or `nil` if `alias` can be used as a `Host` name.
    public static func problem(with alias: String) -> String? {
        if alias.isEmpty { return "Enter a host name." }
        if alias.hasPrefix("-") { return "Host names must not start with “-”." }
        if alias.contains(where: { $0.isWhitespace || $0 == "\"" || $0 == "\0" }) {
            return "Host names must not contain spaces or quotes."
        }
        if alias.count > 255 { return "The host name is too long." }
        return nil
    }
}

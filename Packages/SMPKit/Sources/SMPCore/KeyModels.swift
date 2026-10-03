import Foundation

/// The SSH key algorithms SMP knows about.
public enum KeyAlgorithm: String, Sendable, Codable, CaseIterable, Hashable {
    case ed25519
    case ecdsaP256
    case ecdsaP384
    case ecdsaP521
    case rsa
    case dsa
    case ed25519SK
    case ecdsaSK
    case unknown

    /// Maps an OpenSSH key type name (as found in `.pub` files) to an algorithm.
    /// Certificate type names map to the algorithm of the certified key.
    public init(wireName: String) {
        switch KeyAlgorithm.plainWireName(wireName) {
        case "ssh-ed25519": self = .ed25519
        case "ecdsa-sha2-nistp256": self = .ecdsaP256
        case "ecdsa-sha2-nistp384": self = .ecdsaP384
        case "ecdsa-sha2-nistp521": self = .ecdsaP521
        case "ssh-rsa": self = .rsa
        case "ssh-dss": self = .dsa
        case "sk-ssh-ed25519@openssh.com": self = .ed25519SK
        case "sk-ecdsa-sha2-nistp256@openssh.com": self = .ecdsaSK
        default: self = .unknown
        }
    }

    /// `true` if `wireName` names an OpenSSH certificate type.
    public static func isCertificateWireName(_ wireName: String) -> Bool {
        wireName.contains("-cert-v01@openssh.com")
    }

    /// Strips the certificate suffix: `ssh-ed25519-cert-v01@openssh.com` → `ssh-ed25519`.
    public static func plainWireName(_ wireName: String) -> String {
        guard isCertificateWireName(wireName) else { return wireName }
        let base = wireName.replacingOccurrences(of: "-cert-v01@openssh.com", with: "")
        return base.hasPrefix("sk-") ? base + "@openssh.com" : base
    }

    public var displayName: String {
        switch self {
        case .ed25519: "Ed25519"
        case .ecdsaP256: "ECDSA P-256"
        case .ecdsaP384: "ECDSA P-384"
        case .ecdsaP521: "ECDSA P-521"
        case .rsa: "RSA"
        case .dsa: "DSA"
        case .ed25519SK: "Ed25519-SK"
        case .ecdsaSK: "ECDSA-SK"
        case .unknown: "Unknown"
        }
    }

    /// The type label OpenSSH prints in fingerprints and randomart (`ssh-keygen -l`).
    public var openSSHTypeLabel: String {
        switch self {
        case .ed25519: "ED25519"
        case .ecdsaP256, .ecdsaP384, .ecdsaP521: "ECDSA"
        case .rsa: "RSA"
        case .dsa: "DSA"
        case .ed25519SK: "ED25519-SK"
        case .ecdsaSK: "ECDSA-SK"
        case .unknown: "UNKNOWN"
        }
    }

    /// Key size in bits when it is fixed by the algorithm.
    public var fixedBitLength: Int? {
        switch self {
        case .ed25519, .ed25519SK: 256
        case .ecdsaP256, .ecdsaSK: 256
        case .ecdsaP384: 384
        case .ecdsaP521: 521
        case .rsa, .dsa, .unknown: nil
        }
    }

    /// FIDO2 security-key backed (`-sk`) algorithms.
    public var isSecurityKey: Bool {
        self == .ed25519SK || self == .ecdsaSK
    }
}

/// User-managed metadata for one key, keyed by its SHA256 fingerprint so it survives
/// renames and moves. Never contains secrets.
public struct KeyMetadata: Sendable, Hashable, Codable {
    public var fingerprint: String
    public var displayName: String?
    public var notes: String
    public var isFavorite: Bool
    public var expiresAt: Date?
    /// When the user wants to be reminded to rotate the key.
    public var rotateAt: Date?
    public var archivedAt: Date?
    public var firstSeenAt: Date
    public var lastSeenPath: String?

    public init(
        fingerprint: String,
        displayName: String? = nil,
        notes: String = "",
        isFavorite: Bool = false,
        expiresAt: Date? = nil,
        rotateAt: Date? = nil,
        archivedAt: Date? = nil,
        firstSeenAt: Date = Date(),
        lastSeenPath: String? = nil
    ) {
        self.fingerprint = fingerprint
        self.displayName = displayName
        self.notes = notes
        self.isFavorite = isFavorite
        self.expiresAt = expiresAt
        self.rotateAt = rotateAt
        self.archivedAt = archivedAt
        self.firstSeenAt = firstSeenAt
        self.lastSeenPath = lastSeenPath
    }
}

/// Colors offered for tags. Stored by name so the palette can evolve.
public enum TagColor: String, Sendable, Codable, CaseIterable, Hashable {
    case gray, red, orange, yellow, green, mint, teal, blue, indigo, purple, pink
}

public struct KeyTag: Sendable, Hashable, Codable, Identifiable {
    public var id: Int64
    public var name: String
    public var color: TagColor

    public init(id: Int64, name: String, color: TagColor) {
        self.id = id
        self.name = name
        self.color = color
    }
}

public struct KeyGroup: Sendable, Hashable, Codable, Identifiable {
    public var id: Int64
    public var name: String
    public var sortIndex: Int

    public init(id: Int64, name: String, sortIndex: Int) {
        self.id = id
        self.name = name
        self.sortIndex = sortIndex
    }
}

/// Well-known locations used by SMP itself.
public enum AppPaths {
    public static let bundleIdentifier = "com.kirikakaese.smp"

    /// `~/Library/Application Support/com.kirikakaese.smp`, created with mode 0700 if missing.
    public static func applicationSupportDirectory() throws -> URL {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let directory = base.appending(path: bundleIdentifier, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return directory
    }
}

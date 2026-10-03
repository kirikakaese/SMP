import Foundation
import SMPCore
import SMPSSH

/// One problem the security audit found.
public struct AuditFinding: Sendable, Hashable, Identifiable {
    public enum Severity: Int, Sendable, Hashable, Comparable, CaseIterable {
        case low = 1, medium, high, critical

        public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rawValue < rhs.rawValue }

        public var title: String {
            switch self {
            case .low: "Low"
            case .medium: "Medium"
            case .high: "High"
            case .critical: "Critical"
            }
        }

        /// Points subtracted from the score of 100.
        var weight: Int {
            switch self {
            case .low: 2
            case .medium: 7
            case .high: 15
            case .critical: 25
            }
        }
    }

    /// What SMP can do about it with one click (always confirmed or reviewed first).
    public enum Fix: Sendable, Hashable {
        case setPermissions(path: String, mode: UInt16)
        case addPassphrase(keyID: String)
        case upgradeFormat(keyID: String)
        case rotate(keyID: String)
        /// Remove one line from a config file (shown as a diff before saving).
        case removeConfigLine(file: String, lineIndex: Int)

        public var title: String {
            switch self {
            case .setPermissions(_, let mode): "Set permissions to \(String(mode, radix: 8))"
            case .addPassphrase: "Add a Passphrase…"
            case .upgradeFormat: "Upgrade Format…"
            case .rotate: "Rotate Key…"
            case .removeConfigLine: "Remove the Line…"
            }
        }
    }

    public let rule: String
    public let severity: Severity
    public let title: String
    public let detail: String
    /// What the finding is about, e.g. a key name or a config file line.
    public let subject: String
    /// The library key it concerns (`DiscoveredKey.id`), if any.
    public let keyID: String?
    public let fix: Fix?

    public var id: String { "\(rule)|\(subject)" }
}

/// Everything the audit looks at. Gathered by the caller so the rules stay pure and testable.
public struct AuditInput: Sendable {
    public var keys: [DiscoveredKey]
    public var metadata: [String: KeyMetadata]
    public var configFiles: [LoadedConfigFile]
    public var now: Date

    public init(
        keys: [DiscoveredKey],
        metadata: [String: KeyMetadata],
        configFiles: [LoadedConfigFile],
        now: Date = Date()
    ) {
        self.keys = keys
        self.metadata = metadata
        self.configFiles = configFiles
        self.now = now
    }
}

/// The audit rules.
public enum AuditEngine {
    public static let warningPeriod: TimeInterval = 14 * 24 * 3600

    public static func findings(_ input: AuditInput) -> [AuditFinding] {
        var result: [AuditFinding] = []
        for key in input.keys {
            result += keyFindings(key)
            result += dateFindings(key, metadata: key.fingerprint.flatMap { input.metadata[$0] }, now: input.now)
        }
        for file in input.configFiles {
            result += configFindings(file)
        }
        // The same folder is reported once, not once per key in it.
        var seen = Set<String>()
        return result
            .filter { seen.insert($0.id).inserted }
            .sorted { ($0.severity, $1.subject) > ($1.severity, $0.subject) }
    }

    /// 100 minus a weight per finding, never below 0.
    public static func score(_ findings: [AuditFinding]) -> Int {
        max(0, 100 - findings.reduce(0) { $0 + $1.severity.weight })
    }

    // MARK: Keys

    static func keyFindings(_ key: DiscoveredKey) -> [AuditFinding] {
        key.issues.compactMap { permissionFinding($0, key: key) ?? qualityFinding($0, key: key) }
    }

    static func permissionFinding(_ issue: KeyIssue, key: DiscoveredKey) -> AuditFinding? {
        switch issue {
        case .privateKeyPermissionsTooOpen(let mode):
            guard let path = key.privateKeyFile?.url.path else { return nil }
            return AuditFinding(
                rule: "private-key-permissions", severity: .critical,
                title: "Private key readable by others",
                detail: "Mode \(String(mode, radix: 8)). Other users could copy the key, "
                    + "and ssh refuses to use it.",
                subject: key.name, keyID: key.id, fix: .setPermissions(path: path, mode: 0o600)
            )
        case .publicKeyWritableByOthers:
            guard let path = key.publicKeyFile?.url.path else { return nil }
            return AuditFinding(
                rule: "public-key-permissions", severity: .medium,
                title: "Public key writable by others",
                detail: "Someone could swap it for their own key before you upload it somewhere.",
                subject: key.name, keyID: key.id, fix: .setPermissions(path: path, mode: 0o644)
            )
        case .directoryPermissionsTooOpen:
            let folder = key.primaryFile.url.deletingLastPathComponent().path
            return AuditFinding(
                rule: "folder-permissions", severity: .high,
                title: "Key folder accessible by others",
                detail: "Other users can list or change files in \(folder).",
                subject: folder, keyID: nil, fix: .setPermissions(path: folder, mode: 0o700)
            )
        case .notOwnedByCurrentUser:
            return AuditFinding(
                rule: "not-owned", severity: .high,
                title: "Key file owned by another user",
                detail: "Whoever owns the file can replace or read it. Copy the key into your own folder.",
                subject: key.name, keyID: key.id, fix: nil
            )
        default:
            return nil
        }
    }

    static func qualityFinding(_ issue: KeyIssue, key: DiscoveredKey) -> AuditFinding? {
        switch issue {
        case .noPassphrase:
            return AuditFinding(
                rule: "no-passphrase", severity: .high,
                title: "Private key without passphrase",
                detail: "Anyone who gets a copy of the file can use it immediately.",
                subject: key.name, keyID: key.id, fix: .addPassphrase(keyID: key.id)
            )
        case .weakAlgorithm(let reason):
            let isDSA = key.algorithm == .dsa
            return AuditFinding(
                rule: "weak-algorithm", severity: isDSA ? .critical : .high,
                title: isDSA ? "DSA key (no longer supported by OpenSSH)" : "Weak key",
                detail: reason + " Replace it with an Ed25519 key.",
                subject: key.name, keyID: key.id, fix: .rotate(keyID: key.id)
            )
        case .legacyFormat:
            return AuditFinding(
                rule: "legacy-format", severity: .low,
                title: "Legacy key file format",
                detail: "The OpenSSH format protects passphrases with a stronger key derivation.",
                subject: key.name, keyID: key.id, fix: .upgradeFormat(keyID: key.id)
            )
        case .publicKeyMismatch:
            return AuditFinding(
                rule: "public-key-mismatch", severity: .medium,
                title: "Public key does not match the private key",
                detail: "You might upload or trust the wrong key. Regenerate the .pub file from the private key.",
                subject: key.name, keyID: key.id, fix: nil
            )
        default:
            return nil
        }
    }

    static func dateFindings(_ key: DiscoveredKey, metadata: KeyMetadata?, now: Date) -> [AuditFinding] {
        var result: [AuditFinding] = []
        let canRotate = key.privateKeyFile != nil
        if let expires = metadata?.expiresAt {
            if expires <= now {
                result.append(AuditFinding(
                    rule: "expired", severity: .high, title: "Key past its expiry date",
                    detail: "You marked this key to expire on \(Self.day(expires)).",
                    subject: key.name, keyID: key.id, fix: canRotate ? .rotate(keyID: key.id) : nil
                ))
            } else if expires.timeIntervalSince(now) <= warningPeriod {
                result.append(AuditFinding(
                    rule: "expiring", severity: .medium, title: "Key expires soon",
                    detail: "It expires on \(Self.day(expires)).",
                    subject: key.name, keyID: key.id, fix: canRotate ? .rotate(keyID: key.id) : nil
                ))
            }
        }
        if let rotate = metadata?.rotateAt, rotate <= now {
            result.append(AuditFinding(
                rule: "rotation-due", severity: .medium, title: "Key rotation due",
                detail: "You planned to rotate it on \(Self.day(rotate)).",
                subject: key.name, keyID: key.id, fix: canRotate ? .rotate(keyID: key.id) : nil
            ))
        }
        return result
    }

    static func day(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .omitted)
    }

    // MARK: Config

    static func configFindings(_ file: LoadedConfigFile) -> [AuditFinding] {
        let name = file.url.lastPathComponent
        return file.document.directives().compactMap { directive in
            let value = directive.rawValue.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            let appliesBroadly = directive.isInMatchBlock
                || directive.blockPatterns.contains { $0 == "*" || $0.hasPrefix("*.") }
            let subject = "\(name), line \(directive.lineIndex + 1)"
            let fix = AuditFinding.Fix.removeConfigLine(file: file.url.path, lineIndex: directive.lineIndex)
            switch directive.normalizedKeyword {
            case "forwardagent" where value == "yes" && appliesBroadly:
                return AuditFinding(
                    rule: "forward-agent-everywhere", severity: .high,
                    title: "Agent forwarding for many hosts",
                    detail: "Anyone with root on one of these servers can use your keys while you are connected. "
                        + "Enable ForwardAgent only for hosts that need it.",
                    subject: subject, keyID: nil, fix: fix
                )
            case "stricthostkeychecking" where value == "no" || value == "off":
                return AuditFinding(
                    rule: "no-host-key-checking", severity: .high,
                    title: "Host key checking turned off",
                    detail: "ssh will not notice if someone impersonates the server.",
                    subject: subject, keyID: nil, fix: fix
                )
            case "userknownhostsfile" where value == "/dev/null":
                return AuditFinding(
                    rule: "known-hosts-discarded", severity: .high,
                    title: "Known host keys are thrown away",
                    detail: "With /dev/null, every server is unknown, so impersonation goes unnoticed.",
                    subject: subject, keyID: nil, fix: fix
                )
            case "forwardx11trusted" where value == "yes":
                return AuditFinding(
                    rule: "trusted-x11", severity: .medium,
                    title: "Trusted X11 forwarding",
                    detail: "Remote programs get full access to your X11 display, including keystrokes.",
                    subject: subject, keyID: nil, fix: fix
                )
            default:
                return nil
            }
        }
    }
}

/// Applies the fixes that need no further input.
public protocol AuditFixing: Sendable {
    /// Sets the mode of a key file or key folder. Refuses symbolic links and paths outside `allowedRoots`.
    func setPermissions(path: String, mode: UInt16, allowedRoots: [URL]) throws
}

public struct AuditFixer: AuditFixing {
    public init() {}

    public func setPermissions(path: String, mode: UInt16, allowedRoots: [URL]) throws {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        let inside = allowedRoots.contains { root in
            let rootPath = root.standardizedFileURL.path
            return url.path == rootPath || url.path.hasPrefix(rootPath + "/")
        }
        guard inside else {
            throw SMPError.invalidArgument("SMP only changes permissions inside your key folders.")
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType != .typeSymbolicLink else {
            throw SMPError.invalidArgument("\(url.lastPathComponent) is a symbolic link; fix its target instead.")
        }
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: mode)], ofItemAtPath: url.path)
    }
}

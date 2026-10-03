import Foundation
import SMPCore
import SMPSSH

/// A key as Shortcuts sees it: public information only.
public struct ShortcutKey: Sendable, Hashable, Identifiable {
    public let id: String
    public let name: String
    public let type: String
    public let fingerprint: String
    public let comment: String
    /// The `authorized_keys` line.
    public let publicKey: String

    public init(id: String, name: String, type: String, fingerprint: String, comment: String, publicKey: String) {
        self.id = id
        self.name = name
        self.type = type
        self.fingerprint = fingerprint
        self.comment = comment
        self.publicKey = publicKey
    }
}

/// The audit result Shortcuts returns.
public struct ShortcutAuditSummary: Sendable, Hashable {
    public let score: Int
    public let findings: Int
    /// Findings of medium severity or worse.
    public let important: Int
    /// Titles of the most severe findings, at most five.
    public let topFindings: [String]

    public var sentence: String {
        switch findings {
        case 0:
            return String(localized: "Security score \(score) of 100. Nothing to fix.")
        case 1:
            let finding = topFindings.first ?? ""
            return String(localized: "Security score \(score) of 100. 1 finding: \(finding).")
        default:
            return String(localized: """
                Security score \(score) of 100. \(findings) findings, \(important) of them important.
                """)
        }
    }
}

/// What SMP's Shortcuts actions read. Everything here is public data (key lines, fingerprints,
/// host aliases, tunnel names); nothing reads or returns private key material.
extension ServiceContainer {
    /// Keys with a public key in `~/.ssh` and the added key folders, sorted by name.
    public func shortcutKeys(defaults: UserDefaults = .standard) async throws -> [ShortcutKey] {
        let folders = KeyFolderSettings.allFolders(environment: environment, defaults: defaults)
        return try await keyDiscovery.discoverKeys(in: folders).compactMap { key in
            guard let publicKey = key.publicKey else { return nil }
            return ShortcutKey(
                id: key.id,
                name: key.name,
                type: key.algorithm.displayName,
                fingerprint: publicKey.fingerprintSHA256,
                comment: key.comment,
                publicKey: publicKey.openSSHLine
            )
        }
        .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// Host aliases from `~/.ssh/config` that can be connected to (no wildcards), in file order.
    public func shortcutHosts() throws -> [String] {
        var seen = Set<String>()
        return try hosts.hosts()
            .filter { !$0.block.isWildcard }
            .map(\.alias)
            .filter { seen.insert($0).inserted }
    }

    /// Runs the security audit on the keys and config files on disk.
    public func shortcutAudit(defaults: UserDefaults = .standard) async throws -> ShortcutAuditSummary {
        let folders = KeyFolderSettings.allFolders(environment: environment, defaults: defaults)
        let keys = try await keyDiscovery.discoverKeys(in: folders)
        let input = AuditInput(
            keys: keys,
            metadata: (try? metadata.allMetadata()) ?? [:],
            configFiles: (try? hosts.loadFiles()) ?? []
        )
        let findings = AuditEngine.findings(input)
        return ShortcutAuditSummary(
            score: AuditEngine.score(findings),
            findings: findings.count,
            important: findings.filter { $0.severity >= .medium }.count,
            topFindings: findings.prefix(5).map { "\($0.title) (\($0.subject))" }
        )
    }
}

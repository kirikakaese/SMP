import Foundation

/// A key rotation in progress: replace an old key with a new one everywhere it is used.
/// Persisted after every step so it can be resumed.
public struct RotationJob: Sendable, Hashable, Codable, Identifiable {
    public enum Step: String, Sendable, Hashable, Codable, CaseIterable {
        /// Create the new key.
        case generate
        /// Upload it to providers and install it on servers.
        case deploy
        /// Point `IdentityFile` lines in ~/.ssh/config at the new key.
        case updateConfig
        /// Log in with the new key.
        case verify
        /// Remove the old key from providers and servers and archive it locally (after confirmation).
        case retire

        public var title: String {
            switch self {
            case .generate: "Create the new key"
            case .deploy: "Upload and install it"
            case .updateConfig: "Update ~/.ssh/config"
            case .verify: "Test logins"
            case .retire: "Retire the old key"
            }
        }
    }

    /// One place the key is used.
    public struct Target: Sendable, Hashable, Codable, Identifiable {
        public enum Kind: Sendable, Hashable, Codable {
            /// A provider account; `oldRemoteIDs` are the old key's entries there.
            case provider(accountID: UUID, usages: Set<RemoteKeyUsage>, oldRemoteIDs: [String])
            /// A `Host` alias from ~/.ssh/config whose `IdentityFile` points at the old key.
            case host(alias: String)
        }

        public let kind: Kind
        public var label: String
        public var deployed = false
        public var verified = false
        public var retired = false
        /// Set when the user chose to leave this target out (e.g. the server is gone).
        public var skipped = false
        public var lastError: String?

        public init(kind: Kind, label: String) {
            self.kind = kind
            self.label = label
        }

        public var id: String {
            switch kind {
            case .provider(let accountID, _, _): "provider:\(accountID.uuidString)"
            case .host(let alias): "host:\(alias)"
            }
        }
    }

    public struct LogEntry: Sendable, Hashable, Codable {
        public let date: Date
        public let message: String

        public init(date: Date = Date(), message: String) {
            self.date = date
            self.message = message
        }
    }

    public let id: UUID
    public var oldKeyName: String
    public var oldFingerprint: String
    public var oldPrivateKeyPath: String?
    public var oldPublicKeyPath: String?
    public var oldComment: String
    public var directoryPath: String
    public var newKeyName: String
    public var newPrivateKeyPath: String?
    public var newPublicKeyLine: String?
    public var newFingerprint: String?
    public var targets: [Target]
    public var completedSteps: [Step]
    public var log: [LogEntry]
    public let createdAt: Date
    public var updatedAt: Date

    public init(
        id: UUID = UUID(),
        oldKeyName: String,
        oldFingerprint: String,
        oldPrivateKeyPath: String?,
        oldPublicKeyPath: String?,
        oldComment: String,
        directoryPath: String,
        newKeyName: String,
        targets: [Target],
        createdAt: Date = Date()
    ) {
        self.id = id
        self.oldKeyName = oldKeyName
        self.oldFingerprint = oldFingerprint
        self.oldPrivateKeyPath = oldPrivateKeyPath
        self.oldPublicKeyPath = oldPublicKeyPath
        self.oldComment = oldComment
        self.directoryPath = directoryPath
        self.newKeyName = newKeyName
        self.targets = targets
        self.completedSteps = []
        self.log = []
        self.createdAt = createdAt
        self.updatedAt = createdAt
    }

    public var nextStep: Step? { Step.allCases.first { !completedSteps.contains($0) } }
    public var isFinished: Bool { nextStep == nil }

    public mutating func complete(_ step: Step, _ message: String) {
        if !completedSteps.contains(step) {
            completedSteps.append(step)
        }
        note(message)
    }

    public mutating func note(_ message: String) {
        log.append(LogEntry(message: message))
        updatedAt = Date()
    }

    /// Targets that still take part (not skipped by the user).
    public var activeTargets: [Target] { targets.filter { !$0.skipped } }
}

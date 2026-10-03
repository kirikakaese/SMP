import Foundation

/// One file in an SMP backup. Paths under the home folder are stored as `~/…` so a backup can be
/// restored for a different user name.
public struct BackupFile: Sendable, Hashable, Codable {
    public enum Kind: String, Sendable, Hashable, Codable {
        case privateKey, publicKey, certificate, config, knownHosts
    }

    public var kind: Kind
    public var path: String
    public var mode: Int

    public init(kind: Kind, path: String, mode: Int) {
        self.kind = kind
        self.path = path
        self.mode = mode
    }

    public var fileName: String { (path as NSString).lastPathComponent }

    /// `~/…` for paths inside `home`, the absolute path otherwise.
    public static func storedPath(for url: URL, home: URL) -> String {
        let path = url.standardizedFileURL.path
        let homePath = home.standardizedFileURL.path
        return path.hasPrefix(homePath + "/") ? "~" + path.dropFirst(homePath.count) : path
    }

    /// The location on this Mac for a stored path.
    public static func url(for storedPath: String, home: URL) -> URL {
        if storedPath.hasPrefix("~/") {
            return home.appending(path: String(storedPath.dropFirst(2)), directoryHint: .notDirectory)
        }
        return URL(fileURLWithPath: storedPath)
    }
}

/// SMP's own records: tags, groups, notes, dates, host settings and tunnels. No secrets.
public struct MetadataSnapshot: Sendable, Hashable, Codable {
    public var keys: [KeyMetadata]
    public var tags: [KeyTag]
    public var tagAssignments: [String: [Int64]]
    public var groups: [KeyGroup]
    public var groupAssignments: [String: [Int64]]
    public var hosts: [HostMetadata]
    public var hostTagAssignments: [String: [Int64]]
    public var tunnels: [TunnelProfile]

    public init(
        keys: [KeyMetadata] = [],
        tags: [KeyTag] = [],
        tagAssignments: [String: [Int64]] = [:],
        groups: [KeyGroup] = [],
        groupAssignments: [String: [Int64]] = [:],
        hosts: [HostMetadata] = [],
        hostTagAssignments: [String: [Int64]] = [:],
        tunnels: [TunnelProfile] = []
    ) {
        self.keys = keys
        self.tags = tags
        self.tagAssignments = tagAssignments
        self.groups = groups
        self.groupAssignments = groupAssignments
        self.hosts = hosts
        self.hostTagAssignments = hostTagAssignments
        self.tunnels = tunnels
    }
}

/// The unencrypted description of a backup's contents. Stored inside the encrypted payload, so
/// nobody without the passphrase learns even the file names.
public struct BackupManifest: Sendable, Hashable, Codable {
    public static let currentVersion = 1

    public var version: Int
    public var createdAt: Date
    public var files: [BackupFile]
    public var metadata: MetadataSnapshot

    public init(
        version: Int = currentVersion,
        createdAt: Date = Date(),
        files: [BackupFile],
        metadata: MetadataSnapshot
    ) {
        self.version = version
        self.createdAt = createdAt
        self.files = files
        self.metadata = metadata
    }

    public var keyCount: Int { files.filter { $0.kind == .privateKey }.count }
}

/// What restoring one file will do.
public struct RestoreStep: Sendable, Hashable, Identifiable {
    public enum Action: Sendable, Hashable {
        /// The file does not exist yet and is written as is.
        case create
        /// An identical file is already there; nothing to do.
        case alreadyPresent
        /// A different file is in the way; the backup's version is written next to it.
        case writeAlongside(URL)
        /// Nothing can be written (both names taken).
        case skip(String)
    }

    public let index: Int
    public let file: BackupFile
    public let target: URL
    public let action: Action

    public init(index: Int, file: BackupFile, target: URL, action: Action) {
        self.index = index
        self.file = file
        self.target = target
        self.action = action
    }

    public var id: Int { index }

    /// Where the file ends up, if it is written.
    public var destination: URL? {
        switch action {
        case .create: target
        case .writeAlongside(let url): url
        case .alreadyPresent, .skip: nil
        }
    }
}

/// The outcome of a restore.
public struct RestoreSummary: Sendable, Hashable {
    public var written: [URL] = []
    public var alreadyPresent = 0
    public var skipped: [String] = []
    public var tagsAdded = 0
    public var groupsAdded = 0
    public var notesRestored = 0
    public var hostsRestored = 0
    public var tunnelsAdded = 0

    public init() {}
}

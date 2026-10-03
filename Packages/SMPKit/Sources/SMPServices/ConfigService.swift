import Foundation
import SMPCore
import SMPSSH

/// A loaded config file and the snapshot needed to save it safely.
public struct LoadedConfigFile: Sendable, Identifiable {
    public var id: URL { url }
    public let url: URL
    public var document: SSHConfigDocument
    public let snapshot: FileSnapshot?

    public init(url: URL, document: SSHConfigDocument, snapshot: FileSnapshot?) {
        self.url = url
        self.document = document
        self.snapshot = snapshot
    }
}

/// An `IdentityFile` line that points at a given key.
public struct ConfigReference: Sendable, Hashable, Identifiable {
    public let file: URL
    public let lineIndex: Int
    /// The `Host` patterns (or `Match` criteria) the line applies to.
    public let hostPatterns: [String]
    public let isInMatchBlock: Bool
    /// The value as written, e.g. `~/.ssh/id_ed25519`.
    public let value: String

    public var id: String { "\(file.path):\(lineIndex)" }
    /// 1-based line number for display.
    public var lineNumber: Int { lineIndex + 1 }
}

/// What to do with one config reference when its key is renamed or deleted.
public enum ConfigReferenceEdit: Sendable, Hashable {
    case replaceValue(ConfigReference, newValue: String)
    case commentOut(ConfigReference)
    case remove(ConfigReference)

    var reference: ConfigReference {
        switch self {
        case .replaceValue(let reference, _), .commentOut(let reference), .remove(let reference): reference
        }
    }
}

public protocol ConfigServicing: Sendable {
    /// Loads `~/.ssh/config` and every file it includes.
    func loadAll() throws -> [LoadedConfigFile]
    /// `IdentityFile` lines that refer to any of `keyFiles` (private or public key paths).
    func references(to keyFiles: [URL]) throws -> [ConfigReference]
    /// Applies edits, writing each affected file once with a backup.
    func apply(_ edits: [ConfigReferenceEdit]) throws
    /// Appends a `Host` block to `~/.ssh/config`.
    func appendHost(alias: String, options: [(keyword: String, value: String)]) throws
}

public struct ConfigService: ConfigServicing {
    private let environment: SSHEnvironment
    private let writer: SafeFileWriter

    public init(environment: SSHEnvironment, writer: SafeFileWriter) {
        self.environment = environment
        self.writer = writer
    }

    public func loadAll() throws -> [LoadedConfigFile] {
        var loaded: [LoadedConfigFile] = []
        var visited = Set<String>()
        try load(environment.configFile, into: &loaded, visited: &visited, depth: 0)
        return loaded
    }

    private func load(
        _ url: URL,
        into loaded: inout [LoadedConfigFile],
        visited: inout Set<String>,
        depth: Int
    ) throws {
        let resolved = url.resolvingSymlinksInPath().standardizedFileURL
        guard depth < 16, visited.insert(resolved.path).inserted,
              FileManager.default.fileExists(atPath: resolved.path)
        else { return }
        let data = try Data(contentsOf: resolved)
        guard data.count <= 1_024 * 1_024, let text = String(data: data, encoding: .utf8) else {
            throw SMPError(
                .fileSystem,
                whatHappened: String(localized: "\(url.lastPathComponent) is not a readable SSH config file."),
                howToFix: String(localized: "Make sure the file is UTF-8 text.")
            )
        }
        let document = SSHConfigDocument(text: text)
        loaded.append(LoadedConfigFile(url: url, document: document, snapshot: try FileSnapshot.capture(url)))
        for include in document.directives(named: "Include") {
            for pattern in include.arguments {
                for match in expandInclude(pattern) {
                    try load(match, into: &loaded, visited: &visited, depth: depth + 1)
                }
            }
        }
    }

    /// Resolves an `Include` pattern: `~` expansion, paths relative to `~/.ssh`, and globs.
    func expandInclude(_ pattern: String) -> [URL] {
        var path = expandTilde(pattern)
        if !path.hasPrefix("/") {
            path = environment.sshDirectory.appending(path: path).path
        }
        var result = glob_t()
        defer { globfree(&result) }
        guard glob(path, GLOB_TILDE, nil, &result) == 0 else { return [] }
        return (0..<Int(result.gl_pathc)).compactMap { index in
            result.gl_pathv[index].map { URL(fileURLWithPath: String(cString: $0)) }
        }
    }

    public func references(to keyFiles: [URL]) throws -> [ConfigReference] {
        let wanted = Set(keyFiles.map { $0.standardizedFileURL.path })
        var references: [ConfigReference] = []
        for file in try loadAll() {
            for directive in file.document.directives(named: "IdentityFile") {
                guard let value = directive.arguments.first else { continue }
                let candidates = candidatePaths(for: value)
                if !wanted.isDisjoint(with: candidates) {
                    references.append(ConfigReference(
                        file: file.url,
                        lineIndex: directive.lineIndex,
                        hostPatterns: directive.blockPatterns,
                        isInMatchBlock: directive.isInMatchBlock,
                        value: directive.rawValue
                    ))
                }
            }
        }
        return references
    }

    /// Possible absolute paths an `IdentityFile` value can mean.
    func candidatePaths(for value: String) -> Set<String> {
        var expanded = expandTilde(value)
            .replacingOccurrences(of: "%d", with: environment.homeDirectory.path)
            .replacingOccurrences(of: "%u", with: environment.userName)
        if expanded.hasPrefix("/") {
            return [URL(fileURLWithPath: expanded).standardizedFileURL.path]
        }
        // Relative paths: OpenSSH resolves them against the working directory, which for most
        // users is the home folder; ~/.ssh is checked too because people often write it that way.
        if expanded.hasPrefix("./") {
            expanded.removeFirst(2)
        }
        return [
            environment.homeDirectory.appending(path: expanded).standardizedFileURL.path,
            environment.sshDirectory.appending(path: expanded).standardizedFileURL.path,
        ]
    }

    private func expandTilde(_ value: String) -> String {
        if value == "~" {
            return environment.homeDirectory.path
        }
        if value.hasPrefix("~/") {
            return environment.homeDirectory.path + String(value.dropFirst(1))
        }
        return value
    }

    public func apply(_ edits: [ConfigReferenceEdit]) throws {
        guard !edits.isEmpty else { return }
        let files = try loadAll()
        let byFile = Dictionary(grouping: edits) { $0.reference.file.standardizedFileURL.path }
        for (path, fileEdits) in byFile {
            guard var file = files.first(where: { $0.url.standardizedFileURL.path == path }) else {
                throw SMPError.fileChangedOnDisk(URL(fileURLWithPath: path).lastPathComponent)
            }
            // Apply bottom-up so removals don't shift the indices of later edits.
            for edit in fileEdits.sorted(by: { $0.reference.lineIndex > $1.reference.lineIndex }) {
                let index = edit.reference.lineIndex
                let current = file.document.directives().first { $0.lineIndex == index }
                guard current?.rawValue == edit.reference.value else {
                    throw SMPError.fileChangedOnDisk(file.url.lastPathComponent)
                }
                switch edit {
                case .replaceValue(_, let newValue): file.document.replaceValue(atLine: index, with: newValue)
                case .commentOut: file.document.commentOutLine(index)
                case .remove: file.document.removeLine(index)
                }
            }
            try writer.write(Data(file.document.render().utf8), to: file.url, expected: file.snapshot)
        }
    }

    public func appendHost(alias: String, options: [(keyword: String, value: String)]) throws {
        let url = environment.configFile
        let snapshot = try FileSnapshot.capture(url)
        let existing = try snapshot == nil ? "" : String(contentsOf: url, encoding: .utf8)
        var document = SSHConfigDocument(text: existing)
        document.appendHostBlock(patterns: [alias], options: options)
        try FileManager.default.createDirectory(
            at: environment.sshDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try writer.write(Data(document.render().utf8), to: url, expected: snapshot, mode: 0o600)
    }
}

extension ConfigReference {
    /// The replacement value after renaming the key file, keeping `~`, quotes and folders as written.
    public func renamedValue(from oldName: String, to newName: String) -> String {
        let quoted = value.hasPrefix("\"") && value.hasSuffix("\"") && value.count >= 2
        let inner = quoted ? String(value.dropFirst().dropLast()) : value
        guard let slash = inner.lastIndex(of: "/") else {
            let renamed = inner.replacingOccurrences(of: oldName, with: newName)
            return quoted ? "\"\(renamed)\"" : renamed
        }
        let folder = inner[...slash]
        var fileName = String(inner[inner.index(after: slash)...])
        if fileName == oldName {
            fileName = newName
        } else if fileName == oldName + ".pub" {
            fileName = newName + ".pub"
        }
        let renamed = String(folder) + fileName
        return quoted ? "\"\(renamed)\"" : renamed
    }
}

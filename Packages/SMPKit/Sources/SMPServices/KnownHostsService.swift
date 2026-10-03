import Foundation
import SMPCore
import SMPSSH

public struct LoadedKnownHosts: Sendable {
    public let url: URL
    public let document: KnownHostsDocument
    public let snapshot: FileSnapshot?

    public var entries: [KnownHostsEntry] { document.entries() }
}

public protocol KnownHostsServicing: Sendable {
    func load() throws -> LoadedKnownHosts
    /// Removes the given lines from the file that was loaded (fails if it changed meanwhile).
    func remove(lines: Set<Int>, from loaded: LoadedKnownHosts) throws
    /// Fetches the host keys a server presents (`ssh-keyscan`). Nothing is trusted or saved.
    func scan(host: String, port: Int) async throws -> [SSHPublicKey]
    /// Adds keys for `host`, hashing the host name if the file already uses hashed entries.
    func add(host: String, port: Int, keys: [SSHPublicKey]) throws
    /// Replaces every stored key for `host` with `keys` (after a verified key change).
    func replace(host: String, port: Int, with keys: [SSHPublicKey]) throws
}

public struct KnownHostsService: KnownHostsServicing {
    private let runner: any SSHToolRunning
    private let environment: SSHEnvironment
    private let writer: SafeFileWriter

    public init(runner: any SSHToolRunning, environment: SSHEnvironment, writer: SafeFileWriter) {
        self.runner = runner
        self.environment = environment
        self.writer = writer
    }

    public func load() throws -> LoadedKnownHosts {
        let url = environment.knownHostsFile
        let snapshot = try FileSnapshot.capture(url)
        let text = try snapshot == nil ? "" : String(contentsOf: url, encoding: .utf8)
        return LoadedKnownHosts(url: url, document: KnownHostsDocument(text: text), snapshot: snapshot)
    }

    public func remove(lines: Set<Int>, from loaded: LoadedKnownHosts) throws {
        var document = loaded.document
        document.removeLines(lines)
        try writer.write(Data(document.render().utf8), to: loaded.url, expected: loaded.snapshot, mode: 0o644)
    }

    public func scan(host: String, port: Int) async throws -> [SSHPublicKey] {
        if let problem = HostAlias.problem(with: host) {
            throw SMPError.invalidArgument(problem)
        }
        guard (1...65_535).contains(port) else {
            throw SMPError.invalidArgument(String(localized: "Ports must be between 1 and 65535."))
        }
        let result = try await runner.run(
            .sshKeyscan,
            arguments: ["-T", "10", "-p", String(port), host],
            options: ToolRunOptions(timeout: .seconds(20))
        )
        let keys = Self.parseScan(result.standardOutputString)
        guard !keys.isEmpty else {
            throw SMPError(
                .toolFailed,
                whatHappened: String(localized: "\(host) did not return any host keys."),
                howToFix: String(localized: "Check the host name, port and your network connection."),
                details: result.standardErrorString.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        return keys
    }

    public func add(host: String, port: Int, keys: [SSHPublicKey]) throws {
        let loaded = try load()
        var document = loaded.document
        let hashed = Self.prefersHashing(loaded.entries)
        for key in keys {
            document.append(host: host, port: port, key: key, hashed: hashed)
        }
        try ensureDirectory()
        try writer.write(Data(document.render().utf8), to: loaded.url, expected: loaded.snapshot, mode: 0o644)
    }

    public func replace(host: String, port: Int, with keys: [SSHPublicKey]) throws {
        let loaded = try load()
        var document = loaded.document
        let hashed = Self.prefersHashing(loaded.entries)
        let stale = Set(document.entries(matching: host, port: port).filter { $0.marker == nil }.map(\.lineIndex))
        document.removeLines(stale)
        for key in keys {
            document.append(host: host, port: port, key: key, hashed: hashed)
        }
        try ensureDirectory()
        try writer.write(Data(document.render().utf8), to: loaded.url, expected: loaded.snapshot, mode: 0o644)
    }

    private func ensureDirectory() throws {
        try FileManager.default.createDirectory(
            at: environment.sshDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    /// Lines look like `host keytype base64`; comments (`# host:22 SSH-2.0-…`) are ignored.
    static func parseScan(_ output: String) -> [SSHPublicKey] {
        var seen = Set<Data>()
        return output.split(whereSeparator: \.isNewline).compactMap { line in
            guard !line.hasPrefix("#") else { return nil }
            let fields = line.split(separator: " ", maxSplits: 1)
            guard fields.count == 2, let key = try? SSHPublicKey(line: String(fields[1])),
                  seen.insert(key.blob).inserted
            else { return nil }
            return key
        }
    }

    /// Follows the file's existing style: hash new entries if most existing ones are hashed.
    static func prefersHashing(_ entries: [KnownHostsEntry]) -> Bool {
        let hashed = entries.filter(\.isHashed).count
        return hashed > 0 && hashed * 2 >= entries.count
    }

    /// Whether `text` (a pasted SHA256 or MD5 fingerprint, with or without prefix) matches `key`.
    public static func fingerprint(_ text: String, matches key: SSHPublicKey) -> Bool {
        var candidate = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !candidate.isEmpty else { return false }
        if candidate.uppercased().hasPrefix("SHA256:") {
            candidate = String(candidate.dropFirst("SHA256:".count))
        }
        if candidate.uppercased().hasPrefix("MD5:") {
            candidate = String(candidate.dropFirst("MD5:".count))
        }
        let sha = String(key.fingerprintSHA256.dropFirst("SHA256:".count))
        let md5 = String(key.fingerprintMD5.dropFirst("MD5:".count))
        // Some tools print base64 with padding.
        let unpadded = candidate.trimmingCharacters(in: CharacterSet(charactersIn: "="))
        return unpadded == sha || candidate.lowercased() == md5
    }
}

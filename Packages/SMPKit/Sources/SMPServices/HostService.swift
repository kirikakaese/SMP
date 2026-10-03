import Foundation
import SMPCore
import SMPSSH

/// A `Host` block found in ~/.ssh/config or one of its included files.
public struct HostEntry: Sendable, Hashable, Identifiable {
    public let file: URL
    public let block: SSHConfigBlock

    public var id: String { "\(file.path)#\(block.headerLine)" }
    public var alias: String { block.alias }
}

/// Why a connection test failed, with a human explanation.
public enum ConnectionProblem: String, Sendable, Hashable {
    case authenticationFailed, unknownHostKey, hostKeyChanged, hostNotFound
    case connectionRefused, timedOut, networkUnreachable, other

    public var title: String {
        switch self {
        case .authenticationFailed: "The server rejected the login."
        case .unknownHostKey: "The server's host key is not known yet."
        case .hostKeyChanged: "The server's host key has CHANGED."
        case .hostNotFound: "The host name could not be found."
        case .connectionRefused: "The server refused the connection."
        case .timedOut: "The connection timed out."
        case .networkUnreachable: "The network or host is unreachable."
        case .other: "The connection failed."
        }
    }

    public var howToFix: String {
        switch self {
        case .authenticationFailed:
            "Check the user name and that the right key is deployed to the server and loaded in the agent "
                + "(the test cannot ask for passphrases)."
        case .unknownHostKey:
            "Add the host key under Known Hosts after checking its fingerprint against one from the server's admin."
        case .hostKeyChanged:
            "This can mean the server was reinstalled, or that someone is intercepting the connection. "
                + "Verify the new fingerprint with the server's admin before replacing the stored key."
        case .hostNotFound:
            "Check HostName for typos, and your network or VPN connection."
        case .connectionRefused:
            "Check the port and that an SSH server is running on the host."
        case .timedOut, .networkUnreachable:
            "Check your network, VPN and any firewall between you and the server."
        case .other:
            "See the details below."
        }
    }
}

public enum ConnectionTestResult: Sendable, Equatable {
    case success(String)
    case failure(ConnectionProblem, details: String)

    /// Classifies the outcome of `ssh -o BatchMode=yes -T host true`.
    public static func classify(exitCode: Int32, stderr: String) -> ConnectionTestResult {
        let text = stderr.lowercased()
        let details = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        // Git hosts don't allow a shell but confirm the key: GitHub, GitLab, Bitbucket, Gitea.
        let gitHostSuccess = [
            "successfully authenticated", "welcome to gitlab", "authenticated via ssh key", "logged in as",
        ]
        if exitCode == 0 || gitHostSuccess.contains(where: { text.contains($0) }) {
            return .success(details.isEmpty ? "Connected and authenticated." : details)
        }
        let rules: [(String, ConnectionProblem)] = [
            ("remote host identification has changed", .hostKeyChanged),
            ("host key verification failed", .unknownHostKey),
            ("host key is known", .unknownHostKey),
            ("permission denied", .authenticationFailed),
            ("too many authentication failures", .authenticationFailed),
            ("could not resolve hostname", .hostNotFound),
            ("connection refused", .connectionRefused),
            ("timed out", .timedOut),
            ("network is unreachable", .networkUnreachable),
            ("no route to host", .networkUnreachable),
        ]
        let problem = rules.first { text.contains($0.0) }?.1 ?? .other
        return .failure(problem, details: details)
    }
}

public protocol HostServicing: Sendable {
    /// ~/.ssh/config and its included files.
    func loadFiles() throws -> [LoadedConfigFile]
    /// All `Host` blocks, in file order.
    func hosts() throws -> [HostEntry]
    /// Saves new text for a loaded file (backup, lock, change detection, atomic write).
    func save(_ text: String, to file: LoadedConfigFile) throws
    /// Problems `ssh` reports for `text` (empty if it parses), checked without touching the real file.
    func validate(_ text: String) async throws -> [String]
    /// The effective settings for `alias`, as `ssh -G` resolves them.
    func effectiveConfig(for alias: String) async throws -> [(key: String, value: String)]
    func testConnection(alias: String) async -> ConnectionTestResult
}

public struct HostService: HostServicing {
    private let runner: any SSHToolRunning
    private let environment: SSHEnvironment
    private let config: ConfigService
    private let writer: SafeFileWriter

    public init(runner: any SSHToolRunning, environment: SSHEnvironment, writer: SafeFileWriter) {
        self.runner = runner
        self.environment = environment
        self.writer = writer
        self.config = ConfigService(environment: environment, writer: writer)
    }

    public func loadFiles() throws -> [LoadedConfigFile] {
        try config.loadAll()
    }

    public func hosts() throws -> [HostEntry] {
        try loadFiles().flatMap { file in
            file.document.blocks().filter { !$0.isMatch }.map { HostEntry(file: file.url, block: $0) }
        }
    }

    public func save(_ text: String, to file: LoadedConfigFile) throws {
        try FileManager.default.createDirectory(
            at: environment.sshDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try writer.write(Data(text.utf8), to: file.url, expected: file.snapshot, mode: 0o600)
    }

    public func validate(_ text: String) async throws -> [String] {
        let staging = try StagingDirectory(in: environment.temporaryDirectory)
        defer { staging.remove() }
        let candidate = staging.url.appending(path: "config")
        try Data(text.utf8).withUnsafeBytes { try SecureDelete.createFile(at: candidate, contents: $0, mode: 0o600) }
        let result = try await runner.run(
            .ssh,
            arguments: ["-G", "-F", candidate.path, "smp-validation.invalid"],
            options: ToolRunOptions(timeout: .seconds(10))
        )
        guard !result.succeeded else { return [] }
        return result.standardErrorString
            .split(whereSeparator: \.isNewline)
            .map { $0.replacingOccurrences(of: candidate.path, with: "config") }
            .filter { !$0.lowercased().contains("terminating") }
    }

    public func effectiveConfig(for alias: String) async throws -> [(key: String, value: String)] {
        if let problem = HostAlias.problem(with: alias) {
            throw SMPError.invalidArgument(problem)
        }
        let result = try await runner
            .run(.ssh, arguments: configFileArguments + ["-G", alias], options: ToolRunOptions(timeout: .seconds(10)))
            .requireSuccess()
        return result.standardOutputString.split(whereSeparator: \.isNewline).compactMap { line in
            let parts = line.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { return nil }
            return (String(parts[0]), String(parts[1]))
        }
    }

    public func testConnection(alias: String) async -> ConnectionTestResult {
        if let problem = HostAlias.problem(with: alias) {
            return .failure(.other, details: problem)
        }
        // BatchMode: never prompt. StrictHostKeyChecking=yes: never change known_hosts during a test.
        let arguments = [
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes",
            "-T", alias, "true",
        ]
        do {
            let options = ToolRunOptions(timeout: .seconds(25))
            let result = try await runner.run(.ssh, arguments: arguments, options: options)
            return ConnectionTestResult.classify(exitCode: result.exitCode, stderr: result.standardErrorString)
        } catch let error as SMPError where error.code == .toolTimedOut {
            return .failure(.timedOut, details: error.whatHappened)
        } catch {
            return .failure(.other, details: error.localizedDescription)
        }
    }

    /// ssh reads `~/.ssh/config` from the account's real home folder, not `$HOME`. When SMP works on a
    /// different home folder (tests), point ssh at that folder's config explicitly.
    private var configFileArguments: [String] {
        guard let entry = getpwuid(getuid()), let realHome = entry.pointee.pw_dir else { return [] }
        let accountHome = URL(fileURLWithPath: String(cString: realHome)).standardizedFileURL.path
        guard environment.homeDirectory.standardizedFileURL.path != accountHome else { return [] }
        let config = environment.configFile
        return ["-F", FileManager.default.fileExists(atPath: config.path) ? config.path : "/dev/null"]
    }

    /// The command a user would type to connect, e.g. `ssh myhost`.
    public static func sshCommand(for alias: String) -> String {
        "ssh " + ShellQuoting.quoteIfNeeded(alias)
    }
}

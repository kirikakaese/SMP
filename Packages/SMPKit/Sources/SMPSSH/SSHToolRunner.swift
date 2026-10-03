import Foundation
import SMPCore

/// The OpenSSH command-line tools SMP is allowed to run.
public enum SSHTool: String, Sendable, CaseIterable {
    case sshKeygen = "ssh-keygen"
    case sshAdd = "ssh-add"
    case ssh = "ssh"
    case sshKeyscan = "ssh-keyscan"
    /// Used only to read and set the commit-signing options in the user's global git config.
    case git = "git"

    /// The copy that ships with macOS. SMP deliberately does not pick up Homebrew builds via `PATH`.
    public var systemPath: URL {
        URL(fileURLWithPath: "/usr/bin/\(rawValue)", isDirectory: false)
    }
}

/// Per-call options for `SSHToolRunning.run`.
public struct ToolRunOptions: Sendable {
    /// Bytes written to stdin, then stdin is closed. Use this for public keys and other non-prompt input.
    public var standardInput: SecureBytes?
    /// Passphrases answered, in order, to the tool's prompts via `SSH_ASKPASS`. Never placed in argv.
    public var passphrases: [SecureBytes]
    public var timeout: Duration
    public var workingDirectory: URL?
    /// Extra variables for the child (for example `SSH_AUTH_SOCK` for the built-in agent).
    public var extraEnvironment: [String: String]

    public init(
        standardInput: SecureBytes? = nil,
        passphrases: [SecureBytes] = [],
        timeout: Duration = .seconds(30),
        workingDirectory: URL? = nil,
        extraEnvironment: [String: String] = [:]
    ) {
        self.standardInput = standardInput
        self.passphrases = passphrases
        self.timeout = timeout
        self.workingDirectory = workingDirectory
        self.extraEnvironment = extraEnvironment
    }
}

/// The single entry point for running OpenSSH tools. Inject a fake in tests.
public protocol SSHToolRunning: Sendable {
    func run(_ tool: SSHTool, arguments: [String], options: ToolRunOptions) async throws -> ToolResult
}

extension SSHToolRunning {
    public func run(_ tool: SSHTool, arguments: [String]) async throws -> ToolResult {
        try await run(tool, arguments: arguments, options: ToolRunOptions())
    }
}

/// Runs OpenSSH tools from `/usr/bin` with a minimal, explicit environment.
///
/// - Arguments are always passed as an array, never through a shell.
/// - Secrets travel through stdin or the askpass pipe, never through argv or the environment.
/// - The child sees only `HOME`, `USER`, `LOGNAME`, `PATH`, `TMPDIR`, `LC_ALL`, and `SSH_AUTH_SOCK`
///   (when known), plus `extraEnvironment`.
/// - Only the tool name and argument count are logged, never the arguments.
public struct SSHToolRunner: SSHToolRunning {
    public let environment: SSHEnvironment
    public let toolPaths: [SSHTool: URL]
    private let executor: ProcessExecutor

    public init(
        environment: SSHEnvironment = .current,
        toolPaths: [SSHTool: URL] = [:],
        executor: ProcessExecutor? = nil
    ) {
        self.environment = environment
        self.toolPaths = toolPaths
        self.executor = executor ?? ProcessExecutor(temporaryDirectory: environment.temporaryDirectory)
    }

    public func executableURL(for tool: SSHTool) -> URL {
        toolPaths[tool] ?? tool.systemPath
    }

    public func run(_ tool: SSHTool, arguments: [String], options: ToolRunOptions) async throws -> ToolResult {
        let invocation = ToolInvocation(
            executable: executableURL(for: tool),
            arguments: arguments,
            environment: childEnvironment(extra: options.extraEnvironment),
            workingDirectory: options.workingDirectory,
            standardInput: options.standardInput,
            askpassResponses: options.passphrases,
            timeout: options.timeout
        )
        Log.tools.debug("Running \(tool.rawValue, privacy: .public) with \(arguments.count) argument(s)")
        let result = try await executor.execute(invocation)
        Log.tools.debug("\(tool.rawValue, privacy: .public) exited with \(result.exitCode)")
        return result
    }

    func childEnvironment(extra: [String: String]) -> [String: String] {
        var variables: [String: String] = [
            "HOME": environment.homeDirectory.path,
            "USER": environment.userName,
            "LOGNAME": environment.userName,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": environment.temporaryDirectory.path,
            // Stable, English, parseable output regardless of the user's locale.
            "LC_ALL": "C",
        ]
        if let socket = environment.agentSocketPath {
            variables["SSH_AUTH_SOCK"] = socket
        }
        variables.merge(extra) { _, extraValue in extraValue }
        return variables
    }
}

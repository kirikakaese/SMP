import Foundation
import SMPCore

/// A fully specified child process to run. Built by `SSHToolRunner`; rarely constructed directly.
public struct ToolInvocation: Sendable {
    /// Absolute path of the executable. Never resolved through `PATH`.
    public var executable: URL
    /// Arguments passed as an array. They are never joined into a shell string.
    public var arguments: [String]
    /// The complete environment of the child. Nothing is inherited implicitly.
    public var environment: [String: String]
    public var workingDirectory: URL?
    /// Bytes written to the child's stdin, after which stdin is closed. `nil` connects `/dev/null`.
    public var standardInput: SecureBytes?
    /// Responses served, in order, to `SSH_ASKPASS` prompts (passphrases).
    public var askpassResponses: [SecureBytes]
    public var timeout: Duration

    public init(
        executable: URL,
        arguments: [String] = [],
        environment: [String: String] = [:],
        workingDirectory: URL? = nil,
        standardInput: SecureBytes? = nil,
        askpassResponses: [SecureBytes] = [],
        timeout: Duration = .seconds(30)
    ) {
        self.executable = executable
        self.arguments = arguments
        self.environment = environment
        self.workingDirectory = workingDirectory
        self.standardInput = standardInput
        self.askpassResponses = askpassResponses
        self.timeout = timeout
    }

    /// The executable's file name, used in error messages.
    public var displayName: String { executable.lastPathComponent }

    func validate() throws {
        guard executable.isFileURL, executable.path.hasPrefix("/") else {
            throw SMPError.invalidArgument(String(localized: "The tool path must be an absolute file path."))
        }
        if arguments.contains(where: { $0.utf8.contains(0) }) {
            throw SMPError.invalidArgument(String(localized: """
                A command argument contained a NUL byte and was rejected.
                """))
        }
        if environment.contains(where: { $0.key.isEmpty || $0.key.contains("=") || $0.value.utf8.contains(0) }) {
            throw SMPError.invalidArgument(String(localized: "An environment variable was malformed and was rejected."))
        }
        guard timeout > .zero else {
            throw SMPError.invalidArgument(String(localized: "The timeout must be greater than zero."))
        }
    }
}

/// The outcome of a finished child process.
public struct ToolResult: Sendable, Equatable {
    public let toolName: String
    public let exitCode: Int32
    /// `true` if the process was ended by a signal; `exitCode` then holds the signal number.
    public let terminatedBySignal: Bool
    public let standardOutput: Data
    public let standardError: Data
    /// `true` if output exceeded the capture limit and was cut off.
    public let outputTruncated: Bool

    public init(
        toolName: String,
        exitCode: Int32,
        terminatedBySignal: Bool = false,
        standardOutput: Data = Data(),
        standardError: Data = Data(),
        outputTruncated: Bool = false
    ) {
        self.toolName = toolName
        self.exitCode = exitCode
        self.terminatedBySignal = terminatedBySignal
        self.standardOutput = standardOutput
        self.standardError = standardError
        self.outputTruncated = outputTruncated
    }

    public var succeeded: Bool { exitCode == 0 && !terminatedBySignal }

    public var standardOutputString: String { String(decoding: standardOutput, as: UTF8.self) }
    public var standardErrorString: String { String(decoding: standardError, as: UTF8.self) }

    /// Returns `self` if the tool succeeded, otherwise throws a `toolFailed` error with the trimmed stderr.
    @discardableResult
    public func requireSuccess() throws -> ToolResult {
        guard succeeded else {
            let stderr = standardErrorString.trimmingCharacters(in: .whitespacesAndNewlines)
            throw SMPError.toolFailed(toolName, exitCode: exitCode, stderr: String(stderr.prefix(2_000)))
        }
        return self
    }
}

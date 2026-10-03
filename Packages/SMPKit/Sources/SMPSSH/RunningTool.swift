import Foundation
import SMPCore

/// A long-running OpenSSH process, such as `ssh -N` for a tunnel.
public protocol RunningTool: AnyObject, Sendable {
    var isRunning: Bool { get }
    /// The exit code once the process has ended.
    var exitCode: Int32? { get }
    /// The last few kilobytes of standard error, for explaining failures.
    var errorOutput: String { get }
    /// Stops the process (SIGTERM, then SIGKILL after two seconds).
    func terminate()
}

public protocol SSHToolLaunching: Sendable {
    /// Starts a tool that keeps running. Standard input is `/dev/null`; standard output is discarded.
    /// - Parameter onExit: called once, on a background queue, when the process ends.
    func launch(
        _ tool: SSHTool,
        arguments: [String],
        onExit: @escaping @Sendable (Int32, String) -> Void
    ) throws -> any RunningTool
}

extension SSHToolRunner: SSHToolLaunching {
    public func launch(
        _ tool: SSHTool,
        arguments: [String],
        onExit: @escaping @Sendable (Int32, String) -> Void
    ) throws -> any RunningTool {
        let invocation = ToolInvocation(
            executable: executableURL(for: tool),
            arguments: arguments,
            environment: childEnvironment(extra: [:])
        )
        try invocation.validate()
        Log.tools.debug("Launching \(tool.rawValue, privacy: .public) with \(arguments.count) argument(s)")
        return try ProcessHandle(invocation: invocation, onExit: onExit)
    }
}

/// `RunningTool` backed by `Process`. Mutable state is guarded by `lock`.
final class ProcessHandle: RunningTool, @unchecked Sendable {
    private let process = Process()
    private let errorPipe = Pipe()
    private let lock = NSLock()
    private var errorData = Data()
    private var status: Int32?
    private static let errorLimit = 8 * 1024

    init(invocation: ToolInvocation, onExit: @escaping @Sendable (Int32, String) -> Void) throws {
        guard FileManager.default.isExecutableFile(atPath: invocation.executable.path) else {
            throw SMPError.toolNotFound(invocation.displayName, path: invocation.executable.path)
        }
        process.executableURL = invocation.executable
        process.arguments = invocation.arguments
        process.environment = invocation.environment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errorPipe

        errorPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let chunk = handle.availableData
            guard let self, !chunk.isEmpty else { return }
            self.lock.withLock {
                self.errorData.append(chunk)
                if self.errorData.count > Self.errorLimit {
                    self.errorData.removeFirst(self.errorData.count - Self.errorLimit)
                }
            }
        }
        process.terminationHandler = { [weak self] finished in
            guard let self else { return }
            // Give the pipe a moment to deliver the final error lines.
            usleep(100_000)
            self.errorPipe.fileHandleForReading.readabilityHandler = nil
            let code = finished.terminationStatus
            self.lock.withLock { self.status = code }
            onExit(code, self.errorOutput)
        }
        do {
            try process.run()
        } catch {
            errorPipe.fileHandleForReading.readabilityHandler = nil
            throw SMPError.toolLaunchFailed(invocation.displayName, reason: error.localizedDescription)
        }
    }

    var isRunning: Bool { lock.withLock { status == nil } }
    var exitCode: Int32? { lock.withLock { status } }
    var errorOutput: String {
        lock.withLock { String(decoding: errorData, as: UTF8.self) }
    }

    func terminate() {
        guard isRunning else { return }
        let pid = process.processIdentifier
        kill(pid, SIGTERM)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) { [weak self] in
            if self?.isRunning == true {
                kill(pid, SIGKILL)
            }
        }
    }
}

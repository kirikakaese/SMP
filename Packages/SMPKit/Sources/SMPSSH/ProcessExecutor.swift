import Foundation
import SMPCore

#if canImport(Darwin)
import Darwin
#endif

/// Runs a `ToolInvocation` with `Process`: no shell, explicit environment, captured output,
/// timeout with SIGTERM → SIGKILL escalation, and cooperative task cancellation.
public struct ProcessExecutor: Sendable {
    /// Maximum bytes captured per output stream. Output beyond this is drained and discarded.
    public var maxOutputBytes: Int
    /// How long to wait after SIGTERM before sending SIGKILL.
    public var killGracePeriod: Duration
    /// Directory for the askpass broker's private folder.
    public var temporaryDirectory: URL

    public init(
        maxOutputBytes: Int = 8 * 1024 * 1024,
        killGracePeriod: Duration = .seconds(2),
        temporaryDirectory: URL = FileManager.default.temporaryDirectory
    ) {
        self.maxOutputBytes = maxOutputBytes
        self.killGracePeriod = killGracePeriod
        self.temporaryDirectory = temporaryDirectory
    }

    public func execute(_ invocation: ToolInvocation) async throws -> ToolResult {
        try invocation.validate()
        let name = invocation.displayName
        guard FileManager.default.isExecutableFile(atPath: invocation.executable.path) else {
            throw SMPError.toolNotFound(name, path: invocation.executable.path)
        }
        if Task.isCancelled {
            throw SMPError.toolCancelled(name)
        }

        var environment = invocation.environment
        let broker = try makeBroker(for: invocation)
        if let broker {
            environment.merge(broker.environment) { _, brokerValue in brokerValue }
        }
        defer { broker?.stop() }

        let child = ChildProcess(
            invocation: invocation,
            environment: environment,
            maxOutputBytes: maxOutputBytes,
            killGracePeriod: killGracePeriod
        )

        let status = try await withTaskCancellationHandler {
            try await child.run(onLaunch: { broker?.start() })
        } onCancel: {
            child.cancel()
        }

        let output = await child.collectOutput()
        switch child.outcome {
        case .cancelled:
            throw SMPError.toolCancelled(name)
        case .timedOut:
            throw SMPError.toolTimedOut(name, after: invocation.timeout.totalSeconds)
        case .running, .exited:
            break
        }
        return ToolResult(
            toolName: name,
            exitCode: status.code,
            terminatedBySignal: status.bySignal,
            standardOutput: output.stdout,
            standardError: output.stderr,
            outputTruncated: output.truncated
        )
    }

    private func makeBroker(for invocation: ToolInvocation) throws -> AskpassBroker? {
        guard !invocation.askpassResponses.isEmpty else { return nil }
        return try AskpassBroker(responses: invocation.askpassResponses, temporaryDirectory: temporaryDirectory)
    }
}

private struct CapturedOutput {
    let stdout: Data
    let stderr: Data
    let truncated: Bool
}

extension Duration {
    var totalSeconds: Double {
        let parts = components
        return Double(parts.seconds) + Double(parts.attoseconds) / 1e18
    }

    var dispatchInterval: DispatchTimeInterval {
        .nanoseconds(Int(min(totalSeconds * 1e9, Double(Int.max / 2))))
    }
}

/// Owns one `Process` and the pipes around it. All cross-thread state is guarded by `lock`.
private final class ChildProcess: @unchecked Sendable {
    enum Outcome {
        case running, exited, timedOut, cancelled
    }

    struct Status {
        let code: Int32
        let bySignal: Bool
    }

    private let invocation: ToolInvocation
    private let process = Process()
    private let stdoutPipe = Pipe()
    private let stderrPipe = Pipe()
    private let stdinPipe: Pipe?
    private let stdoutDrain: PipeDrain
    private let stderrDrain: PipeDrain
    private let killGracePeriod: Duration

    private let lock = NSLock()
    private var launched = false
    private var finished = false
    private var state: Outcome = .running

    init(invocation: ToolInvocation, environment: [String: String], maxOutputBytes: Int, killGracePeriod: Duration) {
        self.invocation = invocation
        self.killGracePeriod = killGracePeriod
        stdinPipe = invocation.standardInput == nil ? nil : Pipe()
        stdoutDrain = PipeDrain(handle: stdoutPipe.fileHandleForReading, limit: maxOutputBytes)
        stderrDrain = PipeDrain(handle: stderrPipe.fileHandleForReading, limit: maxOutputBytes)

        process.executableURL = invocation.executable
        process.arguments = invocation.arguments
        process.environment = environment
        if let workingDirectory = invocation.workingDirectory {
            process.currentDirectoryURL = workingDirectory
        }
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        // Without explicit stdin the child would inherit SMP's stdin; use /dev/null instead.
        process.standardInput = stdinPipe ?? FileHandle.nullDevice
    }

    var outcome: Outcome {
        lock.withLock { state }
    }

    func run(onLaunch: @escaping @Sendable () -> Void) async throws -> Status {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Status, Error>) in
            process.terminationHandler = { [self] finishedProcess in
                lock.withLock {
                    finished = true
                    if state == .running { state = .exited }
                }
                let bySignal = finishedProcess.terminationReason == .uncaughtSignal
                continuation.resume(returning: Status(code: finishedProcess.terminationStatus, bySignal: bySignal))
            }

            let cancelledBeforeLaunch = lock.withLock { state == .cancelled }
            if cancelledBeforeLaunch {
                process.terminationHandler = nil
                continuation.resume(throwing: SMPError.toolCancelled(invocation.displayName))
                return
            }

            do {
                try process.run()
            } catch {
                process.terminationHandler = nil
                // The parent still holds the write ends; close them so nothing blocks on the pipes.
                try? stdoutPipe.fileHandleForWriting.close()
                try? stderrPipe.fileHandleForWriting.close()
                continuation.resume(
                    throwing: SMPError.toolLaunchFailed(invocation.displayName, reason: error.localizedDescription)
                )
                return
            }

            let cancelledDuringLaunch = lock.withLock { () -> Bool in
                launched = true
                return state == .cancelled
            }
            stdoutDrain.start()
            stderrDrain.start()
            onLaunch()
            feedStandardInput()
            scheduleTimeout()
            if cancelledDuringLaunch {
                terminate()
            }
        }
    }

    func cancel() {
        let shouldTerminate = lock.withLock { () -> Bool in
            guard state == .running else { return false }
            state = .cancelled
            return launched && !finished
        }
        if shouldTerminate {
            terminate()
        }
    }

    func collectOutput() async -> CapturedOutput {
        let stdout = await stdoutDrain.result()
        let stderr = await stderrDrain.result()
        return CapturedOutput(
            stdout: stdout.data,
            stderr: stderr.data,
            truncated: stdout.truncated || stderr.truncated
        )
    }

    private func scheduleTimeout() {
        let deadline = DispatchTime.now() + invocation.timeout.dispatchInterval
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: deadline) { [self] in
            let shouldTerminate = lock.withLock { () -> Bool in
                guard state == .running, !finished else { return false }
                state = .timedOut
                return true
            }
            if shouldTerminate {
                terminate()
            }
        }
    }

    /// Sends SIGTERM, then SIGKILL if the process is still alive after the grace period.
    private func terminate() {
        let pid = lock.withLock { () -> pid_t? in
            guard launched, !finished else { return nil }
            return process.processIdentifier
        }
        guard let pid else { return }
        kill(pid, SIGTERM)
        let deadline = DispatchTime.now() + killGracePeriod.dispatchInterval
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: deadline) { [self] in
            let stillRunning = lock.withLock { launched && !finished }
            if stillRunning {
                kill(pid, SIGKILL)
            }
        }
    }

    private func feedStandardInput() {
        guard stdinPipe != nil, invocation.standardInput != nil else { return }
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            guard let handle = stdinPipe?.fileHandleForWriting, let input = invocation.standardInput else { return }
            let descriptor = handle.fileDescriptor
            #if os(macOS)
            // A child that exits without reading stdin must not kill SMP with SIGPIPE.
            _ = fcntl(descriptor, F_SETNOSIGPIPE, 1)
            #endif
            _ = input.withUnsafeBytes { FileDescriptorIO.writeAll(descriptor, $0) }
            try? handle.close()
        }
    }
}

/// Reads a pipe to EOF on a background thread, keeping at most `limit` bytes.
private final class PipeDrain: @unchecked Sendable {
    // Safety: `buffer` and `truncated` are written by the reader thread before `done` is
    // signalled and only read after waiting on `done`.
    private let handle: FileHandle
    private let limit: Int
    private var buffer = Data()
    private var truncated = false
    private let done = DispatchGroup()

    init(handle: FileHandle, limit: Int) {
        self.handle = handle
        self.limit = limit
    }

    func start() {
        done.enter()
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let descriptor = handle.fileDescriptor
            var chunk = [UInt8](repeating: 0, count: 16 * 1024)
            while true {
                let bytesRead = chunk.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
                if bytesRead < 0 {
                    if errno == EINTR { continue }
                    break
                }
                if bytesRead == 0 { break }
                let room = limit - buffer.count
                if room > 0 {
                    buffer.append(contentsOf: chunk[0..<min(bytesRead, room)])
                }
                if bytesRead > room {
                    truncated = true
                }
            }
            done.leave()
        }
    }

    func result() async -> (data: Data, truncated: Bool) {
        await withCheckedContinuation { continuation in
            done.notify(queue: .global(qos: .userInitiated)) { [self] in
                continuation.resume(returning: (buffer, truncated))
            }
        }
    }
}

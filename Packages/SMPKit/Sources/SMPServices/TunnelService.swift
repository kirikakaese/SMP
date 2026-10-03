import Foundation
import SMPCore
import SMPSSH

public enum TunnelState: Sendable, Hashable {
    case stopped
    case running
    case failed(String)

    public var isRunning: Bool { self == .running }
}

public protocol TunnelServicing: Sendable {
    func start(_ tunnel: TunnelProfile) throws
    func stop(id: UUID)
    func stopAll()
    func state(of id: UUID) -> TunnelState
    /// Called (on a background queue) whenever a tunnel starts, stops or fails.
    func setChangeHandler(_ handler: @escaping @Sendable () -> Void)
}

/// Runs tunnels as `ssh -N` processes. Tunnels never prompt: they rely on keys loaded in the agent
/// or the Keychain (`BatchMode=yes`), and fail fast if a forward cannot be set up.
public final class TunnelService: TunnelServicing, @unchecked Sendable {
    // Safety: `running`, `stopping`, `failures` and `onChange` are only accessed while holding `lock`.
    private let launcher: any SSHToolLaunching
    private let lock = NSLock()
    private var running: [UUID: any RunningTool] = [:]
    private var failures: [UUID: String] = [:]
    /// Tunnels being stopped on purpose, so their exit is not reported as a failure.
    private var stopping: Set<UUID> = []
    private var onChange: (@Sendable () -> Void)?

    public init(launcher: any SSHToolLaunching) {
        self.launcher = launcher
    }

    public func setChangeHandler(_ handler: @escaping @Sendable () -> Void) {
        lock.withLock { onChange = handler }
    }

    public func start(_ tunnel: TunnelProfile) throws {
        guard state(of: tunnel.id) != .running else { return }
        let arguments = try Self.arguments(for: tunnel)
        let id = tunnel.id
        lock.withLock {
            failures[id] = nil
            stopping.remove(id)
        }
        let handle = try launcher.launch(.ssh, arguments: arguments) { [weak self] code, stderr in
            self?.processEnded(id: id, code: code, stderr: stderr)
        }
        let handler = lock.withLock { () -> (@Sendable () -> Void)? in
            // ssh can fail before we get here (e.g. a port already in use); keep that failure.
            if failures[id] == nil {
                running[id] = handle
            }
            return onChange
        }
        handler?()
    }

    public func stop(id: UUID) {
        let handle = lock.withLock { () -> (any RunningTool)? in
            let handle = running.removeValue(forKey: id)
            if handle != nil {
                stopping.insert(id)
            }
            return handle
        }
        handle?.terminate()
        let handler = lock.withLock { onChange }
        handler?()
    }

    public func stopAll() {
        let handles = lock.withLock { () -> [any RunningTool] in
            let all = Array(running.values)
            stopping.formUnion(running.keys)
            running.removeAll()
            return all
        }
        handles.forEach { $0.terminate() }
    }

    public func state(of id: UUID) -> TunnelState {
        lock.withLock {
            if let handle = running[id], handle.isRunning { return .running }
            if let failure = failures[id] { return .failed(failure) }
            return .stopped
        }
    }

    private func processEnded(id: UUID, code: Int32, stderr: String) {
        let handler = lock.withLock { () -> (@Sendable () -> Void)? in
            running.removeValue(forKey: id)
            // A tunnel ended by `stop` ended on purpose; anything else is a failure.
            guard stopping.remove(id) == nil else { return onChange }
            let message = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            failures[id] = message.isEmpty ? "ssh exited with code \(code)." : message
            return onChange
        }
        handler?()
    }

    /// `ssh -N` arguments for a tunnel. Validates every user-provided value.
    public static func arguments(for tunnel: TunnelProfile) throws -> [String] {
        if let problem = HostAlias.problem(with: tunnel.hostAlias) {
            throw SMPError.invalidArgument(problem)
        }
        guard !tunnel.forwards.isEmpty else {
            throw SMPError.invalidArgument("Add at least one port forward.")
        }
        var arguments = [
            "-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
        ]
        for forward in tunnel.forwards {
            if let problem = forward.problem {
                throw SMPError.invalidArgument(problem)
            }
            arguments += forward.arguments
        }
        arguments.append(tunnel.hostAlias)
        return arguments
    }
}

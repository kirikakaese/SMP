import Foundation
import SMPCore
import SMPSSH
import ServiceManagement

/// Whether the agent helper is registered as a login item.
public enum AgentHelperStatus: Sendable, Hashable {
    case notRegistered
    case enabled
    /// Registered, but the user has to allow it in System Settings → General → Login Items.
    case requiresApproval
    /// The helper is missing from the app bundle (e.g. a development build without it).
    case notFound
}

/// Starts and stops SMP's agent helper and checks whether it answers.
public protocol AgentHelperControlling: Sendable {
    func status() -> AgentHelperStatus
    func register() throws
    func unregister() async throws
    func openLoginItemsSettings()
    /// Number of identities the agent on `socket` offers, or `nil` if nothing answers there.
    func identityCount(socket: URL) async -> Int?
}

public struct AgentHelperService: AgentHelperControlling {
    private let runner: any SSHToolRunning

    public init(runner: any SSHToolRunning) {
        self.runner = runner
    }

    private var service: SMAppService { SMAppService.loginItem(identifier: AgentPaths.helperBundleIdentifier) }

    public func status() -> AgentHelperStatus {
        switch service.status {
        case .enabled: .enabled
        case .requiresApproval: .requiresApproval
        case .notFound: .notFound
        default: .notRegistered
        }
    }

    public func register() throws {
        do {
            try service.register()
        } catch {
            throw SMPError(
                .toolLaunchFailed,
                whatHappened: String(localized: "SMP could not start its agent."),
                howToFix: String(localized: "Allow “SMP Agent” in System Settings → General → Login Items."),
                details: error.localizedDescription
            )
        }
    }

    public func unregister() async throws {
        do {
            try await service.unregister()
        } catch {
            throw SMPError(
                .toolFailed, whatHappened: String(localized: """
                    SMP could not stop its agent.
                    """), details: error.localizedDescription
            )
        }
    }

    public func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    public func identityCount(socket: URL) async -> Int? {
        let options = ToolRunOptions(timeout: .seconds(5), extraEnvironment: ["SSH_AUTH_SOCK": socket.path])
        guard let result = try? await runner.run(.sshAdd, arguments: ["-L"], options: options) else { return nil }
        // ssh-add: exit 0 = identities listed, 1 = no identities, 2 = no agent.
        switch result.exitCode {
        case 0: return result.standardOutputString.split(whereSeparator: \.isNewline).count
        case 1: return 0
        default: return nil
        }
    }
}

/// A helper that is always in the given state. For tests and previews.
public final class FakeAgentHelper: AgentHelperControlling, @unchecked Sendable {
    private let lock = NSLock()
    private var current: AgentHelperStatus
    private let identities: Int?

    public init(status: AgentHelperStatus = .notRegistered, identities: Int? = nil) {
        self.current = status
        self.identities = identities
    }

    public func status() -> AgentHelperStatus { lock.withLock { current } }
    public func register() throws { lock.withLock { current = .enabled } }
    public func unregister() async throws { lock.withLock { current = .notRegistered } }
    public func openLoginItemsSettings() {}
    public func identityCount(socket: URL) async -> Int? {
        lock.withLock { current == .enabled ? identities ?? 0 : nil }
    }
}

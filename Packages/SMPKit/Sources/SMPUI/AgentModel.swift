import Foundation
import Observation
import SMPCore
import SMPServices

/// State behind SSH → Agent: the login-item helper, whether ssh uses it, and its settings.
@MainActor
@Observable
public final class AgentModel {
    public private(set) var helperStatus: AgentHelperStatus = .notRegistered
    /// Identities the running agent offers, or `nil` if it does not answer.
    public private(set) var identityCount: Int?
    /// Whether `ssh -G` resolves `IdentityAgent` to SMP's socket for a host without its own setting.
    public private(set) var isUsedBySSH: Bool?
    public private(set) var isChecking = false
    public var lastError: SMPError?
    public var settings: AgentSettings {
        didSet { settings.save(to: defaults) }
    }

    @ObservationIgnored let services: ServiceContainer
    @ObservationIgnored private let defaults: UserDefaults
    public let socketURL: URL?

    public init(
        services: ServiceContainer,
        defaults: UserDefaults = UserDefaults(suiteName: AgentPaths.sharedDefaultsSuite) ?? .standard,
        socketURL: URL? = try? AgentPaths.socketURL()
    ) {
        self.services = services
        self.defaults = defaults
        self.socketURL = socketURL
        self.settings = AgentSettings.load(from: defaults)
    }

    /// The value for `IdentityAgent`, e.g. `"~/Library/Application Support/com.kirikakaese.smp/agent.sock"`.
    public var identityAgentValue: String? {
        socketURL.map { AgentPaths.identityAgentValue(for: $0, homeDirectory: services.environment.homeDirectory) }
    }

    public var socketPathFits: Bool {
        (socketURL?.path.utf8.count ?? .max) <= AgentPaths.maxSocketPathLength
    }

    public func refresh() async {
        isChecking = true
        defer { isChecking = false }
        helperStatus = services.agentHelper.status()
        if let socketURL {
            identityCount = await services.agentHelper.identityCount(socket: socketURL)
        }
        isUsedBySSH = await checkSSHConfig()
    }

    public func enable() async {
        do {
            try services.agentHelper.register()
        } catch {
            lastError = error.asSMPError
        }
        // The helper needs a moment to create its socket.
        try? await Task.sleep(for: .seconds(1))
        await refresh()
    }

    public func disable() async {
        do {
            try await services.agentHelper.unregister()
        } catch {
            lastError = error.asSMPError
        }
        await refresh()
    }

    public func openLoginItemsSettings() {
        services.agentHelper.openLoginItemsSettings()
    }

    /// Shows the `~/.ssh/config` change (as a reviewed diff) that routes ssh through the agent.
    public func proposeConfigChange(using hosts: HostsModel) {
        guard let identityAgentValue else { return }
        hosts.reload()
        hosts.proposeIdentityAgent(identityAgentValue)
    }

    private func checkSSHConfig() async -> Bool? {
        guard let socketURL else { return nil }
        // A host name that matches no specific block, so only catch-all settings apply.
        guard let effective = try? await services.hosts.effectiveConfig(for: "smp-agent-check.invalid") else {
            return nil
        }
        guard let value = effective.first(where: { $0.key == "identityagent" })?.value else { return false }
        return Self.expand(value, home: services.environment.homeDirectory) == socketURL.path
    }

    /// Expands `~` and strips quotes the way ssh does for `IdentityAgent`.
    nonisolated static func expand(_ value: String, home: URL) -> String {
        var path = value.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        if path == "~" || path.hasPrefix("~/") {
            path = home.path + path.dropFirst()
        }
        return path
    }
}

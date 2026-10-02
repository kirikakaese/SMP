import Foundation
import SMPCore
import SMPSSH

/// The state of the ssh-agent reachable through `SSH_AUTH_SOCK`.
public enum AgentStatus: Sendable, Hashable {
    /// No agent socket, or the agent did not answer.
    case unavailable
    /// The agent is running; the set holds the SHA256 fingerprints of loaded identities.
    case running(loadedFingerprints: Set<String>)

    public var loadedFingerprints: Set<String> {
        if case .running(let fingerprints) = self { return fingerprints }
        return []
    }
}

public protocol AgentServicing: Sendable {
    func status() async -> AgentStatus
}

/// Queries the system ssh-agent with `ssh-add -l`. More agent control arrives in milestone 5.
public struct AgentService: AgentServicing {
    private let runner: any SSHToolRunning

    public init(runner: any SSHToolRunning) {
        self.runner = runner
    }

    public func status() async -> AgentStatus {
        guard let result = try? await runner.run(
            .sshAdd,
            arguments: ["-l", "-E", "sha256"],
            options: ToolRunOptions(timeout: .seconds(5))
        ) else {
            return .unavailable
        }
        // ssh-add -l: exit 0 = identities listed, 1 = agent has no identities, 2 = no agent.
        switch result.exitCode {
        case 0: return .running(loadedFingerprints: Self.parseFingerprints(result.standardOutputString))
        case 1: return .running(loadedFingerprints: [])
        default: return .unavailable
        }
    }

    /// Extracts `SHA256:…` fingerprints from `ssh-add -l -E sha256` output.
    static func parseFingerprints(_ output: String) -> Set<String> {
        var fingerprints = Set<String>()
        for line in output.split(whereSeparator: \.isNewline) {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count >= 2, fields[1].hasPrefix("SHA256:") else { continue }
            fingerprints.insert(String(fields[1]))
        }
        return fingerprints
    }
}

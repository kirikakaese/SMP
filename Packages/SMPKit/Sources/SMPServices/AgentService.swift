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
    /// Loads a key into the agent (`ssh-add`). The passphrase is passed through askpass.
    /// - Parameters:
    ///   - storeInKeychain: also save the passphrase in the macOS Keychain (`--apple-use-keychain`).
    ///   - lifetime: remove the key from the agent again after this many seconds (`-t`).
    func add(keyFile: URL, passphrase: SecureBytes?, storeInKeychain: Bool, lifetime: Int?) async throws
    /// Removes a key from the agent (`ssh-add -d`). With `removeFromKeychain`, the stored
    /// passphrase is deleted from the Keychain as well.
    func remove(keyFile: URL, removeFromKeychain: Bool) async throws
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

    public func add(keyFile: URL, passphrase: SecureBytes?, storeInKeychain: Bool, lifetime: Int?) async throws {
        var arguments: [String] = []
        if storeInKeychain {
            arguments.append("--apple-use-keychain")
        }
        if let lifetime {
            arguments += ["-t", String(lifetime)]
        }
        arguments.append(keyFile.path)
        let result = try await runner.run(
            .sshAdd,
            arguments: arguments,
            options: ToolRunOptions(passphrases: passphrase.map { [$0] } ?? [], timeout: .seconds(30))
        )
        guard result.succeeded else {
            let stderr = result.standardErrorString
            if stderr.contains("Could not open a connection") || stderr.contains("Error connecting to agent") {
                throw SMPError(
                    .toolFailed,
                    whatHappened: String(localized: "No ssh-agent is running."),
                    howToFix: String(localized: """
                        macOS starts the agent automatically when you log in. Log out and back in, \
                        or start one with “eval $(ssh-agent)” in Terminal.
                        """),
                    details: stderr
                )
            }
            // ssh-add reports a wrong passphrase only in its re-prompt ("Bad passphrase, try again"),
            // then gives up with exit code 1 once askpass has no more answers.
            if result.exitCode == 1, !stderr.lowercased().contains("invalid format") {
                throw SMPError.wrongPassphrase(keyFile.lastPathComponent)
            }
            throw SMPError.toolFailed("ssh-add", exitCode: result.exitCode, stderr: stderr)
        }
    }

    public func remove(keyFile: URL, removeFromKeychain: Bool) async throws {
        var arguments = ["-d"]
        if removeFromKeychain {
            arguments.insert("--apple-use-keychain", at: 0)
        }
        arguments.append(keyFile.path)
        let result = try await runner.run(.sshAdd, arguments: arguments, options: ToolRunOptions(timeout: .seconds(10)))
        // Exit 1 means "not loaded", which is fine when removing.
        guard result.exitCode == 0 || result.exitCode == 1 else {
            throw SMPError.toolFailed("ssh-add", exitCode: result.exitCode, stderr: result.standardErrorString)
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

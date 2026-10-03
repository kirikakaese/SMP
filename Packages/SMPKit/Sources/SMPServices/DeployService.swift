import Foundation
import SMPCore
import SMPSSH

public enum DeployOutcome: Sendable, Equatable {
    case added
    case alreadyPresent
}

public protocol DeployServicing: Sendable {
    /// Appends `key` to `~/.ssh/authorized_keys` on `host` unless it is already there (like `ssh-copy-id`).
    func install(_ key: SSHPublicKey, on host: String, password: SecureBytes?) async throws -> DeployOutcome
    /// Reads the server's `~/.ssh/authorized_keys`.
    func authorizedKeys(on host: String, password: SecureBytes?) async throws -> [AuthorizedKeysEntry]
    /// Removes exactly this line from the server's `authorized_keys` (a backup stays on the server).
    func remove(_ entry: AuthorizedKeysEntry, from host: String, password: SecureBytes?) async throws
    /// Logs in with only `keyFile` to prove the deployed key works.
    func verifyLogin(on host: String, keyFile: URL, passphrase: SecureBytes?) async -> ConnectionTestResult
}

/// Manages `authorized_keys` on servers over SSH.
///
/// Remote scripts always run under `sh -c`, whatever the login shell. Key lines travel on stdin,
/// never inside the command. Unknown host keys are refused (`StrictHostKeyChecking=yes`): verify
/// and add them under Known Hosts first.
public struct DeployService: DeployServicing {
    private let runner: any SSHToolRunning

    public init(runner: any SSHToolRunning) {
        self.runner = runner
    }

    // MARK: Remote scripts (POSIX sh)

    static let installScript = """
        umask 077
        mkdir -p "$HOME/.ssh" || exit 3
        f="$HOME/.ssh/authorized_keys"
        touch "$f" || exit 3
        chmod 700 "$HOME/.ssh"; chmod 600 "$f"
        IFS= read -r key || exit 4
        if grep -qxF -- "$key" "$f"; then echo SMP_PRESENT; exit 0; fi
        if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi
        printf '%s\\n' "$key" >> "$f" && echo SMP_ADDED
        """

    static let listScript = """
        cat "$HOME/.ssh/authorized_keys" 2>/dev/null
        exit 0
        """

    static let removeScript = """
        f="$HOME/.ssh/authorized_keys"
        [ -f "$f" ] || exit 5
        IFS= read -r line || exit 4
        cp -p "$f" "$f.smp-backup" || exit 3
        grep -vxF -- "$line" "$f.smp-backup" > "$f.smp-tmp"
        status=$?
        if [ "$status" -gt 1 ]; then rm -f "$f.smp-tmp"; exit 3; fi
        chmod 600 "$f.smp-tmp" && mv "$f.smp-tmp" "$f" && echo SMP_REMOVED
        """

    // MARK: Operations

    public func install(_ key: SSHPublicKey, on host: String, password: SecureBytes?) async throws -> DeployOutcome {
        let result = try await run(Self.installScript, on: host, input: key.openSSHLine + "\n", password: password)
        if result.standardOutputString.contains("SMP_PRESENT") { return .alreadyPresent }
        guard result.standardOutputString.contains("SMP_ADDED") else {
            throw failure(result, action: "install the key on \(host)")
        }
        return .added
    }

    public func authorizedKeys(on host: String, password: SecureBytes?) async throws -> [AuthorizedKeysEntry] {
        let result = try await run(Self.listScript, on: host, input: nil, password: password)
        guard result.succeeded else { throw failure(result, action: "read authorized_keys on \(host)") }
        return AuthorizedKeysEntry.parse(result.standardOutputString)
    }

    public func remove(_ entry: AuthorizedKeysEntry, from host: String, password: SecureBytes?) async throws {
        let result = try await run(Self.removeScript, on: host, input: entry.line + "\n", password: password)
        guard result.standardOutputString.contains("SMP_REMOVED") else {
            throw failure(result, action: "remove the key from \(host)")
        }
    }

    public func verifyLogin(on host: String, keyFile: URL, passphrase: SecureBytes?) async -> ConnectionTestResult {
        let arguments = [
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", keyFile.path,
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-T", host, "true",
        ]
        do {
            let result = try await runner.run(
                .ssh,
                arguments: arguments,
                options: ToolRunOptions(passphrases: passphrase.map { [$0] } ?? [], timeout: .seconds(30))
            )
            return ConnectionTestResult.classify(exitCode: result.exitCode, stderr: result.standardErrorString)
        } catch {
            return .failure(.other, details: error.localizedDescription)
        }
    }

    // MARK: Helpers

    /// Arguments for running `script` on `host`. With a password, public-key authentication is
    /// switched off so the password can only ever answer a password prompt.
    static func arguments(script: String, host: String, usesPassword: Bool) throws -> [String] {
        if let problem = HostAlias.problem(with: host) {
            throw SMPError.invalidArgument(problem)
        }
        var arguments = ["-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15"]
        if usesPassword {
            arguments += [
                "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=keyboard-interactive,password",
                "-o", "NumberOfPasswordPrompts=1",
            ]
        } else {
            arguments += ["-o", "BatchMode=yes"]
        }
        arguments += ["-T", host, "exec sh -c " + ShellQuoting.quote(script)]
        return arguments
    }

    private func run(
        _ script: String,
        on host: String,
        input: String?,
        password: SecureBytes?
    ) async throws -> ToolResult {
        let usesPassword = !(password?.isEmpty ?? true)
        let options = ToolRunOptions(
            standardInput: input.map { SecureBytes(utf8: $0) },
            passphrases: usesPassword ? [password].compactMap { $0 } : [],
            timeout: .seconds(45)
        )
        return try await runner.run(
            .ssh,
            arguments: try Self.arguments(script: script, host: host, usesPassword: usesPassword),
            options: options
        )
    }

    private func failure(_ result: ToolResult, action: String) -> SMPError {
        let stderr = result.standardErrorString.trimmingCharacters(in: .whitespacesAndNewlines)
        if case .failure(let problem, _) = ConnectionTestResult.classify(exitCode: result.exitCode, stderr: stderr),
           problem != .other {
            return SMPError(.toolFailed, whatHappened: problem.title, howToFix: problem.howToFix, details: stderr)
        }
        let hint: String? = switch result.exitCode {
        case 3: "The server's ~/.ssh folder or authorized_keys file could not be written."
        case 5: "The server has no ~/.ssh/authorized_keys file."
        default: nil
        }
        return SMPError(.toolFailed, whatHappened: String(localized: """
            SMP could not \(action).
            """), howToFix: hint, details: stderr)
    }
}

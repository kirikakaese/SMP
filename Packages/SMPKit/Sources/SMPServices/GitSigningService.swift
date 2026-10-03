import Foundation
import SMPCore
import SMPSSH

/// The commit-signing options currently in the global git config.
public struct GitSigningState: Sendable, Hashable {
    public var values: [String: String]

    public init(values: [String: String] = [:]) {
        self.values = values
    }

    public var format: String? { values[GitSigningService.Key.format] }
    public var signingKey: String? { values[GitSigningService.Key.signingKey] }
    public var signsCommits: Bool { values[GitSigningService.Key.commitSign]?.lowercased() == "true" }
    public var email: String? { values[GitSigningService.Key.email] }

    /// Whether git signs with SSH using the given public key file.
    public func usesSSHKey(atPath path: String) -> Bool {
        format == "ssh" && signingKey == path && signsCommits
    }
}

/// One setting that changes.
public struct GitConfigChange: Sendable, Hashable, Identifiable {
    public let key: String
    public let oldValue: String?
    public let newValue: String

    public var id: String { key }
}

/// Everything "Set up commit signing" will do, shown to the user before anything is written.
public struct GitSigningPlan: Sendable, Hashable {
    public let changes: [GitConfigChange]
    public let allowedSignersFile: URL
    /// The line added to the allowed signers file, or `nil` if it is already there.
    public let allowedSignersLine: String?
}

public protocol GitSigningServicing: Sendable {
    func currentState() async throws -> GitSigningState
    func plan(
        publicKeyFile: URL,
        publicKey: SSHPublicKey,
        email: String,
        signTags: Bool
    ) async throws -> GitSigningPlan
    func apply(_ plan: GitSigningPlan) async throws
}

/// Configures git to sign commits with an SSH key: `gpg.format ssh`, `user.signingkey`,
/// `commit.gpgsign`, and an allowed signers file so `git log --show-signature` can verify them.
/// Writes only to the global git config, through `git config --global`.
public struct GitSigningService: GitSigningServicing {
    enum Key {
        static let format = "gpg.format"
        static let signingKey = "user.signingkey"
        static let commitSign = "commit.gpgsign"
        static let tagSign = "tag.gpgsign"
        static let allowedSigners = "gpg.ssh.allowedsignersfile"
        static let email = "user.email"
        static let all = [format, signingKey, commitSign, tagSign, allowedSigners, email]
    }

    private let runner: any SSHToolRunning
    private let environment: SSHEnvironment
    private let writer: SafeFileWriter

    public init(runner: any SSHToolRunning, environment: SSHEnvironment, writer: SafeFileWriter) {
        self.runner = runner
        self.environment = environment
        self.writer = writer
    }

    public func currentState() async throws -> GitSigningState {
        var values: [String: String] = [:]
        for key in Key.all {
            let result = try await git(["config", "--global", "--get", key])
            // Exit code 1 means "not set".
            if result.exitCode == 0 {
                values[key] = result.standardOutputString.trimmingCharacters(in: .whitespacesAndNewlines)
            } else if result.exitCode != 1 {
                throw gitFailure(result)
            }
        }
        return GitSigningState(values: values)
    }

    public func plan(
        publicKeyFile: URL,
        publicKey: SSHPublicKey,
        email: String,
        signTags: Bool
    ) async throws -> GitSigningPlan {
        let email = email.trimmingCharacters(in: .whitespaces)
        guard !email.isEmpty, !email.contains(where: { $0.isWhitespace || $0 == "\"" }) else {
            throw SMPError.invalidArgument("Enter the email address you commit with.")
        }
        guard !publicKey.isCertificate else {
            throw SMPError.invalidArgument("Choose the key itself, not its certificate.")
        }
        let state = try await currentState()
        let allowedSigners = environment.sshDirectory.appending(path: "allowed_signers")
        var wanted: [(String, String)] = [
            (Key.format, "ssh"),
            (Key.signingKey, publicKeyFile.path),
            (Key.commitSign, "true"),
            (Key.allowedSigners, allowedSigners.path),
        ]
        if signTags {
            wanted.append((Key.tagSign, "true"))
        }
        if state.email == nil {
            wanted.append((Key.email, email))
        }
        let changes = wanted.compactMap { pair -> GitConfigChange? in
            let (key, value) = pair
            return state.values[key] == value
                ? nil : GitConfigChange(key: key, oldValue: state.values[key], newValue: value)
        }
        let line = Self.allowedSignersLine(email: email, publicKey: publicKey)
        let existing = (try? String(contentsOf: allowedSigners, encoding: .utf8)) ?? ""
        let present = existing.split(whereSeparator: \.isNewline).contains { Self.sameEntry(String($0), as: line) }
        return GitSigningPlan(
            changes: changes, allowedSignersFile: allowedSigners, allowedSignersLine: present ? nil : line
        )
    }

    public func apply(_ plan: GitSigningPlan) async throws {
        if let line = plan.allowedSignersLine {
            try appendAllowedSigner(line, to: plan.allowedSignersFile)
        }
        for change in plan.changes {
            let result = try await git(["config", "--global", change.key, change.newValue])
            guard result.succeeded else { throw gitFailure(result) }
        }
    }

    // MARK: Helpers

    /// `email namespaces="git" type base64` (the comment is left out).
    static func allowedSignersLine(email: String, publicKey: SSHPublicKey) -> String {
        "\(email) namespaces=\"git\" \(publicKey.wireType) \(publicKey.blob.base64EncodedString())"
    }

    /// Same principal and key, ignoring options and comments.
    static func sameEntry(_ line: String, as wanted: String) -> Bool {
        let have = line.split(separator: " ")
        let want = wanted.split(separator: " ")
        guard let principal = want.first, let blob = want.last else { return false }
        return have.first == principal && have.contains(blob)
    }

    private func appendAllowedSigner(_ line: String, to url: URL) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let snapshot = try FileSnapshot.capture(url)
        var text = ""
        if snapshot != nil {
            text = try String(contentsOf: url, encoding: .utf8)
        }
        if !text.isEmpty, !text.hasSuffix("\n") {
            text += "\n"
        }
        text += line + "\n"
        _ = try writer.write(Data(text.utf8), to: url, expected: snapshot, mode: 0o644)
    }

    private func git(_ arguments: [String]) async throws -> ToolResult {
        try await runner.run(.git, arguments: arguments, options: ToolRunOptions(timeout: .seconds(15)))
    }

    private func gitFailure(_ result: ToolResult) -> SMPError {
        let stderr = result.standardErrorString.trimmingCharacters(in: .whitespacesAndNewlines)
        let missingTools = stderr.contains("xcrun") || stderr.contains("developer tools")
        return SMPError(
            .toolFailed,
            whatHappened: "git could not change its settings.",
            howToFix: missingTools ? "Install the Xcode Command Line Tools (xcode-select --install)." : nil,
            details: stderr
        )
    }
}

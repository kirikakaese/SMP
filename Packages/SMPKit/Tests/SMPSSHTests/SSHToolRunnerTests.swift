import Foundation
import SMPCore
import Testing

@testable import SMPSSH

/// A private temporary `HOME` for one test. Tests must never touch the real `~/.ssh`.
final class TemporaryHome: Sendable {
    let url: URL

    init() throws {
        url = FileManager.default.temporaryDirectory
            .appending(path: "smp-test-home-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: url.appending(path: ".ssh"),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    deinit {
        try? FileManager.default.removeItem(at: url)
    }

    var environment: SSHEnvironment {
        SSHEnvironment(homeDirectory: url, userName: "smp-test")
    }
}

@Suite("SSHToolRunner")
struct SSHToolRunnerTests {
    @Test func usesSystemToolsByDefault() {
        let environment = SSHEnvironment(homeDirectory: URL(fileURLWithPath: "/tmp"), userName: "u")
        let runner = SSHToolRunner(environment: environment)
        #expect(runner.executableURL(for: .sshKeygen).path == "/usr/bin/ssh-keygen")
        #expect(runner.executableURL(for: .sshAdd).path == "/usr/bin/ssh-add")
    }

    @Test func childEnvironmentIsMinimalAndExplicit() {
        let environment = SSHEnvironment(
            homeDirectory: URL(fileURLWithPath: "/tmp/home"),
            userName: "alice",
            agentSocketPath: "/tmp/agent.sock"
        )
        let runner = SSHToolRunner(environment: environment)
        let variables = runner.childEnvironment(extra: ["LC_ALL": "en_US.UTF-8"])
        #expect(variables["HOME"] == "/tmp/home")
        #expect(variables["USER"] == "alice")
        #expect(variables["SSH_AUTH_SOCK"] == "/tmp/agent.sock")
        #expect(variables["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
        #expect(variables["LC_ALL"] == "en_US.UTF-8", "extra variables override the defaults")
        let expectedKeys: Set = ["HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LC_ALL", "SSH_AUTH_SOCK"]
        #expect(Set(variables.keys) == expectedKeys)
    }

    @Test func omitsAgentSocketWhenUnknown() {
        let environment = SSHEnvironment(homeDirectory: URL(fileURLWithPath: "/tmp"), userName: "u")
        #expect(SSHToolRunner(environment: environment).childEnvironment(extra: [:])["SSH_AUTH_SOCK"] == nil)
    }

    @Test func runsOverriddenToolPath() async throws {
        let home = try TemporaryHome()
        let runner = SSHToolRunner(
            environment: home.environment,
            toolPaths: [.ssh: URL(fileURLWithPath: "/usr/bin/env")]
        )
        let result = try await runner.run(.ssh, arguments: [])
        #expect(result.standardOutputString.contains("HOME=\(home.url.path)"))
    }
}

/// End-to-end checks against the real `/usr/bin/ssh-keygen`, isolated in a temporary `HOME`.
@Suite(
    "ssh-keygen integration",
    .enabled(if: FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-keygen"))
)
struct SSHKeygenIntegrationTests {
    @Test func generatesPassphraseProtectedKeyWithoutPassphraseInArgv() async throws {
        let home = try TemporaryHome()
        let runner = SSHToolRunner(environment: home.environment)
        let keyPath = home.url.appending(path: ".ssh/id_ed25519_test").path

        let passphrase = SecureBytes(utf8: "correct horse battery staple")
        // ssh-keygen asks for the new passphrase twice (entry + confirmation).
        let generated = try await runner.run(
            .sshKeygen,
            arguments: ["-t", "ed25519", "-C", "smp-test", "-f", keyPath],
            options: ToolRunOptions(passphrases: [passphrase, passphrase])
        )
        try generated.requireSuccess()
        #expect(FileManager.default.fileExists(atPath: keyPath))
        #expect(FileManager.default.fileExists(atPath: keyPath + ".pub"))

        // If the askpass hand-off had failed, ssh-keygen would have written an unencrypted key.
        #expect(try privateKeyCipherName(atPath: keyPath) != "none")

        // The right passphrase, delivered through askpass, derives the public key.
        let derived = try await runner.run(
            .sshKeygen,
            arguments: ["-y", "-f", keyPath],
            options: ToolRunOptions(passphrases: [passphrase])
        )
        try derived.requireSuccess()
        let publicKey = try String(contentsOfFile: keyPath + ".pub", encoding: .utf8)
        #expect(derived.standardOutputString.hasPrefix("ssh-ed25519 "))
        let derivedKey = derived.standardOutputString.trimmingCharacters(in: .whitespacesAndNewlines)
        #expect(publicKey.hasPrefix(derivedKey))
    }

    @Test func reportsSHA256Fingerprint() async throws {
        let home = try TemporaryHome()
        let runner = SSHToolRunner(environment: home.environment)
        let keyPath = home.url.appending(path: ".ssh/id_unencrypted_test").path

        try await runner
            .run(.sshKeygen, arguments: ["-t", "ed25519", "-N", "", "-C", "fp-test", "-f", keyPath])
            .requireSuccess()
        let fingerprint = try await runner
            .run(.sshKeygen, arguments: ["-l", "-E", "sha256", "-f", keyPath + ".pub"])
            .requireSuccess()
        #expect(fingerprint.standardOutputString.contains("SHA256:"))
        #expect(fingerprint.standardOutputString.contains("(ED25519)"))
        #expect(fingerprint.standardOutputString.contains("fp-test"))
    }

    @Test func doesNotOverwriteExistingKeyWithoutConfirmation() async throws {
        let home = try TemporaryHome()
        let runner = SSHToolRunner(environment: home.environment)
        let keyPath = home.url.appending(path: ".ssh/id_existing").path
        try await runner
            .run(.sshKeygen, arguments: ["-t", "ed25519", "-N", "", "-f", keyPath])
            .requireSuccess()
        let original = try Data(contentsOf: URL(fileURLWithPath: keyPath))

        // stdin is /dev/null, so ssh-keygen's "Overwrite (y/n)?" question reads EOF and declines.
        _ = try await runner.run(.sshKeygen, arguments: ["-t", "ed25519", "-N", "", "-f", keyPath])
        #expect(try Data(contentsOf: URL(fileURLWithPath: keyPath)) == original)
    }
}

/// Reads the cipher name from an OpenSSH-format private key ("none" means unencrypted).
func privateKeyCipherName(atPath path: String) throws -> String {
    let text = try String(contentsOfFile: path, encoding: .utf8)
    let body = text
        .split(separator: "\n")
        .filter { !$0.hasPrefix("-----") }
        .joined()
    let data = try #require(Data(base64Encoded: body))
    let magic = Array("openssh-key-v1".utf8) + [0]
    let bytes = [UInt8](data)
    try #require(bytes.starts(with: magic))
    var offset = magic.count
    try #require(bytes.count >= offset + 4)
    let length = bytes[offset..<offset + 4].reduce(0) { ($0 << 8) | Int($1) }
    offset += 4
    try #require(bytes.count >= offset + length)
    return String(decoding: bytes[offset..<offset + length], as: UTF8.self)
}

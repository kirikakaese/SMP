import Foundation
import SMPCore
import SMPSSH
import Testing

@testable import SMPServices

/// A throwaway ssh-agent on a private socket; never touches the user's agent.
final class TemporaryAgent {
    let socketPath: String
    private let process = Process()

    init() throws {
        // Unix socket paths are limited to 104 bytes, so keep it short and in /tmp.
        socketPath = "/tmp/smp-\(UUID().uuidString.prefix(8)).sock"
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-agent")
        process.arguments = ["-D", "-a", socketPath]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        let deadline = Date().addingTimeInterval(5)
        while !FileManager.default.fileExists(atPath: socketPath), Date() < deadline {
            usleep(50_000)
        }
    }

    deinit {
        process.terminate()
        process.waitUntilExit()
        unlink(socketPath)
    }
}

@Suite(
    "AgentService (ssh-agent)",
    .enabled(if: FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-agent"))
)
struct AgentIntegrationTests {
    @Test func addsAndRemovesKeysWithPassphrase() async throws {
        let agentProcess = try TemporaryAgent()
        let home = try TestHome()
        var environment = home.environment
        environment.agentSocketPath = agentProcess.socketPath
        let runner = SSHToolRunner(environment: environment)
        let agent = AgentService(runner: runner)
        let keys = KeyService(
            runner: runner,
            environment: environment,
            config: home.config,
            archive: ArchiveService(
                directory: home.support.appending(path: "Archive"),
                keychain: InMemoryKeychainService()
            ),
            agent: agent
        )
        let passphrase = SecureBytes(utf8: "agent test passphrase")
        let created = try await keys.generate(KeyGenerationRequest(
            fileName: "agent_key", directory: home.ssh, comment: "", passphrase: passphrase
        ))
        let keyFile = try #require(created.privateKeyURL)

        #expect(await agent.status() == .running(loadedFingerprints: []))

        let wrong = await asyncErrorCode {
            try await agent.add(
                keyFile: keyFile,
                passphrase: SecureBytes(utf8: "wrong"),
                storeInKeychain: false,
                lifetime: nil
            )
        }
        #expect(wrong == .passphraseRequired)

        try await agent.add(keyFile: keyFile, passphrase: passphrase, storeInKeychain: false, lifetime: 60)
        #expect(await agent.status().loadedFingerprints == [created.publicKey.fingerprintSHA256])

        try await agent.remove(keyFile: created.publicKeyURL, removeFromKeychain: false)
        #expect(await agent.status().loadedFingerprints.isEmpty)
    }
}

private let puttygenPath = ["/opt/homebrew/bin/puttygen", "/usr/local/bin/puttygen"]
    .first { FileManager.default.isExecutableFile(atPath: $0) }

/// Converts keys produced by the real PuTTYgen and proves the result works with OpenSSH.
@Suite("PuTTYgen compatibility", .enabled(if: puttygenPath != nil))
struct PuTTYgenCompatibilityTests {
    static let variants: [[String]] = [
        ["-t", "ed25519"],
        ["-t", "ed25519", "--ppk-param", "version=2"],
        ["-t", "rsa", "-b", "2048"],
        ["-t", "ecdsa", "-b", "256"],
    ]

    private func run(_ executable: String, _ arguments: [String], input: String? = nil) async throws -> ToolResult {
        try await ProcessExecutor().execute(ToolInvocation(
            executable: URL(fileURLWithPath: executable),
            arguments: arguments,
            environment: ["PATH": "/usr/bin:/bin", "HOME": FileManager.default.temporaryDirectory.path],
            standardInput: input.map { SecureBytes(utf8: $0) },
            timeout: .seconds(60)
        )).requireSuccess()
    }

    @Test(arguments: PuTTYgenCompatibilityTests.variants)
    func convertedKeysWorkWithOpenSSH(arguments: [String]) async throws {
        let puttygen = try #require(puttygenPath)
        let home = try TestHome()
        let ppk = home.root.appending(path: "key.ppk")
        let generateArguments = arguments + ["-C", "from-puttygen", "-o", ppk.path, "--new-passphrase", "/dev/null"]
        _ = try await run(puttygen, generateArguments)
        let expectedPublic = try await run(puttygen, [ppk.path, "-L"]).standardOutputString

        let converted = try PuTTYKeyConverter.convert(SecureFileReader.read(ppk, maxBytes: 64 * 1024))
        let keyURL = home.ssh.appending(path: "converted")
        try converted.withUnsafeBytes { try SecureDelete.createFile(at: keyURL, contents: $0, mode: 0o600) }

        // OpenSSH derives the same public key …
        let derived = try await run("/usr/bin/ssh-keygen", ["-y", "-P", "", "-f", keyURL.path])
            .standardOutputString
        #expect(try SSHPublicKey(line: derived).blob == SSHPublicKey(line: expectedPublic).blob)

        // … and the private half really works: sign with it and verify the signature.
        let message = home.root.appending(path: "message.txt")
        try Data("hello".utf8).write(to: message)
        _ = try await run("/usr/bin/ssh-keygen", ["-Y", "sign", "-f", keyURL.path, "-n", "smp-test", message.path])
        _ = try await run(
            "/usr/bin/ssh-keygen",
            ["-Y", "check-novalidate", "-n", "smp-test", "-s", message.path + ".sig"],
            input: "hello"
        )
    }
}

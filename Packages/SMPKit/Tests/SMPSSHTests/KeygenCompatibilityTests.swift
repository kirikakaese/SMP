import Foundation
import SMPCore
import Testing

@testable import SMPSSH

/// Checks SMP's own parsing against the real `/usr/bin/ssh-keygen`, in a temporary HOME.
@Suite(
    "ssh-keygen compatibility",
    .enabled(if: FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-keygen"))
)
struct KeygenCompatibilityTests {
    static let keyTypes: [[String]] = [
        ["-t", "ed25519"],
        ["-t", "ecdsa", "-b", "256"],
        ["-t", "ecdsa", "-b", "521"],
        ["-t", "rsa", "-b", "3072"],
    ]

    @Test(arguments: KeygenCompatibilityTests.keyTypes)
    func fingerprintsAndRandomartMatchSSHKeygen(typeArguments: [String]) async throws {
        let home = try TemporaryHome()
        let runner = SSHToolRunner(environment: home.environment)
        let keyPath = home.url.appending(path: ".ssh/compat_key").path
        try await runner
            .run(.sshKeygen, arguments: typeArguments + ["-N", "", "-C", "compat", "-f", keyPath])
            .requireSuccess()

        let publicKey = try SSHPublicKey(line: String(contentsOfFile: keyPath + ".pub", encoding: .utf8))

        // `ssh-keygen -lv` prints "<bits> <fingerprint> <comment> (<TYPE>)" followed by the randomart.
        let output = try await runner
            .run(.sshKeygen, arguments: ["-l", "-v", "-E", "sha256", "-f", keyPath + ".pub"])
            .requireSuccess()
            .standardOutputString
        let lines = output.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let summary = lines[0].split(separator: " ").map(String.init)
        #expect(summary[0] == publicKey.bitLength.map(String.init))
        #expect(summary[1] == publicKey.fingerprintSHA256)
        #expect(summary.last == "(\(publicKey.algorithm.openSSHTypeLabel))")
        #expect(Array(lines[1...11]).joined(separator: "\n") == Randomart.render(publicKey))

        let md5 = try await runner
            .run(.sshKeygen, arguments: ["-l", "-E", "md5", "-f", keyPath + ".pub"])
            .requireSuccess()
            .standardOutputString
        #expect(md5.split(separator: " ")[1] == publicKey.fingerprintMD5)

        // The private key's embedded public key is the same key.
        let info = try #require(try PrivateKeyInspector.inspect(fileAt: URL(fileURLWithPath: keyPath)))
        #expect(info.format == .openSSH)
        #expect(info.isEncrypted == false)
        #expect(info.embeddedPublicKey?.fingerprintSHA256 == publicKey.fingerprintSHA256)
    }

    @Test func detectsEncryptionOfRealKeys() async throws {
        let home = try TemporaryHome()
        let runner = SSHToolRunner(environment: home.environment)
        let keyPath = home.url.appending(path: ".ssh/encrypted_key").path
        let passphrase = SecureBytes(utf8: "a long test passphrase")
        try await runner.run(
            .sshKeygen,
            arguments: ["-t", "ed25519", "-a", "32", "-f", keyPath],
            options: ToolRunOptions(passphrases: [passphrase, passphrase])
        ).requireSuccess()

        let info = try #require(try PrivateKeyInspector.inspect(fileAt: URL(fileURLWithPath: keyPath)))
        #expect(info.isEncrypted == true)
        #expect(info.kdfRounds == 32)
        let publicKey = try SSHPublicKey(line: String(contentsOfFile: keyPath + ".pub", encoding: .utf8))
        #expect(info.embeddedPublicKey?.fingerprintSHA256 == publicKey.fingerprintSHA256)
    }
}

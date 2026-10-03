import Foundation
import SMPCore
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

/// End-to-end key operations against the real `/usr/bin/ssh-keygen` in a temporary HOME.
@Suite(
    "KeyService (ssh-keygen)",
    .enabled(if: FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-keygen"))
)
struct KeyServiceTests {
    struct Fixture {
        let home: TestHome
        let service: KeyService
        let archive: ArchiveService
        let runner: SSHToolRunner

        init() throws {
            home = try TestHome()
            runner = SSHToolRunner(environment: home.environment)
            archive = ArchiveService(
                directory: home.support.appending(path: "Archive"),
                keychain: InMemoryKeychainService()
            )
            service = KeyService(
                runner: runner,
                environment: home.environment,
                config: home.config,
                archive: archive,
                agent: AgentService(runner: runner)
            )
        }

        @discardableResult
        func generate(
            _ name: String,
            comment: String = "",
            passphrase: String? = nil
        ) async throws -> KeyOperationResult {
            try await service.generate(KeyGenerationRequest(
                fileName: name,
                directory: home.ssh,
                comment: comment,
                passphrase: passphrase.map { SecureBytes(utf8: $0) }
            ))
        }

        func key(_ name: String) throws -> DiscoveredKey {
            try #require(try KeyDiscoveryService().scan(directory: home.ssh).first { $0.name == name })
        }

        func mode(_ name: String) throws -> Int? {
            let attributes = try FileManager.default.attributesOfItem(atPath: home.ssh.appending(path: name).path)
            return (attributes[.posixPermissions] as? NSNumber)?.intValue
        }

        func info(_ name: String) throws -> PrivateKeyInfo? {
            try PrivateKeyInspector.inspect(fileAt: home.ssh.appending(path: name))
        }
    }

    static let passphrase = "a reasonably long test passphrase"

    // MARK: Generate

    @Test func generatesEncryptedKeyWithCorrectPermissions() async throws {
        let fixture = try Fixture()
        let result = try await fixture.service.generate(KeyGenerationRequest(
            fileName: "id_ed25519",
            directory: fixture.home.ssh,
            comment: "test@smp",
            passphrase: SecureBytes(utf8: Self.passphrase),
            kdfRounds: 32
        ))
        #expect(result.publicKey.algorithm == .ed25519)
        #expect(result.publicKey.comment == "test@smp")
        #expect(try fixture.mode("id_ed25519") == 0o600)
        #expect(try fixture.mode("id_ed25519.pub") == 0o644)
        let info = try #require(try fixture.info("id_ed25519"))
        #expect(info.isEncrypted == true)
        #expect(info.kdfRounds == 32)
        // No staging folders are left behind.
        let names = try FileManager.default.contentsOfDirectory(atPath: fixture.home.ssh.path)
        #expect(names.filter { $0.hasPrefix(".") }.isEmpty)
    }

    @Test(arguments: [KeyGenerationRequest.KeyType.ecdsa(bits: 384), .rsa(bits: 3072)])
    func generatesOtherTypesWithoutPassphrase(type: KeyGenerationRequest.KeyType) async throws {
        let fixture = try Fixture()
        let result = try await fixture.service.generate(KeyGenerationRequest(
            type: type, fileName: "other", directory: fixture.home.ssh, comment: ""
        ))
        #expect(result.publicKey.bitLength == (type == .rsa(bits: 3072) ? 3072 : 384))
        #expect(try fixture.info("other")?.isEncrypted == false)
    }

    @Test func rejectsWeakRSAAndBadNames() async throws {
        let fixture = try Fixture()
        let weak = await asyncErrorCode {
            _ = try await fixture.service.generate(KeyGenerationRequest(
                type: .rsa(bits: 2048), fileName: "weak", directory: fixture.home.ssh, comment: ""
            ))
        }
        #expect(weak == .invalidArgument)
        let badName = await asyncErrorCode {
            _ = try await fixture.service.generate(KeyGenerationRequest(
                fileName: "../escape", directory: fixture.home.ssh, comment: ""
            ))
        }
        #expect(badName == .invalidArgument)
    }

    @Test func neverOverwritesWithoutConfirmationAndArchivesOnReplace() async throws {
        let fixture = try Fixture()
        let request = KeyGenerationRequest(fileName: "dup", directory: fixture.home.ssh, comment: "first")
        let first = try await fixture.service.generate(request)
        let again = await asyncErrorCode { _ = try await fixture.service.generate(request) }
        #expect(again == .alreadyExists)

        var replace = request
        replace.comment = "second"
        replace.replaceExisting = true
        let second = try await fixture.service.generate(replace)
        #expect(second.replacedKey?.fingerprint == first.publicKey.fingerprintSHA256)
        #expect(try fixture.archive.list().count == 1)
        #expect(try fixture.key("dup").comment == "second")
    }

    // MARK: Import

    @Test func importsOpenSSHAndPuTTYKeys() async throws {
        let fixture = try Fixture()
        let openSSH = try await fixture.service.importKey(KeyImportRequest(
            contents: SecureBytes(utf8: Fixtures.ed25519Private),
            fileName: "imported",
            directory: fixture.home.ssh,
            comment: "from fixture"
        ))
        #expect(openSSH.publicKey.fingerprintSHA256 == Fixtures.expectedFingerprints["ed25519Public"]?.sha256)
        #expect(try fixture.mode("imported") == 0o600)

        let putty = try await fixture.service.importKey(KeyImportRequest(
            contents: SecureBytes(utf8: Fixtures.rsa2048PuTTYv2),
            fileName: "from_putty",
            directory: fixture.home.ssh
        ))
        #expect(putty.publicKey.fingerprintSHA256 == Fixtures.expectedFingerprints["rsa2048Public"]?.sha256)
        #expect(putty.publicKey.comment == "putty-rsa")
        #expect(try fixture.info("from_putty")?.format == .openSSH)
    }

    @Test func importsEncryptedPEMOnlyWithCorrectPassphrase() async throws {
        let fixture = try Fixture()
        func request(_ passphrase: String?) -> KeyImportRequest {
            KeyImportRequest(
                contents: SecureBytes(utf8: Fixtures.rsa2048PEMEncryptedPrivate),
                fileName: "legacy",
                directory: fixture.home.ssh,
                passphrase: passphrase.map { SecureBytes(utf8: $0) }
            )
        }
        let missing = await asyncErrorCode { _ = try await fixture.service.importKey(request(nil)) }
        #expect(missing == .passphraseRequired)
        let wrong = await asyncErrorCode { _ = try await fixture.service.importKey(request("wrong")) }
        #expect(wrong == .passphraseRequired)
        #expect(!FileManager.default.fileExists(atPath: fixture.home.ssh.appending(path: "legacy").path))

        let result = try await fixture.service.importKey(request("pw"))
        #expect(result.publicKey.fingerprintSHA256 == Fixtures.expectedFingerprints["rsa2048Public"]?.sha256)
        #expect(try fixture.info("legacy")?.format == .pem)
    }

    @Test func importsPublicKeysAndRejectsGarbage() async throws {
        let fixture = try Fixture()
        let result = try await fixture.service.importKey(KeyImportRequest(
            contents: SecureBytes(utf8: Fixtures.ecdsaP256Public),
            fileName: "partner",
            directory: fixture.home.ssh
        ))
        #expect(result.privateKeyURL == nil)
        #expect(try fixture.home.read("partner.pub").hasPrefix("ecdsa-sha2-nistp256 "))

        let garbage = await asyncErrorCode {
            _ = try await fixture.service.importKey(KeyImportRequest(
                contents: SecureBytes(utf8: "hello world"),
                fileName: "garbage",
                directory: fixture.home.ssh
            ))
        }
        #expect(garbage == .keyOperationFailed)
    }

    // MARK: Edit

    @Test func renamesFilesAndConfigReferences() async throws {
        let fixture = try Fixture()
        try await fixture.generate("old")
        try fixture.home.write("config", "Host srv\n  IdentityFile ~/.ssh/old\n")

        let result = try await fixture.service.rename(try fixture.key("old"), to: "new", updateConfig: true)
        #expect(result.updatedConfigReferences == 1)
        #expect(FileManager.default.fileExists(atPath: fixture.home.ssh.appending(path: "new").path))
        #expect(FileManager.default.fileExists(atPath: fixture.home.ssh.appending(path: "new.pub").path))
        #expect(!FileManager.default.fileExists(atPath: fixture.home.ssh.appending(path: "old").path))
        #expect(try fixture.home.read("config") == "Host srv\n  IdentityFile ~/.ssh/new\n")
    }

    @Test func changesPassphraseAndVerifiesTheResult() async throws {
        let fixture = try Fixture()
        try await fixture.generate("k")

        // Add a passphrase.
        try await fixture.service.changePassphrase(
            of: try fixture.key("k"), current: nil, new: SecureBytes(utf8: Self.passphrase), kdfRounds: 16
        )
        #expect(try fixture.info("k")?.isEncrypted == true)

        // Wrong current passphrase is rejected and leaves the key unchanged.
        let wrong = await asyncErrorCode {
            try await fixture.service.changePassphrase(
                of: try fixture.key("k"),
                current: SecureBytes(utf8: "nope"),
                new: SecureBytes(utf8: "x y z w"),
                kdfRounds: 16
            )
        }
        #expect(wrong == .passphraseRequired)
        #expect(try fixture.info("k")?.isEncrypted == true)

        // Remove it again.
        try await fixture.service.changePassphrase(
            of: try fixture.key("k"), current: SecureBytes(utf8: Self.passphrase), new: nil, kdfRounds: 16
        )
        #expect(try fixture.info("k")?.isEncrypted == false)
    }

    @Test func changesCommentInBothFiles() async throws {
        let fixture = try Fixture()
        try await fixture.generate("c", comment: "before", passphrase: Self.passphrase)
        try await fixture.service.changeComment(
            of: try fixture.key("c"), to: "after", passphrase: SecureBytes(utf8: Self.passphrase)
        )
        #expect(try fixture.home.read("c.pub").hasSuffix(" after\n"))
        #expect(try fixture.info("c")?.isEncrypted == true)
    }

    @Test func upgradesLegacyFormatKeepingThePassphrase() async throws {
        let fixture = try Fixture()
        try fixture.home.write("legacy", Fixtures.rsa2048PEMEncryptedPrivate)
        try fixture.home.write("legacy.pub", Fixtures.rsa2048Public + "\n", mode: 0o644)
        try await fixture.service.upgradeFormat(of: try fixture.key("legacy"), passphrase: SecureBytes(utf8: "pw"))
        let info = try #require(try fixture.info("legacy"))
        #expect(info.format == .openSSH)
        #expect(info.isEncrypted == true)
        #expect(info.embeddedPublicKey?.fingerprintSHA256 == Fixtures.expectedFingerprints["rsa2048Public"]?.sha256)
    }

    // MARK: Impact, delete, export

    @Test func reportsImpactAndDeletesWithConfigCleanup() async throws {
        let fixture = try Fixture()
        try await fixture.generate("gone")
        try fixture.home.write("config", "Host a\n  IdentityFile ~/.ssh/gone\nHost b\n  IdentityFile ~/.ssh/gone.pub\n")
        let gitconfig = fixture.home.home.appending(path: ".gitconfig")
        try Data("[user]\n\tsigningkey = ~/.ssh/gone.pub\n".utf8).write(to: gitconfig)

        let key = try fixture.key("gone")
        let report = try await fixture.service.impactReport(for: key, isLoadedInAgent: false)
        #expect(report.configReferences.count == 2)
        #expect(report.gitSigningReferences.count == 1)
        #expect(!report.isEmpty)

        try await fixture.service.deletePermanently(
            key,
            configEdits: [.commentOut(report.configReferences[0]), .remove(report.configReferences[1])]
        )
        #expect(!FileManager.default.fileExists(atPath: fixture.home.ssh.appending(path: "gone").path))
        #expect(!FileManager.default.fileExists(atPath: fixture.home.ssh.appending(path: "gone.pub").path))
        #expect(try fixture.home.read("config") == "Host a\n  # IdentityFile ~/.ssh/gone\nHost b\n")
    }

    @Test func exportsPrivateKeyWithPrivatePermissions() async throws {
        let fixture = try Fixture()
        try await fixture.generate("e")
        let destination = fixture.home.root.appending(path: "export_e")
        try fixture.service.exportPrivateKey(try fixture.key("e"), to: destination)
        let attributes = try FileManager.default.attributesOfItem(atPath: destination.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(try Data(contentsOf: destination) == Data(contentsOf: fixture.home.ssh.appending(path: "e")))
    }
}

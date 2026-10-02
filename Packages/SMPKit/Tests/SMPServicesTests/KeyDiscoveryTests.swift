import Foundation
import SMPCore
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

/// A temporary folder that plays the role of `~/.ssh` in discovery tests.
final class TemporaryKeyFolder: Sendable {
    let url: URL

    init(mode: Int = 0o700) throws {
        url = FileManager.default.temporaryDirectory
            .appending(path: "smp-keys-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }

    deinit {
        try? FileManager.default.removeItem(at: url)
    }

    @discardableResult
    func write(_ name: String, _ contents: String, mode: Int = 0o600) throws -> URL {
        let file = url.appending(path: name)
        try Data(contents.utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: file.path)
        return file
    }
}

@Suite("KeyDiscoveryService")
struct KeyDiscoveryTests {
    let service = KeyDiscoveryService()

    @Test func pairsPrivateAndPublicKeys() async throws {
        let folder = try TemporaryKeyFolder()
        try folder.write("id_ed25519", Fixtures.ed25519Private)
        try folder.write("id_ed25519.pub", Fixtures.ed25519Public, mode: 0o644)

        let keys = try await service.discoverKeys(in: [folder.url])
        #expect(keys.count == 1)
        let key = try #require(keys.first)
        #expect(key.name == "id_ed25519")
        #expect(key.kind == .pair)
        #expect(key.algorithm == .ed25519)
        #expect(key.comment == "alice@example.com")
        #expect(key.isPassphraseProtected == false)
        #expect(key.fingerprint == Fixtures.expectedFingerprints["ed25519Public"]?.sha256)
        #expect(key.issues == [.noPassphrase])
        #expect(key.privateKeyFile?.permissions == 0o600)
    }

    @Test func encryptedKeyWithCertificateHasNoIssues() async throws {
        let folder = try TemporaryKeyFolder()
        try folder.write("work", Fixtures.ed25519EncryptedPrivate)
        try folder.write("work.pub", Fixtures.ed25519EncryptedPublic, mode: 0o644)
        try folder.write("work-cert.pub", Fixtures.ed25519Certificate, mode: 0o644)

        let key = try #require(try await service.discoverKeys(in: [folder.url]).first)
        #expect(key.isPassphraseProtected == true)
        #expect(key.certificate?.isCertificate == true)
        #expect(key.certificateFile != nil)
        #expect(key.issues.isEmpty)
    }

    @Test func findsPrivateOnlyAndOrphanedPublicKeys() async throws {
        let folder = try TemporaryKeyFolder()
        try folder.write("lonely", Fixtures.ed25519Private)
        try folder.write("orphan.pub", Fixtures.rsa3072Public, mode: 0o644)

        let keys = try await service.discoverKeys(in: [folder.url])
        let lonely = try #require(keys.first { $0.name == "lonely" })
        #expect(lonely.kind == .privateOnly)
        #expect(lonely.publicKey != nil, "the public key is read from the private key header")
        let orphan = try #require(keys.first { $0.name == "orphan" })
        #expect(orphan.kind == .publicOnly)
        #expect(orphan.issues.contains(.orphanedPublicKey))
    }

    @Test func flagsPermissionsWeakKeysAndLegacyFormats() async throws {
        let folder = try TemporaryKeyFolder(mode: 0o755)
        try folder.write("open_key", Fixtures.ed25519Private, mode: 0o644)
        try folder.write("legacy_rsa", Fixtures.rsa2048PEMEncryptedPrivate)
        try folder.write("legacy_rsa.pub", Fixtures.rsa2048Public, mode: 0o666)
        try folder.write("old_dsa.pub", Fixtures.dsaPublic, mode: 0o644)

        let keys = try await service.discoverKeys(in: [folder.url])
        let open = try #require(keys.first { $0.name == "open_key" })
        #expect(open.issues.contains(.privateKeyPermissionsTooOpen(0o644)))
        #expect(open.issues.contains(.directoryPermissionsTooOpen(0o755)))

        let legacy = try #require(keys.first { $0.name == "legacy_rsa" })
        #expect(legacy.issues.contains(.legacyFormat(.pem)))
        #expect(legacy.issues.contains(.publicKeyWritableByOthers(0o666)))
        #expect(legacy.issues.contains { if case .weakAlgorithm = $0 { true } else { false } })
        #expect(!legacy.issues.contains(.noPassphrase))
        #expect(legacy.publicKey?.bitLength == 2048, "PEM keys take their public key from the .pub file")

        let dsa = try #require(keys.first { $0.name == "old_dsa" })
        #expect(dsa.issues.contains { if case .weakAlgorithm = $0 { true } else { false } })
    }

    @Test func detectsMismatchedPublicKey() async throws {
        let folder = try TemporaryKeyFolder()
        try folder.write("mixed", Fixtures.ed25519Private)
        try folder.write("mixed.pub", Fixtures.ed25519EncryptedPublic, mode: 0o644)

        let key = try #require(try await service.discoverKeys(in: [folder.url]).first)
        #expect(key.issues.contains(.publicKeyMismatch))
        // The private key's own public half wins.
        #expect(key.fingerprint == Fixtures.expectedFingerprints["ed25519Public"]?.sha256)
    }

    @Test func ignoresNonKeyFiles() async throws {
        let folder = try TemporaryKeyFolder()
        try folder.write("config", "Host *\n  AddKeysToAgent yes\n")
        try folder.write("known_hosts", "example.com \(Fixtures.ed25519Public)\n")
        try folder.write("notes.txt", "just some text\n")
        try folder.write("empty", "")
        let socketsFolder = folder.url.appending(path: "sockets")
        try FileManager.default.createDirectory(at: socketsFolder, withIntermediateDirectories: true)

        #expect(try await service.discoverKeys(in: [folder.url]).isEmpty)
    }

    @Test func scansSeveralFoldersOnceEach() async throws {
        let first = try TemporaryKeyFolder()
        let second = try TemporaryKeyFolder()
        try first.write("a.pub", Fixtures.ed25519Public, mode: 0o644)
        try second.write("b.pub", Fixtures.ecdsaP256Public, mode: 0o644)

        let keys = try await service.discoverKeys(in: [first.url, second.url, first.url])
        #expect(keys.map(\.name) == ["a", "b"])
    }

    @Test func missingFolderYieldsNoKeys() async throws {
        let missing = FileManager.default.temporaryDirectory.appending(path: "smp-missing-\(UUID().uuidString)")
        #expect(try await service.discoverKeys(in: [missing]).isEmpty)
    }

    @Test func symbolicPermissions() {
        let info = KeyFileInfo(
            url: URL(fileURLWithPath: "/x"), permissions: 0o640, isOwnedByCurrentUser: true,
            isSymbolicLink: false, size: 1, createdAt: nil, modifiedAt: nil
        )
        #expect(info.symbolicPermissions == "rw-r-----")
    }
}

@Suite("AgentService")
struct AgentServiceTests {
    @Test func parsesFingerprintsFromSSHAddOutput() {
        let output = """
            256 SHA256:AAAAbbbbCCCC alice@example.com (ED25519)
            3072 SHA256:ZZZZyyyy+/xx work key with spaces (RSA)
            The agent has no identities.
            """
        #expect(AgentService.parseFingerprints(output) == ["SHA256:AAAAbbbbCCCC", "SHA256:ZZZZyyyy+/xx"])
    }

    @Test func reportsUnavailableAgentWithoutSocket() async {
        let environment = SSHEnvironment(
            homeDirectory: FileManager.default.temporaryDirectory,
            userName: "test",
            agentSocketPath: "/nonexistent/agent.sock"
        )
        let status = await AgentService(runner: SSHToolRunner(environment: environment)).status()
        #expect(status == .unavailable)
    }
}

@Suite("FileWatcherService")
struct FileWatcherTests {
    @Test(.timeLimit(.minutes(1)))
    func reportsChangesInWatchedFolder() async throws {
        let folder = try TemporaryKeyFolder()
        let stream = FileWatcherService(latency: 0.1).changes(in: [folder.url])

        // Keep changing the folder until the watcher reports something.
        let writer = Task {
            for attempt in 0..<40 where !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(250))
                try? folder.write("file-\(attempt).pub", Fixtures.ed25519Public, mode: 0o644)
            }
        }
        defer { writer.cancel() }

        var iterator = stream.makeAsyncIterator()
        let event: Void? = await iterator.next()
        #expect(event != nil)
    }
}

@Suite("KeyFolderSettings")
struct KeyFolderSettingsTests {
    @Test func storesUniqueStandardizedFolders() throws {
        let suite = "smp-tests-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        KeyFolderSettings.setAdditionalFolders(
            [URL(fileURLWithPath: "/tmp/a/../keys"), URL(fileURLWithPath: "/tmp/keys")],
            in: defaults
        )
        #expect(KeyFolderSettings.additionalFolders(in: defaults).map(\.path) == ["/tmp/keys"])

        let environment = SSHEnvironment(homeDirectory: URL(fileURLWithPath: "/Users/test"), userName: "test")
        #expect(KeyFolderSettings.allFolders(environment: environment, defaults: defaults).map(\.path)
            == ["/Users/test/.ssh", "/tmp/keys"])
    }
}

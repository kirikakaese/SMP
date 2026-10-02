import Foundation
import SMPCore
import SMPPersistence
import SMPServices
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPUI

private func makeKey(
    _ name: String,
    line: String,
    kind: DiscoveredKey.Kind = .pair,
    issues: [KeyIssue] = []
) throws -> DiscoveredKey {
    let file = KeyFileInfo(
        url: URL(fileURLWithPath: "/keys/\(name)"), permissions: 0o600, isOwnedByCurrentUser: true,
        isSymbolicLink: false, size: 100, createdAt: nil, modifiedAt: nil
    )
    return DiscoveredKey(
        name: name, kind: kind, publicKey: try SSHPublicKey(line: line),
        privateKeyFile: kind == .publicOnly ? nil : file, privateKeyInfo: nil,
        publicKeyFile: file, certificateFile: nil, certificate: nil, issues: issues
    )
}

@Suite("LibraryModel filtering")
struct LibraryFilterTests {
    let work = KeyTag(id: 1, name: "work", color: .blue)

    func items() throws -> [LibraryItem] {
        [
            LibraryItem(
                key: try makeKey("id_ed25519", line: Fixtures.ed25519Public),
                metadata: KeyMetadata(fingerprint: "a", isFavorite: true),
                tagIDs: [1],
                isLoadedInAgent: true
            ),
            LibraryItem(
                key: try makeKey("old_rsa", line: Fixtures.rsa2048Public, issues: [.noPassphrase]),
                groupIDs: [7]
            ),
            LibraryItem(key: try makeKey("yubikey", line: Fixtures.ed25519SKPublic)),
            LibraryItem(
                key: try makeKey("retired", line: Fixtures.ecdsaP256Public),
                metadata: KeyMetadata(fingerprint: "d", archivedAt: Date())
            ),
        ]
    }

    private func names(_ selection: SidebarSelection?, search: String = "") throws -> [String] {
        LibraryModel.filter(try items(), selection: selection, searchText: search, tags: [work]).map(\.key.name)
    }

    @Test func librarySections() throws {
        #expect(try names(.library(.allKeys)) == ["id_ed25519", "old_rsa", "yubikey"])
        #expect(try names(.library(.favorites)) == ["id_ed25519"])
        #expect(try names(.library(.hardware)) == ["yubikey"])
        #expect(try names(.library(.loadedInAgent)) == ["id_ed25519"])
        #expect(try names(.library(.needsAttention)) == ["old_rsa"])
        #expect(try names(.library(.archived)) == ["retired"])
        #expect(try names(.library(.secureEnclave)).isEmpty)
    }

    @Test func tagsAndGroups() throws {
        #expect(try names(.tag(1)) == ["id_ed25519"])
        #expect(try names(.group(7)) == ["old_rsa"])
    }

    @Test func searchMatchesNameCommentFingerprintTypeAndTag() throws {
        let fingerprint = try #require(Fixtures.expectedFingerprints["rsa2048Public"]?.sha256)
        #expect(try names(.library(.allKeys), search: "ALICE@") == ["id_ed25519"])
        #expect(try names(.library(.allKeys), search: String(fingerprint.prefix(15))) == ["old_rsa"])
        #expect(try names(.library(.allKeys), search: "ed25519-sk") == ["yubikey"])
        #expect(try names(.library(.allKeys), search: "work") == ["id_ed25519"])
        #expect(try names(.library(.allKeys), search: "no such key").isEmpty)
    }

    @Test func sortsByTypeThenName() throws {
        let sorted = LibraryModel.sorted(try items(), by: .type).map(\.key.name)
        #expect(sorted == ["retired", "id_ed25519", "yubikey", "old_rsa"])
    }

    @Test func expiredKeysNeedAttention() throws {
        let item = LibraryItem(
            key: try makeKey("expiring", line: Fixtures.ed25519Public),
            metadata: KeyMetadata(fingerprint: "x", expiresAt: Date(timeIntervalSinceNow: -60))
        )
        #expect(item.isExpired())
        #expect(item.needsAttention)
    }
}

@Suite("LibraryModel loading")
@MainActor
struct LibraryModelLoadingTests {
    private func makeModel(home: URL) throws -> LibraryModel {
        let environment = SSHEnvironment(homeDirectory: home, userName: "test", agentSocketPath: "/nonexistent.sock")
        let runner = SSHToolRunner(environment: environment)
        let services = ServiceContainer(
            environment: environment,
            toolRunner: runner,
            keychain: InMemoryKeychainService(),
            keyDiscovery: KeyDiscoveryService(),
            agent: AgentService(runner: runner),
            metadata: try GRDBMetadataStore.inMemory(),
            fileWatcher: FileWatcherService()
        )
        let suite = "smp-ui-tests-\(UUID().uuidString)"
        return LibraryModel(services: services, defaults: UserDefaults(suiteName: suite) ?? .standard)
    }

    @Test func loadsKeysAndPersistsMetadataEdits() async throws {
        let home = FileManager.default.temporaryDirectory.appending(path: "smp-ui-home-\(UUID().uuidString)")
        let ssh = home.appending(path: ".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ssh.path)
        defer { try? FileManager.default.removeItem(at: home) }
        let privateKey = ssh.appending(path: "id_ed25519")
        try Data(Fixtures.ed25519EncryptedPrivate.utf8).write(to: privateKey)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: privateKey.path)
        try Data(Fixtures.ed25519EncryptedPublic.utf8).write(to: ssh.appending(path: "id_ed25519.pub"))

        let model = try makeModel(home: home)
        await model.reload()
        #expect(model.lastError == nil)
        #expect(model.items.count == 1)
        #expect(model.agentStatus == .unavailable)
        let item = try #require(model.items.first)

        model.setFavorite(true, for: item)
        let tag = try #require(model.createTag(named: "work", color: .green))
        model.toggleTag(tag.id, for: try #require(model.items.first))
        model.setNotes("Used for CI", for: try #require(model.items.first))

        await model.reload()
        let reloaded = try #require(model.items.first)
        #expect(reloaded.isFavorite)
        #expect(reloaded.tagIDs == [tag.id])
        #expect(reloaded.metadata?.notes == "Used for CI")

        model.sidebarSelection = .library(.favorites)
        #expect(model.visibleItems.count == 1)
        model.searchText = "nothing matches this"
        #expect(model.visibleItems.isEmpty)
    }
}

import Foundation
import SMPCore
import SMPPersistence
import SMPServices
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPUI

@MainActor
@Suite("Secure Enclave keys in the library")
struct SecureEnclaveLibraryTests {
    let home: URL
    let store = InMemorySecureEnclaveKeyStore()
    let services: ServiceContainer

    init() throws {
        home = FileManager.default.temporaryDirectory.appending(path: "smp-se-\(UUID().uuidString)")
        let ssh = home.appending(path: ".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ssh.path)
        services = ServiceContainer.make(
            environment: SSHEnvironment(homeDirectory: home, userName: "test", agentSocketPath: "/nonexistent.sock"),
            supportDirectory: home.appending(path: "support"),
            keychain: InMemoryKeychainService(),
            metadata: try GRDBMetadataStore.inMemory(),
            authenticator: FakeAuthenticator(),
            secureEnclave: store,
            agentHelper: FakeAgentHelper(status: .enabled, identities: 1)
        )
    }

    private func makeModel() -> LibraryModel {
        LibraryModel(services: services, defaults: UserDefaults(suiteName: "smp-se-\(UUID().uuidString)") ?? .standard)
    }

    @Test func createsKeysWithAPublicKeyFileAndShowsThemInTheirSection() async throws {
        defer { try? FileManager.default.removeItem(at: home) }
        let model = makeModel()
        try await model.createSecureEnclaveKey(
            name: "id_se", comment: "me (Secure Enclave)", policy: .everyUse, savePublicKey: true
        )
        let pub = home.appending(path: ".ssh/id_se.pub")
        let key = try #require(try store.keys().first)
        #expect(try String(contentsOf: pub, encoding: .utf8) == key.openSSHLine + "\n")

        let item = try #require(model.items.first { $0.isSecureEnclave })
        #expect(item.secureEnclave?.id == key.id)
        #expect(item.issues.isEmpty)  // No "orphaned public key" warning.
        #expect(!item.isVirtualSecureEnclaveEntry)
        #expect(model.selectedKeyIDs == [item.id])
        let enclaveItems = LibraryModel.filter(
            model.items, selection: .library(.secureEnclave), searchText: "", tags: []
        )
        #expect(enclaveItems.count == 1)

        // A second key with the same file name is refused before anything is created.
        await #expect(throws: SMPError.self) {
            try await model.createSecureEnclaveKey(name: "id_se", comment: "", policy: .everyUse, savePublicKey: true)
        }
        #expect(try store.keys().count == 1)
    }

    @Test func listsKeysWithoutPublicKeyFiles() async throws {
        defer { try? FileManager.default.removeItem(at: home) }
        let model = makeModel()
        try await model.createSecureEnclaveKey(
            name: "only-keychain", comment: "", policy: .notifyOnly, savePublicKey: false
        )
        let item = try #require(model.items.first)
        #expect(item.isVirtualSecureEnclaveEntry)
        #expect(item.displayName == "only-keychain")

        let export = home.appending(path: "exported.pub")
        try model.exportPublicKey(item, to: export)
        #expect(try String(contentsOf: export, encoding: .utf8).hasPrefix("ecdsa-sha2-nistp256 "))
    }

    @Test func keepsTheTouchIDRequirementFixed() async throws {
        defer { try? FileManager.default.removeItem(at: home) }
        let model = makeModel()
        try await model.createSecureEnclaveKey(name: "id_se", comment: "", policy: .everyUse, savePublicKey: false)
        let item = try #require(model.items.first)

        model.setSigningPolicy(.reuse(seconds: 300), for: item)
        #expect(try store.keys().first?.policy == .reuse(seconds: 300))
        #expect(model.items.first?.secureEnclave?.policy == .reuse(seconds: 300))

        model.setSigningPolicy(.notifyOnly, for: try #require(model.items.first))
        #expect(model.lastError?.code == .invalidArgument)
        #expect(try store.keys().first?.policy == .reuse(seconds: 300))
    }

    @Test func archivingSkipsAndDeletingRemovesSecureEnclaveKeys() async throws {
        defer { try? FileManager.default.removeItem(at: home) }
        let model = makeModel()
        try await model.createSecureEnclaveKey(name: "id_se", comment: "", policy: .everyUse, savePublicKey: true)
        let item = try #require(model.items.first)

        await model.archive([item], undoManager: nil)
        #expect(model.notice?.contains("cannot be archived") == true)
        #expect(try store.keys().count == 1)
        #expect(FileManager.default.fileExists(atPath: home.appending(path: ".ssh/id_se.pub").path))

        try await model.deletePermanently([try #require(model.items.first)], configEdits: [:])
        #expect(try store.keys().isEmpty)
        #expect(!FileManager.default.fileExists(atPath: home.appending(path: ".ssh/id_se.pub").path))
        #expect(model.items.isEmpty)
    }

    @Test func attachesKeysByFingerprint() throws {
        defer { try? FileManager.default.removeItem(at: home) }
        let key = try store.create(name: "laptop", comment: "", policy: .everyUse)
        let file = KeyFileInfo(
            url: URL(fileURLWithPath: "/keys/laptop.pub"), permissions: 0o644, isOwnedByCurrentUser: true,
            isSymbolicLink: false, size: 100, createdAt: nil, modifiedAt: nil
        )
        let onDisk = DiscoveredKey(
            name: "laptop", kind: .publicOnly, publicKey: try key.publicKey(), privateKeyFile: nil,
            privateKeyInfo: nil, publicKeyFile: file, certificateFile: nil, certificate: nil,
            issues: [.orphanedPublicKey]
        )
        let unrelated = DiscoveredKey(
            name: "other", kind: .publicOnly, publicKey: try SSHPublicKey(line: Fixtures.ed25519Public),
            privateKeyFile: nil, privateKeyInfo: nil, publicKeyFile: file, certificateFile: nil, certificate: nil,
            issues: [.orphanedPublicKey]
        )
        let items = LibraryModel.attachSecureEnclaveKeys(
            [key], to: [LibraryItem(key: onDisk), LibraryItem(key: unrelated)]
        )
        #expect(items.count == 2)
        #expect(items[0].isSecureEnclave && items[0].issues.isEmpty)
        #expect(!items[1].isSecureEnclave && items[1].issues == [.orphanedPublicKey])
    }
}

@MainActor
@Suite("AgentModel")
struct AgentModelTests {
    @Test func reportsHelperStateAndPersistsSettings() async throws {
        let home = FileManager.default.temporaryDirectory.appending(path: "smp-agent-ui-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home.appending(path: ".ssh"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let helper = FakeAgentHelper(identities: 3)
        let services = ServiceContainer.make(
            environment: SSHEnvironment(homeDirectory: home, userName: "test", agentSocketPath: "/nonexistent.sock"),
            supportDirectory: home.appending(path: "support"),
            keychain: InMemoryKeychainService(),
            metadata: try GRDBMetadataStore.inMemory(),
            authenticator: FakeAuthenticator(),
            agentHelper: helper
        )
        let suite = "smp-agent-model-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        // Outside the home folder, so the config line is an absolute path ssh prints unchanged.
        let socket = URL(fileURLWithPath: "/tmp/smp-agent-ui-\(UUID().uuidString.prefix(8)).sock")
        let model = AgentModel(services: services, defaults: defaults, socketURL: socket)

        await model.refresh()
        #expect(model.helperStatus == .notRegistered)
        #expect(model.identityCount == nil)
        #expect(model.isUsedBySSH == false)

        await model.enable()
        #expect(model.helperStatus == .enabled)
        #expect(model.identityCount == 3)

        model.settings.forwardedReuseSeconds = 300
        #expect(AgentSettings.load(from: defaults).forwardedReuseSeconds == 300)
        #expect(model.identityAgentValue == "\"\(socket.path)\"")

        // After the reviewed config change is saved, ssh -G resolves IdentityAgent to the socket.
        let hosts = HostsModel(services: services)
        model.proposeConfigChange(using: hosts)
        let change = try #require(hosts.pendingChange)
        #expect(change.newText == "Host *\n    IdentityAgent \"\(socket.path)\"\n")
        #expect(await hosts.applyPendingChange())
        await model.refresh()
        #expect(model.isUsedBySSH == true)
    }

    @Test func expandsTildeAndQuotes() {
        let home = URL(fileURLWithPath: "/Users/alice")
        #expect(AgentModel.expand("\"~/a b/agent.sock\"", home: home) == "/Users/alice/a b/agent.sock")
        #expect(AgentModel.expand("/tmp/agent.sock", home: home) == "/tmp/agent.sock")
    }
}

@MainActor
@Suite("HostsModel IdentityAgent proposal")
struct IdentityAgentProposalTests {
    @Test func reusesAnExistingCatchAllBlock() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: "smp-ia-\(UUID().uuidString)")
        let ssh = home.appending(path: ".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        try Data("Host web\n    User a\n\nHost *\n    ServerAliveInterval 30\n".utf8)
            .write(to: ssh.appending(path: "config"))
        let services = ServiceContainer.make(
            environment: SSHEnvironment(homeDirectory: home, userName: "test", agentSocketPath: "/nonexistent.sock"),
            supportDirectory: home.appending(path: "support"),
            keychain: InMemoryKeychainService(),
            metadata: try GRDBMetadataStore.inMemory(),
            authenticator: FakeAuthenticator()
        )
        let hosts = HostsModel(services: services)
        hosts.reload()
        hosts.proposeIdentityAgent("\"~/agent.sock\"")
        let change = try #require(hosts.pendingChange)
        #expect(change.newText
            == "Host web\n    User a\n\nHost *\n    ServerAliveInterval 30\n    IdentityAgent \"~/agent.sock\"\n")
    }
}

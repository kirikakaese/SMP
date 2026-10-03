import Foundation
import SMPCore
import SMPPersistence
import SMPProviders
import SMPServices
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPUI

/// A provider that holds keys in memory and can be told to fail.
private final class MemoryProvider: ProviderClientMaking, ProviderClient, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [RemoteKey] = []
    private var currentAccount = UUID()
    var fails = false

    func client(for account: ProviderAccount, token: SecureBytes) throws -> any ProviderClient {
        lock.withLock { currentAccount = account.id }
        return self
    }

    func currentUsername() async throws -> String { "alice" }

    func listKeys() async throws -> [RemoteKey] {
        if fails { throw SMPError(.network, whatHappened: "offline") }
        return lock.withLock { stored }
    }

    func addKey(title: String, publicKey: SSHPublicKey, usages: Set<RemoteKeyUsage>) async throws -> [RemoteKey] {
        lock.withLock {
            let key = RemoteKey(
                remoteID: String(stored.count + 1), accountID: currentAccount, title: title,
                publicKeyLine: publicKey.openSSHLine, fingerprint: publicKey.fingerprintSHA256, usages: usages
            )
            stored.append(key)
            return [key]
        }
    }

    func deleteKey(_ key: RemoteKey) async throws {
        lock.withLock { stored.removeAll { $0.remoteID == key.remoteID } }
    }
}

@MainActor
@Suite("ProvidersModel")
struct ProvidersModelTests {
    private let provider = MemoryProvider()

    private func makeServices(authenticates: Bool = true) throws -> ServiceContainer {
        let home = FileManager.default.temporaryDirectory.appending(path: "smp-providers-\(UUID().uuidString)")
        return ServiceContainer.make(
            environment: SSHEnvironment(homeDirectory: home, userName: "test", agentSocketPath: "/nonexistent.sock"),
            supportDirectory: home.appending(path: "support"),
            keychain: InMemoryKeychainService(),
            metadata: try GRDBMetadataStore.inMemory(),
            authenticator: FakeAuthenticator(succeeds: authenticates),
            providerClients: provider
        )
    }

    private func libraryItem() throws -> LibraryItem {
        let file = KeyFileInfo(
            url: URL(fileURLWithPath: "/keys/id_ed25519.pub"), permissions: 0o644, isOwnedByCurrentUser: true,
            isSymbolicLink: false, size: 100, createdAt: nil, modifiedAt: nil
        )
        let key = DiscoveredKey(
            name: "id_ed25519", kind: .publicOnly, publicKey: try SSHPublicKey(line: Fixtures.ed25519Public),
            privateKeyFile: nil, privateKeyInfo: nil, publicKeyFile: file, certificateFile: nil, certificate: nil,
            issues: []
        )
        return LibraryItem(key: key)
    }

    @Test func addsAccountsUploadsMatchesAndRemovesKeys() async throws {
        let model = ProvidersModel(services: try makeServices())
        let account = try await model.addAccount(
            kind: .github, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "token")
        )
        #expect(model.accounts == [account])

        let item = try libraryItem()
        try await model.upload(item, to: account, title: "Laptop", usages: [.authentication])
        let remote = model.remoteKeys(matching: item.key.fingerprint)
        #expect(remote.map(\.title) == ["Laptop"])
        #expect(model.keys(for: account).count == 1)

        model.selectedKeyID = remote.first?.id
        await model.delete(try #require(remote.first))
        #expect(model.keys.isEmpty)
        #expect(model.selectedKeyID == nil)
    }

    @Test func removalNeedsAuthentication() async throws {
        let model = ProvidersModel(services: try makeServices(authenticates: false))
        let account = try await model.addAccount(
            kind: .github, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "token")
        )
        try await model.upload(try libraryItem(), to: account, title: "Laptop", usages: [.authentication])
        await model.delete(try #require(model.keys.first))
        #expect(model.keys.count == 1)
        #expect(model.lastError?.code == .authenticationFailed)
    }

    @Test func refreshAllKeepsCachedKeysWhenOffline() async throws {
        let model = ProvidersModel(services: try makeServices())
        let account = try await model.addAccount(
            kind: .gitlab, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "token")
        )
        try await model.upload(try libraryItem(), to: account, title: "Laptop", usages: [.authentication])
        provider.fails = true
        await model.refreshAll()
        #expect(model.keys.count == 1)
        #expect(model.notice?.contains("Could not refresh") == true)
        #expect(model.lastError == nil)

        model.removeAccount(account)
        #expect(model.accounts.isEmpty)
        #expect(model.keys.isEmpty)
    }
}

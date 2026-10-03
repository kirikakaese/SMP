import Foundation
import SMPCore
import SMPPersistence
import SMPProviders
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

/// An in-memory provider: one user, a list of keys, and a record of the tokens it was given.
final class FakeProvider: ProviderClientMaking, ProviderClient, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [RemoteKey] = []
    private var tokens: [String] = []
    private var nextID = 1
    var username = "alice"
    var accountID = UUID()

    var seenTokens: [String] { lock.withLock { tokens } }
    var keys: [RemoteKey] { lock.withLock { stored } }

    func client(for account: ProviderAccount, token: SecureBytes) throws -> any ProviderClient {
        let text = token.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
        guard text != "bad" else { throw SMPError(.providerRejected, whatHappened: "rejected") }
        lock.withLock {
            tokens.append(text)
            accountID = account.id
        }
        return self
    }

    func currentUsername() async throws -> String { username }

    func listKeys() async throws -> [RemoteKey] { keys }

    func addKey(title: String, publicKey: SSHPublicKey, usages: Set<RemoteKeyUsage>) async throws -> [RemoteKey] {
        lock.withLock {
            let key = RemoteKey(
                remoteID: String(nextID), accountID: accountID, title: title, publicKeyLine: publicKey.openSSHLine,
                fingerprint: publicKey.fingerprintSHA256, usages: usages
            )
            nextID += 1
            stored.append(key)
            return [key]
        }
    }

    func deleteKey(_ key: RemoteKey) async throws {
        lock.withLock { stored.removeAll { $0.remoteID == key.remoteID } }
    }
}

@Suite("ProviderService")
struct ProviderServiceTests {
    let keychain = InMemoryKeychainService()
    let provider = FakeProvider()
    let service: ProviderService

    init() throws {
        service = ProviderService(keychain: keychain, metadata: try GRDBMetadataStore.inMemory(), factory: provider)
    }

    @Test func addsAccountsAfterCheckingTheToken() async throws {
        let account = try await service.addAccount(
            kind: .github, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "good")
        )
        #expect(account.username == "alice")
        #expect(account.serverURL.absoluteString == "https://github.com")
        #expect(try service.accounts() == [account])
        let stored = try #require(try keychain.secret(for: .providerToken(accountID: account.id.uuidString)))
        #expect(stored.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } == "good")

        // The same user cannot be added twice; a rejected token saves nothing.
        await #expect(throws: SMPError.self) {
            _ = try await service.addAccount(
                kind: .github, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "x")
            )
        }
        await #expect(throws: SMPError.self) {
            _ = try await service.addAccount(
                kind: .gitlab, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "bad")
            )
        }
        #expect(try service.accounts().count == 1)
    }

    @Test func uploadsRefreshesAndDeletes() async throws {
        let account = try await service.addAccount(
            kind: .gitlab, serverURL: URL(string: "https://GitLab.Example.com/"), loginEmail: nil,
            token: SecureBytes(utf8: "good")
        )
        #expect(account.serverURL.absoluteString == "https://gitlab.example.com")
        let key = try SSHPublicKey(line: Fixtures.ed25519Public)
        let added = try await service.upload(key, title: " Laptop ", usages: [.authentication], to: account)
        #expect(added.first?.title == "Laptop")
        #expect(try service.cachedKeys().map(\.fingerprint) == [key.fingerprintSHA256])
        #expect(try service.accounts().first?.lastSyncedAt != nil)

        try await service.delete(try #require(added.first), from: account)
        #expect(try service.cachedKeys().isEmpty)
        #expect(provider.seenTokens.allSatisfy { $0 == "good" })

        await #expect(throws: SMPError.self) {
            _ = try await service.upload(key, title: "two\nlines", usages: [.authentication], to: account)
        }
    }

    @Test func updatesTokensOnlyForTheSameUser() async throws {
        let account = try await service.addAccount(
            kind: .github, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "old")
        )
        try await service.updateToken(for: account, token: SecureBytes(utf8: "new"))
        _ = try await service.refresh(account)
        #expect(provider.seenTokens.last == "new")

        provider.username = "mallory"
        await #expect(throws: SMPError.self) {
            try await service.updateToken(for: account, token: SecureBytes(utf8: "other"))
        }
    }

    @Test func removingAnAccountForgetsTokenAndCache() async throws {
        let account = try await service.addAccount(
            kind: .github, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "good")
        )
        _ = try await service.upload(
            try SSHPublicKey(line: Fixtures.ed25519Public), title: "x", usages: [.authentication], to: account
        )
        try service.removeAccount(account)
        #expect(try service.accounts().isEmpty)
        #expect(try service.cachedKeys().isEmpty)
        #expect(try keychain.secret(for: .providerToken(accountID: account.id.uuidString)) == nil)
        // The key on the provider is untouched.
        #expect(provider.keys.count == 1)
        await #expect(throws: SMPError.self) { _ = try await service.refresh(account) }
    }

    @Test func normalizesServerAddresses() throws {
        #expect(try ProviderService.normalizedServer(URL(string: "https://Git.Example.com:8443/forgejo/"))
            .absoluteString == "https://git.example.com:8443/forgejo")
        #expect(throws: SMPError.self) {
            _ = try ProviderService.normalizedServer(URL(string: "http://git.example.com"))
        }
        #expect(throws: SMPError.self) { _ = try ProviderService.normalizedServer(nil) }
    }
}

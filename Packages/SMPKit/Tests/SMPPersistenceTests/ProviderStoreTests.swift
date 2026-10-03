import Foundation
import SMPCore
import SMPPersistence
import Testing

@Suite("GRDBMetadataStore provider accounts")
struct ProviderStoreTests {
    let store: GRDBMetadataStore

    init() throws {
        store = try GRDBMetadataStore.inMemory()
    }

    private func key(_ id: String, account: UUID, usages: Set<RemoteKeyUsage> = [.authentication]) -> RemoteKey {
        RemoteKey(
            remoteID: id, accountID: account, title: "key \(id)", publicKeyLine: "ssh-ed25519 AAAA",
            fingerprint: "SHA256:\(id)", usages: usages, createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
    }

    @Test func savesAccountsAndReplacesCachedKeys() throws {
        let github = ProviderAccount(
            kind: .github, serverURL: try #require(URL(string: "https://github.com")), username: "alice"
        )
        var bitbucket = ProviderAccount(
            kind: .bitbucket, serverURL: try #require(URL(string: "https://bitbucket.org")), username: "alice",
            loginEmail: "alice@example.com"
        )
        try store.saveProviderAccount(github)
        try store.saveProviderAccount(bitbucket)
        bitbucket.lastSyncedAt = Date(timeIntervalSince1970: 1_800_000_000)
        try store.saveProviderAccount(bitbucket)
        #expect(try store.allProviderAccounts() == [bitbucket, github])

        try store.replaceProviderKeys([key("1", account: github.id), key("2", account: github.id, usages: [.signing])],
                                      for: github.id)
        try store.replaceProviderKeys([key("3", account: bitbucket.id)], for: bitbucket.id)
        #expect(try store.providerKeys().count == 3)
        try store.replaceProviderKeys([key("4", account: github.id)], for: github.id)
        #expect(try Set(store.providerKeys().map(\.remoteID)) == ["3", "4"])
        #expect(try store.providerKeys().first { $0.remoteID == "4" } == key("4", account: github.id))

        try store.deleteProviderAccount(id: github.id)
        #expect(try store.allProviderAccounts() == [bitbucket])
        #expect(try store.providerKeys().map(\.remoteID) == ["3"])
    }
}

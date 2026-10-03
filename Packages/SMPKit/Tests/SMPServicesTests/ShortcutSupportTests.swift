import Foundation
import SMPCore
import SMPPersistence
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

@Suite("Shortcuts support")
struct ShortcutSupportTests {
    private func container(_ home: TestHome) throws -> ServiceContainer {
        ServiceContainer.make(
            environment: home.environment,
            supportDirectory: home.support,
            keychain: InMemoryKeychainService(),
            metadata: try GRDBMetadataStore.inMemory(),
            authenticator: FakeAuthenticator()
        )
    }

    private var defaults: UserDefaults {
        UserDefaults(suiteName: "smp-shortcuts-\(UUID().uuidString)") ?? .standard
    }

    @Test func listsKeysWithPublicDataOnly() async throws {
        let home = try TestHome()
        try home.write("work.pub", Fixtures.ed25519Public + "\n", mode: 0o644)
        try home.write("legacy.pub", Fixtures.rsa3072Public + "\n", mode: 0o644)
        let keys = try await container(home).shortcutKeys(defaults: defaults)

        #expect(keys.map(\.name) == ["legacy", "work"])
        let work = try #require(keys.last)
        #expect(work.type == "Ed25519")
        let expected = try SSHPublicKey(line: Fixtures.ed25519Public).openSSHLine
        #expect(work.publicKey == expected)
        #expect(work.fingerprint.hasPrefix("SHA256:"))
    }

    @Test func offersOnlyHostsThatCanBeConnectedTo() throws {
        let home = try TestHome()
        try home.write("config", """
            Host *
                ServerAliveInterval 30
            Host web db
                HostName example.com
            Host *.corp
                User me
            Host web
                Port 2222

            """)
        #expect(try container(home).shortcutHosts() == ["web"])
    }

    @Test func summarizesTheAudit() async throws {
        let home = try TestHome()
        try home.write("config", "Host *\n    StrictHostKeyChecking no\n")
        let summary = try await container(home).shortcutAudit(defaults: defaults)
        #expect(summary.findings == 1)
        #expect(summary.score < 100)
        #expect(summary.sentence.contains("1 finding"))
    }
}

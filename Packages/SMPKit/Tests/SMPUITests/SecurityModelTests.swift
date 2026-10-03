import Foundation
import SMPCore
import SMPPersistence
import SMPServices
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPUI

@MainActor
@Suite("SecurityModel")
struct SecurityModelTests {
    @Test func auditsTheLibraryAndFixesPermissions() async throws {
        let home = FileManager.default.temporaryDirectory.appending(path: "smp-security-\(UUID().uuidString)")
        let ssh = home.appending(path: ".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ssh.path)
        defer { try? FileManager.default.removeItem(at: home) }
        let privateKey = ssh.appending(path: "id_ed25519")
        try Data(Fixtures.ed25519EncryptedPrivate.utf8).write(to: privateKey)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: privateKey.path)
        try Data(Fixtures.ed25519EncryptedPublic.utf8).write(to: ssh.appending(path: "id_ed25519.pub"))
        try Data("Host *\n    ForwardAgent yes\n".utf8).write(to: ssh.appending(path: "config"))

        let services = ServiceContainer.make(
            environment: SSHEnvironment(homeDirectory: home, userName: "test", agentSocketPath: "/nonexistent.sock"),
            supportDirectory: home.appending(path: "support"),
            keychain: InMemoryKeychainService(),
            metadata: try GRDBMetadataStore.inMemory(),
            authenticator: FakeAuthenticator()
        )
        let defaults = UserDefaults(suiteName: "smp-sec-\(UUID())") ?? .standard
        let library = LibraryModel(services: services, defaults: defaults)
        let hosts = HostsModel(services: services)
        let security = SecurityModel(services: services)
        await library.reload()
        security.runAudit(library: library)
        #expect(Set(security.findings.map(\.rule)) == ["private-key-permissions", "forward-agent-everywhere"])
        #expect(security.score == 100 - 25 - 15)
        #expect(security.importantCount == 2)

        let permissions = try #require(security.findings.first { $0.rule == "private-key-permissions" })
        await security.fix(permissions, library: library, hosts: hosts)
        let mode = try FileManager.default.attributesOfItem(atPath: privateKey.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)
        #expect(security.findings.map(\.rule) == ["forward-agent-everywhere"])

        // Config fixes go through the reviewed diff.
        let forward = try #require(security.findings.first)
        await security.fix(forward, library: library, hosts: hosts)
        #expect(hosts.pendingChange?.newText == "Host *\n")
    }

    @Test func sharesExpiryAndRotationDatesWithTheAgent() throws {
        let file = KeyFileInfo(
            url: URL(fileURLWithPath: "/keys/a"), permissions: 0o600, isOwnedByCurrentUser: true,
            isSymbolicLink: false, size: 1, createdAt: nil, modifiedAt: nil
        )
        let key = DiscoveredKey(
            name: "a", kind: .pair, publicKey: try SSHPublicKey(line: Fixtures.ed25519Public), privateKeyFile: file,
            privateKeyInfo: nil, publicKeyFile: nil, certificateFile: nil, certificate: nil, issues: []
        )
        let expires = Date(timeIntervalSince1970: 1_900_000_000)
        let fingerprint = try #require(key.fingerprint)
        let items = [
            LibraryItem(
                key: key, metadata: KeyMetadata(fingerprint: fingerprint, expiresAt: expires, rotateAt: expires)
            ),
            LibraryItem(key: key, metadata: KeyMetadata(fingerprint: fingerprint, expiresAt: expires)),
        ]
        let schedule = LibraryModel.reminderSchedule(for: items)
        #expect(schedule.entries.map(\.kind) == [.expiry, .rotation])
        #expect(schedule.entries.allSatisfy { $0.keyName == "a" && $0.date == expires })
    }
}

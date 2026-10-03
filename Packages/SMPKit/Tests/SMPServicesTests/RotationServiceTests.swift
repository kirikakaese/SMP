import Foundation
import SMPCore
import SMPPersistence
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

/// Servers in memory: an authorized_keys list per alias.
final class FakeServers: DeployServicing, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: [String]] = [:]
    var failingAliases: Set<String> = []
    var verified: [String] = []

    func lines(on alias: String) -> [String] { lock.withLock { keys[alias] ?? [] } }

    func seed(_ line: String, on alias: String) {
        lock.withLock { keys[alias, default: []].append(line) }
    }

    func install(_ key: SSHPublicKey, on host: String, password: SecureBytes?) async throws -> DeployOutcome {
        try lock.withLock {
            if failingAliases.contains(host) { throw SMPError(.toolFailed, whatHappened: "unreachable") }
            keys[host, default: []].append(key.openSSHLine)
            return .added
        }
    }

    func authorizedKeys(on host: String, password: SecureBytes?) async throws -> [AuthorizedKeysEntry] {
        AuthorizedKeysEntry.parse(lines(on: host).joined(separator: "\n"))
    }

    func remove(_ entry: AuthorizedKeysEntry, from host: String, password: SecureBytes?) async throws {
        lock.withLock { keys[host]?.removeAll { $0 == entry.line } }
    }

    func verifyLogin(on host: String, keyFile: URL, passphrase: SecureBytes?) async -> ConnectionTestResult {
        lock.withLock { verified.append(host) }
        return .success("ok")
    }
}

@Suite("RotationService", .serialized)
struct RotationServiceTests {
    let home: TestHome
    let keys: KeyService
    let provider = FakeProvider()
    let providers: ProviderService
    let servers = FakeServers()
    let rotation: RotationService

    init() throws {
        home = try TestHome()
        let runner = SSHToolRunner(environment: home.environment)
        let archive = ArchiveService(
            directory: home.support.appending(path: "Archive"), keychain: InMemoryKeychainService()
        )
        keys = KeyService(
            runner: runner, environment: home.environment, config: home.config, archive: archive,
            agent: AgentService(runner: runner)
        )
        providers = ProviderService(
            keychain: InMemoryKeychainService(), metadata: try GRDBMetadataStore.inMemory(), factory: provider
        )
        rotation = RotationService(services: RotationDependencies(
            keys: keys, config: home.config, providers: providers, deploy: servers
        ))
    }

    private func oldKey() async throws -> DiscoveredKey {
        _ = try await keys.generate(KeyGenerationRequest(
            fileName: "id_ed25519", directory: home.ssh, comment: "me@laptop"
        ))
        let discovered = try await KeyDiscoveryService().discoverKeys(in: [home.ssh])
        return try #require(discovered.first { $0.name == "id_ed25519" })
    }

    @Test func plansFromConfigAndProviders() async throws {
        let old = try await oldKey()
        try home.write("config", """
            Host web db
                IdentityFile ~/.ssh/id_ed25519
            Host *.corp
                IdentityFile ~/.ssh/id_ed25519
            Host other
                IdentityFile ~/.ssh/id_other

            """)
        let account = try await providers.addAccount(
            kind: .github, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "t")
        )
        let publicKey = try #require(old.publicKey)
        _ = try await providers.upload(publicKey, title: "laptop", usages: [.authentication, .signing], to: account)

        let job = try rotation.plan(for: old)
        #expect(job.targets.map(\.label) == [account.displayName, "web", "db"])
        #expect(job.newKeyName.hasPrefix("id_ed25519_"))
        if case .provider(_, let usages, let ids) = job.targets[0].kind {
            #expect(usages == [.authentication, .signing])
            #expect(ids.count == 1)
        } else {
            Issue.record("Expected a provider target first")
        }
    }

    @Test func rotatesEndToEnd() async throws {
        let old = try await oldKey()
        let oldLine = try #require(old.publicKey).openSSHLine
        try home.write("config", "Host web\n    IdentityFile ~/.ssh/id_ed25519\n")
        servers.seed(oldLine, on: "web")
        let account = try await providers.addAccount(
            kind: .gitlab, serverURL: nil, loginEmail: nil, token: SecureBytes(utf8: "t")
        )
        let publicKey = try #require(old.publicKey)
        _ = try await providers.upload(publicKey, title: "laptop", usages: [.authentication], to: account)

        var job = try rotation.plan(for: old)
        job.newKeyName = "id_ed25519_new"
        job = try await rotation.generate(job, passphrase: nil)
        #expect(FileManager.default.fileExists(atPath: home.ssh.appending(path: "id_ed25519_new").path))
        let newFingerprint = try #require(job.newFingerprint)

        job = await rotation.deploy(job)
        #expect(job.completedSteps.contains(.deploy))
        #expect(servers.lines(on: "web").count == 2)
        #expect(provider.keys.map(\.fingerprint).contains(newFingerprint))

        job = try rotation.updateConfig(job)
        #expect(try home.read("config") == "Host web\n    IdentityFile ~/.ssh/id_ed25519_new\n")

        job = await rotation.verify(job, passphrase: nil)
        #expect(job.completedSteps.contains(.verify))
        #expect(servers.verified.contains("web"))
        #expect(servers.verified.contains("git@gitlab.com"))

        job = await rotation.retire(job)
        #expect(job.isFinished)
        #expect(servers.lines(on: "web").count == 1)
        #expect(servers.lines(on: "web").first?.contains(oldLine.split(separator: " ")[1]) == false)
        #expect(provider.keys.map(\.fingerprint) == [newFingerprint])
    }

    @Test func keepsGoingAfterAFailureAndAllowsSkipping() async throws {
        let old = try await oldKey()
        try home.write("config", "Host web gone\n    IdentityFile ~/.ssh/id_ed25519\n")
        servers.failingAliases = ["gone"]
        var job = try rotation.plan(for: old)
        job = try await rotation.generate(job, passphrase: nil)
        job = await rotation.deploy(job)
        #expect(!job.completedSteps.contains(.deploy))
        #expect(job.targets.first { $0.label == "gone" }?.lastError != nil)
        #expect(job.targets.first { $0.label == "web" }?.deployed == true)

        // Skipping the unreachable server lets the step complete; web is not deployed twice.
        if let index = job.targets.firstIndex(where: { $0.label == "gone" }) {
            job.targets[index].skipped = true
        }
        job = await rotation.deploy(job)
        #expect(job.completedSteps.contains(.deploy))
        #expect(servers.lines(on: "web").count == 1)
    }

    @Test func suggestsNamesThatDoNotExist() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)  // 2027
        #expect(RotationService.suggestedName(for: "id_ed25519", in: home.ssh, now: now) == "id_ed25519_2027")
        try home.write("id_ed25519_2027", "x")
        #expect(RotationService.suggestedName(for: "id_ed25519", in: home.ssh, now: now) == "id_ed25519_2027-2")
        #expect(RotationService.suggestedName(for: "id_ed25519_2026", in: home.ssh, now: now) == "id_ed25519_2027-2")
    }
}

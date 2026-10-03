import CryptoKit
import Foundation
import SMPCore
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

@Suite("Secure Enclave key store (software stand-in)")
struct SecureEnclaveStoreTests {
    @Test func createsSignsUpdatesAndDeletes() throws {
        let store = InMemorySecureEnclaveKeyStore()
        let key = try store.create(name: "laptop", comment: "me@laptop", policy: .everyUse)
        #expect(try store.keys().map(\.id) == [key.id])
        #expect(key.publicKeyX963.count == 65)

        let data = Data("sign me".utf8)
        let raw = try store.sign(data, with: key.id, context: nil)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        let publicKey = try P256.Signing.PublicKey(x963Representation: key.publicKeyX963)
        #expect(publicKey.isValidSignature(signature, for: data))
        #expect(store.signatures == 1)

        var renamed = key
        renamed.name = "work"
        renamed.policy = .reuse(seconds: 300)
        try store.update(renamed)
        #expect(try store.keys().first?.policy == .reuse(seconds: 300))

        store.failsSigning = true
        #expect(throws: SMPError.self) { try store.sign(data, with: key.id, context: nil) }

        try store.delete(id: key.id)
        #expect(try store.keys().isEmpty)
        #expect(throws: SMPError.self) { try store.sign(data, with: key.id, context: nil) }
    }

    @Test func publicKeysAreValidOpenSSHKeys() throws {
        let store = InMemorySecureEnclaveKeyStore()
        let key = try store.create(name: "laptop", comment: "me@laptop", policy: .notifyOnly)
        let publicKey = try key.publicKey()
        #expect(publicKey.algorithm == .ecdsaP256)
        #expect(publicKey.comment == "me@laptop")
        #expect(publicKey.blob == key.publicKeyBlob)
        #expect(key.openSSHLine.hasPrefix("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY"))
    }

    @Test func policiesDescribeTheirTouchIDRequirement() {
        #expect(SigningPolicy.everyUse.requiresUserPresence)
        #expect(SigningPolicy.reuse(seconds: 60).requiresUserPresence)
        #expect(!SigningPolicy.notifyOnly.requiresUserPresence)
        #expect(SigningPolicy.reuse(seconds: 300).title == "Touch ID, then allow for 5 min")
    }
}

@Suite("KeyService public keys and security keys")
struct KeyServicePublicKeyTests {
    @Test func installsPublicKeysWithoutOverwriting() throws {
        let home = try TestHome()
        let service = KeyService(
            runner: SSHToolRunner(environment: home.environment),
            environment: home.environment,
            config: home.config,
            archive: ArchiveService(
                directory: home.support.appending(path: "Archive"), keychain: InMemoryKeychainService()
            ),
            agent: AgentService(runner: SSHToolRunner(environment: home.environment))
        )
        let key = try SSHPublicKey(line: Fixtures.ecdsaP256Public)
        let url = try service.installPublicKey(key, fileName: "id_se")
        #expect(url.lastPathComponent == "id_se.pub")
        #expect(try home.read("id_se.pub") == key.openSSHLine + "\n")
        #expect(errorCode { _ = try service.installPublicKey(key, fileName: "id_se") } == .alreadyExists)
        #expect(errorCode { _ = try service.installPublicKey(key, fileName: "../escape") } == .invalidArgument)
    }

    @Test func picksUnusedNamesAndKnowsExistingKeys() throws {
        let home = try TestHome()
        try home.write("id_ed25519_sk_rk", "x")
        try home.write("id_ed25519_sk_rk-2.pub", Fixtures.ed25519Public + "\n", mode: 0o644)
        #expect(KeyService.unusedName(for: "id_ed25519_sk_rk", in: home.ssh) == "id_ed25519_sk_rk-3")
        #expect(KeyService.unusedName(for: "fresh", in: home.ssh) == "fresh")
        let fingerprints = KeyService.publicKeyFingerprints(in: home.ssh)
        #expect(fingerprints == [try SSHPublicKey(line: Fixtures.ed25519Public).fingerprintSHA256])
    }
}

@Suite("Agent settings and paths")
struct AgentSettingsTests {
    @Test func persistsSettingsInTheSharedSuite() throws {
        let suite = "smp-agent-tests-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        #expect(AgentSettings.load(from: defaults) == AgentSettings())
        AgentSettings(confirmForwardedSignatures: false, forwardedReuseSeconds: 300).save(to: defaults)
        let expected = AgentSettings(confirmForwardedSignatures: false, forwardedReuseSeconds: 300)
        #expect(AgentSettings.load(from: defaults) == expected)
    }

    @Test func writesIdentityAgentRelativeToHome() {
        let home = URL(fileURLWithPath: "/Users/alice")
        let socket = URL(fileURLWithPath: "/Users/alice/Library/Application Support/com.kirikakaese.smp/agent.sock")
        #expect(AgentPaths.identityAgentValue(for: socket, homeDirectory: home)
            == "\"~/Library/Application Support/com.kirikakaese.smp/agent.sock\"")
        #expect(AgentPaths.identityAgentValue(for: URL(fileURLWithPath: "/tmp/a.sock"), homeDirectory: home)
            == "\"/tmp/a.sock\"")
    }

    @Test func fakeHelperReportsItsState() async throws {
        let helper = FakeAgentHelper(identities: 2)
        #expect(helper.status() == .notRegistered)
        #expect(await helper.identityCount(socket: URL(fileURLWithPath: "/tmp/x")) == nil)
        try helper.register()
        #expect(await helper.identityCount(socket: URL(fileURLWithPath: "/tmp/x")) == 2)
        try await helper.unregister()
        #expect(helper.status() == .notRegistered)
    }
}

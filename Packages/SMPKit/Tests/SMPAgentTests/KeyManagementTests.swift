import Foundation
import SMPCore
import SMPServices
import SMPSSH
import Testing

@testable import SMPAgent

/// Records what reaches the system agent.
private final class RecordingUpstream: AgentUpstream, @unchecked Sendable {
    private let lock = NSLock()
    private var received: [Data] = []

    var payloads: [Data] { lock.withLock { received } }

    func send(_ payload: Data) throws -> Data {
        lock.withLock { received.append(payload) }
        return SSHAgentCodec.success
    }
}

private let app = PeerProcess(pid: 7, name: "SMP", parentName: "launchd")

private func command(_ command: AgentKeyCommand) throws -> Data {
    SSHAgentCodec.extensionRequest(name: AgentKeyCommand.extensionName, contents: try JSONEncoder().encode(command))
}

private func reply(_ response: Data) throws -> AgentKeyReply {
    try JSONDecoder().decode(AgentKeyReply.self, from: try SSHAgentCodec.parseExtensionResponse(response))
}

@Suite("Key management through the agent")
struct KeyManagementTests {
    let store = InMemorySecureEnclaveKeyStore()

    private func handler(allows: Bool, upstream: (any AgentUpstream)? = nil) -> AgentRequestHandler {
        AgentRequestHandler(
            store: store, upstream: upstream, authorizer: FixedSignatureAuthorizer(approves: true),
            peerVerifier: FixedPeerVerifier(allows: allows)
        )
    }

    @Test func createsListsUpdatesAndDeletesForSMP() throws {
        let agent = handler(allows: true)
        let created = try reply(agent.handle(
            try command(.create(name: "laptop", comment: "me@laptop", policy: .everyUse)), from: app
        )).result()
        #expect(created.map(\.name) == ["laptop"])
        let key = try #require(created.first)
        #expect(try reply(agent.handle(try command(.list), from: app)).result() == [key])

        var renamed = key
        renamed.name = "work laptop"
        renamed.policy = .reuse(seconds: 300)
        _ = try reply(agent.handle(try command(.update(renamed)), from: app)).result()
        #expect(try store.keys().first?.name == "work laptop")
        #expect(try store.keys().first?.policy == .reuse(seconds: 300))

        _ = try reply(agent.handle(try command(.delete(id: key.id)), from: app)).result()
        #expect(try store.keys().isEmpty)
    }

    @Test func refusesEveryoneElse() throws {
        _ = try store.create(name: "laptop", comment: "", policy: .everyUse)
        let log = ActivityCollector()
        let agent = AgentRequestHandler(
            store: store, upstream: nil, authorizer: FixedSignatureAuthorizer(approves: true),
            peerVerifier: FixedPeerVerifier(allows: false), record: log.add
        )
        for request in [try command(.list), try command(.delete(id: UUID()))] {
            #expect(agent.handle(request, from: app) == SSHAgentCodec.failure)
        }
        #expect(try store.keys().count == 1)
        #expect(log.entries.map(\.outcome) == [.refused, .refused])
        // Listing identities stays open to every process, as with any agent.
        let answer = agent.handle(SSHAgentCodec.requestIdentities, from: app)
        #expect(try SSHAgentCodec.parseIdentitiesAnswer(answer).count == 1)
    }

    @Test func updatesCannotChangeThePublicKeyOrTheTouchIDRequirement() throws {
        let agent = handler(allows: true)
        let key = try store.create(name: "laptop", comment: "", policy: .everyUse)

        var weakened = key
        weakened.policy = .notifyOnly
        let refused = try reply(agent.handle(try command(.update(weakened)), from: app))
        #expect(throws: SMPError.self) { try refused.result() }
        #expect(try store.keys().first?.policy == .everyUse)

        let forged = SecureEnclaveKeyInfo(
            id: key.id, name: "laptop", comment: "", policy: .everyUse, publicKeyX963: Data(repeating: 4, count: 65)
        )
        _ = try reply(agent.handle(try command(.update(forged)), from: app)).result()
        #expect(try store.keys().first?.publicKeyX963 == key.publicKeyX963)

        let missing = try reply(agent.handle(try command(.delete(id: UUID())), from: app))
        #expect((try? missing.result()) != nil)  // Deleting an unknown key is not an error.
        let empty = try reply(agent.handle(try command(.create(name: "  ", comment: "", policy: .everyUse)), from: app))
        #expect(throws: SMPError.self) { try empty.result() }
    }

    @Test func forwardsOtherExtensionsAndRejectsGarbage() throws {
        let upstream = RecordingUpstream()
        let agent = handler(allows: true, upstream: upstream)
        let sessionBind = SSHAgentCodec.extensionRequest(name: "session-bind@openssh.com", contents: Data([1, 2, 3]))
        #expect(agent.handle(sessionBind, from: app) == SSHAgentCodec.success)
        #expect(upstream.payloads == [sessionBind])

        let garbage = SSHAgentCodec.extensionRequest(name: AgentKeyCommand.extensionName, contents: Data("{".utf8))
        #expect(agent.handle(garbage, from: app) == SSHAgentCodec.failure)
        #expect(upstream.payloads.count == 1)
    }

    @Test func turnsErrorsIntoRepliesAndBack() throws {
        let error = SMPError(.keychain, whatHappened: "Nope.", howToFix: "Try again.", details: "OSStatus -1")
        let decoded = try JSONDecoder().decode(
            AgentKeyReply.self, from: try JSONEncoder().encode(AgentKeyReply(error: error))
        )
        #expect(throws: error) { try decoded.result() }
    }
}

@Suite("AgentKeyClient over a real socket", .serialized)
struct AgentKeyClientTests {
    private func makeDirectory() throws -> URL {
        let directory = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appending(path: "smp-keys-\(UUID().uuidString.prefix(8))", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        return directory
    }

    private func server(at socket: URL, store: InMemorySecureEnclaveKeyStore, allows: Bool) -> AgentServer {
        AgentServer(socketURL: socket, handler: AgentRequestHandler(
            store: store, upstream: nil, authorizer: FixedSignatureAuthorizer(approves: true),
            peerVerifier: FixedPeerVerifier(allows: allows)
        ))
    }

    @Test func managesKeysInTheAgent() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let socket = directory.appending(path: "agent.sock")
        let store = InMemorySecureEnclaveKeyStore()
        let agent = server(at: socket, store: store, allows: true)
        try agent.start()
        defer { agent.stop() }

        let client = AgentKeyClient(socketURL: socket, timeoutSeconds: 5)
        let key = try client.create(name: "laptop", comment: "me@laptop", policy: .reuse(seconds: 60))
        #expect(try store.keys() == [key])
        #expect(try client.keys() == [key])
        var renamed = key
        renamed.comment = "work"
        try client.update(renamed)
        #expect(try client.keys().first?.comment == "work")
        try client.delete(id: key.id)
        #expect(try client.keys().isEmpty)
        #expect(throws: SMPError.self) { try client.sign(Data([1]), with: key.id, context: nil) }
    }

    @Test func reportsAMissingOrRefusingAgent() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let socket = directory.appending(path: "agent.sock")
        let client = AgentKeyClient(socketURL: socket, timeoutSeconds: 5)
        #expect(errorCode { try client.keys() } == .agentNotRunning)

        let agent = server(at: socket, store: InMemorySecureEnclaveKeyStore(), allows: false)
        try agent.start()
        defer { agent.stop() }
        #expect(errorCode { try client.keys() } == .agentNotRunning)
    }

    @Test func codeSignatureVerifierRefusesProcessesOutsideTheApp() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let helper = directory.appending(path: "SMP.app/Contents/Library/LoginItems/SMPAgentHelper.app")
        try FileManager.default.createDirectory(at: helper, withIntermediateDirectories: true)
        let bundle = try #require(Bundle(url: helper))
        let verifier = try #require(CodeSignaturePeerVerifier(helperBundle: bundle))

        // This test process is not SMP.app, whatever its signature.
        var fds: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { fds.forEach { close($0) } }
        #expect(!verifier.mayManageKeys(PeerProcess.of(socket: fds[0])))
        #expect(!verifier.mayManageKeys(app))  // No audit token.

        let outside = try #require(Bundle(url: directory))
        #expect(CodeSignaturePeerVerifier(helperBundle: outside) == nil)
    }
}

private func errorCode(_ body: () throws -> Void) -> SMPError.Code? {
    do {
        try body()
        return nil
    } catch {
        return (error as? SMPError)?.code
    }
}

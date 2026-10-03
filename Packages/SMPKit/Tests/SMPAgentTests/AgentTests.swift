import CryptoKit
import Foundation
import SMPCore
import SMPServices
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPAgent

/// Records forwarded payloads and answers like a system agent holding one key.
private final class FakeUpstream: AgentUpstream, @unchecked Sendable {
    private let lock = NSLock()
    private var received: [Data] = []
    let identity: SSHAgentIdentity

    init() throws {
        let key = try SSHPublicKey(line: Fixtures.ed25519Public)
        identity = SSHAgentIdentity(keyBlob: key.blob, comment: "alice@example.com")
    }

    var payloads: [Data] { lock.withLock { received } }

    func send(_ payload: Data) throws -> Data {
        lock.withLock { received.append(payload) }
        switch SSHAgentCodec.type(of: payload) {
        case .requestIdentities: return SSHAgentCodec.identitiesAnswer([identity])
        case .signRequest: return SSHAgentCodec.signResponse(signature: Data([7, 7, 7]))
        default: return SSHAgentCodec.success
        }
    }
}

/// Parses an `ecdsa-sha2-nistp256` signature blob back into a CryptoKit signature.
private func ecdsaSignature(fromBlob blob: Data) throws -> P256.Signing.ECDSASignature {
    try blob.withUnsafeBytes { buffer in
        var outer = SSHWireReader(buffer)
        #expect(try outer.readUTF8() == "ecdsa-sha2-nistp256")
        let inner = Data(try outer.readBytes())
        return try inner.withUnsafeBytes { innerBuffer in
            var reader = SSHWireReader(innerBuffer)
            func scalar() throws -> Data {
                let bytes = try reader.readBytes().drop { $0 == 0 }
                return Data(repeating: 0, count: 32 - bytes.count) + Data(bytes)
            }
            let r = try scalar()
            let s = try scalar()
            return try P256.Signing.ECDSASignature(rawRepresentation: r + s)
        }
    }
}

private let peer = PeerProcess(pid: 42, name: "ssh", parentName: "git")

@Suite("AgentRequestHandler")
struct AgentRequestHandlerTests {
    let store = InMemorySecureEnclaveKeyStore()

    @Test func listsSecureEnclaveKeysFirstAndDeduplicates() throws {
        let key = try store.create(name: "laptop", comment: "me@laptop", policy: .everyUse)
        let upstream = try FakeUpstream()
        let handler = AgentRequestHandler(
            store: store, upstream: upstream, authorizer: FixedSignatureAuthorizer(approves: true)
        )
        let answer = try SSHAgentCodec.parseIdentitiesAnswer(
            handler.handle(SSHAgentCodec.requestIdentities, from: peer)
        )
        #expect(answer.map(\.comment) == ["me@laptop", "alice@example.com"])
        #expect(answer.first?.keyBlob == key.publicKeyBlob)
    }

    @Test func signsWithSecureEnclaveKeysAfterApproval() throws {
        let key = try store.create(name: "laptop", comment: "", policy: .reuse(seconds: 60))
        let authorizer = FixedSignatureAuthorizer(approves: true)
        let log = ActivityCollector()
        let handler = AgentRequestHandler(store: store, upstream: nil, authorizer: authorizer, record: log.add)
        let data = Data("session id and user auth request".utf8)
        let request = SSHAgentSignRequest(keyBlob: key.publicKeyBlob, data: data, flags: 0)

        let response = handler.handle(SSHAgentCodec.signRequest(request), from: peer)
        let blob = try SSHAgentCodec.parseSignResponse(response)
        let publicKey = try P256.Signing.PublicKey(x963Representation: key.publicKeyX963)
        #expect(publicKey.isValidSignature(try ecdsaSignature(fromBlob: blob), for: data))

        #expect(authorizer.requests.first?.policy == .reuse(seconds: 60))
        #expect(authorizer.requests.first?.reason == "sign with “laptop” for git (ssh)")
        let activity = log.entries
        #expect(activity.map(\.outcome) == [.signed])
        #expect(activity.first?.peer == "git (ssh)")
    }

    @Test func declinedApprovalNeverSigns() throws {
        let key = try store.create(name: "laptop", comment: "", policy: .everyUse)
        let handler = AgentRequestHandler(
            store: store, upstream: nil, authorizer: FixedSignatureAuthorizer(approves: false)
        )
        let request = SSHAgentSignRequest(keyBlob: key.publicKeyBlob, data: Data([1]), flags: 0)
        #expect(handler.handle(SSHAgentCodec.signRequest(request), from: peer) == SSHAgentCodec.failure)
        #expect(store.signatures == 0)
    }

    @Test func forwardsOtherKeysWithConfirmationPerSettings() throws {
        let upstream = try FakeUpstream()
        let request = SSHAgentSignRequest(keyBlob: upstream.identity.keyBlob, data: Data([1]), flags: 0)
        let payload = SSHAgentCodec.signRequest(request)

        let asking = FixedSignatureAuthorizer(approves: true)
        let confirming = AgentRequestHandler(
            store: store, upstream: upstream, authorizer: asking,
            settings: { AgentSettings(confirmForwardedSignatures: true, forwardedReuseSeconds: 300) }
        )
        #expect(try SSHAgentCodec.parseSignResponse(confirming.handle(payload, from: peer)) == Data([7, 7, 7]))
        #expect(asking.requests.map(\.policy) == [.reuse(seconds: 300)])
        #expect(asking.requests.first?.keyName == "alice@example.com")
        #expect(upstream.payloads.contains(payload))

        let silent = FixedSignatureAuthorizer(approves: false)
        let trusting = AgentRequestHandler(
            store: store, upstream: upstream, authorizer: silent,
            settings: { AgentSettings(confirmForwardedSignatures: false) }
        )
        #expect(SSHAgentCodec.type(of: trusting.handle(payload, from: peer)) == .signResponse)
        #expect(silent.requests.isEmpty)

        let declining = AgentRequestHandler(store: store, upstream: upstream, authorizer: silent)
        let before = upstream.payloads.count
        #expect(declining.handle(payload, from: peer) == SSHAgentCodec.failure)
        #expect(upstream.payloads.count == before + 1)  // Only the identity lookup, no sign request.
    }

    @Test func refusesRequestsCarryingSecrets() throws {
        let upstream = try FakeUpstream()
        let handler = AgentRequestHandler(
            store: store, upstream: upstream, authorizer: FixedSignatureAuthorizer(approves: true)
        )
        for type: SSHAgentMessageType in [.addIdentity, .addIdentityConstrained, .lock, .unlock] {
            let payload = Data([type.rawValue, 0, 0, 0, 1, 0x41])
            #expect(handler.handle(payload, from: peer) == SSHAgentCodec.failure)
        }
        #expect(upstream.payloads.isEmpty)

        // Harmless requests are forwarded unchanged.
        let removeAll = Data([SSHAgentMessageType.removeAllIdentities.rawValue])
        #expect(handler.handle(removeAll, from: peer) == SSHAgentCodec.success)
        #expect(upstream.payloads == [removeAll])
    }

    @Test func failsGracefullyWithoutAnUpstreamAgent() {
        let handler = AgentRequestHandler(
            store: store, upstream: nil, authorizer: FixedSignatureAuthorizer(approves: true)
        )
        let request = SSHAgentSignRequest(keyBlob: Data([1, 2]), data: Data([1]), flags: 0)
        #expect(handler.handle(SSHAgentCodec.signRequest(request), from: peer) == SSHAgentCodec.failure)
        #expect(handler.handle(Data([SSHAgentMessageType.removeAllIdentities.rawValue]), from: peer)
            == SSHAgentCodec.failure)
        #expect(handler.handle(Data([13, 0]), from: peer) == SSHAgentCodec.failure)
        #expect(handler.handle(Data(), from: peer) == SSHAgentCodec.failure)
    }
}

/// Collects activity entries from the handler's background threads.
final class ActivityCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var collected: [AgentActivity] = []

    var entries: [AgentActivity] { lock.withLock { collected } }

    var add: @Sendable (AgentActivity) -> Void {
        { [self] entry in lock.withLock { collected.append(entry) } }
    }
}

@Suite("AgentServer with real OpenSSH clients", .serialized)
struct AgentServerTests {
    /// A short socket path: Unix socket addresses are limited to 104 bytes.
    private func makeDirectory() throws -> URL {
        let directory = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appending(path: "smp-agent-\(UUID().uuidString.prefix(8))", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        return directory
    }

    private func run(
        _ tool: String,
        _ arguments: [String],
        socket: URL,
        input: URL? = nil
    ) throws -> (Int32, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/\(tool)")
        process.arguments = arguments
        process.environment = ["SSH_AUTH_SOCK": socket.path, "PATH": "/usr/bin:/bin", "HOME": "/tmp"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        process.standardInput = try input.map { try FileHandle(forReadingFrom: $0) } ?? FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    @Test func servesKeysToSSHAddAndSignsForSSHKeygen() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = InMemorySecureEnclaveKeyStore()
        let key = try store.create(name: "test-key", comment: "test@smp", policy: .everyUse)
        let socket = directory.appending(path: "agent.sock")
        let server = AgentServer(
            socketURL: socket,
            handler: AgentRequestHandler(
                store: store, upstream: nil, authorizer: FixedSignatureAuthorizer(approves: true)
            )
        )
        try server.start()
        defer { server.stop() }

        let mode = try FileManager.default.attributesOfItem(atPath: socket.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)

        let (listStatus, listed) = try run("ssh-add", ["-L"], socket: socket)
        #expect(listStatus == 0)
        #expect(listed.trimmingCharacters(in: .whitespacesAndNewlines) == key.openSSHLine)

        // ssh-keygen -Y sign uses the agent when only the public key file is available.
        let publicKeyFile = directory.appending(path: "key.pub")
        try Data((key.openSSHLine + "\n").utf8).write(to: publicKeyFile)
        let message = directory.appending(path: "message.txt")
        try Data("signed through SMP's agent\n".utf8).write(to: message)
        let (signStatus, signOutput) = try run(
            "ssh-keygen", ["-Y", "sign", "-f", publicKeyFile.path, "-n", "file", message.path], socket: socket
        )
        #expect(signStatus == 0, "\(signOutput)")
        #expect(store.signatures == 1)

        let allowedSigners = directory.appending(path: "allowed_signers")
        try Data("test@smp \(key.openSSHLine)\n".utf8).write(to: allowedSigners)
        let (checkStatus, checkOutput) = try run(
            "ssh-keygen",
            [
                "-Y", "verify", "-f", allowedSigners.path, "-I", "test@smp", "-n", "file",
                "-s", message.path + ".sig",
            ],
            socket: socket,
            input: message
        )
        #expect(checkStatus == 0, "\(checkOutput)")
    }

    @Test func refusesToStartTwiceAndCleansUpStaleSockets() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let socket = directory.appending(path: "agent.sock")
        let handler = AgentRequestHandler(
            store: InMemorySecureEnclaveKeyStore(),
            upstream: nil,
            authorizer: FixedSignatureAuthorizer(approves: true)
        )
        let first = AgentServer(socketURL: socket, handler: handler)
        try first.start()
        let second = AgentServer(socketURL: socket, handler: handler)
        #expect(throws: SMPError.self) { try second.start() }
        first.stop()
        #expect(!FileManager.default.fileExists(atPath: socket.path))

        // A plain file in the way is never deleted.
        try Data("not a socket".utf8).write(to: socket)
        #expect(throws: SMPError.self) { try second.start() }
        #expect(FileManager.default.fileExists(atPath: socket.path))
    }

    @Test func excludesItsOwnSocketAsUpstream() {
        let own = URL(fileURLWithPath: "/tmp/smp-own.sock")
        let looping = UnixSocketAgentClient.systemAgent(environment: ["SSH_AUTH_SOCK": own.path], excluding: own)
        #expect(looping == nil)
        #expect(UnixSocketAgentClient.systemAgent(environment: [:], excluding: own) == nil)
        let system = UnixSocketAgentClient.systemAgent(
            environment: ["SSH_AUTH_SOCK": "/private/tmp/com.apple.launchd.x/Listeners"], excluding: own
        )
        #expect(system?.path == "/private/tmp/com.apple.launchd.x/Listeners")
    }
}

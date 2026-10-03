import Darwin
import Foundation
import SMPCore
import SMPSSH

/// The agent that SMP forwards requests to for keys it does not hold itself (the system ssh-agent).
public protocol AgentUpstream: Sendable {
    /// Sends one request payload and returns the response payload.
    func send(_ payload: Data) throws -> Data
}

extension AgentUpstream {
    public func identities() throws -> [SSHAgentIdentity] {
        try SSHAgentCodec.parseIdentitiesAnswer(send(SSHAgentCodec.requestIdentities))
    }
}

/// Talks to an agent over its Unix socket, one connection per request.
public struct UnixSocketAgentClient: AgentUpstream {
    public let path: String
    private let timeoutSeconds: Int

    public init(path: String, timeoutSeconds: Int = 60) {
        self.path = path
        self.timeoutSeconds = timeoutSeconds
    }

    /// The system agent's socket for this login session, unless it is SMP's own socket.
    public static func systemAgent(environment: [String: String], excluding ownSocket: URL) -> Self? {
        guard let path = environment["SSH_AUTH_SOCK"], !path.isEmpty else { return nil }
        let resolvedOwn = ownSocket.resolvingSymlinksInPath().path
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        // Forwarding to ourselves would loop forever.
        guard resolved != resolvedOwn else { return nil }
        return Self(path: path)
    }

    public func send(_ payload: Data) throws -> Data {
        let fd = try UnixSocket.connect(to: path, timeoutSeconds: timeoutSeconds)
        defer { close(fd) }
        guard UnixSocket.writeMessage(fd, payload) else { throw UnixSocket.posixError("forward the request") }
        guard let response = UnixSocket.readMessage(fd) else {
            throw SMPError(.toolFailed, whatHappened: String(localized: "The system ssh-agent did not answer."))
        }
        return response
    }
}

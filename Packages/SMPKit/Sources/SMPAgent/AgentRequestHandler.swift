import CryptoKit
import Foundation
import LocalAuthentication
import SMPCore
import SMPServices
import SMPSSH

/// One entry in the agent's activity log. Holds no key material or signed data.
public struct AgentActivity: Sendable, Hashable, Identifiable {
    public enum Outcome: String, Sendable, Hashable {
        case signed, forwarded, declined, refused, failed
    }

    public let id = UUID()
    public let date: Date
    public let peer: String
    public let keyName: String
    public let outcome: Outcome
    public let detail: String?

    public init(date: Date = Date(), peer: String, keyName: String, outcome: Outcome, detail: String? = nil) {
        self.date = date
        self.peer = peer
        self.keyName = keyName
        self.outcome = outcome
        self.detail = detail
    }
}

/// Answers agent protocol requests: Secure Enclave keys are served here, everything else is
/// forwarded to the system agent. Requests that would carry secrets are refused. SMP itself
/// manages the Secure Enclave keys through the `AgentKeyCommand` extension.
public final class AgentRequestHandler: Sendable {
    private let store: any SecureEnclaveKeyStoring
    private let upstream: (any AgentUpstream)?
    private let authorizer: any SignatureAuthorizing
    private let peerVerifier: any PeerVerifying
    private let settings: @Sendable () -> AgentSettings
    private let record: @Sendable (AgentActivity) -> Void
    private let keysChanged: @Sendable () -> Void

    public init(
        store: any SecureEnclaveKeyStoring,
        upstream: (any AgentUpstream)?,
        authorizer: any SignatureAuthorizing,
        peerVerifier: any PeerVerifying = FixedPeerVerifier(allows: false),
        settings: @escaping @Sendable () -> AgentSettings = { AgentSettings() },
        record: @escaping @Sendable (AgentActivity) -> Void = { _ in },
        keysChanged: @escaping @Sendable () -> Void = {}
    ) {
        self.store = store
        self.upstream = upstream
        self.authorizer = authorizer
        self.peerVerifier = peerVerifier
        self.settings = settings
        self.record = record
        self.keysChanged = keysChanged
    }

    /// Handles one request payload and returns the response payload. Never throws: failures are
    /// answered with `SSH_AGENT_FAILURE`.
    public func handle(_ payload: Data, from peer: PeerProcess) -> Data {
        guard let type = SSHAgentCodec.type(of: payload) else { return forward(payload) }
        switch type {
        case .requestIdentities:
            return SSHAgentCodec.identitiesAnswer(identities())
        case .signRequest:
            return sign(payload, peer: peer)
        case .extension:
            return handleExtension(payload, peer: peer)
        default:
            if type.carriesSecrets {
                record(AgentActivity(
                    peer: peer.displayName, keyName: "—", outcome: .refused,
                    detail: "Adding keys or locking goes to the system agent, not SMP's agent."
                ))
                return SSHAgentCodec.failure
            }
            return forward(payload)
        }
    }

    // MARK: Identities

    func identities() -> [SSHAgentIdentity] {
        let own = ((try? store.keys()) ?? []).map {
            SSHAgentIdentity(keyBlob: $0.publicKeyBlob, comment: $0.comment.isEmpty ? $0.name : $0.comment)
        }
        let ownBlobs = Set(own.map(\.keyBlob))
        let forwarded = ((try? upstream?.identities()) ?? []).filter { !ownBlobs.contains($0.keyBlob) }
        return own + forwarded
    }

    // MARK: Signing

    private func sign(_ payload: Data, peer: PeerProcess) -> Data {
        guard let request = try? SSHAgentCodec.parseSignRequest(payload) else { return SSHAgentCodec.failure }
        let keys = (try? store.keys()) ?? []
        if let key = keys.first(where: { $0.publicKeyBlob == request.keyBlob }) {
            return signWithSecureEnclave(request, key: key, peer: peer)
        }
        guard let upstream else { return SSHAgentCodec.failure }
        let name = forwardedKeyName(for: request.keyBlob)
        let current = settings()
        if current.confirmForwardedSignatures {
            let policy: SigningPolicy = current.forwardedReuseSeconds > 0
                ? .reuse(seconds: current.forwardedReuseSeconds) : .everyUse
            let approval = SignatureApproval(
                keyID: Self.fingerprint(of: request.keyBlob), keyName: name, peer: peer, policy: policy
            )
            do {
                _ = try authorizer.authorize(approval)
            } catch {
                record(AgentActivity(peer: peer.displayName, keyName: name, outcome: .declined))
                return SSHAgentCodec.failure
            }
        }
        do {
            let response = try upstream.send(payload)
            let outcome: AgentActivity.Outcome = SSHAgentCodec.type(of: response) == .signResponse
                ? .forwarded : .failed
            record(AgentActivity(peer: peer.displayName, keyName: name, outcome: outcome))
            return response
        } catch {
            record(AgentActivity(peer: peer.displayName, keyName: name, outcome: .failed, detail: "System agent"))
            return SSHAgentCodec.failure
        }
    }

    private func signWithSecureEnclave(
        _ request: SSHAgentSignRequest,
        key: SecureEnclaveKeyInfo,
        peer: PeerProcess
    ) -> Data {
        let approval = SignatureApproval(
            keyID: key.id.uuidString, keyName: key.name, peer: peer, policy: key.policy
        )
        let context: LAContext?
        do {
            context = try authorizer.authorize(approval)
        } catch {
            record(AgentActivity(peer: peer.displayName, keyName: key.name, outcome: .declined))
            return SSHAgentCodec.failure
        }
        do {
            let raw = try store.sign(request.data, with: key.id, context: context)
            let signature = try SSHAgentCodec.ecdsaP256SignatureBlob(raw: raw)
            let detail = key.policy == .notifyOnly ? "Signed without a prompt (notification only)." : nil
            record(AgentActivity(peer: peer.displayName, keyName: key.name, outcome: .signed, detail: detail))
            return SSHAgentCodec.signResponse(signature: signature)
        } catch {
            record(AgentActivity(peer: peer.displayName, keyName: key.name, outcome: .failed))
            return SSHAgentCodec.failure
        }
    }

    private func forwardedKeyName(for blob: Data) -> String {
        let identity = (try? upstream?.identities())?.first { $0.keyBlob == blob }
        if let comment = identity?.comment, !comment.isEmpty { return comment }
        return Self.fingerprint(of: blob)
    }

    static func fingerprint(of blob: Data) -> String {
        let digest = Data(SHA256.hash(data: blob)).base64EncodedString()
        return "SHA256:" + digest.trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    // MARK: Key management (SMP only)

    private func handleExtension(_ payload: Data, peer: PeerProcess) -> Data {
        guard let request = try? SSHAgentCodec.parseExtensionRequest(payload) else {
            return SSHAgentCodec.failure
        }
        // Other extensions (e.g. OpenSSH's session-bind) are the system agent's business.
        guard request.name == AgentKeyCommand.extensionName else { return forward(payload) }
        guard peerVerifier.mayManageKeys(peer) else {
            record(AgentActivity(
                peer: peer.displayName, keyName: "—", outcome: .refused,
                detail: "Only SMP can manage Secure Enclave keys."
            ))
            return SSHAgentCodec.failure
        }
        guard let command = try? JSONDecoder().decode(AgentKeyCommand.self, from: request.contents) else {
            return SSHAgentCodec.failure
        }
        let reply: AgentKeyReply
        do {
            reply = AgentKeyReply(keys: try perform(command))
        } catch {
            reply = AgentKeyReply(error: (error as? SMPError) ?? SMPError(
                .keychain, whatHappened: "SMP Agent could not change its keys.", details: error.localizedDescription
            ))
        }
        guard let contents = try? JSONEncoder().encode(reply) else { return SSHAgentCodec.failure }
        return SSHAgentCodec.extensionResponse(contents)
    }

    private func perform(_ command: AgentKeyCommand) throws -> [SecureEnclaveKeyInfo] {
        switch command {
        case .list:
            return try store.keys()
        case .create(let name, let comment, let policy):
            let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed.count <= 200, comment.count <= 1000 else {
                throw SMPError.invalidArgument("The key needs a name of at most 200 characters.")
            }
            let key = try store.create(name: trimmed, comment: comment, policy: policy)
            keysChanged()
            return [key]
        case .update(let changed):
            // Only the name, comment and policy can change; the public key and Touch ID
            // requirement stay as created.
            guard var key = try store.keys().first(where: { $0.id == changed.id }) else {
                throw SMPError.invalidArgument("The Secure Enclave key no longer exists.")
            }
            guard changed.policy.requiresUserPresence == key.policy.requiresUserPresence else {
                throw SMPError.invalidArgument(
                    "Whether a key needs Touch ID is fixed when it is created. Create a new key to change it."
                )
            }
            key.name = changed.name
            key.comment = changed.comment
            key.policy = changed.policy
            try store.update(key)
            keysChanged()
            return []
        case .delete(let id):
            try store.delete(id: id)
            keysChanged()
            return []
        }
    }

    // MARK: Forwarding

    private func forward(_ payload: Data) -> Data {
        guard let upstream, let response = try? upstream.send(payload) else { return SSHAgentCodec.failure }
        return response
    }
}

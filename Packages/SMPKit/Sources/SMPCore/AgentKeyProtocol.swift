import Foundation

/// What the app asks SMP Agent to do with Secure Enclave keys. Only the agent stores them (in
/// the login keychain), so the app needs no shared Keychain group and works when ad-hoc signed.
///
/// Sent as JSON inside an `SSH_AGENTC_EXTENSION` request named `extensionName` on the agent's
/// socket. The agent answers only SMP itself (checked by code signature); messages carry public
/// key data only.
public enum AgentKeyCommand: Sendable, Hashable, Codable {
    case list
    case create(name: String, comment: String, policy: SigningPolicy)
    case update(SecureEnclaveKeyInfo)
    case delete(id: UUID)

    public static let extensionName = "manage-keys@smp.kirikakaese.com"
}

/// The agent's answer to an `AgentKeyCommand`: the keys (all of them for `list`, the new one for
/// `create`, none otherwise) or what went wrong.
public struct AgentKeyReply: Sendable, Hashable, Codable {
    public struct Failure: Sendable, Hashable, Codable {
        public var code: String
        public var whatHappened: String
        public var howToFix: String?
        public var details: String?
    }

    public var keys: [SecureEnclaveKeyInfo]
    public var failure: Failure?

    public init(keys: [SecureEnclaveKeyInfo] = []) {
        self.keys = keys
        self.failure = nil
    }

    public init(error: SMPError) {
        self.keys = []
        self.failure = Failure(
            code: error.code.rawValue,
            whatHappened: error.whatHappened,
            howToFix: error.howToFix,
            details: error.details
        )
    }

    /// The keys, or the agent's error rethrown as an `SMPError`.
    public func result() throws -> [SecureEnclaveKeyInfo] {
        if let failure {
            throw SMPError(
                SMPError.Code(rawValue: failure.code) ?? .keychain,
                whatHappened: failure.whatHappened,
                howToFix: failure.howToFix,
                details: failure.details
            )
        }
        return keys
    }
}

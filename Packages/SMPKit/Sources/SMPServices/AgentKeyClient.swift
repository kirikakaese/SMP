import CryptoKit
import Foundation
import LocalAuthentication
import SMPCore
import SMPSSH

/// The app's view of the Secure Enclave keys: every call is a request to SMP Agent, which alone
/// stores and uses the keys. Signing is not offered here; ssh and git sign through the agent.
public struct AgentKeyClient: SecureEnclaveKeyStoring {
    private let socketURL: URL
    private let timeoutSeconds: Int

    public init(socketURL: URL, timeoutSeconds: Int = 10) {
        self.socketURL = socketURL
        self.timeoutSeconds = timeoutSeconds
    }

    public var isAvailable: Bool { SecureEnclave.isAvailable }

    public func keys() throws -> [SecureEnclaveKeyInfo] {
        try send(.list)
    }

    public func create(name: String, comment: String, policy: SigningPolicy) throws -> SecureEnclaveKeyInfo {
        guard let key = try send(.create(name: name, comment: comment, policy: policy)).first else {
            throw SMPError(.keyOperationFailed, whatHappened: "SMP Agent did not return the new key.")
        }
        return key
    }

    public func update(_ key: SecureEnclaveKeyInfo) throws {
        _ = try send(.update(key))
    }

    public func delete(id: UUID) throws {
        _ = try send(.delete(id: id))
    }

    public func sign(_ data: Data, with id: UUID, context: LAContext?) throws -> Data {
        throw SMPError.invalidArgument("Secure Enclave keys sign through SMP Agent, not in the app.")
    }

    private func send(_ command: AgentKeyCommand) throws -> [SecureEnclaveKeyInfo] {
        let request = SSHAgentCodec.extensionRequest(
            name: AgentKeyCommand.extensionName, contents: try JSONEncoder().encode(command)
        )
        let fd: Int32
        do {
            fd = try UnixSocket.connect(to: socketURL.path, timeoutSeconds: timeoutSeconds)
        } catch {
            throw Self.notRunning
        }
        defer { close(fd) }
        guard UnixSocket.writeMessage(fd, request), let response = UnixSocket.readMessage(fd) else {
            throw Self.notRunning
        }
        guard let contents = try? SSHAgentCodec.parseExtensionResponse(response) else {
            throw SMPError(
                .agentNotRunning,
                whatHappened: "SMP Agent refused to manage Secure Enclave keys for this copy of SMP.",
                howToFix: "Open SMP from the same app bundle as the running SMP Agent. After updating "
                    + "SMP, quit SMP Agent from its menu bar icon and start it again."
            )
        }
        return try JSONDecoder().decode(AgentKeyReply.self, from: contents).result()
    }

    static let notRunning = SMPError(
        .agentNotRunning,
        whatHappened: "SMP Agent is not running.",
        howToFix: "Secure Enclave keys are kept by SMP Agent. Start it to see and manage them."
    )
}

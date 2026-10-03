import Foundation
import LocalAuthentication
import SMPCore

/// One signature that needs the user's approval.
public struct SignatureApproval: Sendable, Hashable {
    /// Identifies the key for reuse windows (Secure Enclave key id or public key fingerprint).
    public let keyID: String
    public let keyName: String
    public let peer: PeerProcess
    public let policy: SigningPolicy

    public init(keyID: String, keyName: String, peer: PeerProcess, policy: SigningPolicy) {
        self.keyID = keyID
        self.keyName = keyName
        self.peer = peer
        self.policy = policy
    }

    /// Shown in the Touch ID dialog after "SMP Agent is trying to …".
    public var reason: String {
        "sign with “\(keyName)” for \(peer.displayName)"
    }
}

/// Decides whether a signature may happen.
public protocol SignatureAuthorizing: Sendable {
    /// Returns an evaluated `LAContext` (or `nil` when the policy needs no prompt).
    /// Throws if the user cancels or fails authentication.
    func authorize(_ approval: SignatureApproval) throws -> LAContext?
}

/// Asks for Touch ID or the login password, honoring reuse windows.
public final class LocalSignatureAuthorizer: SignatureAuthorizing, @unchecked Sendable {
    // Safety: `approved` is only accessed while holding `lock`.
    private let lock = NSLock()
    private var approved: [String: (context: LAContext, expires: Date)] = [:]

    public init() {}

    /// Forgets every reuse window, e.g. when the Mac sleeps or the screen locks.
    public func reset() {
        let contexts = lock.withLock { () -> [LAContext] in
            defer { approved.removeAll() }
            return approved.values.map(\.context)
        }
        contexts.forEach { $0.invalidate() }
    }

    public func authorize(_ approval: SignatureApproval) throws -> LAContext? {
        switch approval.policy {
        case .notifyOnly:
            return nil
        case .everyUse:
            return try evaluate(reason: approval.reason)
        case .reuse(let seconds):
            let cached = lock.withLock { () -> LAContext? in
                guard let entry = approved[approval.keyID], entry.expires > Date() else { return nil }
                return entry.context
            }
            if let cached { return cached }
            let context = try evaluate(reason: approval.reason)
            lock.withLock {
                approved[approval.keyID] = (context, Date().addingTimeInterval(TimeInterval(max(0, seconds))))
            }
            return context
        }
    }

    private final class Outcome: @unchecked Sendable {
        var success = false
        var error: Error?
    }

    private func evaluate(reason: String) throws -> LAContext {
        let context = LAContext()
        context.localizedFallbackTitle = "Use Password"
        let outcome = Outcome()
        let done = DispatchSemaphore(value: 0)
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            outcome.success = success
            outcome.error = error
            done.signal()
        }
        done.wait()
        guard outcome.success else {
            throw SMPError(
                .authenticationFailed,
                whatHappened: "The signature was not approved.",
                details: outcome.error?.localizedDescription
            )
        }
        return context
    }
}

/// Approves or declines everything without asking. For tests.
public final class FixedSignatureAuthorizer: SignatureAuthorizing, @unchecked Sendable {
    private let lock = NSLock()
    private let approves: Bool
    private var seen: [SignatureApproval] = []

    public init(approves: Bool) {
        self.approves = approves
    }

    public var requests: [SignatureApproval] { lock.withLock { seen } }

    public func authorize(_ approval: SignatureApproval) throws -> LAContext? {
        lock.withLock { seen.append(approval) }
        guard approves else { throw SMPError(.authenticationFailed, whatHappened: "Declined.") }
        return nil
    }
}

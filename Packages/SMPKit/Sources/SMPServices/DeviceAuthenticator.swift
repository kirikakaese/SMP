import Foundation
import LocalAuthentication
import SMPCore

/// Asks the user to prove presence with Touch ID or their login password.
public protocol DeviceAuthenticating: Sendable {
    /// Throws `authenticationFailed` if the user cancels or fails.
    func authenticate(reason: String) async throws
}

public struct DeviceAuthenticator: DeviceAuthenticating {
    public init() {}

    /// Whether this Mac can ask for Touch ID or the login password at all (it cannot without a
    /// login password). Features like the app lock must stay off when it cannot.
    public static func isAvailable() -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    public func authenticate(reason: String) async throws {
        let context = LAContext()
        context.localizedFallbackTitle = "Use Password"
        var error: NSError?
        // .deviceOwnerAuthentication allows Touch ID, Apple Watch or the login password.
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw SMPError(
                .authenticationFailed,
                whatHappened: "SMP could not ask for Touch ID or your password.",
                howToFix: "Make sure your Mac has a login password set.",
                details: error?.localizedDescription
            )
        }
        do {
            _ = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            throw SMPError(
                .authenticationFailed,
                whatHappened: "Authentication was cancelled or failed, so nothing was changed.",
                details: error.localizedDescription
            )
        }
    }
}

/// Always succeeds (or always fails). For tests and previews only.
public struct FakeAuthenticator: DeviceAuthenticating {
    public let succeeds: Bool

    public init(succeeds: Bool = true) {
        self.succeeds = succeeds
    }

    public func authenticate(reason: String) async throws {
        guard succeeds else {
            throw SMPError(.authenticationFailed, whatHappened: "Authentication failed.")
        }
    }
}

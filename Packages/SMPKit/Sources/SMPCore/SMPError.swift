import Foundation

/// The single error type surfaced to the UI.
///
/// Every error carries a human-readable explanation of *what happened* and, where possible,
/// *how to fix it*. Messages must never contain secret material; file paths are allowed because
/// they are shown to the user who owns them, but they are never sent anywhere.
public struct SMPError: Error, Sendable, Equatable {
    public enum Code: String, Sendable {
        case toolNotFound
        case toolLaunchFailed
        case toolFailed
        case toolTimedOut
        case toolCancelled
        case invalidArgument
        case keychain
        case fileSystem
        /// A file changed on disk after SMP read it; nothing was written.
        case fileChangedOnDisk
        /// A file or key with the requested name already exists.
        case alreadyExists
        /// A key operation (generate, import, convert, change passphrase …) failed.
        case keyOperationFailed
        /// The passphrase was wrong or missing.
        case passphraseRequired
        /// Touch ID / password re-authentication failed or was cancelled.
        case authenticationFailed
        /// A provider could not be reached (offline, DNS, TLS, timeout).
        case network
        /// A provider rejected a request (bad token, missing scope, invalid key, rate limit).
        case providerRejected
        /// SMP Agent, which holds the Secure Enclave keys, is not running or did not answer.
        case agentNotRunning
    }

    public let code: Code
    public let whatHappened: String
    public let howToFix: String?
    /// Extra technical detail (for example a trimmed `stderr`). Shown behind a disclosure, never logged.
    public let details: String?

    public init(_ code: Code, whatHappened: String, howToFix: String? = nil, details: String? = nil) {
        self.code = code
        self.whatHappened = whatHappened
        self.howToFix = howToFix
        self.details = details
    }
}

extension SMPError: LocalizedError {
    public var errorDescription: String? { whatHappened }
    public var recoverySuggestion: String? { howToFix }
    public var failureReason: String? { details }
}

extension SMPError {
    public static func toolNotFound(_ name: String, path: String) -> SMPError {
        SMPError(
            .toolNotFound,
            whatHappened: "SMP could not find the \(name) tool at \(path).",
            howToFix: "OpenSSH ships with macOS. Check that \(path) exists and is executable, "
                + "or reinstall the Command Line Tools with “xcode-select --install”."
        )
    }

    public static func toolLaunchFailed(_ name: String, reason: String) -> SMPError {
        SMPError(
            .toolLaunchFailed,
            whatHappened: "SMP could not start \(name).",
            howToFix: "Try again. If the problem persists, restart your Mac.",
            details: reason
        )
    }

    public static func toolFailed(_ name: String, exitCode: Int32, stderr: String) -> SMPError {
        SMPError(
            .toolFailed,
            whatHappened: "\(name) reported an error (exit code \(exitCode)).",
            howToFix: nil,
            details: stderr.isEmpty ? nil : stderr
        )
    }

    public static func toolTimedOut(_ name: String, after seconds: Double) -> SMPError {
        SMPError(
            .toolTimedOut,
            whatHappened: "\(name) did not finish within \(Int(seconds.rounded())) seconds and was stopped.",
            howToFix: "Check your network connection or the host you are connecting to, then try again."
        )
    }

    public static func toolCancelled(_ name: String) -> SMPError {
        SMPError(.toolCancelled, whatHappened: "\(name) was cancelled.")
    }

    public static func invalidArgument(_ message: String) -> SMPError {
        SMPError(.invalidArgument, whatHappened: message)
    }
}

extension SMPError {
    public static func fileChangedOnDisk(_ name: String) -> SMPError {
        SMPError(
            .fileChangedOnDisk,
            whatHappened: "\(name) was changed by another program after SMP read it. Nothing was saved.",
            howToFix: "Review the file, then try again. SMP reloads it before saving."
        )
    }

    public static func alreadyExists(_ name: String) -> SMPError {
        SMPError(
            .alreadyExists,
            whatHappened: "A file named “\(name)” already exists.",
            howToFix: "Choose another name, or confirm that the existing key should be archived and replaced."
        )
    }

    public static func wrongPassphrase(_ keyName: String) -> SMPError {
        SMPError(
            .passphraseRequired,
            whatHappened: "The passphrase for “\(keyName)” is missing or incorrect.",
            howToFix: "Enter the key's current passphrase and try again."
        )
    }

    public static func keyOperationFailed(
        _ whatHappened: String,
        howToFix: String? = nil,
        details: String? = nil
    ) -> SMPError {
        SMPError(.keyOperationFailed, whatHappened: whatHappened, howToFix: howToFix, details: details)
    }
}

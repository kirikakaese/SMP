import Foundation

/// Describes the user environment SMP operates on.
///
/// Everything that touches `~/.ssh` resolves paths through this value, so tests can point it at
/// a temporary directory and never touch the real home folder.
public struct SSHEnvironment: Sendable, Equatable {
    public var homeDirectory: URL
    public var userName: String
    /// The `SSH_AUTH_SOCK` passed to child processes, if any.
    public var agentSocketPath: String?
    /// Directory for short-lived private files (askpass FIFOs and the like).
    public var temporaryDirectory: URL

    public init(
        homeDirectory: URL,
        userName: String,
        agentSocketPath: String? = nil,
        temporaryDirectory: URL = FileManager.default.temporaryDirectory
    ) {
        self.homeDirectory = homeDirectory
        self.userName = userName
        self.agentSocketPath = agentSocketPath
        self.temporaryDirectory = temporaryDirectory
    }

    /// The environment of the logged-in user running SMP.
    public static var current: SSHEnvironment {
        let processEnvironment = ProcessInfo.processInfo.environment
        return SSHEnvironment(
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser,
            userName: NSUserName(),
            agentSocketPath: processEnvironment["SSH_AUTH_SOCK"]
        )
    }

    public var sshDirectory: URL {
        homeDirectory.appending(path: ".ssh", directoryHint: .isDirectory)
    }

    public var configFile: URL {
        sshDirectory.appending(path: "config", directoryHint: .notDirectory)
    }

    public var knownHostsFile: URL {
        sshDirectory.appending(path: "known_hosts", directoryHint: .notDirectory)
    }
}

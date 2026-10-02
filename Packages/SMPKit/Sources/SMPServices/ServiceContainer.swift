import Foundation
import SMPCore
import SMPSSH

/// The set of services the app runs with. Views and view models receive it by injection,
/// so tests and previews can swap in fakes.
///
/// More services (keys, agent, config, known_hosts, providers, audit, file watching) are added
/// here as their milestones land.
public struct ServiceContainer: Sendable {
    public var environment: SSHEnvironment
    public var toolRunner: any SSHToolRunning
    public var keychain: any KeychainServicing

    public init(environment: SSHEnvironment, toolRunner: any SSHToolRunning, keychain: any KeychainServicing) {
        self.environment = environment
        self.toolRunner = toolRunner
        self.keychain = keychain
    }

    /// Services wired to the real system.
    public static func live(environment: SSHEnvironment = .current) -> ServiceContainer {
        ServiceContainer(
            environment: environment,
            toolRunner: SSHToolRunner(environment: environment),
            keychain: KeychainService()
        )
    }

    /// Services that never touch the real `~/.ssh` or Keychain. For SwiftUI previews and UI tests.
    public static func preview() -> ServiceContainer {
        let environment = SSHEnvironment(
            homeDirectory: FileManager.default.temporaryDirectory.appending(path: "smp-preview-home"),
            userName: "preview"
        )
        return ServiceContainer(
            environment: environment,
            toolRunner: SSHToolRunner(environment: environment),
            keychain: InMemoryKeychainService()
        )
    }
}

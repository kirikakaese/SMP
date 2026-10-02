import Foundation
import SMPCore
import SMPPersistence
import SMPSSH

/// The set of services the app runs with. Views and view models receive it by injection,
/// so tests and previews can swap in fakes.
///
/// More services (config, known_hosts, providers, audit) are added here as their milestones land.
public struct ServiceContainer: Sendable {
    public var environment: SSHEnvironment
    public var toolRunner: any SSHToolRunning
    public var keychain: any KeychainServicing
    public var keyDiscovery: any KeyDiscovering
    public var agent: any AgentServicing
    public var metadata: any MetadataStoring
    public var fileWatcher: any FileWatching
    /// Set when a service could not start normally (for example, the metadata store could not be
    /// opened and an in-memory store is used instead). Shown to the user.
    public var startupIssue: SMPError?

    public init(
        environment: SSHEnvironment,
        toolRunner: any SSHToolRunning,
        keychain: any KeychainServicing,
        keyDiscovery: any KeyDiscovering,
        agent: any AgentServicing,
        metadata: any MetadataStoring,
        fileWatcher: any FileWatching,
        startupIssue: SMPError? = nil
    ) {
        self.environment = environment
        self.toolRunner = toolRunner
        self.keychain = keychain
        self.keyDiscovery = keyDiscovery
        self.agent = agent
        self.metadata = metadata
        self.fileWatcher = fileWatcher
        self.startupIssue = startupIssue
    }

    /// Services wired to the real system.
    public static func live(environment: SSHEnvironment = .current) -> ServiceContainer {
        let runner = SSHToolRunner(environment: environment)
        var issue: SMPError?
        let metadata: any MetadataStoring
        do {
            metadata = try GRDBMetadataStore.live()
        } catch {
            Log.app.error("Metadata store could not be opened; using a temporary in-memory store")
            issue = SMPError(
                .fileSystem,
                whatHappened: "SMP could not open its library database. Tags, groups and notes will not be saved.",
                howToFix: "Check that ~/Library/Application Support/com.kirikakaese.smp is writable, then restart SMP.",
                details: error.localizedDescription
            )
            metadata = Self.inMemoryMetadata()
        }
        return ServiceContainer(
            environment: environment,
            toolRunner: runner,
            keychain: KeychainService(),
            keyDiscovery: KeyDiscoveryService(),
            agent: AgentService(runner: runner),
            metadata: metadata,
            fileWatcher: FileWatcherService(),
            startupIssue: issue
        )
    }

    /// Services that never touch the real `~/.ssh` or Keychain. For SwiftUI previews and UI tests.
    public static func preview() -> ServiceContainer {
        let environment = SSHEnvironment(
            homeDirectory: FileManager.default.temporaryDirectory.appending(path: "smp-preview-home"),
            userName: "preview"
        )
        let runner = SSHToolRunner(environment: environment)
        return ServiceContainer(
            environment: environment,
            toolRunner: runner,
            keychain: InMemoryKeychainService(),
            keyDiscovery: KeyDiscoveryService(),
            agent: AgentService(runner: runner),
            metadata: inMemoryMetadata(),
            fileWatcher: FileWatcherService()
        )
    }

    private static func inMemoryMetadata() -> any MetadataStoring {
        // An in-memory SQLite database cannot fail to open short of memory exhaustion.
        // swiftlint:disable:next force_try
        try! GRDBMetadataStore.inMemory()
    }
}

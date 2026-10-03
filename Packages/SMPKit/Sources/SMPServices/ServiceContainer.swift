import Foundation
import SMPCore
import SMPPersistence
import SMPSSH

/// The set of services the app runs with. Views and view models receive it by injection,
/// so tests and previews can swap in fakes.
public struct ServiceContainer: Sendable {
    public var environment: SSHEnvironment
    public var toolRunner: any SSHToolRunning
    public var keychain: any KeychainServicing
    public var keyDiscovery: any KeyDiscovering
    public var agent: any AgentServicing
    public var metadata: any MetadataStoring
    public var fileWatcher: any FileWatching
    public var config: any ConfigServicing
    public var archive: any ArchiveServicing
    public var keys: any KeyManaging
    public var authenticator: any DeviceAuthenticating
    public var hosts: any HostServicing
    public var knownHosts: any KnownHostsServicing
    public var terminal: any TerminalLaunching
    public var tunnels: any TunnelServicing
    public var deploy: any DeployServicing
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
        config: any ConfigServicing,
        archive: any ArchiveServicing,
        keys: any KeyManaging,
        authenticator: any DeviceAuthenticating,
        hosts: any HostServicing,
        knownHosts: any KnownHostsServicing,
        terminal: any TerminalLaunching,
        tunnels: any TunnelServicing,
        deploy: any DeployServicing,
        startupIssue: SMPError? = nil
    ) {
        self.environment = environment
        self.toolRunner = toolRunner
        self.keychain = keychain
        self.keyDiscovery = keyDiscovery
        self.agent = agent
        self.metadata = metadata
        self.fileWatcher = fileWatcher
        self.config = config
        self.archive = archive
        self.keys = keys
        self.authenticator = authenticator
        self.hosts = hosts
        self.knownHosts = knownHosts
        self.terminal = terminal
        self.tunnels = tunnels
        self.deploy = deploy
        self.startupIssue = startupIssue
    }

    /// Wires services together around a support directory (Application Support in the app,
    /// a temporary folder in tests and previews).
    public static func make(
        environment: SSHEnvironment,
        supportDirectory: URL,
        keychain: any KeychainServicing,
        metadata: any MetadataStoring,
        authenticator: any DeviceAuthenticating,
        startupIssue: SMPError? = nil
    ) -> ServiceContainer {
        let runner = SSHToolRunner(environment: environment)
        let agent = AgentService(runner: runner)
        let writer = SafeFileWriter(backupDirectory: supportDirectory.appending(path: "Backups"))
        let config = ConfigService(environment: environment, writer: writer)
        let archive = ArchiveService(directory: supportDirectory.appending(path: "Archive"), keychain: keychain)
        return ServiceContainer(
            environment: environment,
            toolRunner: runner,
            keychain: keychain,
            keyDiscovery: KeyDiscoveryService(),
            agent: agent,
            metadata: metadata,
            fileWatcher: FileWatcherService(),
            config: config,
            archive: archive,
            keys: KeyService(runner: runner, environment: environment, config: config, archive: archive, agent: agent),
            authenticator: authenticator,
            hosts: HostService(runner: runner, environment: environment, writer: writer),
            knownHosts: KnownHostsService(runner: runner, environment: environment, writer: writer),
            terminal: TerminalLauncher(homeDirectory: environment.homeDirectory),
            tunnels: TunnelService(launcher: runner),
            deploy: DeployService(runner: runner),
            startupIssue: startupIssue
        )
    }

    /// Services wired to the real system.
    public static func live(environment: SSHEnvironment = .current) -> ServiceContainer {
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
            metadata = inMemoryMetadata()
        }
        let support = (try? AppPaths.applicationSupportDirectory())
            ?? FileManager.default.temporaryDirectory.appending(path: AppPaths.bundleIdentifier)
        return make(
            environment: environment,
            supportDirectory: support,
            keychain: KeychainService(),
            metadata: metadata,
            authenticator: DeviceAuthenticator(),
            startupIssue: issue
        )
    }

    /// Services that never touch the real `~/.ssh` or Keychain. For SwiftUI previews and UI tests.
    public static func preview() -> ServiceContainer {
        let root = FileManager.default.temporaryDirectory.appending(path: "smp-preview")
        let environment = SSHEnvironment(homeDirectory: root.appending(path: "home"), userName: "preview")
        return make(
            environment: environment,
            supportDirectory: root.appending(path: "support"),
            keychain: InMemoryKeychainService(),
            metadata: inMemoryMetadata(),
            authenticator: FakeAuthenticator()
        )
    }

    private static func inMemoryMetadata() -> any MetadataStoring {
        // An in-memory SQLite database cannot fail to open short of memory exhaustion.
        // swiftlint:disable:next force_try
        try! GRDBMetadataStore.inMemory()
    }
}

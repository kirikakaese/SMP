import AppIntents
import AppKit
import SMPCore
import SMPServices

/// The services of the running app, shared with Shortcuts actions so that tunnels started from
/// Shortcuts are the same ones SMP's window shows.
@MainActor
enum AppContext {
    static var services: ServiceContainer?

    static func current() throws -> ServiceContainer {
        guard let services else {
            throw SMPError(.toolFailed, whatHappened: "SMP is still starting. Try again.")
        }
        return services
    }
}

// MARK: Entities

struct KeyEntity: AppEntity {
    static var typeDisplayRepresentation: TypeDisplayRepresentation { "SSH Key" }
    static var defaultQuery: KeyQuery { KeyQuery() }

    let id: String
    @Property(title: "Name") var name: String
    @Property(title: "Type") var type: String
    @Property(title: "Fingerprint") var fingerprint: String
    @Property(title: "Comment") var comment: String
    @Property(title: "Public Key") var publicKey: String

    init(_ key: ShortcutKey) {
        id = key.id
        name = key.name
        type = key.type
        fingerprint = key.fingerprint
        comment = key.comment
        publicKey = key.publicKey
    }

    var displayRepresentation: DisplayRepresentation {
        DisplayRepresentation(title: "\(name)", subtitle: "\(type) · \(fingerprint)")
    }
}

struct KeyQuery: EntityQuery {
    func entities(for identifiers: [String]) async throws -> [KeyEntity] {
        try await suggestedEntities().filter { identifiers.contains($0.id) }
    }

    func suggestedEntities() async throws -> [KeyEntity] {
        try await AppContext.current().shortcutKeys().map(KeyEntity.init)
    }
}

struct HostEntity: AppEntity {
    static var typeDisplayRepresentation: TypeDisplayRepresentation { "SSH Host" }
    static var defaultQuery: HostQuery { HostQuery() }

    let id: String

    var displayRepresentation: DisplayRepresentation { DisplayRepresentation(title: "\(id)") }
}

struct HostQuery: EntityQuery {
    func entities(for identifiers: [String]) async throws -> [HostEntity] {
        try await suggestedEntities().filter { identifiers.contains($0.id) }
    }

    func suggestedEntities() async throws -> [HostEntity] {
        try await AppContext.current().shortcutHosts().map(HostEntity.init(id:))
    }
}

struct TunnelEntity: AppEntity {
    static var typeDisplayRepresentation: TypeDisplayRepresentation { "SSH Tunnel" }
    static var defaultQuery: TunnelQuery { TunnelQuery() }

    let id: UUID
    let name: String
    let host: String

    var displayRepresentation: DisplayRepresentation {
        DisplayRepresentation(title: "\(name)", subtitle: "via \(host)")
    }
}

struct TunnelQuery: EntityQuery {
    func entities(for identifiers: [UUID]) async throws -> [TunnelEntity] {
        try await suggestedEntities().filter { identifiers.contains($0.id) }
    }

    func suggestedEntities() async throws -> [TunnelEntity] {
        try await AppContext.current().metadata.allTunnels().map {
            TunnelEntity(id: $0.id, name: $0.name, host: $0.hostAlias)
        }
    }
}

// MARK: Actions

struct CopyPublicKeyIntent: AppIntent {
    static var title: LocalizedStringResource { "Copy Public Key" }
    static var description: IntentDescription {
        "Copies an SSH key's public key line to the clipboard and returns it. Private keys never leave SMP."
    }

    @Parameter(title: "Key") var key: KeyEntity

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.publicKey, forType: .string)
        return .result(value: key.publicKey, dialog: "Copied the public key of \(key.name).")
    }
}

struct ListKeysIntent: AppIntent {
    static var title: LocalizedStringResource { "List SSH Keys" }
    static var description: IntentDescription {
        "Returns the keys in ~/.ssh and SMP's key folders with name, type, fingerprint and public key."
    }

    func perform() async throws -> some IntentResult & ReturnsValue<[KeyEntity]> {
        .result(value: try await KeyQuery().suggestedEntities())
    }
}

struct ConnectToHostIntent: AppIntent {
    static var title: LocalizedStringResource { "Connect to SSH Host" }
    static var description: IntentDescription {
        "Opens your terminal app and connects to a host from ~/.ssh/config."
    }

    @Parameter(title: "Host") var host: HostEntity

    @MainActor
    func perform() async throws -> some IntentResult {
        let services = try AppContext.current()
        let preferred = UserDefaults.standard.string(forKey: "terminalApp").flatMap(TerminalApp.init(rawValue:))
        try services.terminal.connect(to: host.id, in: preferred ?? .terminal)
        return .result()
    }
}

struct StartTunnelIntent: AppIntent {
    static var title: LocalizedStringResource { "Start SSH Tunnel" }
    static var description: IntentDescription {
        "Starts a saved tunnel. It runs while SMP is open, like tunnels started in SMP's window."
    }

    @Parameter(title: "Tunnel") var tunnel: TunnelEntity

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let services = try AppContext.current()
        guard let profile = try services.metadata.allTunnels().first(where: { $0.id == tunnel.id }) else {
            throw SMPError.invalidArgument("The tunnel “\(tunnel.name)” no longer exists.")
        }
        try services.tunnels.start(profile)
        return .result(dialog: "Started the tunnel \(tunnel.name).")
    }
}

struct StopTunnelIntent: AppIntent {
    static var title: LocalizedStringResource { "Stop SSH Tunnel" }

    @Parameter(title: "Tunnel") var tunnel: TunnelEntity

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        try AppContext.current().tunnels.stop(id: tunnel.id)
        return .result(dialog: "Stopped the tunnel \(tunnel.name).")
    }
}

struct RunSecurityAuditIntent: AppIntent {
    static var title: LocalizedStringResource { "Check SSH Security" }
    static var description: IntentDescription {
        "Runs SMP's security audit on your keys and ~/.ssh/config and returns the score (0–100)."
    }

    func perform() async throws -> some IntentResult & ReturnsValue<Int> & ProvidesDialog {
        let summary = try await AppContext.current().shortcutAudit()
        return .result(value: summary.score, dialog: "\(summary.sentence)")
    }
}

// MARK: Suggested phrases

struct SMPShortcuts: AppShortcutsProvider {
    @AppShortcutsBuilder
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: CopyPublicKeyIntent(),
            phrases: ["Copy an SSH public key with \(.applicationName)"],
            shortTitle: "Copy Public Key",
            systemImageName: "doc.on.clipboard"
        )
        AppShortcut(
            intent: ListKeysIntent(),
            phrases: ["List my SSH keys in \(.applicationName)"],
            shortTitle: "List SSH Keys",
            systemImageName: "key"
        )
        AppShortcut(
            intent: ConnectToHostIntent(),
            phrases: ["Connect to an SSH host with \(.applicationName)"],
            shortTitle: "Connect to Host",
            systemImageName: "terminal"
        )
        AppShortcut(
            intent: StartTunnelIntent(),
            phrases: ["Start an SSH tunnel with \(.applicationName)"],
            shortTitle: "Start Tunnel",
            systemImageName: "point.3.connected.trianglepath.dotted"
        )
        AppShortcut(
            intent: RunSecurityAuditIntent(),
            phrases: ["Check my SSH security with \(.applicationName)"],
            shortTitle: "Check Security",
            systemImageName: "checkmark.shield"
        )
    }
}

import AppKit
import Observation
import SMPAgent
import SMPCore
import SMPServices
import UserNotifications

/// Runs SMP's agent inside the login-item helper and publishes its state to the menu bar extra.
@MainActor
@Observable
final class AgentController {
    private(set) var isRunning = false
    private(set) var problem: String?
    private(set) var activity: [AgentActivity] = []
    private(set) var secureEnclaveKeyCount = 0
    private(set) var forwardsToSystemAgent = false
    private(set) var socketPath = ""

    @ObservationIgnored private var server: AgentServer?
    @ObservationIgnored private let authorizer = LocalSignatureAuthorizer()
    @ObservationIgnored private let store = SecureEnclaveKeyStore(
        accessGroup: SecureEnclaveKeyStore.bundleAccessGroup()
    )
    @ObservationIgnored private var observers: [NSObjectProtocol] = []

    init() {
        start()
        observeLockAndSleep()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, _ in }
    }

    func start() {
        do {
            let socket = try AgentPaths.socketURL()
            socketPath = socket.path
            let upstream = UnixSocketAgentClient.systemAgent(
                environment: ProcessInfo.processInfo.environment, excluding: socket
            )
            forwardsToSystemAgent = upstream != nil
            let handler = AgentRequestHandler(
                store: store,
                upstream: upstream,
                authorizer: authorizer,
                settings: {
                    AgentSettings.load(from: UserDefaults(suiteName: AgentPaths.sharedDefaultsSuite) ?? .standard)
                },
                record: { [weak self] entry in
                    Task { @MainActor [weak self] in self?.record(entry) }
                }
            )
            let server = AgentServer(socketURL: socket, handler: handler)
            try server.start()
            self.server = server
            isRunning = true
            problem = nil
            refreshKeys()
        } catch {
            isRunning = false
            problem = (error as? SMPError)?.whatHappened ?? error.localizedDescription
            Log.app.error("Agent did not start")
        }
    }

    func stop() {
        server?.stop()
        server = nil
        isRunning = false
    }

    func refreshKeys() {
        secureEnclaveKeyCount = (try? store.keys().count) ?? 0
    }

    var identityAgentLine: String {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let value = AgentPaths.identityAgentValue(for: URL(fileURLWithPath: socketPath), homeDirectory: home)
        return "IdentityAgent " + value
    }

    func copyIdentityAgentLine() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(identityAgentLine, forType: .string)
    }

    func openMainApp() {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: AppPaths.bundleIdentifier) else {
            return
        }
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
    }

    private func record(_ entry: AgentActivity) {
        activity.insert(entry, at: 0)
        if activity.count > 20 {
            activity.removeLast(activity.count - 20)
        }
        refreshKeys()
        if entry.outcome == .signed, entry.detail != nil {
            notify(entry)
        }
    }

    /// Keys with the "notification only" policy sign without a prompt; tell the user each time.
    private func notify(_ entry: AgentActivity) {
        let content = UNMutableNotificationContent()
        content.title = "Signed with “\(entry.keyName)”"
        content.body = "Requested by \(entry.peer)."
        let request = UNNotificationRequest(identifier: entry.id.uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    /// Reuse windows end when the screen locks or the Mac sleeps.
    private func observeLockAndSleep() {
        let reset: @Sendable (Notification) -> Void = { [authorizer] _ in authorizer.reset() }
        observers.append(DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main, using: reset
        ))
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(workspace.addObserver(forName: name, object: nil, queue: .main, using: reset))
        }
    }
}

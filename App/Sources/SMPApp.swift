import SMPCore
import SMPServices
import SMPUI
import SwiftUI

@main
struct SMPApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    private let services: ServiceContainer
    @State private var library: LibraryModel
    @State private var hosts: HostsModel
    @State private var knownHosts: KnownHostsModel
    @State private var tunnels: TunnelsModel
    @State private var agent: AgentModel
    @State private var providers: ProvidersModel
    @State private var security: SecurityModel
    @State private var appLock: AppLockModel
    @State private var appIcon: AppIconModel
    @State private var updates = UpdateModel()

    init() {
        let services = ServiceContainer.live()
        self.services = services
        AppContext.services = services
        _library = State(initialValue: LibraryModel(
            services: services, reminderScheduleURL: try? ReminderSchedule.fileURL()
        ))
        _hosts = State(initialValue: HostsModel(services: services))
        _knownHosts = State(initialValue: KnownHostsModel(services: services))
        _tunnels = State(initialValue: TunnelsModel(services: services))
        _agent = State(initialValue: AgentModel(services: services))
        _providers = State(initialValue: ProvidersModel(services: services))
        _security = State(initialValue: SecurityModel(services: services))
        // On by default, but not before the first-run introduction has been seen.
        let appLock = AppLockModel(
            authenticator: services.authenticator,
            isAvailable: DeviceAuthenticator.isAvailable(),
            startsLocked: OnboardingState.isCompleted()
        )
        appLock.startMonitoring()
        _appLock = State(initialValue: appLock)
        let appIcon = AppIconModel()
        _appIcon = State(initialValue: appIcon)
        // macOS shows the bundle's icon until launching has finished; the chosen one replaces it then.
        _ = NotificationCenter.default.addObserver(
            forName: NSApplication.didFinishLaunchingNotification,
            object: nil,
            queue: .main
        ) { _ in
            MainActor.assumeIsolated { appIcon.apply() }
        }
        // Tunnels are child ssh processes; don't leave them running after SMP quits.
        _ = NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification,
            object: nil,
            queue: .main
        ) { _ in
            services.tunnels.stopAll()
        }
    }

    var body: some Scene {
        WindowGroup(AboutPanel.productName, id: "main") {
            RootView(
                model: library,
                hosts: hosts,
                knownHosts: knownHosts,
                tunnels: tunnels,
                agent: agent,
                providers: providers,
                security: security,
                appLock: appLock
            )
                .environment(\.services, services)
                .frame(minWidth: 960, minHeight: 560)
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About \(AboutPanel.productName)") {
                    AboutPanel.show()
                }
                Button("Check for Updates…") { updates.checkNow() }
                    .disabled(!updates.canCheck)
            }
            CommandGroup(after: .appSettings) {
                Button("Lock SMP") { appLock.lock() }
                    .keyboardShortcut("l", modifiers: [.command, .control])
                    .disabled(!appLock.isAvailable || !appLock.settings.isEnabled)
            }
            SidebarCommands()
            LibraryCommands(model: library)
        }

        Settings {
            SettingsView(library: library, appLock: appLock, appIcon: appIcon) {
                UpdateSettingsView(model: updates)
                    .frame(width: SettingsTab.width, height: SettingsTab.height)
                    .tabItem { Label("Updates", systemImage: "arrow.down.circle") }
            }
        }
    }
}

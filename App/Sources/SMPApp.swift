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

    init() {
        let services = ServiceContainer.live()
        self.services = services
        _library = State(initialValue: LibraryModel(services: services))
        _hosts = State(initialValue: HostsModel(services: services))
        _knownHosts = State(initialValue: KnownHostsModel(services: services))
        _tunnels = State(initialValue: TunnelsModel(services: services))
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
            RootView(model: library, hosts: hosts, knownHosts: knownHosts, tunnels: tunnels)
                .environment(\.services, services)
                .frame(minWidth: 960, minHeight: 560)
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About \(AboutPanel.productName)") {
                    AboutPanel.show()
                }
            }
            SidebarCommands()
            LibraryCommands(model: library)
        }

        Settings {
            SettingsView(library: library)
        }
    }
}

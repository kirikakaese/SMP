import SMPServices
import SMPUI
import SwiftUI

@main
struct SMPApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    private let services: ServiceContainer
    @State private var library: LibraryModel

    init() {
        let services = ServiceContainer.live()
        self.services = services
        _library = State(initialValue: LibraryModel(services: services))
    }

    var body: some Scene {
        WindowGroup(AboutPanel.productName, id: "main") {
            RootView(model: library)
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

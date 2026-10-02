import SMPServices
import SMPUI
import SwiftUI

@main
struct SMPApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    private let services = ServiceContainer.live()

    var body: some Scene {
        WindowGroup(AboutPanel.productName, id: "main") {
            RootView()
                .environment(\.services, services)
                .frame(minWidth: 860, minHeight: 520)
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About \(AboutPanel.productName)") {
                    AboutPanel.show()
                }
            }
        }

        Settings {
            SettingsView()
        }
    }
}

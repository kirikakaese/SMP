import SwiftUI

/// The Settings window. Panes are filled in as features land.
public struct SettingsView: View {
    public init() {}

    public var body: some View {
        TabView {
            Form {
                LabeledContent("Privacy") {
                    Text("SMP collects no telemetry.")
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            .tabItem { Label("General", systemImage: "gearshape") }
        }
        .frame(width: 460, height: 240)
    }
}

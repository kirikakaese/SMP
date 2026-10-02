import SwiftUI

/// The main window: sidebar / list / detail.
public struct RootView: View {
    @State private var selection: SidebarItem? = .allKeys

    public init() {}

    public var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section("Library") {
                    ForEach(SidebarItem.allCases) { item in
                        Label(item.title, systemImage: item.systemImage)
                            .tag(item)
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 220)
        } content: {
            ContentUnavailableView(
                "No Keys Yet",
                systemImage: "key",
                description: Text("Key discovery arrives in the next milestone.")
            )
            .navigationTitle(selection?.title ?? "SMP")
            .navigationSplitViewColumnWidth(min: 260, ideal: 320)
        } detail: {
            ContentUnavailableView("No Selection", systemImage: "sidebar.right")
        }
    }
}


import SMPCore
import SwiftUI

/// The main window: sidebar / key list / key detail.
public struct RootView: View {
    @Bindable private var model: LibraryModel

    public init(model: LibraryModel) {
        self.model = model
    }

    public var body: some View {
        NavigationSplitView {
            SidebarView(model: model)
        } content: {
            KeyListView(model: model)
        } detail: {
            if let item = model.selectedItem {
                KeyDetailView(model: model, item: item)
            } else if model.selectedKeyIDs.count > 1 {
                ContentUnavailableView(
                    "\(model.selectedKeyIDs.count) Keys Selected",
                    systemImage: "key.horizontal"
                )
            } else {
                ContentUnavailableView("No Selection", systemImage: "key", description: Text("Select a key."))
            }
        }
        .task {
            await model.reload()
            model.startWatching()
        }
        .alert(
            isPresented: Binding(get: { model.lastError != nil }, set: { if !$0 { model.lastError = nil } }),
            error: model.lastError
        ) { _ in
            Button("OK") { model.lastError = nil }
        } message: { error in
            Text([error.howToFix, error.details].compactMap { $0 }.joined(separator: "\n\n"))
        }
    }
}

import SMPCore
import SwiftUI

/// The main window: sidebar / key list / key detail.
public struct RootView: View {
    @Bindable private var model: LibraryModel
    @Environment(\.undoManager) private var undoManager

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
        .sheet(item: $model.activeSheet) { sheet in
            LibrarySheetHost(model: model, sheet: sheet)
        }
        .overlay(alignment: .bottom) {
            if let notice = model.notice {
                NoticeBanner(text: notice) { model.notice = nil }
            }
        }
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first, model.activeSheet == nil else { return false }
            model.activeSheet = .importKey(url)
            return true
        }
        .onChange(of: undoManager, initial: true) { model.windowUndoManager = undoManager }
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

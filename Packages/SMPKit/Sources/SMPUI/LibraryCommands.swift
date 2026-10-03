import SwiftUI

/// Menu bar commands for the key library.
public struct LibraryCommands: Commands {
    private let model: LibraryModel

    public init(model: LibraryModel) {
        self.model = model
    }

    public var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Key…") { model.activeSheet = .newKey }
                .keyboardShortcut("n")
            Button("New Secure Enclave Key…") { model.activeSheet = .newSecureEnclaveKey }
                .keyboardShortcut("n", modifiers: [.command, .option])
            Button("Import Key…") { model.activeSheet = .importKey(nil) }
                .keyboardShortcut("i")
            Button("Download Keys from Security Key…") { model.activeSheet = .downloadResidentKeys }
        }
        CommandGroup(after: .importExport) {
            Button("Back Up…") { model.activeSheet = .backup }
                .keyboardShortcut("b", modifiers: [.command, .shift])
            Button("Restore from Backup…") { model.activeSheet = .restoreBackup }
        }
        CommandMenu("Key") {
            KeyMenuContent(model: model)
        }
    }
}

/// Separate view so the menu observes the selection and the undo manager.
private struct KeyMenuContent: View {
    let model: LibraryModel
    @Environment(\.undoManager) private var undoManager

    var body: some View {
        let selected = model.selectedItems
        let single = selected.count == 1 ? selected.first : nil
        let onDisk = selected.filter { !$0.isArchived }

        Button("Copy Public Key") {
            if let single { KeyActions.copyPublicKey(single) }
        }
        .keyboardShortcut("c", modifiers: [.command, .shift])
        .disabled(single?.key.publicKey == nil)

        Divider()
        if let single, !single.isArchived {
            KeyEditMenuItems(model: model, item: single)
        }
        Divider()

        // ⌘⌫ / ⌥⌘⌫ are handled by the key list itself (see KeyListView), so they never
        // fire while the user is editing text such as notes.
        Button(onDisk.count > 1
            ? String(localized: "Archive \(onDisk.count) Keys (⌘⌫)")
            : String(localized: "Archive (⌘⌫)")) {
            Task { await model.archive(onDisk, undoManager: undoManager) }
        }
        .disabled(onDisk.isEmpty)

        Button("Delete… (⌥⌘⌫)") { model.activeSheet = .delete(selected) }
            .disabled(selected.isEmpty)
    }
}

import AppKit
import SMPCore

/// Side-effecting actions on a key. None of them reads private key contents.
@MainActor
enum KeyActions {
    static func copyPublicKey(_ item: LibraryItem) {
        guard let line = item.key.publicKey?.openSSHLine else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(line, forType: .string)
    }

    static func revealInFinder(_ item: LibraryItem) {
        let urls = [item.key.privateKeyFile?.url, item.key.publicKeyFile?.url].compactMap { $0 }
        NSWorkspace.shared.activateFileViewerSelecting(urls)
    }

    /// Opens Terminal in the key's folder. Choosing another terminal app arrives in milestone 4.
    static func openInTerminal(_ item: LibraryItem) {
        let folder = item.key.primaryFile.url.deletingLastPathComponent()
        guard let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else {
            return
        }
        NSWorkspace.shared.open([folder], withApplicationAt: terminal, configuration: NSWorkspace.OpenConfiguration())
    }
}

extension KeyActions {
    /// Asks where to save the public key, then writes it.
    static func savePublicKey(_ item: LibraryItem, model: LibraryModel) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = item.key.name + ".pub"
        panel.title = String(localized: "Save Public Key")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try model.exportPublicKey(item, to: url)
        } catch {
            model.report(error, whatHappened: String(localized: "SMP could not save the public key."))
        }
    }

    /// Asks for a destination, then exports the private key after Touch ID / password.
    static func exportPrivateKey(_ item: LibraryItem, model: LibraryModel) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = item.key.name
        panel.title = String(localized: "Export Private Key")
        panel.message = String(localized: """
            Anyone with this file can use the key unless it has a passphrase. Store it securely.
            """)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do {
                try await model.exportPrivateKey(item, to: url)
            } catch {
                model.report(error, whatHappened: String(localized: "SMP could not export the private key."))
            }
        }
    }
}

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

import SwiftUI

/// Presents the sheet for a `LibrarySheet` value.
struct LibrarySheetHost: View {
    let model: LibraryModel
    let sheet: LibrarySheet

    var body: some View {
        switch sheet {
        case .newKey:
            NewKeySheet(model: model)
        case .importKey(let url):
            ImportKeySheet(model: model, initialURL: url)
        case .rename(let item):
            RenameKeySheet(model: model, item: item)
        case .changePassphrase(let item):
            ChangePassphraseSheet(model: model, item: item)
        case .changeComment(let item):
            ChangeCommentSheet(model: model, item: item)
        case .upgradeFormat(let item):
            UpgradeFormatSheet(model: model, item: item)
        case .delete(let items):
            DeleteKeySheet(model: model, items: items)
        case .qrCode(let item):
            QRCodeSheet(item: item)
        case .deploy(let item):
            DeployKeySheet(library: model, item: item)
        }
    }
}

/// A transient confirmation at the bottom of the window.
struct NoticeBanner: View {
    let text: String
    let onDismiss: () -> Void

    var body: some View {
        HStack {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            Text(text)
            Button {
                onDismiss()
            } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Dismiss")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(.regularMaterial, in: Capsule())
        .shadow(radius: 4)
        .padding(.bottom, 16)
        .task(id: text) {
            try? await Task.sleep(for: .seconds(6))
            onDismiss()
        }
    }
}

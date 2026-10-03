import SMPCore
import SMPServices
import SwiftUI

/// The middle column: the filtered, searchable, sortable list of keys.
struct KeyListView: View {
    @Bindable var model: LibraryModel
    @Environment(\.undoManager) private var undoManager

    var body: some View {
        List(model.visibleItems, selection: $model.selectedKeyIDs) { item in
            KeyRow(item: item, tags: model.tags(for: item))
        }
        .contextMenu(forSelectionType: String.self) { ids in
            let selected = model.items.filter { ids.contains($0.id) }
            if selected.count == 1, let item = selected.first {
                KeyActionsMenu(model: model, item: item)
            } else if selected.count > 1 {
                BulkActionsMenu(model: model, items: selected)
            }
        } primaryAction: { ids in
            model.selectedKeyIDs = ids
        }
        .onKeyPress(keys: [.delete]) { press in
            guard press.modifiers.contains(.command), !model.selectedItems.isEmpty else { return .ignored }
            if press.modifiers.contains(.option) {
                model.activeSheet = .delete(model.selectedItems)
            } else {
                let onDisk = model.selectedItems.filter { !$0.isArchived }
                Task { await model.archive(onDisk, undoManager: undoManager) }
            }
            return .handled
        }
        .overlay {
            if model.visibleItems.isEmpty, !model.isLoading {
                if model.searchText.isEmpty {
                    ContentUnavailableView(
                        "No Keys",
                        systemImage: "key",
                        description: Text("Keys in ~/.ssh and your added folders appear here.")
                    )
                } else {
                    ContentUnavailableView.search(text: model.searchText)
                }
            }
        }
        .searchable(text: $model.searchText, placement: .toolbar, prompt: "Name, comment, fingerprint or tag")
        .navigationTitle(title)
        .navigationSplitViewColumnWidth(min: 280, ideal: 340)
        .toolbar {
            ToolbarItem {
                Menu {
                    Picker("Sort By", selection: $model.sortOrder) {
                        ForEach(KeySortOrder.allCases) { Text($0.title).tag($0) }
                    }
                    .pickerStyle(.inline)
                } label: {
                    Label("Sort", systemImage: "arrow.up.arrow.down")
                }
            }
            ToolbarItem {
                Menu {
                    Button("New Key…") { model.activeSheet = .newKey }
                    Button("New Secure Enclave Key…") { model.activeSheet = .newSecureEnclaveKey }
                    Divider()
                    Button("Import Key…") { model.activeSheet = .importKey(nil) }
                    Button("Download Keys from Security Key…") { model.activeSheet = .downloadResidentKeys }
                } label: {
                    Label("Add Key", systemImage: "plus")
                } primaryAction: {
                    model.activeSheet = .newKey
                }
                .help("Create a new key (⌘N) or import one (⌘I)")
            }
            ToolbarItem {
                Button {
                    Task { await model.reload() }
                } label: {
                    Label("Rescan", systemImage: "arrow.clockwise")
                }
                .keyboardShortcut("r")
                .help("Rescan key folders (⌘R)")
            }
        }
    }

    private var title: String {
        switch model.sidebarSelection {
        case .library(let item): item.title
        case .tag(let id): model.tags.first { $0.id == id }?.name ?? "Tag"
        case .group(let id): model.groups.first { $0.id == id }?.name ?? "Group"
        case .ssh(let section): section.title
        case nil: "Keys"
        }
    }
}

/// One row in the key list.
struct KeyRow: View {
    let item: LibraryItem
    let tags: [KeyTag]

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: iconName)
                .font(.title2)
                .foregroundStyle(item.key.kind == .publicOnly ? Color.secondary : Color.accentColor)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(item.displayName).fontWeight(.medium).lineLimit(1)
                    ForEach(tags) { tag in
                        Circle().fill(tag.color.color).frame(width: 7, height: 7)
                            .accessibilityHidden(true)
                    }
                }
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            if item.isLoadedInAgent {
                Image(systemName: "person.badge.key.fill").foregroundStyle(.green).help("Loaded in agent")
            }
            if item.isFavorite {
                Image(systemName: "star.fill").foregroundStyle(.yellow).help("Favorite")
            }
            if item.needsAttention {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange).help("Needs attention")
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityText)
    }

    private var iconName: String {
        if item.key.algorithm.isSecurityKey { return "cable.connector" }
        switch item.key.kind {
        case .pair: return "key.fill"
        case .privateOnly: return "key"
        case .publicOnly: return "key.slash"
        }
    }

    private var subtitle: String {
        var parts = [item.key.algorithm.displayName]
        if let bits = item.key.publicKey?.bitLength, item.key.algorithm == .rsa || item.key.algorithm == .dsa {
            parts[0] += " \(bits)"
        }
        if !item.key.comment.isEmpty {
            parts.append(item.key.comment)
        }
        return parts.joined(separator: " · ")
    }

    private var accessibilityText: String {
        var parts = [item.displayName, subtitle]
        if item.isLoadedInAgent { parts.append("loaded in agent") }
        if item.isFavorite { parts.append("favorite") }
        if item.needsAttention { parts.append("needs attention") }
        return parts.joined(separator: ", ")
    }
}

/// Actions shared by the context menu and the detail toolbar.
struct KeyActionsMenu: View {
    let model: LibraryModel
    let item: LibraryItem
    @Environment(\.undoManager) private var undoManager

    var body: some View {
        Button("Copy Public Key") { KeyActions.copyPublicKey(item) }
            .disabled(item.key.publicKey == nil)
        if item.isArchived {
            Button("Restore from Archive") {
                if let archive = item.archive {
                    Task { await model.restore(archiveID: archive.id) }
                }
            }
            Button("Delete Permanently…") { model.activeSheet = .delete([item]) }
        } else {
            Button("Reveal in Finder") { KeyActions.revealInFinder(item) }
            Button("Open in Terminal") { KeyActions.openInTerminal(item) }
            Divider()
            KeyEditMenuItems(model: model, item: item)
            Divider()
            Button("Archive") { Task { await model.archive([item], undoManager: undoManager) } }
            Button("Delete…") { model.activeSheet = .delete([item]) }
        }
        Divider()
        Button(item.isFavorite ? "Remove from Favorites" : "Add to Favorites") {
            model.setFavorite(!item.isFavorite, for: item)
        }
        .disabled(!item.canStoreMetadata)
        if !model.tags.isEmpty {
            Menu("Tags") {
                ForEach(model.tags) { tag in
                    Toggle(tag.name, isOn: Binding(
                        get: { item.tagIDs.contains(tag.id) },
                        set: { _ in model.toggleTag(tag.id, for: item) }
                    ))
                }
            }
            .disabled(!item.canStoreMetadata)
        }
        if !model.groups.isEmpty {
            Menu("Groups") {
                ForEach(model.groups) { group in
                    Toggle(group.name, isOn: Binding(
                        get: { item.groupIDs.contains(group.id) },
                        set: { _ in model.toggleGroup(group.id, for: item) }
                    ))
                }
            }
            .disabled(!item.canStoreMetadata)
        }
    }
}

/// Rename, passphrase, comment, format and export actions for one key on disk.
struct KeyEditMenuItems: View {
    let model: LibraryModel
    let item: LibraryItem

    var body: some View {
        if item.isSecureEnclave {
            secureEnclaveItems
        } else {
            fileKeyItems
        }
    }

    /// The private half of a Secure Enclave key cannot be renamed, re-encrypted or exported.
    @ViewBuilder private var secureEnclaveItems: some View {
        Button("Show QR Code") { model.activeSheet = .qrCode(item) }
        Button("Save Public Key…") { KeyActions.savePublicKey(item, model: model) }
        Button("Deploy to Server…") { model.activeSheet = .deploy(item) }
    }

    @ViewBuilder private var fileKeyItems: some View {
        let hasPrivateKey = item.key.privateKeyFile != nil
        let format = item.key.privateKeyInfo?.format
        Button("Rename…") { model.activeSheet = .rename(item) }
        Button("Change Passphrase…") { model.activeSheet = .changePassphrase(item) }
            .disabled(!hasPrivateKey || format == .putty)
        Button("Change Comment…") { model.activeSheet = .changeComment(item) }
            .disabled(format != .openSSH)
        if format == .pem || format == .pkcs8 {
            Button("Upgrade to OpenSSH Format…") { model.activeSheet = .upgradeFormat(item) }
        }
        Menu("Export") {
            Button("Save Public Key…") { KeyActions.savePublicKey(item, model: model) }
                .disabled(item.key.publicKey == nil)
            Button("Show QR Code") { model.activeSheet = .qrCode(item) }
                .disabled(item.key.publicKey == nil)
            Divider()
            Button("Export Private Key…") { KeyActions.exportPrivateKey(item, model: model) }
                .disabled(!hasPrivateKey)
        }
        Button("Deploy to Server…") { model.activeSheet = .deploy(item) }
            .disabled(item.key.publicKey == nil || item.isArchived)
    }
}

/// Actions for several selected keys.
struct BulkActionsMenu: View {
    let model: LibraryModel
    let items: [LibraryItem]
    @Environment(\.undoManager) private var undoManager

    var body: some View {
        let onDisk = items.filter { !$0.isArchived }
        if !onDisk.isEmpty {
            Button("Archive \(onDisk.count) Keys") { Task { await model.archive(onDisk, undoManager: undoManager) } }
        }
        Button("Delete \(items.count) Keys…") { model.activeSheet = .delete(items) }
    }
}

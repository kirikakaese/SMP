import SMPCore
import SwiftUI

extension TagColor {
    var color: Color {
        switch self {
        case .gray: .gray
        case .red: .red
        case .orange: .orange
        case .yellow: .yellow
        case .green: .green
        case .mint: .mint
        case .teal: .teal
        case .blue: .blue
        case .indigo: .indigo
        case .purple: .purple
        case .pink: .pink
        }
    }

    var title: String { rawValue.capitalized }
}

/// The library sidebar: fixed sections, then user tags and groups.
struct SidebarView: View {
    @Bindable var model: LibraryModel
    let providers: ProvidersModel

    @State private var isAddingTag = false
    @State private var newGroupName = ""
    @State private var isAddingGroup = false
    @State private var pendingDeletion: SidebarSelection?
    @State private var pendingAccountRemoval: ProviderAccount?

    var body: some View {
        List(selection: $model.sidebarSelection) {
            Section("Library") {
                ForEach(SidebarItem.allCases) { item in
                    Label(item.title, systemImage: item.systemImage)
                        .badge(model.count(for: item))
                        .tag(SidebarSelection.library(item))
                }
            }
            Section("SSH") {
                ForEach(SSHSection.allCases) { section in
                    Label(section.title, systemImage: section.systemImage)
                        .tag(SidebarSelection.ssh(section))
                }
            }
            Section("Providers") {
                ForEach(providers.accounts) { account in
                    Label(account.displayName, systemImage: account.kind.systemImage)
                        .badge(providers.keys(for: account).count)
                        .tag(SidebarSelection.provider(account.id))
                        .contextMenu {
                            Button("Refresh") { Task { await providers.refresh(account) } }
                            Button("Remove from SMP…", role: .destructive) { pendingAccountRemoval = account }
                        }
                }
                Button {
                    providers.isAddingAccount = true
                } label: {
                    Label("Add Account…", systemImage: "plus.circle")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
            if !model.tags.isEmpty {
                Section("Tags") {
                    ForEach(model.tags) { tag in
                        Label {
                            Text(tag.name)
                        } icon: {
                            Image(systemName: "tag.fill").foregroundStyle(tag.color.color)
                        }
                        .tag(SidebarSelection.tag(tag.id))
                        .contextMenu {
                            Button("Delete Tag…", role: .destructive) { pendingDeletion = .tag(tag.id) }
                        }
                    }
                }
            }
            if !model.groups.isEmpty {
                Section("Groups") {
                    ForEach(model.groups) { group in
                        Label(group.name, systemImage: "folder")
                            .tag(SidebarSelection.group(group.id))
                            .contextMenu {
                                Button("Delete Group…", role: .destructive) { pendingDeletion = .group(group.id) }
                            }
                    }
                }
            }
        }
        .navigationSplitViewColumnWidth(min: 190, ideal: 230)
        .safeAreaInset(edge: .bottom) {
            HStack {
                Menu {
                    Button("New Tag…") { isAddingTag = true }
                    Button("New Group…") { isAddingGroup = true }
                } label: {
                    Image(systemName: "plus")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel("Add tag or group")
                Spacer()
            }
            .padding(8)
        }
        .sheet(isPresented: $isAddingTag) {
            NewTagSheet { name, color in
                model.createTag(named: name, color: color)
            }
        }
        .alert("New Group", isPresented: $isAddingGroup) {
            TextField("Name", text: $newGroupName)
            Button("Create") {
                model.createGroup(named: newGroupName)
                newGroupName = ""
            }
            Button("Cancel", role: .cancel) { newGroupName = "" }
        }
        .confirmationDialog(
            deletionTitle,
            isPresented: Binding(get: { pendingDeletion != nil }, set: { if !$0 { pendingDeletion = nil } })
        ) {
            Button("Delete", role: .destructive) {
                switch pendingDeletion {
                case .tag(let id): model.deleteTag(id: id)
                case .group(let id): model.deleteGroup(id: id)
                default: break
                }
                pendingDeletion = nil
            }
        } message: {
            Text("Keys are not deleted. Only the assignment is removed.")
        }
        .confirmationDialog(
            "Remove \(pendingAccountRemoval?.displayName ?? "") from SMP?",
            isPresented: Binding(
                get: { pendingAccountRemoval != nil }, set: { if !$0 { pendingAccountRemoval = nil } }
            )
        ) {
            Button("Remove", role: .destructive) {
                if let account = pendingAccountRemoval {
                    if model.sidebarSelection == .provider(account.id) {
                        model.sidebarSelection = .library(.allKeys)
                    }
                    providers.removeAccount(account)
                }
                pendingAccountRemoval = nil
            }
        } message: {
            Text("SMP deletes the account's token from the Keychain. Keys on the provider stay as they are.")
        }
        .sheet(isPresented: Binding(get: { providers.isAddingAccount }, set: { providers.isAddingAccount = $0 })) {
            AddProviderAccountSheet(providers: providers)
        }
    }

    private var deletionTitle: String {
        switch pendingDeletion {
        case .tag(let id): "Delete the tag “\(model.tags.first { $0.id == id }?.name ?? "")”?"
        case .group(let id): "Delete the group “\(model.groups.first { $0.id == id }?.name ?? "")”?"
        default: ""
        }
    }
}

/// Asks for a tag's name and color.
struct NewTagSheet: View {
    let onCreate: (String, TagColor) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var color: TagColor = .blue

    var body: some View {
        Form {
            TextField("Name", text: $name)
            Picker("Color", selection: $color) {
                ForEach(TagColor.allCases, id: \.self) { color in
                    Label {
                        Text(color.title)
                    } icon: {
                        Image(systemName: "circle.fill").foregroundStyle(color.color)
                    }
                    .tag(color)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 320)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Create") {
                    onCreate(name, color)
                    dismiss()
                }
                .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }
}

import AppKit
import QuickLook
import SMPCore
import SMPServices
import SMPSSH
import SwiftUI

/// The right column: everything known about one key.
struct KeyDetailView: View {
    let model: LibraryModel
    let item: LibraryItem

    @State private var notesDraft = ""
    @State private var nameDraft = ""
    @State private var quickLookURL: URL?

    var body: some View {
        Form {
            header
            if !item.key.issues.isEmpty || item.isExpired() {
                attentionSection
            }
            fingerprintSection
            detailsSection
            filesSection
            organizeSection
        }
        .formStyle(.grouped)
        .navigationTitle(item.displayName)
        .quickLookPreview($quickLookURL)
        .toolbar { toolbarContent }
        .onAppear(perform: loadDrafts)
        .onChange(of: item.id) { loadDrafts() }
    }

    // MARK: Sections

    private var header: some View {
        Section {
            HStack(alignment: .top, spacing: 16) {
                if let publicKey = item.key.publicKey, !publicKey.isCertificate {
                    Text(Randomart.render(publicKey))
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .accessibilityLabel("Randomart image of the key fingerprint")
                }
                VStack(alignment: .leading, spacing: 6) {
                    TextField("Name", text: $nameDraft)
                        .font(.title2.weight(.semibold))
                        .textFieldStyle(.plain)
                        .disabled(!item.canStoreMetadata)
                        .onSubmit { model.setDisplayName(nameDraft, for: item) }
                        .accessibilityLabel("Display name")
                    Text(item.key.algorithm.displayName + bitsSuffix)
                        .foregroundStyle(.secondary)
                    if !item.key.comment.isEmpty {
                        Text(item.key.comment).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
            }
        }
    }

    private var attentionSection: some View {
        Section("Needs Attention") {
            ForEach(Array(item.key.issues.enumerated()), id: \.offset) { _, issue in
                Label(issue.summary, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            if item.isExpired() {
                Label("This key passed its expiry date.", systemImage: "calendar.badge.exclamationmark")
                    .foregroundStyle(.orange)
            }
        }
    }

    private var fingerprintSection: some View {
        Section("Fingerprints") {
            if let publicKey = item.key.publicKey {
                copyableRow("SHA256", value: publicKey.fingerprintSHA256)
                copyableRow("MD5", value: publicKey.fingerprintMD5)
            } else {
                Text("The public key is not available for this file.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var detailsSection: some View {
        Section("Details") {
            LabeledContent("Type", value: item.key.algorithm.displayName)
            if let bits = item.key.publicKey?.bitLength {
                LabeledContent("Size", value: "\(bits) bits")
            }
            LabeledContent("Passphrase", value: passphraseText)
            if let info = item.key.privateKeyInfo {
                LabeledContent("Format", value: info.format.displayName)
                if let rounds = info.kdfRounds {
                    LabeledContent("KDF rounds", value: "\(rounds)")
                }
            }
            LabeledContent("Agent", value: agentText)
            if item.key.certificate != nil {
                LabeledContent("Certificate", value: "Present")
            }
        }
    }

    private var filesSection: some View {
        Section("Files") {
            if let file = item.key.privateKeyFile {
                fileRow("Private key", file: file)
            }
            if let file = item.key.publicKeyFile {
                fileRow("Public key", file: file)
            }
            if let file = item.key.certificateFile {
                fileRow("Certificate", file: file)
            }
        }
    }

    private var organizeSection: some View {
        Section("Organize") {
            Toggle("Favorite", isOn: Binding(
                get: { item.isFavorite },
                set: { model.setFavorite($0, for: item) }
            ))
            if !model.tags.isEmpty {
                tagsRow
            }
            if !model.groups.isEmpty {
                groupsRow
            }
            expiryRows
            notesEditor
        }
        .disabled(!item.canStoreMetadata)
    }

    private var tagsRow: some View {
        LabeledContent("Tags") {
            HStack {
                ForEach(model.tags(for: item)) { tag in
                    Text(tag.name)
                        .font(.caption)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(tag.color.color.opacity(0.2), in: Capsule())
                }
                Menu("Edit") {
                    ForEach(model.tags) { tag in
                        Toggle(tag.name, isOn: Binding(
                            get: { item.tagIDs.contains(tag.id) },
                            set: { _ in model.toggleTag(tag.id, for: item) }
                        ))
                    }
                }
                .fixedSize()
            }
        }
    }

    private var groupsRow: some View {
        LabeledContent("Groups") {
            Menu(model.groups(for: item).map(\.name).joined(separator: ", ").ifEmpty("None")) {
                ForEach(model.groups) { group in
                    Toggle(group.name, isOn: Binding(
                        get: { item.groupIDs.contains(group.id) },
                        set: { _ in model.toggleGroup(group.id, for: item) }
                    ))
                }
            }
            .fixedSize()
        }
    }

    @ViewBuilder
    private var expiryRows: some View {
        Toggle("Expires", isOn: Binding(
            get: { item.metadata?.expiresAt != nil },
            set: { enabled in
                let oneYearFromNow = Calendar.current.date(byAdding: .year, value: 1, to: Date())
                model.setExpiry(enabled ? oneYearFromNow : nil, for: item)
            }
        ))
        if let expiry = item.metadata?.expiresAt {
            DatePicker("Expiry date", selection: Binding(
                get: { expiry },
                set: { model.setExpiry($0, for: item) }
            ), displayedComponents: .date)
        }
    }

    private var notesEditor: some View {
        VStack(alignment: .leading) {
            Text("Notes")
            TextEditor(text: $notesDraft)
                .font(.body)
                .frame(minHeight: 70)
                .scrollContentBackground(.hidden)
                .onChange(of: notesDraft) { _, newValue in
                    if newValue != (item.metadata?.notes ?? "") {
                        model.setNotes(newValue, for: item)
                    }
                }
                .accessibilityLabel("Notes")
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItemGroup {
            Button {
                KeyActions.copyPublicKey(item)
            } label: {
                Label("Copy Public Key", systemImage: "doc.on.doc")
            }
            .keyboardShortcut("c", modifiers: [.command, .shift])
            .help("Copy the public key (⇧⌘C)")
            .disabled(item.key.publicKey == nil)

            Button {
                quickLookURL = item.key.publicKeyFile?.url
            } label: {
                Label("Quick Look", systemImage: "eye")
            }
            .keyboardShortcut("y")
            .help("Preview the public key (⌘Y)")
            .disabled(item.key.publicKeyFile == nil)

            Button {
                KeyActions.revealInFinder(item)
            } label: {
                Label("Reveal in Finder", systemImage: "folder")
            }
            .keyboardShortcut("r", modifiers: [.command, .shift])
            .help("Reveal in Finder (⇧⌘R)")

            Button {
                KeyActions.openInTerminal(item)
            } label: {
                Label("Open in Terminal", systemImage: "terminal")
            }
            .help("Open the key's folder in Terminal")
        }
    }

    // MARK: Helpers

    private var bitsSuffix: String {
        guard let bits = item.key.publicKey?.bitLength, item.key.algorithm.fixedBitLength == nil else { return "" }
        return " · \(bits) bits"
    }

    private var passphraseText: String {
        switch item.key.isPassphraseProtected {
        case true?: "Protected"
        case false?: "None"
        case nil: item.key.privateKeyFile == nil ? "No private key" : "Unknown"
        }
    }

    private var agentText: String {
        switch model.agentStatus {
        case .unavailable: "Agent not available"
        case .running: item.isLoadedInAgent ? "Loaded" : "Not loaded"
        }
    }

    private func copyableRow(_ title: String, value: String) -> some View {
        LabeledContent(title) {
            HStack {
                Text(value)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy \(title) fingerprint")
                .accessibilityLabel("Copy \(title) fingerprint")
            }
        }
    }

    private func fileRow(_ title: String, file: KeyFileInfo) -> some View {
        LabeledContent(title) {
            VStack(alignment: .trailing, spacing: 2) {
                Text(file.url.path(percentEncoded: false))
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.head)
                Text(fileDetails(file))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func fileDetails(_ file: KeyFileInfo) -> String {
        var parts = [file.symbolicPermissions + " (" + String(file.permissions, radix: 8) + ")"]
        if let created = file.createdAt {
            parts.append("created " + created.formatted(date: .abbreviated, time: .shortened))
        }
        if let modified = file.modifiedAt {
            parts.append("modified " + modified.formatted(date: .abbreviated, time: .shortened))
        }
        if file.isSymbolicLink {
            parts.append("symlink")
        }
        return parts.joined(separator: " · ")
    }

    private func loadDrafts() {
        notesDraft = item.metadata?.notes ?? ""
        nameDraft = item.displayName
    }
}

extension String {
    fileprivate func ifEmpty(_ replacement: String) -> String {
        isEmpty ? replacement : self
    }
}

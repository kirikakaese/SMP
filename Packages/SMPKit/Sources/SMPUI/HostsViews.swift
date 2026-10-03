import SMPCore
import SMPServices
import SMPSSH
import SwiftUI

/// The middle column for the Hosts section.
struct HostListView: View {
    @Bindable var model: HostsModel
    @State private var isAddingHost = false
    @State private var rawEditorFile: LoadedConfigFile?

    var body: some View {
        List(model.visibleHosts, selection: $model.selectedHostID) { host in
            HostRow(model: model, host: host)
        }
        .overlay {
            if model.visibleHosts.isEmpty {
                ContentUnavailableView(
                    model.searchText.isEmpty ? "No Hosts" : "No Matches",
                    systemImage: "server.rack",
                    description: Text(model.searchText.isEmpty
                        ? String(localized: "Add a host, or edit ~/.ssh/config directly.")
                        : "")
                )
            }
        }
        .searchable(text: $model.searchText, placement: .toolbar, prompt: "Alias, host name or user")
        .navigationTitle("Hosts")
        .navigationSplitViewColumnWidth(min: 260, ideal: 320)
        .toolbar {
            ToolbarItem {
                Button {
                    isAddingHost = true
                } label: {
                    Label("Add Host", systemImage: "plus")
                }
                .help("Add a host to ~/.ssh/config")
            }
            ToolbarItem {
                Menu {
                    ForEach(model.files, id: \.url) { file in
                        Button(file.url.path(percentEncoded: false)) { rawEditorFile = file }
                    }
                    if model.files.isEmpty {
                        Text("~/.ssh/config does not exist yet")
                    }
                } label: {
                    Label("Edit Config", systemImage: "doc.text")
                }
                .help("Edit the config file as text")
            }
            ToolbarItem {
                Button {
                    model.reload()
                } label: {
                    Label("Reload", systemImage: "arrow.clockwise")
                }
                .keyboardShortcut("r")
            }
        }
        .sheet(isPresented: $isAddingHost) { NewHostSheet(model: model) }
        .sheet(item: $rawEditorFile) { file in RawConfigEditorSheet(model: model, file: file) }
        .sheet(item: $model.pendingChange) { change in ConfigDiffSheet(model: model, change: change) }
        .task { model.reload() }
    }
}

struct HostRow: View {
    let model: HostsModel
    let host: HostEntry

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: host.block.isWildcard ? "asterisk.circle" : "server.rack")
                .font(.title3)
                .foregroundStyle(host.block.isWildcard ? Color.secondary : Color.accentColor)
                .frame(width: 26)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(host.block.patterns.joined(separator: " ")).fontWeight(.medium).lineLimit(1)
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 4)
            if model.metadata[host.alias]?.isFavorite == true {
                Image(systemName: "star.fill").foregroundStyle(.yellow).accessibilityLabel("Favorite")
            }
            statusIcon
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }

    private var subtitle: String {
        if host.block.isWildcard { return String(localized: "Defaults for matching hosts") }
        let user = host.block.value(of: "User").map { "\($0)@" } ?? ""
        let name = host.block.value(of: "HostName") ?? host.alias
        let port = host.block.value(of: "Port").map { ":\($0)" } ?? ""
        return user + name + port
    }

    @ViewBuilder
    private var statusIcon: some View {
        if model.testsRunning.contains(host.alias) {
            ProgressView().controlSize(.small)
        } else {
            switch model.testResults[host.alias] {
            case .success:
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green).help("Last test succeeded")
            case .failure:
                Image(systemName: "xmark.octagon.fill").foregroundStyle(.red).help("Last test failed")
            case nil: EmptyView()
            }
        }
    }
}

/// The detail column for one host.
struct HostDetailView: View {
    let model: HostsModel
    let library: LibraryModel
    let host: HostEntry

    @AppStorage("terminalApp") private var terminalApp: TerminalApp = .terminal
    @State private var drafts: [String: String] = [:]
    @State private var effective: [(key: String, value: String)] = []
    @State private var aliasPrompt: AliasPrompt?
    @State private var confirmDelete = false
    @State private var showsServerKeys = false
    @State private var notesDraft = ""

    enum AliasPrompt: String, Identifiable {
        case duplicate, rename
        var id: String { rawValue }
    }

    var body: some View {
        Form {
            headerSection
            if let result = model.testResults[host.alias] {
                ConnectionResultView(result: result, host: host.alias)
            }
            fieldsSection
            otherOptionsSection
            organizeSection
            effectiveSection
        }
        .formStyle(.grouped)
        .navigationTitle(host.alias)
        .toolbar { toolbar }
        .onAppear(perform: loadDrafts)
        .onChange(of: host) { loadDrafts() }
        .sheet(item: $aliasPrompt) { prompt in
            AliasPromptSheet(title: prompt == .duplicate ? "Duplicate Host" : "Rename Host",
                             initial: prompt == .duplicate ? host.alias + "-copy" : host.alias) { alias in
                if prompt == .duplicate {
                    model.proposeDuplicate(host, as: alias)
                } else {
                    model.proposeRename(host, to: alias)
                }
            }
        }
        .sheet(isPresented: $showsServerKeys) {
            AuthorizedKeysSheet(hosts: model, library: library, host: host.alias)
        }
        .confirmationDialog("Delete the host “\(host.alias)”?", isPresented: $confirmDelete) {
            Button("Review Deletion…", role: .destructive) { model.proposeDelete(host) }
        } message: {
            Text("You'll see the change to \(host.file.lastPathComponent) before it is saved. A backup is kept.")
        }
    }

    // MARK: Sections

    private var headerSection: some View {
        Section {
            LabeledContent("Defined in") {
                Text("\(host.file.path(percentEncoded: false)), line \(host.block.headerLine + 1)")
                    .textSelection(.enabled)
                    .foregroundStyle(.secondary)
            }
            if host.block.patterns.count > 1 {
                LabeledContent("Also matches", value: host.block.patterns.dropFirst().joined(separator: " "))
            }
            if host.block.isWildcard {
                Text("This block sets defaults for every host matching its patterns.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private var fieldsSection: some View {
        Section {
            ForEach(SSHConfigKeywords.common, id: \.self) { keyword in
                fieldRow(keyword)
            }
            HStack {
                Spacer()
                Button("Revert") { loadDrafts() }
                    .disabled(changedEdits.isEmpty)
                Button("Review & Save…") { model.proposeEdits(changedEdits, on: host) }
                    .keyboardShortcut("s")
                    .disabled(changedEdits.isEmpty)
            }
        } header: {
            Text("Settings")
        } footer: {
            Text("IdentityFile, LocalForward and RemoteForward take one value per line. Empty fields are removed.")
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func fieldRow(_ keyword: String) -> some View {
        let binding = Binding(get: { drafts[keyword] ?? "" }, set: { drafts[keyword] = $0 })
        if SSHConfigKeywords.repeatable.contains(keyword.lowercased()) {
            LabeledContent(keyword) {
                TextEditor(text: binding)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 36)
                    .accessibilityLabel(keyword)
            }
        } else if ["IdentitiesOnly", "ForwardAgent", "UseKeychain", "AddKeysToAgent"].contains(keyword) {
            Picker(keyword, selection: binding) {
                Text("Not set").tag("")
                Text("yes").tag("yes")
                Text("no").tag("no")
                if keyword == "AddKeysToAgent" {
                    Text("ask").tag("ask")
                    Text("confirm").tag("confirm")
                }
            }
        } else {
            TextField(keyword, text: binding, prompt: Text(placeholder(for: keyword)))
                .font(.system(.body, design: .monospaced))
        }
        if keyword == "ForwardAgent", drafts[keyword] == "yes", host.block.isWildcard {
            Label("ForwardAgent on a wildcard host exposes your agent to every matching server.",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.caption)
                .foregroundStyle(.orange)
        }
    }

    private var otherOptionsSection: some View {
        let shown = Set(SSHConfigKeywords.common.map { $0.lowercased() })
        let others = host.block.options.filter { !shown.contains($0.normalizedKeyword) }
        return Section("Other Options") {
            if others.isEmpty {
                Text("None").foregroundStyle(.secondary)
            }
            ForEach(others, id: \.lineIndex) { option in
                LabeledContent(option.keyword) {
                    HStack {
                        Text(option.rawValue).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        if !SSHConfigKeywords.known.contains(option.normalizedKeyword) {
                            Image(systemName: "questionmark.circle")
                                .foregroundStyle(.orange)
                                .help("SMP doesn't recognize this option. Check for a typo.")
                        }
                    }
                }
            }
            Text("Edit other options in the text editor (toolbar → Edit Config).")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var organizeSection: some View {
        Section("Organize") {
            Toggle("Favorite", isOn: Binding(
                get: { model.metadata[host.alias]?.isFavorite ?? false },
                set: { model.setFavorite($0, for: host) }
            ))
            if !library.tags.isEmpty {
                LabeledContent("Tags") {
                    Menu(tagSummary) {
                        ForEach(library.tags) { tag in
                            Toggle(tag.name, isOn: Binding(
                                get: { model.hostTags[host.alias]?.contains(tag.id) ?? false },
                                set: { _ in model.toggleTag(tag.id, for: host) }
                            ))
                        }
                    }
                    .fixedSize()
                }
            }
            TextField("Notes", text: $notesDraft, axis: .vertical)
                .lineLimit(2...5)
                .onSubmit { model.setNotes(notesDraft, for: host) }
                .onChange(of: notesDraft) { _, value in
                    if value != (model.metadata[host.alias]?.notes ?? "") {
                        model.setNotes(value, for: host)
                    }
                }
            if let last = model.metadata[host.alias]?.lastConnectedAt {
                LabeledContent("Last opened", value: last.formatted(date: .abbreviated, time: .shortened))
            }
        }
    }

    private var effectiveSection: some View {
        Section {
            DisclosureGroup("Effective configuration (ssh -G)") {
                if effective.isEmpty {
                    Button("Resolve") { Task { effective = await model.effectiveConfig(host) } }
                }
                ForEach(effective, id: \.key) { entry in
                    LabeledContent(entry.key) {
                        Text(entry.value).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                }
            }
            .disabled(host.block.isWildcard)
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup {
            Menu {
                ForEach(model.installedTerminals()) { app in
                    Button("Open in \(app.displayName)") { model.connect(host, in: app) }
                }
            } label: {
                Label("Connect", systemImage: "terminal")
            } primaryAction: {
                model.connect(host, in: terminalApp)
            }
            .disabled(host.block.isWildcard)
            .help("Connect in \(terminalApp.displayName)")

            Button {
                Task { await model.testConnection(host) }
            } label: {
                Label("Test Connection", systemImage: "bolt.horizontal.circle")
            }
            .disabled(host.block.isWildcard || model.testsRunning.contains(host.alias))
            .help("Try to log in without prompting (BatchMode)")

            Menu {
                Button("Copy ssh Command") { model.copyCommand(host) }
                Button("Authorized Keys on Server…") { showsServerKeys = true }
                    .disabled(host.block.isWildcard)
                Divider()
                Button("Duplicate…") { aliasPrompt = .duplicate }
                Button("Rename…") { aliasPrompt = .rename }
                Divider()
                Button("Delete…", role: .destructive) { confirmDelete = true }
            } label: {
                Label("More", systemImage: "ellipsis.circle")
            }
        }
    }

    // MARK: Helpers

    private var tagSummary: String {
        let ids = model.hostTags[host.alias] ?? []
        let names = library.tags.filter { ids.contains($0.id) }.map(\.name)
        return names.isEmpty ? String(localized: "None") : names.joined(separator: ", ")
    }

    private func placeholder(for keyword: String) -> String {
        switch keyword {
        case "HostName": "server.example.com"
        case "User": "Your user name on the server"
        case "Port": "22"
        case "ProxyJump": "bastion"
        default: ""
        }
    }

    private func loadDrafts() {
        var values: [String: String] = [:]
        for keyword in SSHConfigKeywords.common {
            values[keyword] = host.block.values(of: keyword).joined(separator: "\n")
        }
        drafts = values
        notesDraft = model.metadata[host.alias]?.notes ?? ""
        effective = []
    }

    private var changedEdits: [(keyword: String, values: [String])] {
        SSHConfigKeywords.common.compactMap { keyword in
            let original = host.block.values(of: keyword)
            let draft = (drafts[keyword] ?? "")
                .split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            let values = SSHConfigKeywords.repeatable.contains(keyword.lowercased()) ? draft : Array(draft.prefix(1))
            return values == original ? nil : (keyword, values)
        }
    }
}

/// Explains a connection test result, with a shortcut to fix host key problems.
struct ConnectionResultView: View {
    let result: ConnectionTestResult
    let host: String

    var body: some View {
        Section {
            switch result {
            case .success(let message):
                Label("Connection works", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                if !message.isEmpty {
                    Text(message).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
            case .failure(let problem, let details):
                Label(problem.title, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
                Text(problem.howToFix).font(.callout)
                if problem == .unknownHostKey || problem == .hostKeyChanged {
                    Text("Open Known Hosts in the sidebar to "
                        + (problem == .unknownHostKey ? "add" : "verify and replace") + " the key for \(host).")
                        .font(.callout).foregroundStyle(.secondary)
                }
                if !details.isEmpty {
                    DisclosureGroup("Details") {
                        Text(details).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                }
            }
        }
    }
}

import SMPCore
import SMPServices
import SwiftUI

extension ProviderKind {
    var systemImage: String {
        switch self {
        case .github: "chevron.left.forwardslash.chevron.right"
        case .gitlab: "square.stack.3d.up"
        case .bitbucket: "bucket"
        case .gitea: "cup.and.saucer"
        }
    }
}

extension RemoteKey {
    var usageSummary: String {
        RemoteKeyUsage.allCases.filter(usages.contains).map(\.title).joined(separator: " & ")
    }
}

/// The middle column for one provider account: its keys, matched against local keys.
struct ProviderKeysView: View {
    @Bindable var providers: ProvidersModel
    let library: LibraryModel
    let account: ProviderAccount
    @State private var isUploading = false

    var body: some View {
        let keys = providers.keys(for: account)
        List(keys, selection: $providers.selectedKeyID) { key in
            RemoteKeyRow(key: key, localName: localItem(for: key)?.displayName)
        }
        .overlay {
            if keys.isEmpty {
                ContentUnavailableView(
                    "No SSH Keys",
                    systemImage: "key",
                    description: Text("Upload a key from your library to use it with \(account.kind.displayName).")
                )
            }
        }
        .navigationTitle(account.displayName)
        .navigationSubtitle(syncText)
        .navigationSplitViewColumnWidth(min: 300, ideal: 360)
        .toolbar {
            ToolbarItem {
                Button {
                    isUploading = true
                } label: {
                    Label("Upload Key", systemImage: "square.and.arrow.up")
                }
                .help("Upload a public key from your library")
            }
            ToolbarItem {
                Button {
                    Task { await providers.refresh(account) }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(providers.refreshing.contains(account.id))
            }
        }
        .sheet(isPresented: $isUploading) {
            UploadKeySheet(providers: providers, library: library, item: nil, account: account)
        }
        .task(id: account.id) { await providers.refreshIfStale(account) }
    }

    private var syncText: String {
        if providers.refreshing.contains(account.id) { return String(localized: "Refreshing…") }
        guard let synced = account.lastSyncedAt else { return String(localized: "Not refreshed yet") }
        let when = synced.formatted(.relative(presentation: .named))
        return String(localized: "Updated \(when)")
    }

    private func localItem(for key: RemoteKey) -> LibraryItem? {
        library.items.first { $0.key.fingerprint != nil && $0.key.fingerprint == key.fingerprint }
    }
}

struct RemoteKeyRow: View {
    let key: RemoteKey
    let localName: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(key.title.isEmpty ? String(localized: "Untitled key") : key.title).fontWeight(.medium).lineLimit(1)
                Spacer()
                Text(key.usageSummary).font(.caption).foregroundStyle(.secondary)
            }
            if let localName {
                Label("Matches “\(localName)”", systemImage: "checkmark.circle.fill")
                    .font(.caption).foregroundStyle(.green)
            } else {
                Label("Not on this Mac", systemImage: "questionmark.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// The detail column for one remote key.
struct RemoteKeyDetailView: View {
    let providers: ProvidersModel
    let library: LibraryModel
    @State private var confirmRemoval = false

    var body: some View {
        if let key = providers.selectedKey, let account = providers.account(key.accountID) {
            let local = library.items.first { $0.key.fingerprint != nil && $0.key.fingerprint == key.fingerprint }
            Form {
                Section {
                    LabeledContent("Title", value: key.title)
                    LabeledContent("Account", value: account.displayName)
                    LabeledContent("Used for", value: key.usageSummary)
                    if let fingerprint = key.fingerprint {
                        LabeledContent("Fingerprint") {
                            Text(fingerprint).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                    if let created = key.createdAt {
                        LabeledContent("Added", value: created.formatted(date: .abbreviated, time: .shortened))
                    }
                    if let used = key.lastUsedAt {
                        LabeledContent("Last used", value: used.formatted(date: .abbreviated, time: .shortened))
                    }
                    if let expires = key.expiresAt {
                        LabeledContent("Expires", value: expires.formatted(date: .abbreviated, time: .omitted))
                    }
                }
                Section("On this Mac") {
                    if let local {
                        LabeledContent("Local key", value: local.displayName)
                        let hosts = providers.hostsUsing(local)
                        LabeledContent(
                            "Used by hosts",
                            value: hosts.isEmpty ? "None in ~/.ssh/config" : hosts.joined(separator: ", ")
                        )
                        Button("Show in Library") {
                            library.sidebarSelection = .library(.allKeys)
                            library.selectedKeyIDs = [local.id]
                        }
                    } else {
                        Text("No key with this fingerprint was found in your key folders.")
                            .foregroundStyle(.secondary)
                    }
                }
                Section {
                    Button("Remove from \(account.kind.displayName)…", role: .destructive) { confirmRemoval = true }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(key.title)
            .confirmationDialog(
                "Remove “\(key.title)” from \(account.displayName)?",
                isPresented: $confirmRemoval
            ) {
                Button("Remove Key", role: .destructive) { Task { await providers.delete(key) } }
            } message: {
                Text(removalMessage(local: local))
            }
        } else {
            ContentUnavailableView("No Key Selected", systemImage: "key")
        }
    }

    private func removalMessage(local: LibraryItem?) -> String {
        guard let local else {
            return String(localized: """
                No local key matches it, so it may belong to another computer. This cannot be undone.
                """)
        }
        let hosts = providers.hostsUsing(local)
        let hostText = hosts.isEmpty ? "" : " Hosts using it: \(hosts.joined(separator: ", "))."
        return String(localized: """
            Your local key “\(local.displayName)” will no longer work with this account.\(hostText) \
            You can upload it again later. Touch ID or your password is required.
            """)
    }
}

/// Adds a provider account with a personal access token.
struct AddProviderAccountSheet: View {
    let providers: ProvidersModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    @State private var kind: ProviderKind = .github
    @State private var selfHosted = false
    @State private var server = ""
    @State private var email = ""
    @State private var token = ""
    @State private var isWorking = false
    @State private var error: SMPError?

    var body: some View {
        Form {
            Section {
                Picker("Provider", selection: $kind) {
                    ForEach(ProviderKind.allCases) { Text($0.displayName).tag($0) }
                }
                if kind == .github || kind == .gitlab {
                    Toggle("Self-hosted server", isOn: $selfHosted)
                }
                if needsServer {
                    TextField("Server", text: $server, prompt: Text("https://git.example.com"))
                }
                if kind.needsUsername {
                    TextField("Atlassian account email", text: $email)
                }
                SecureField("Personal access token", text: $token)
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Required permissions: \(kind.requiredScopes).")
                    Text("The token is checked with \(kind.displayName), then stored only in your Keychain.")
                    if let url = tokenURL {
                        Button("Create a token…") { openURL(url) }
                            .buttonStyle(.link)
                    }
                }
                .foregroundStyle(.secondary)
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .disabled(isWorking)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(isWorking
                    ? String(localized: "Checking…")
                    : String(localized: "Add Account")) { Task { await add() } }
                    .disabled(token.isEmpty || (needsServer && server.isEmpty) || (kind.needsUsername && email.isEmpty))
            }
        }
    }

    private var needsServer: Bool { kind == .gitea || selfHosted }

    private var serverURL: URL? {
        needsServer ? URL(string: server.trimmingCharacters(in: .whitespaces)) : kind.defaultServerURL
    }

    private var tokenURL: URL? {
        serverURL.flatMap { kind.tokenSettingsURL(server: $0) }
    }

    private func add() async {
        isWorking = true
        error = nil
        defer { isWorking = false }
        let secret = SecureBytes(utf8: token.trimmingCharacters(in: .whitespacesAndNewlines))
        defer { secret.wipe() }
        do {
            _ = try await providers.addAccount(
                kind: kind,
                serverURL: serverURL,
                loginEmail: kind.needsUsername ? email.trimmingCharacters(in: .whitespaces) : nil,
                token: secret
            )
            token = ""
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

/// Uploads a library key to a provider account.
struct UploadKeySheet: View {
    let providers: ProvidersModel
    let library: LibraryModel
    @Environment(\.dismiss) private var dismiss

    @State private var itemID: String?
    @State private var accountID: UUID?
    @State private var title = ""
    @State private var forAuthentication = true
    @State private var forSigning = false
    @State private var isWorking = false
    @State private var error: SMPError?

    init(
        providers: ProvidersModel,
        library: LibraryModel,
        item: LibraryItem?,
        account: ProviderAccount?,
        signing: Bool = false
    ) {
        self.providers = providers
        self.library = library
        _forAuthentication = State(initialValue: !signing)
        _forSigning = State(initialValue: signing)
        _itemID = State(initialValue: item?.id)
        _accountID = State(initialValue: account?.id ?? providers.accounts.first?.id)
        _title = State(initialValue: item.map(Self.defaultTitle) ?? "")
    }

    private var uploadable: [LibraryItem] {
        library.items.filter { !$0.isArchived && $0.key.publicKey != nil && $0.key.publicKey?.isCertificate == false }
    }

    private var item: LibraryItem? { uploadable.first { $0.id == itemID } }
    private var account: ProviderAccount? { accountID.flatMap(providers.account) }

    var body: some View {
        Form {
            Picker("Key", selection: $itemID) {
                Text("Choose a key").tag(String?.none)
                ForEach(uploadable) { Text($0.displayName).tag(Optional($0.id)) }
            }
            .onChange(of: itemID) { if let item { title = Self.defaultTitle(item) } }
            Picker("Account", selection: $accountID) {
                ForEach(providers.accounts) { Text($0.displayName).tag(Optional($0.id)) }
            }
            TextField("Title", text: $title)
            Toggle("Use for authentication (git push/pull over SSH)", isOn: $forAuthentication)
            Toggle("Use for signing commits", isOn: $forSigning)
                .disabled(account?.kind.supportsSigningKeys != true)
            if let item, let account, !providers.remoteKeys(matching: item.key.fingerprint)
                .filter({ $0.accountID == account.id }).isEmpty {
                Label("This key is already on \(account.displayName).", systemImage: "info.circle")
                    .foregroundStyle(.secondary)
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 500)
        .disabled(isWorking)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(isWorking
                    ? String(localized: "Uploading…")
                    : String(localized: "Upload")) { Task { await upload() } }
                    .disabled(item == nil || account == nil || usages.isEmpty || title.isEmpty)
            }
        }
    }

    private var usages: Set<RemoteKeyUsage> {
        var result: Set<RemoteKeyUsage> = []
        if forAuthentication { result.insert(.authentication) }
        if forSigning, account?.kind.supportsSigningKeys == true { result.insert(.signing) }
        return result
    }

    static func defaultTitle(_ item: LibraryItem) -> String {
        let comment = item.key.comment.trimmingCharacters(in: .whitespaces)
        return comment.isEmpty ? item.displayName : comment
    }

    private func upload() async {
        guard let item, let account else { return }
        isWorking = true
        error = nil
        defer { isWorking = false }
        do {
            try await providers.upload(item, to: account, title: title, usages: usages)
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

/// "On providers" in the key detail: where this key is uploaded, and an upload button.
struct KeyProvidersSection: View {
    let providers: ProvidersModel
    let library: LibraryModel
    let item: LibraryItem
    @State private var isUploading = false

    var body: some View {
        let remote = providers.remoteKeys(matching: item.key.fingerprint)
        Section("On Providers") {
            if remote.isEmpty {
                Text(providers.accounts.isEmpty
                    ? "Add a provider account in the sidebar to upload keys."
                    : "Not on any of your provider accounts.")
                    .foregroundStyle(.secondary)
            }
            ForEach(remote) { key in
                LabeledContent(providers.account(key.accountID)?.displayName ?? "Unknown account") {
                    Text("\(key.title) · \(key.usageSummary)").foregroundStyle(.secondary)
                }
            }
            if !providers.accounts.isEmpty, item.key.publicKey != nil {
                Button("Upload to Provider…") { isUploading = true }
            }
        }
        .sheet(isPresented: $isUploading) {
            UploadKeySheet(providers: providers, library: library, item: item, account: nil)
        }
    }
}

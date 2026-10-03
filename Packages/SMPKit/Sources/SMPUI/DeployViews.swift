import SMPCore
import SMPServices
import SMPSSH
import SwiftUI

/// Copies a public key to a server's authorized_keys (like ssh-copy-id), then optionally tests it.
struct DeployKeySheet: View {
    let library: LibraryModel
    let item: LibraryItem
    @Environment(\.dismiss) private var dismiss

    enum Step: Equatable {
        case idle, installing, verifying, done(String), failed
    }

    @State private var aliases: [String] = []
    @State private var host = ""
    @State private var usePassword = false
    @State private var password = ""
    @State private var verify = true
    @State private var keyPassphrase = ""
    @State private var step: Step = .idle
    @State private var verification: ConnectionTestResult?
    @State private var error: SMPError?

    var body: some View {
        Form {
            Section {
                LabeledContent("Key", value: item.displayName)
                if let fingerprint = item.key.fingerprint {
                    LabeledContent("Fingerprint") {
                        Text(fingerprint).font(.system(.caption, design: .monospaced))
                    }
                }
            }
            Section {
                TextField("Server", text: $host, prompt: Text("alias from ~/.ssh/config or user@host"))
                if !aliases.isEmpty {
                    Menu("Choose a Host") {
                        ForEach(aliases, id: \.self) { alias in Button(alias) { host = alias } }
                    }
                    .fixedSize()
                }
                Toggle("Log in with a password", isOn: $usePassword)
                if usePassword {
                    SecureField("Server password", text: $password)
                    Text("Used once to install the key, through a private pipe. It is never stored.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } header: {
                Text("Server")
            } footer: {
                Text("The server's host key must already be in Known Hosts.").foregroundStyle(.secondary)
            }
            Section {
                Toggle("Test a login with this key afterwards", isOn: $verify)
                    .disabled(item.key.privateKeyFile == nil)
                if verify, item.key.isPassphraseProtected == true {
                    SecureField("Key passphrase (for the test)", text: $keyPassphrase)
                }
            }
            Section("Progress") {
                progressRow("Install the public key", active: step == .installing, done: installFinished)
                if verify {
                    progressRow("Test the login", active: step == .verifying, done: isDone)
                }
                if case .done(let message) = step {
                    Label(message, systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                }
                if let verification {
                    ConnectionResultView(result: verification, host: host)
                }
                if let error {
                    ErrorBanner(error: error)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .disabled(step == .installing || step == .verifying)
        .task {
            let entries = (try? library.services.hosts.hosts()) ?? []
            aliases = entries.filter { !$0.block.isWildcard }.map(\.alias)
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(isDone ? "Close" : "Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Deploy") { Task { await deploy() } }
                    .disabled(HostAlias.problem(with: host) != nil || item.key.publicKey == nil || isDone)
            }
        }
    }

    private var isDone: Bool { if case .done = step { true } else { false } }

    private var installFinished: Bool {
        switch step {
        case .verifying, .done: true
        default: false
        }
    }

    private func progressRow(_ title: String, active: Bool, done: Bool) -> some View {
        HStack {
            if active {
                ProgressView().controlSize(.small)
            } else {
                Image(systemName: done ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(done ? Color.green : Color.secondary)
            }
            Text(title)
        }
    }

    private func deploy() async {
        guard let publicKey = item.key.publicKey else { return }
        error = nil
        verification = nil
        step = .installing
        let secret = usePassword ? SecureBytes.passphrase(password) : nil
        defer { secret?.wipe() }
        do {
            let outcome = try await library.services.deploy.install(publicKey, on: host, password: secret)
            password = ""
            if verify, let keyFile = item.key.privateKeyFile?.url {
                step = .verifying
                let keySecret = SecureBytes.passphrase(keyPassphrase)
                verification = await library.services.deploy.verifyLogin(
                    on: host, keyFile: keyFile, passphrase: keySecret
                )
                keySecret?.wipe()
                keyPassphrase = ""
            }
            step = .done(outcome == .added ? "The key was added to \(host)." : "\(host) already had this key.")
        } catch {
            step = .failed
            self.error = error.asSMPError
        }
    }
}

/// Lists and removes keys in a server's authorized_keys.
struct AuthorizedKeysSheet: View {
    let hosts: HostsModel
    let library: LibraryModel
    let host: String
    @Environment(\.dismiss) private var dismiss

    @State private var entries: [AuthorizedKeysEntry] = []
    @State private var usePassword = false
    @State private var password = ""
    @State private var isLoading = false
    @State private var loaded = false
    @State private var pendingRemoval: AuthorizedKeysEntry?
    @State private var error: SMPError?

    var body: some View {
        Form {
            Section {
                Toggle("Log in with a password", isOn: $usePassword)
                if usePassword {
                    SecureField("Server password", text: $password)
                }
                Button(isLoading ? "Loading…" : (loaded ? "Reload" : "Load Keys")) { Task { await load() } }
                    .disabled(isLoading)
            } header: {
                Text("~/.ssh/authorized_keys on \(host)")
            }
            if loaded {
                Section("\(entries.count) key(s)") {
                    ForEach(entries) { entry in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(title(for: entry))
                                    .fontWeight(localName(for: entry) == nil ? .regular : .semibold)
                                Text("\(entry.publicKey.algorithm.displayName) · \(entry.publicKey.fingerprintSHA256)")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                if let options = entry.options {
                                    Text(options).font(.caption).foregroundStyle(.orange)
                                }
                            }
                            Spacer()
                            Button("Remove…", role: .destructive) { pendingRemoval = entry }
                        }
                    }
                }
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 600, height: 460)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }
            }
        }
        .confirmationDialog(
            "Remove this key from \(host)?",
            isPresented: Binding(get: { pendingRemoval != nil }, set: { if !$0 { pendingRemoval = nil } })
        ) {
            Button("Remove", role: .destructive) {
                if let entry = pendingRemoval {
                    Task { await remove(entry) }
                }
            }
        } message: {
            Text("Anyone using this key loses access to \(host). If it is the key you are logged in with, "
                + "make sure you have another way in. A backup is kept on the server as authorized_keys.smp-backup.")
        }
    }

    private func title(for entry: AuthorizedKeysEntry) -> String {
        if let name = localName(for: entry) { return name }
        return entry.publicKey.comment.isEmpty ? "No comment" : entry.publicKey.comment
    }

    /// The local key with the same fingerprint, if any.
    private func localName(for entry: AuthorizedKeysEntry) -> String? {
        library.items.first { $0.key.fingerprint == entry.publicKey.fingerprintSHA256 }?.displayName
    }

    private func load() async {
        isLoading = true
        error = nil
        defer { isLoading = false }
        let secret = usePassword ? SecureBytes.passphrase(password) : nil
        defer { secret?.wipe() }
        do {
            entries = try await library.services.deploy.authorizedKeys(on: host, password: secret)
            loaded = true
        } catch {
            self.error = error.asSMPError
        }
    }

    private func remove(_ entry: AuthorizedKeysEntry) async {
        let secret = usePassword ? SecureBytes.passphrase(password) : nil
        defer { secret?.wipe() }
        do {
            try await library.services.deploy.remove(entry, from: host, password: secret)
            await load()
        } catch {
            self.error = error.asSMPError
        }
    }
}

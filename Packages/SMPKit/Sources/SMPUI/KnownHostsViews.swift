import SMPCore
import SMPServices
import SMPSSH
import SwiftUI

/// The middle column for the Known Hosts section.
struct KnownHostsListView: View {
    @Bindable var model: KnownHostsModel
    @State private var confirmRemoval = false

    var body: some View {
        List(model.visibleEntries, selection: $model.selectedLines) { entry in
            KnownHostRow(entry: entry)
                .tag(entry.lineIndex)
        }
        .overlay {
            if model.visibleEntries.isEmpty {
                ContentUnavailableView(
                    model.searchText.isEmpty ? "No Known Hosts" : "No Matching Keys",
                    systemImage: "checkmark.shield",
                    description: Text(model.searchText.isEmpty
                        ? "Hosts you connect to are remembered here."
                        : "Search also matches hashed entries by host name.")
                )
            }
        }
        .searchable(text: $model.searchText, placement: .toolbar, prompt: "Host, host:port or fingerprint")
        .navigationTitle("Known Hosts")
        .navigationSplitViewColumnWidth(min: 280, ideal: 340)
        .toolbar {
            ToolbarItem {
                Button {
                    model.addRequest = HostKeyRequest(host: "")
                } label: {
                    Label("Add Host Key", systemImage: "plus")
                }
                .help("Fetch, verify and add a server's host key")
            }
            ToolbarItem {
                Button(role: .destructive) {
                    confirmRemoval = true
                } label: {
                    Label("Remove", systemImage: "trash")
                }
                .disabled(model.selectedLines.isEmpty)
            }
        }
        .confirmationDialog(
            "Remove \(model.selectedLines.count) host key(s)?",
            isPresented: $confirmRemoval
        ) {
            Button("Remove", role: .destructive) { model.remove(lines: model.selectedLines) }
        } message: {
            Text("""
                SSH will ask you to verify these hosts again on the next connection. \
                A backup of known_hosts is kept.
                """)
        }
        .sheet(item: $model.addRequest) { request in AddHostKeySheet(model: model, initial: request) }
        .sheet(item: $model.changedKeyRequest) { request in ChangedHostKeySheet(model: model, request: request) }
        .task { model.reload() }
    }
}

struct KnownHostRow: View {
    let entry: KnownHostsEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 4) {
                if entry.isHashed {
                    Image(systemName: "number").foregroundStyle(.secondary).help("Hashed host name")
                }
                Text(entry.isHashed ? String(localized: "Hashed entry") : entry.hostPatterns.joined(separator: ", "))
                    .fontWeight(.medium)
                    .lineLimit(1)
                if let marker = entry.marker {
                    Text(marker.rawValue).font(.caption).foregroundStyle(.orange)
                }
            }
            Text(subtitle)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .accessibilityElement(children: .combine)
    }

    private var subtitle: String {
        let type = entry.publicKey?.algorithm.displayName ?? String(localized: "Unknown key")
        return "\(type) · \(entry.publicKey?.fingerprintSHA256 ?? "")"
    }
}

/// The detail column for the Known Hosts section.
struct KnownHostDetailView: View {
    let model: KnownHostsModel

    var body: some View {
        let selected = model.entries.filter { model.selectedLines.contains($0.lineIndex) }
        if selected.count == 1, let entry = selected.first {
            Form {
                Section("Host") {
                    if entry.isHashed {
                        LabeledContent("Host name", value: String(localized: "Hashed (HashKnownHosts)"))
                        Text("Search for a host name to find out whether this entry belongs to it.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        LabeledContent("Patterns", value: entry.hostPatterns.joined(separator: ", "))
                    }
                    if let marker = entry.marker {
                        LabeledContent("Marker", value: marker.rawValue)
                    }
                    LabeledContent("Line", value: "\(entry.lineIndex + 1)")
                }
                if let key = entry.publicKey {
                    Section("Key") {
                        LabeledContent("Type", value: key.algorithm.displayName)
                        LabeledContent("SHA256") {
                            Text(key.fingerprintSHA256)
                                .font(.system(.body, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        LabeledContent("MD5") {
                            Text(key.fingerprintMD5)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        Text(Randomart.render(key)).font(.system(size: 11, design: .monospaced))
                    }
                }
                if !entry.isHashed, let host = entry.hostPatterns.first, !host.contains("*") {
                    Section {
                        Button("The host key changed… Verify and replace") {
                            let (name, port) = KnownHostsModel.split(host)
                            model.changedKeyRequest = HostKeyRequest(host: name, port: port)
                        }
                    }
                }
            }
            .formStyle(.grouped)
        } else {
            ContentUnavailableView(
                selected.isEmpty ? "No Selection" : "\(selected.count) Keys Selected",
                systemImage: "checkmark.shield",
                description: Text("\(model.entries.count) keys, \(model.hashedCount) with hashed host names.")
            )
        }
    }
}

/// Fetches a server's host keys with ssh-keyscan and adds them after the user verified a fingerprint.
struct AddHostKeySheet: View {
    let model: KnownHostsModel
    let initial: HostKeyRequest
    @Environment(\.dismiss) private var dismiss

    @State private var host = ""
    @State private var port = "22"
    @State private var keys: [SSHPublicKey] = []
    @State private var expected = ""
    @State private var acceptUnverified = false
    @State private var isScanning = false
    @State private var error: SMPError?

    var body: some View {
        Form {
            Section {
                TextField("Host", text: $host, prompt: Text("server.example.com"))
                TextField("Port", text: $port)
                Button(isScanning
                    ? String(localized: "Fetching…")
                    : String(localized: "Fetch Host Keys")) { Task { await scan() } }
                    .disabled(host.isEmpty || isScanning)
            } footer: {
                Text("""
                    Fetching a key does not prove it belongs to the server. Compare the fingerprint with one \
                    you got through another channel (the server's admin, the provider's documentation).
                    """)
                    .foregroundStyle(.secondary)
            }
            if !keys.isEmpty {
                Section("Keys presented by \(host)") {
                    ForEach(keys, id: \.blob) { key in
                        FingerprintRow(key: key, expected: expected)
                    }
                    TextField("Expected fingerprint", text: $expected, prompt: Text("SHA256:… (paste to verify)"))
                        .font(.system(.body, design: .monospaced))
                    if verifiedKey == nil {
                        Toggle("I checked the fingerprint another way and trust these keys", isOn: $acceptUnverified)
                    }
                }
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 560)
        .onAppear {
            host = initial.host
            port = String(initial.port)
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Add to Known Hosts") { add() }
                    .disabled(keys.isEmpty || (verifiedKey == nil && !acceptUnverified))
            }
        }
    }

    private var request: HostKeyRequest { HostKeyRequest(host: host, port: Int(port) ?? 22) }

    private var verifiedKey: SSHPublicKey? {
        keys.first { KnownHostsService.fingerprint(expected, matches: $0) }
    }

    private func scan() async {
        isScanning = true
        error = nil
        defer { isScanning = false }
        do {
            keys = try await model.scan(request)
        } catch {
            self.error = error.asSMPError
        }
    }

    private func add() {
        do {
            // With a verified fingerprint, only add that key; otherwise the user accepted all.
            try model.add(verifiedKey.map { [$0] } ?? keys, for: request)
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

/// Guided flow for "REMOTE HOST IDENTIFICATION HAS CHANGED".
struct ChangedHostKeySheet: View {
    let model: KnownHostsModel
    let request: HostKeyRequest
    @Environment(\.dismiss) private var dismiss

    @State private var current: [SSHPublicKey] = []
    @State private var expected = ""
    @State private var isScanning = false
    @State private var error: SMPError?

    var body: some View {
        Form {
            Section {
                Label("Stop and verify before you continue.", systemImage: "exclamationmark.shield.fill")
                    .foregroundStyle(.red)
                    .font(.headline)
                Text("""
                    A changed host key is expected after a server is reinstalled, but it can also mean someone \
                    is intercepting your connection. Ask the server's admin (or check the provider's published \
                    fingerprints) for the new key's fingerprint and paste it below.
                    """)
            }
            Section("Stored keys for \(request.host)") {
                let stored = model.storedEntries(for: request)
                if stored.isEmpty {
                    Text("None").foregroundStyle(.secondary)
                }
                ForEach(stored) { entry in
                    if let key = entry.publicKey {
                        FingerprintRow(key: key, expected: "")
                    }
                }
            }
            Section("Keys the server presents now") {
                Button(isScanning
                    ? String(localized: "Fetching…")
                    : String(localized: "Fetch Current Keys")) { Task { await scan() } }
                    .disabled(isScanning)
                ForEach(current, id: \.blob) { key in
                    FingerprintRow(key: key, expected: expected)
                }
                TextField("Verified fingerprint", text: $expected, prompt: Text("SHA256:…"))
                    .font(.system(.body, design: .monospaced))
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 580)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Replace Stored Key") { replace() }
                    .disabled(verifiedKey == nil)
                    .help("Only possible after the pasted fingerprint matches a key the server presents.")
            }
        }
    }

    private var verifiedKey: SSHPublicKey? {
        current.first { KnownHostsService.fingerprint(expected, matches: $0) }
    }

    private func scan() async {
        isScanning = true
        error = nil
        defer { isScanning = false }
        do {
            current = try await model.scan(request)
        } catch {
            self.error = error.asSMPError
        }
    }

    private func replace() {
        guard let verifiedKey else { return }
        do {
            try model.replace([verifiedKey], for: request)
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

/// A key's type and fingerprint, marked when it matches an expected fingerprint.
struct FingerprintRow: View {
    let key: SSHPublicKey
    let expected: String

    var body: some View {
        let matches = KnownHostsService.fingerprint(expected, matches: key)
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(key.algorithm.displayName).font(.callout)
                Text(key.fingerprintSHA256)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }
            Spacer()
            if matches {
                Label("Verified", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

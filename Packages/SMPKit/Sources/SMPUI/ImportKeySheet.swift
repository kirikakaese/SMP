import SMPCore
import SMPServices
import SMPSSH
import SwiftUI
import UniformTypeIdentifiers

/// Imports an existing key from a file (picker or drag & drop) or pasted text.
struct ImportKeySheet: View {
    let model: LibraryModel
    let initialURL: URL?
    @Environment(\.dismiss) private var dismiss

    @State private var source: SecureBytes?
    @State private var sourceLabel = ""
    @State private var info: PrivateKeyInfo?
    @State private var isPublicKeyOnly = false
    @State private var pastedText = ""
    @State private var isChoosingFile = false
    @State private var isDropTargeted = false

    @State private var fileName = ""
    @State private var passphrase = ""
    @State private var comment = ""
    @State private var replaceExisting = false
    @State private var isWorking = false
    @State private var error: SMPError?

    var body: some View {
        Form {
            sourceSection
            if source != nil {
                detailsSection
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .frame(minHeight: 380)
        .disabled(isWorking)
        .fileImporter(isPresented: $isChoosingFile, allowedContentTypes: [.item]) { result in
            if case .success(let url) = result {
                load(url)
            }
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { close() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(isWorking ? "Importing…" : "Import") { Task { await runImport() } }
                    .disabled(!canImport)
            }
        }
        .onAppear {
            if let initialURL { load(initialURL) }
        }
        .onDisappear { source?.wipe() }
    }

    // MARK: Sections

    private var sourceSection: some View {
        Section("Key") {
            VStack(spacing: 8) {
                Image(systemName: source == nil ? "square.and.arrow.down" : "checkmark.circle.fill")
                    .font(.largeTitle)
                    .foregroundStyle(source == nil ? Color.secondary : Color.green)
                Text(source == nil ? "Drop a key file here" : sourceLabel)
                    .font(.headline)
                Button(source == nil ? "Choose File…" : "Choose Another File…") { isChoosingFile = true }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 16)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(
                        isDropTargeted ? Color.accentColor : Color.secondary.opacity(0.4),
                        style: StrokeStyle(lineWidth: 2, dash: [6])
                    )
            )
            .dropDestination(for: URL.self) { urls, _ in
                guard let url = urls.first else { return false }
                load(url)
                return true
            } isTargeted: { isDropTargeted = $0 }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Key file drop area")

            DisclosureGroup("Or paste a key") {
                TextEditor(text: $pastedText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(height: 90)
                    .accessibilityLabel("Pasted key")
                Button("Use Pasted Key") { usePastedText() }
                    .disabled(pastedText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
    }

    private var detailsSection: some View {
        Section {
            if let info {
                LabeledContent("Format", value: info.format.displayName)
                LabeledContent("Passphrase", value: info.isEncrypted == true ? "Protected" : "None")
                if info.format == .putty {
                    Text("The key will be converted to the OpenSSH format.")
                        .font(.callout).foregroundStyle(.secondary)
                } else if info.format.isLegacy {
                    Text("Legacy format. You can upgrade it to the OpenSSH format after importing.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            } else if isPublicKeyOnly {
                LabeledContent("Contents", value: "Public key only")
            }
            TextField("File name in ~/.ssh", text: $fileName)
            if let problem = KeyFileName.problem(with: fileName) {
                Text(problem).font(.callout).foregroundStyle(.red)
            } else if nameExists {
                Toggle("Archive the existing “\(fileName)” and replace it", isOn: $replaceExisting)
                    .foregroundStyle(.orange)
            }
            if info?.isEncrypted == true {
                SecureField("Current passphrase", text: $passphrase)
                Text(info?.format == .openSSH
                     ? "Optional: lets SMP verify the key before importing it."
                     : "Required to check the key and derive its public key.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            TextField("Comment", text: $comment, prompt: Text("optional"))
        } header: {
            Text("Import as")
        } footer: {
            Text("The private key is saved with permissions 600 and never leaves your Mac.")
                .foregroundStyle(.secondary)
        }
    }

    // MARK: Logic

    private var nameExists: Bool {
        let existing = model.existingFileNames()
        return existing.contains(fileName) || existing.contains(fileName + ".pub")
    }

    private var canImport: Bool {
        source != nil
            && KeyFileName.problem(with: fileName) == nil
            && (!nameExists || replaceExisting)
            && !isWorking
    }

    private func load(_ url: URL) {
        error = nil
        do {
            let contents = try SecureFileReader.read(url, maxBytes: PrivateKeyInspector.maxFileSize)
            accept(contents, label: url.lastPathComponent, suggestedName: Self.baseName(of: url))
        } catch {
            self.error = error.asSMPError
        }
    }

    private func usePastedText() {
        let contents = SecureBytes(utf8: pastedText.trimmingCharacters(in: .whitespaces) + "\n")
        pastedText = ""
        accept(contents, label: "Pasted key", suggestedName: "imported_key")
    }

    private func accept(_ contents: SecureBytes, label: String, suggestedName: String) {
        source?.wipe()
        source = contents
        sourceLabel = label
        info = PrivateKeyInspector.inspect(contents: contents)
        isPublicKeyOnly = info == nil
        if let comment = info?.comment {
            self.comment = comment
        }
        if fileName.isEmpty || KeyFileName.problem(with: fileName) != nil {
            let candidate = KeyFileName.problem(with: suggestedName) == nil ? suggestedName : "imported_key"
            fileName = KeyFileName.suggestion(base: candidate, existing: model.existingFileNames())
        }
    }

    private func runImport() async {
        guard let source else { return }
        isWorking = true
        error = nil
        defer { isWorking = false }
        let secret = SecureBytes.passphrase(passphrase)
        defer { secret?.wipe() }
        do {
            _ = try await model.importKey(KeyImportRequest(
                contents: source,
                fileName: fileName,
                directory: model.sshDirectory,
                passphrase: secret,
                comment: comment.isEmpty ? nil : comment,
                replaceExisting: replaceExisting
            ))
            passphrase = ""
            close()
        } catch {
            self.error = error.asSMPError
        }
    }

    private func close() {
        source?.wipe()
        source = nil
        dismiss()
    }

    /// `~/Downloads/server.ppk` → `server`; keeps names like `id_ed25519`.
    static func baseName(of url: URL) -> String {
        let name = url.lastPathComponent
        for suffix in [".ppk", ".pem", ".key", ".txt", ".pub"] where name.lowercased().hasSuffix(suffix) {
            return String(name.dropLast(suffix.count))
        }
        return name
    }
}

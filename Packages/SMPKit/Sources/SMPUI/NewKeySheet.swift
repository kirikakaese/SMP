import AppKit
import SMPCore
import SMPServices
import SMPSSH
import SwiftUI

/// Creates a new key: a short form with an "Advanced" section, then a success screen.
struct NewKeySheet: View {
    enum TypeChoice: String, CaseIterable, Identifiable {
        case ed25519, ecdsa, rsa, ed25519SK, ecdsaSK
        var id: String { rawValue }

        var title: String {
            switch self {
            case .ed25519: String(localized: "Ed25519 (recommended)")
            case .ecdsa: "ECDSA"
            case .rsa: "RSA"
            case .ed25519SK: String(localized: "Ed25519 on security key (FIDO2)")
            case .ecdsaSK: String(localized: "ECDSA on security key (FIDO2)")
            }
        }
    }

    let model: LibraryModel
    @Environment(\.dismiss) private var dismiss

    @State private var type: TypeChoice = .ed25519
    @State private var ecdsaBits = 256
    @State private var rsaBits = 4096
    @State private var fileName = "id_ed25519"
    @State private var fileNameEdited = false
    @State private var comment = KeyFileName.defaultComment()
    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var kdfRounds = KeyService.defaultKDFRounds
    @State private var securityKey = SecurityKeyOptions()
    @State private var pin = ""
    @State private var replaceExisting = false
    @State private var options = NewKeyOptions()
    @State private var hasExpiry = false
    @State private var expiry = Calendar.current.date(byAdding: .year, value: 1, to: Date()) ?? Date()
    @State private var showsAdvanced = false

    @State private var isWorking = false
    @State private var error: SMPError?
    @State private var created: (result: KeyOperationResult, warnings: [String])?

    var body: some View {
        Group {
            if let created {
                NewKeySuccessView(result: created.result, warnings: created.warnings) { dismiss() }
            } else {
                form
            }
        }
        .frame(width: 520)
        .frame(minHeight: 420)
        .onAppear(perform: suggestName)
    }

    // MARK: Form

    private var form: some View {
        Form {
            keySection
            passphraseSection
            followUpSection
            advancedSection
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .disabled(isWorking)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(isWorking
                    ? String(localized: "Creating…")
                    : String(localized: "Create Key")) { Task { await create() } }
                    .disabled(!canCreate)
            }
        }
        .overlay {
            if isWorking {
                ProgressView(isSecurityKeyType ? "Touch your security key when it blinks…" : "Creating key…")
                    .padding()
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
            }
        }
    }

    private var keySection: some View {
        Section {
            Picker("Type", selection: $type) {
                ForEach(TypeChoice.allCases) { Text($0.title).tag($0) }
            }
            .onChange(of: type) { suggestName() }
            if type == .ecdsa {
                Picker("Curve", selection: $ecdsaBits) {
                    Text("P-256").tag(256)
                    Text("P-384").tag(384)
                    Text("P-521").tag(521)
                }
                .pickerStyle(.segmented)
            }
            if type == .rsa {
                Picker("Size", selection: $rsaBits) {
                    Text("3072 bits").tag(3072)
                    Text("4096 bits").tag(4096)
                }
                .pickerStyle(.segmented)
            }
            TextField("File name", text: Binding(
                get: { fileName },
                set: { fileName = $0; fileNameEdited = true }
            ))
            if let problem = KeyFileName.problem(with: fileName) {
                Text(problem).font(.callout).foregroundStyle(.red)
            } else if nameExists {
                Toggle("Archive the existing “\(fileName)” and replace it", isOn: $replaceExisting)
                    .foregroundStyle(.orange)
            }
            TextField("Comment", text: $comment)
        } header: {
            Text("Key")
        } footer: {
            Text("Saved in ~/.ssh with permissions 600 (private) and 644 (public).")
                .foregroundStyle(.secondary)
        }
    }

    private var passphraseSection: some View {
        Section("Passphrase") {
            PassphraseFields(passphrase: $passphrase, confirmation: $confirmation)
        }
    }

    private var followUpSection: some View {
        Section("After creating") {
            Toggle("Add to ssh-agent now", isOn: $options.addToAgent)
            Toggle("Store passphrase in Keychain", isOn: $options.storePassphraseInKeychain)
                .disabled(passphrase.isEmpty)
            TextField("Add to ~/.ssh/config for host (alias)", text: $options.hostAlias)
            if !options.hostAlias.isEmpty {
                TextField("HostName", text: $options.hostName, prompt: Text("e.g. server.example.com"))
                TextField("User", text: $options.hostUser, prompt: Text("optional"))
            }
            if !model.tags.isEmpty {
                LabeledContent("Tags") {
                    Menu(tagSummary) {
                        ForEach(model.tags) { tag in
                            Toggle(tag.name, isOn: Binding(
                                get: { options.tagIDs.contains(tag.id) },
                                set: { isOn in
                                    if isOn {
                                        options.tagIDs.insert(tag.id)
                                    } else {
                                        options.tagIDs.remove(tag.id)
                                    }
                                }
                            ))
                        }
                    }
                    .fixedSize()
                }
            }
            Toggle("Remind me to rotate this key", isOn: $hasExpiry)
            if hasExpiry {
                DatePicker("Expires", selection: $expiry, in: Date()..., displayedComponents: .date)
            }
        }
    }

    private var advancedSection: some View {
        Section {
            DisclosureGroup("Advanced", isExpanded: $showsAdvanced) {
                Stepper("KDF rounds: \(kdfRounds)", value: $kdfRounds, in: 16...1_000, step: 16)
                    .help("More rounds make guessing the passphrase slower, and unlocking the key slightly slower.")
                if isSecurityKeyType {
                    Toggle("Resident key (stored on the security key)", isOn: $securityKey.resident)
                    Toggle("Require PIN or biometrics on every use", isOn: $securityKey.verifyRequired)
                    TextField("Application", text: $securityKey.application, prompt: Text("ssh: (default)"))
                    TextField(
                        "FIDO provider library",
                        text: $securityKey.providerPath,
                        prompt: Text("optional path")
                    )
                    SecureField("Security key PIN", text: $pin, prompt: Text("only if your key asks for one"))
                }
            }
        }
    }

    private var isSecurityKeyType: Bool { type == .ed25519SK || type == .ecdsaSK }
    private var nameExists: Bool {
        let existing = model.existingFileNames()
        return existing.contains(fileName) || existing.contains(fileName + ".pub")
    }

    private var canCreate: Bool {
        KeyFileName.problem(with: fileName) == nil
            && (!nameExists || replaceExisting)
            && passphrase == confirmation
            && !isWorking
    }

    private var tagSummary: String {
        let names = model.tags.filter { options.tagIDs.contains($0.id) }.map(\.name)
        return names.isEmpty ? String(localized: "None") : names.joined(separator: ", ")
    }

    private var keyType: KeyGenerationRequest.KeyType {
        switch type {
        case .ed25519: .ed25519
        case .ecdsa: .ecdsa(bits: ecdsaBits)
        case .rsa: .rsa(bits: rsaBits)
        case .ed25519SK: .ed25519SK
        case .ecdsaSK: .ecdsaSK
        }
    }

    private func suggestName() {
        guard !fileNameEdited else { return }
        fileName = KeyFileName.suggestion(base: keyType.defaultFileName, existing: model.existingFileNames())
    }

    private func create() async {
        isWorking = true
        error = nil
        defer { isWorking = false }
        let request = KeyGenerationRequest(
            type: keyType,
            fileName: fileName,
            directory: model.sshDirectory,
            comment: comment,
            passphrase: SecureBytes.passphrase(passphrase),
            kdfRounds: kdfRounds,
            securityKey: securityKey,
            securityKeyPIN: SecureBytes.passphrase(pin),
            replaceExisting: replaceExisting
        )
        var followUp = options
        followUp.expiresAt = hasExpiry ? expiry : nil
        do {
            created = try await model.generate(request, options: followUp)
            passphrase = ""
            confirmation = ""
            pin = ""
        } catch {
            self.error = error.asSMPError
        }
        request.passphrase?.wipe()
        request.securityKeyPIN?.wipe()
    }
}

/// Shown after a key was created: fingerprint, randomart and next steps.
struct NewKeySuccessView: View {
    let result: KeyOperationResult
    let warnings: [String]
    let onDone: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            Label("Key created", systemImage: "checkmark.seal.fill")
                .font(.title2.weight(.semibold))
                .foregroundStyle(.green)
            Text(Randomart.render(result.publicKey))
                .font(.system(size: 12, design: .monospaced))
                .accessibilityLabel("Randomart image of the new key's fingerprint")
            Text(result.publicKey.fingerprintSHA256)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
            if let replaced = result.replacedKey {
                Text("The previous “\(replaced.name)” was moved to the archive.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            ForEach(warnings, id: \.self) { warning in
                Label(warning, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
            HStack {
                Button("Copy Public Key") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(result.publicKey.openSSHLine, forType: .string)
                }
                Button("Reveal in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([result.privateKeyURL ?? result.publicKeyURL])
                }
                Spacer()
                Button("Done", action: onDone)
                    .keyboardShortcut(.defaultAction)
            }
            Text("Next: add the public key to the servers or services you want to use it with.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(24)
    }
}

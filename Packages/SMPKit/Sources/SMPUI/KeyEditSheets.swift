import SMPCore
import SMPServices
import SwiftUI

/// Shared chrome for the small edit sheets: a form, an inline error, Cancel / confirm buttons.
private struct EditSheet<Content: View>: View {
    let title: String
    let confirmTitle: String
    let canConfirm: Bool
    let isWorking: Bool
    let error: SMPError?
    let onConfirm: @MainActor () async -> Void
    @ViewBuilder let content: () -> Content
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            content()
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(title)
        .frame(width: 460)
        .disabled(isWorking)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(confirmTitle) { Task { await onConfirm() } }
                    .disabled(!canConfirm || isWorking)
            }
        }
    }
}

struct RenameKeySheet: View {
    let model: LibraryModel
    let item: LibraryItem
    @Environment(\.dismiss) private var dismiss

    @State private var newName = ""
    @State private var references: [ConfigReference] = []
    @State private var updateConfig = true
    @State private var isWorking = false
    @State private var error: SMPError?

    var body: some View {
        EditSheet(
            title: "Rename Key",
            confirmTitle: "Rename",
            canConfirm: KeyFileName.problem(with: newName) == nil && newName != item.key.name,
            isWorking: isWorking,
            error: error,
            onConfirm: rename
        ) {
            Section {
                TextField("New file name", text: $newName)
                if let problem = KeyFileName.problem(with: newName), !newName.isEmpty {
                    Text(problem).font(.callout).foregroundStyle(.red)
                }
            } footer: {
                Text("The private key, public key and certificate are renamed together.")
                    .foregroundStyle(.secondary)
            }
            if !references.isEmpty {
                Section("~/.ssh/config") {
                    Toggle("Update \(references.count) IdentityFile reference(s)", isOn: $updateConfig)
                    ForEach(references) { reference in
                        Text("Line \(reference.lineNumber): Host \(reference.hostPatterns.joined(separator: " "))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text("A backup of the config file is saved before it is changed.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .task {
            newName = item.key.name
            references = await model.configReferences(for: item)
        }
    }

    private func rename() async {
        isWorking = true
        defer { isWorking = false }
        do {
            _ = try await model.rename(item, to: newName, updateConfig: updateConfig)
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

struct ChangePassphraseSheet: View {
    let model: LibraryModel
    let item: LibraryItem
    @Environment(\.dismiss) private var dismiss

    @State private var current = ""
    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var kdfRounds = KeyService.defaultKDFRounds
    @State private var isWorking = false
    @State private var error: SMPError?

    private var isEncrypted: Bool { item.key.isPassphraseProtected == true }

    var body: some View {
        EditSheet(
            title: "Change Passphrase",
            confirmTitle: passphrase.isEmpty ? (isEncrypted ? "Remove Passphrase" : "Save") : "Change Passphrase",
            canConfirm: passphrase == confirmation && (!isEncrypted || !current.isEmpty),
            isWorking: isWorking,
            error: error,
            onConfirm: change
        ) {
            if isEncrypted {
                Section("Current") {
                    SecureField("Current passphrase", text: $current)
                }
            }
            Section("New") {
                PassphraseFields(passphrase: $passphrase, confirmation: $confirmation, title: "New passphrase")
                Stepper("KDF rounds: \(kdfRounds)", value: $kdfRounds, in: 16...1_000, step: 16)
            }
            if passphrase.isEmpty, isEncrypted {
                Section {
                    Label(
                        "Leaving the new passphrase empty removes protection: anyone with the file can use the key.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(.orange)
                }
            }
            Section {
                Text("""
                    If the old passphrase is saved in your Keychain, add the key to the agent again \
                    with “Store passphrase in Keychain” to update it.
                    """)
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func change() async {
        isWorking = true
        defer { isWorking = false }
        let old = SecureBytes.passphrase(current)
        let new = SecureBytes.passphrase(passphrase)
        defer {
            old?.wipe()
            new?.wipe()
        }
        do {
            try await model.changePassphrase(item, current: old, new: new, kdfRounds: kdfRounds)
            current = ""
            passphrase = ""
            confirmation = ""
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

struct ChangeCommentSheet: View {
    let model: LibraryModel
    let item: LibraryItem
    @Environment(\.dismiss) private var dismiss

    @State private var comment = ""
    @State private var passphrase = ""
    @State private var isWorking = false
    @State private var error: SMPError?

    var body: some View {
        EditSheet(
            title: "Change Comment",
            confirmTitle: "Save",
            canConfirm: item.key.isPassphraseProtected != true || !passphrase.isEmpty,
            isWorking: isWorking,
            error: error,
            onConfirm: save
        ) {
            Section {
                TextField("Comment", text: $comment)
                if item.key.isPassphraseProtected == true {
                    SecureField("Passphrase", text: $passphrase)
                }
            } footer: {
                Text("Updates both the private and the public key file.").foregroundStyle(.secondary)
            }
        }
        .onAppear { comment = item.key.comment }
    }

    private func save() async {
        isWorking = true
        defer { isWorking = false }
        let secret = SecureBytes.passphrase(passphrase)
        defer { secret?.wipe() }
        do {
            try await model.changeComment(item, to: comment, passphrase: secret)
            passphrase = ""
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

struct UpgradeFormatSheet: View {
    let model: LibraryModel
    let item: LibraryItem
    @Environment(\.dismiss) private var dismiss

    @State private var passphrase = ""
    @State private var isWorking = false
    @State private var error: SMPError?

    var body: some View {
        EditSheet(
            title: "Upgrade Key Format",
            confirmTitle: "Upgrade",
            canConfirm: item.key.isPassphraseProtected != true || !passphrase.isEmpty,
            isWorking: isWorking,
            error: error,
            onConfirm: upgrade
        ) {
            Section {
                Text("Converts the key from the legacy \(item.key.privateKeyInfo?.format.displayName ?? """"
                    ) format \
                    to the OpenSSH format, which protects the passphrase with a stronger key derivation (bcrypt). \
                    The key itself and its fingerprint stay the same.
                    """)
                if item.key.isPassphraseProtected == true {
                    SecureField("Passphrase", text: $passphrase)
                }
            }
        }
    }

    private func upgrade() async {
        isWorking = true
        defer { isWorking = false }
        let secret = SecureBytes.passphrase(passphrase)
        defer { secret?.wipe() }
        do {
            try await model.upgradeFormat(item, passphrase: secret)
            passphrase = ""
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

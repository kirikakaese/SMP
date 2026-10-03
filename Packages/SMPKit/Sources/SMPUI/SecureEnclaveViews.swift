import SMPCore
import SMPServices
import SwiftUI

/// The policy choices offered in pickers, as stable tags.
enum PolicyChoice: Hashable, CaseIterable, Identifiable {
    case everyUse, oneMinute, fiveMinutes, fifteenMinutes, notifyOnly

    var id: Self { self }

    init(_ policy: SigningPolicy) {
        switch policy {
        case .everyUse: self = .everyUse
        case .notifyOnly: self = .notifyOnly
        case .reuse(let seconds) where seconds <= 60: self = .oneMinute
        case .reuse(let seconds) where seconds <= 300: self = .fiveMinutes
        case .reuse: self = .fifteenMinutes
        }
    }

    var policy: SigningPolicy {
        switch self {
        case .everyUse: .everyUse
        case .oneMinute: .reuse(seconds: 60)
        case .fiveMinutes: .reuse(seconds: 300)
        case .fifteenMinutes: .reuse(seconds: 900)
        case .notifyOnly: .notifyOnly
        }
    }
}

/// Shown in the key detail for Secure Enclave keys.
struct SecureEnclaveSection: View {
    let model: LibraryModel
    let item: LibraryItem
    let key: SecureEnclaveKeyInfo

    var body: some View {
        Section("Secure Enclave") {
            Label("The private key lives in this Mac's Secure Enclave and can never be copied or exported.",
                  systemImage: "lock.shield.fill")
                .foregroundStyle(.secondary)
            Picker("Signing", selection: Binding(
                get: { PolicyChoice(key.policy) },
                set: { model.setSigningPolicy($0.policy, for: item) }
            )) {
                ForEach(PolicyChoice.allCases) { choice in
                    Text(choice.policy.title)
                        .tag(choice)
                        .selectionDisabled(choice.policy.requiresUserPresence != key.policy.requiresUserPresence)
                }
            }
            LabeledContent("Created", value: key.createdAt.formatted(date: .abbreviated, time: .shortened))
            Text("Use it through SMP's agent: see SSH → Agent. To pick this key for a host, set "
                + "IdentityFile to its .pub file.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

/// Shown instead of the Secure Enclave key list when SMP Agent, which keeps the keys, does not answer.
struct AgentProblemView: View {
    let model: LibraryModel
    let problem: SMPError
    @State private var isStarting = false

    var body: some View {
        ContentUnavailableView {
            Label(problem.whatHappened, systemImage: "lock.shield")
        } description: {
            Text(problem.howToFix ?? "")
        } actions: {
            StartAgentButton(model: model, isStarting: $isStarting)
        }
    }
}

/// Starts SMP Agent, for places where Secure Enclave keys need it.
struct StartAgentButton: View {
    let model: LibraryModel
    @Binding var isStarting: Bool

    var body: some View {
        Button {
            Task {
                isStarting = true
                defer { isStarting = false }
                await model.startAgent()
            }
        } label: {
            if isStarting {
                ProgressView().controlSize(.small)
            } else {
                Text("Start SMP Agent")
            }
        }
        .disabled(isStarting)
    }
}

/// Creates a key in the Secure Enclave.
struct NewSecureEnclaveKeySheet: View {
    let model: LibraryModel
    @Environment(\.dismiss) private var dismiss

    @State private var name = "id_ecdsa_secure_enclave"
    @State private var comment = KeyFileName.defaultComment() + " (Secure Enclave)"
    @State private var policy: PolicyChoice = .everyUse
    @State private var savePublicKey = true
    @State private var isWorking = false
    @State private var isStartingAgent = false
    @State private var error: SMPError?

    private var policyNote: String {
        policy == .notifyOnly
            ? "Signatures happen without a prompt while your Mac is unlocked. This cannot be changed later."
            : "Signatures need Touch ID or your login password. This requirement cannot be removed later."
    }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $name)
                if let problem = KeyFileName.problem(with: name), !name.isEmpty {
                    Text(problem).font(.callout).foregroundStyle(.red)
                }
                TextField("Comment", text: $comment)
                LabeledContent("Type", value: "ECDSA P-256 (the only type the Secure Enclave supports)")
            }
            Section {
                Picker("Signing", selection: $policy) {
                    ForEach(PolicyChoice.allCases) { Text($0.policy.title).tag($0) }
                }
                Text(policyNote)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Touch ID")
            }
            Section {
                Toggle("Save the public key as ~/.ssh/\(name).pub", isOn: $savePublicKey)
            } footer: {
                Text("The private key can never leave this Mac: it is not part of backups or archives, "
                    + "and it is gone if this Mac is erased. Keep a second way into your servers. "
                    + "SMP Agent keeps the key and signs with it.")
                    .foregroundStyle(.secondary)
            }
            if let error {
                Section {
                    ErrorBanner(error: error)
                    if error.code == .agentNotRunning {
                        StartAgentButton(model: model, isStarting: $isStartingAgent)
                            .onChange(of: isStartingAgent) { _, starting in
                                if !starting, model.secureEnclaveProblem == nil { self.error = nil }
                            }
                    }
                }
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
                Button("Create") {
                    Task {
                        isWorking = true
                        defer { isWorking = false }
                        do {
                            try await model.createSecureEnclaveKey(
                                name: name, comment: comment, policy: policy.policy, savePublicKey: savePublicKey
                            )
                            dismiss()
                        } catch {
                            self.error = error.asSMPError
                        }
                    }
                }
                .disabled(KeyFileName.problem(with: name) != nil || isWorking)
            }
        }
    }
}

/// Downloads resident keys from a FIDO2 security key (`ssh-keygen -K`).
struct DownloadResidentKeysSheet: View {
    let model: LibraryModel
    @Environment(\.dismiss) private var dismiss

    @State private var pin = ""
    @State private var providerPath = ""
    @State private var isWorking = false
    @State private var error: SMPError?

    var body: some View {
        Form {
            Section {
                SecureField("PIN", text: $pin)
                TextField("FIDO provider library", text: $providerPath, prompt: Text("optional"))
            } footer: {
                Text("Keys created with “Resident key” live on the security key itself. Downloading saves "
                    + "small handle files to ~/.ssh; they only work while the security key is plugged in. "
                    + "The OpenSSH built into macOS needs a FIDO provider library for this.")
                    .foregroundStyle(.secondary)
            }
            if isWorking {
                Section {
                    ProgressView("Touch your security key when it blinks…")
                }
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
                Button("Download") {
                    Task { await download() }
                }
                .disabled(isWorking)
            }
        }
    }

    private func download() async {
        isWorking = true
        error = nil
        defer { isWorking = false }
        let secret = SecureBytes.passphrase(pin)
        defer { secret?.wipe() }
        do {
            _ = try await model.downloadResidentKeys(pin: secret, providerPath: providerPath)
            pin = ""
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

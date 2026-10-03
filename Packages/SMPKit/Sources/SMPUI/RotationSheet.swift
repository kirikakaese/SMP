import SMPCore
import SMPServices
import SwiftUI

/// Guides a key rotation step by step. The job is saved after every step, so closing the sheet
/// (or quitting SMP) keeps the progress; the rotation can be resumed from Security → Audit.
struct RotationSheet: View {
    enum Start {
        case key(LibraryItem)
        case job(RotationJob)
    }

    let library: LibraryModel
    let start: Start
    @Environment(\.dismiss) private var dismiss

    @State private var job: RotationJob?
    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var testPassphrase = ""
    @State private var isWorking = false
    @State private var confirmRetire = false
    @State private var error: SMPError?

    var body: some View {
        Form {
            if let job {
                overview(job)
                stepsSection(job)
                targetsSection(job)
                actionSection(job)
                if !job.log.isEmpty {
                    Section("Log") {
                        ForEach(Array(job.log.suffix(8).enumerated()), id: \.offset) { _, entry in
                            Text(entry.message).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 600, height: 620)
        .disabled(isWorking)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(job?.isFinished == true ? "Done" : "Close") { dismiss() }
            }
        }
        .confirmationDialog("Retire the old key?", isPresented: $confirmRetire) {
            Button("Remove Old Key and Archive It", role: .destructive) { Task { await retire() } }
        } message: {
            Text(retireMessage)
        }
        .task { prepare() }
    }

    // MARK: Sections

    private func overview(_ job: RotationJob) -> some View {
        Section {
            LabeledContent("Old key", value: job.oldKeyName)
            if job.completedSteps.contains(.generate) {
                LabeledContent("New key", value: job.newKeyName)
            } else {
                TextField("New key name", text: Binding(
                    get: { job.newKeyName },
                    set: { self.job?.newKeyName = $0 }
                ))
            }
        } footer: {
            Text("SMP replaces the old key everywhere it is used, then retires it. You can close this "
                + "window at any time; the rotation continues where it stopped.")
                .foregroundStyle(.secondary)
        }
    }

    private func stepsSection(_ job: RotationJob) -> some View {
        Section("Steps") {
            ForEach(RotationJob.Step.allCases, id: \.self) { step in
                let done = job.completedSteps.contains(step)
                Label {
                    Text(step.title).fontWeight(job.nextStep == step ? .semibold : .regular)
                } icon: {
                    Image(systemName: symbol(for: step, in: job))
                        .foregroundStyle(done ? Color.green : Color.secondary)
                }
            }
        }
    }

    private func targetsSection(_ job: RotationJob) -> some View {
        Section {
            if job.targets.isEmpty {
                Text("SMP found no provider account or ~/.ssh/config host that uses this key. "
                    + "Upload the new key manually where you used the old one.")
                    .foregroundStyle(.secondary)
            }
            ForEach(job.targets) { target in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(target.label).strikethrough(target.skipped)
                        Spacer()
                        Text(status(of: target)).font(.caption).foregroundStyle(.secondary)
                        if target.lastError != nil || target.skipped {
                            Toggle("Skip", isOn: Binding(
                                get: { target.skipped },
                                set: { skip in setSkipped(skip, target: target) }
                            ))
                            .toggleStyle(.checkbox)
                        }
                    }
                    if let message = target.lastError, !target.skipped {
                        Text(message).font(.caption).foregroundStyle(.red)
                    }
                }
            }
        } header: {
            Text("Where the key is used")
        }
    }

    @ViewBuilder
    private func actionSection(_ job: RotationJob) -> some View {
        Section {
            switch job.nextStep {
            case .generate:
                PassphraseFields(passphrase: $passphrase, confirmation: $confirmation)
                Button("Create New Key") {
                    let key = secret(passphrase)
                    Task { await run { try await rotation.generate($0, passphrase: key) } }
                }
                .disabled(passphrase != confirmation)
            case .deploy:
                Button("Upload and Install the New Key") { Task { await run { await rotation.deploy($0) } } }
            case .updateConfig:
                Button("Update ~/.ssh/config") { Task { await run { try rotation.updateConfig($0) } } }
            case .verify:
                SecureField("Passphrase of the new key (if it has one)", text: $testPassphrase)
                Button("Test Logins") {
                    let key = secret(testPassphrase)
                    Task { await run { await rotation.verify($0, passphrase: key) } }
                }
            case .retire:
                Button("Retire the Old Key…", role: .destructive) { confirmRetire = true }
            case nil:
                Label("Rotation complete.", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
            }
            if isWorking {
                ProgressView().controlSize(.small)
            }
        }
    }

    // MARK: Actions

    private var rotation: RotationService { library.services.rotation }

    private var retireMessage: String {
        let places = job?.activeTargets.map(\.label).joined(separator: ", ") ?? ""
        let removal = places.isEmpty ? "" : "SMP removes the old key from: \(places). "
        return removal + "The old key files are then moved to SMP's encrypted archive, where you can restore them."
    }

    private func prepare() {
        guard job == nil else { return }
        switch start {
        case .job(let saved):
            job = saved
        case .key(let item):
            do {
                job = try rotation.plan(for: item.key)
            } catch {
                self.error = error.asSMPError
            }
        }
    }

    private func symbol(for step: RotationJob.Step, in job: RotationJob) -> String {
        if job.completedSteps.contains(step) { return "checkmark.circle.fill" }
        return job.nextStep == step ? "arrow.right.circle" : "circle"
    }

    private func secret(_ text: String) -> SecureBytes? {
        SecureBytes.passphrase(text)
    }

    private func setSkipped(_ skipped: Bool, target: RotationJob.Target) {
        guard var current = job, let index = current.targets.firstIndex(where: { $0.id == target.id }) else { return }
        current.targets[index].skipped = skipped
        current.note(skipped ? "Skipping \(target.label)." : "Including \(target.label) again.")
        save(current)
    }

    private func status(of target: RotationJob.Target) -> String {
        if target.skipped { return "Skipped" }
        if target.retired { return "Old key removed" }
        if target.verified { return "Login works" }
        if target.deployed { return "New key added" }
        return "Waiting"
    }

    /// Runs one step, then saves the job (also when the step failed half-way).
    private func run(_ step: @escaping (RotationJob) async throws -> RotationJob) async {
        guard let current = job else { return }
        isWorking = true
        error = nil
        defer { isWorking = false }
        do {
            save(try await step(current))
            if current.nextStep == .generate {
                passphrase = ""
                confirmation = ""
                await library.reload()
            }
        } catch {
            self.error = error.asSMPError
        }
    }

    private func retire() async {
        await run { await rotation.retire($0) }
        guard let current = job, current.completedSteps.contains(.retire) else { return }
        // Archive the old key files locally (reversible from the archive).
        await library.reload()
        let old = library.items.first { $0.key.privateKeyFile?.url.path == current.oldPrivateKeyPath && !$0.isArchived }
        if let old {
            await library.archive([old], undoManager: nil)
        }
        var finished = current
        finished.note(old == nil ? "The old key files were already gone." : "Archived the old key.")
        save(finished)
    }

    private func save(_ updated: RotationJob) {
        job = updated
        do {
            try library.services.metadata.saveRotationJob(updated)
        } catch {
            self.error = error.asSMPError
        }
    }
}

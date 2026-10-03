import SMPCore
import SMPServices
import SwiftUI

extension AuditFinding.Severity {
    var color: Color {
        switch self {
        case .low: .secondary
        case .medium: .yellow
        case .high: .orange
        case .critical: .red
        }
    }
}

/// The middle column for Security → Audit: score, rotations in progress, and findings.
struct AuditView: View {
    @Bindable var security: SecurityModel
    let library: LibraryModel
    @Bindable var hosts: HostsModel

    var body: some View {
        List(selection: $security.selectedFindingID) {
            Section {
                HStack(spacing: 16) {
                    Gauge(value: Double(security.score), in: 0...100) {
                        Text("Score")
                    } currentValueLabel: {
                        Text("\(security.score)")
                    }
                    .gaugeStyle(.accessoryCircularCapacity)
                    .tint(scoreColor)
                    VStack(alignment: .leading) {
                        Text(summary).font(.headline)
                        if let lastRun = security.lastRun {
                            Text("Checked \(lastRun.formatted(date: .omitted, time: .shortened))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .padding(.vertical, 4)
            }
            if !security.unfinishedRotations.isEmpty {
                Section("Rotations in Progress") {
                    ForEach(security.unfinishedRotations) { job in
                        HStack {
                            VStack(alignment: .leading) {
                                Text("\(job.oldKeyName) → \(job.newKeyName)")
                                Text("Next: \(job.nextStep?.title ?? "—")").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Resume") { library.activeSheet = .resumeRotation(job) }
                            Button("Discard", role: .destructive) { security.discardRotation(job) }
                        }
                    }
                }
            }
            ForEach(AuditFinding.Severity.allCases.reversed(), id: \.self) { severity in
                let group = security.findings.filter { $0.severity == severity }
                if !group.isEmpty {
                    Section(severity.title) {
                        ForEach(group) { finding in
                            FindingRow(finding: finding).tag(finding.id)
                        }
                    }
                }
            }
        }
        .overlay {
            if security.findings.isEmpty, security.lastRun != nil {
                ContentUnavailableView(
                    "No Problems Found", systemImage: "checkmark.shield.fill",
                    description: Text("Your keys, their files and your SSH config passed every check.")
                )
            }
        }
        .navigationTitle("Audit")
        .navigationSplitViewColumnWidth(min: 320, ideal: 380)
        .toolbar {
            ToolbarItem {
                Button {
                    security.runAudit(library: library)
                } label: {
                    Label("Check Again", systemImage: "arrow.clockwise")
                }
            }
        }
        .sheet(
            item: $hosts.pendingChange,
            onDismiss: { security.runAudit(library: library) },
            content: { change in ConfigDiffSheet(model: hosts, change: change) }
        )
        .task(id: library.items.count) { security.runAudit(library: library) }
        .onChange(of: library.activeSheet == nil) { _, closed in
            if closed { security.runAudit(library: library) }
        }
    }

    private var summary: String {
        switch security.findings.count {
        case 0: String(localized: "Everything looks good")
        case 1: String(localized: "1 thing to look at")
        default: String(localized: "\(security.findings.count) things to look at")
        }
    }

    private var scoreColor: Color {
        switch security.score {
        case 90...: .green
        case 70..<90: .yellow
        default: .red
        }
    }
}

struct FindingRow: View {
    let finding: AuditFinding

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(finding.severity.color)
                .accessibilityLabel(finding.severity.title)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title).fontWeight(.medium)
                Text(finding.subject).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
        }
    }
}

/// The detail column for Security → Audit.
struct FindingDetailView: View {
    let security: SecurityModel
    let library: LibraryModel
    let hosts: HostsModel

    var body: some View {
        if let finding = security.selectedFinding {
            Form {
                Section {
                    LabeledContent("Severity") {
                        Text(finding.severity.title).foregroundStyle(finding.severity.color)
                    }
                    LabeledContent("Concerns", value: finding.subject)
                    Text(finding.detail)
                }
                if let fix = finding.fix {
                    Section {
                        Button(fix.title) {
                            Task { await security.fix(finding, library: library, hosts: hosts) }
                        }
                    } footer: {
                        Text(footer(for: fix)).foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(finding.title)
        } else {
            ContentUnavailableView(
                "No Finding Selected", systemImage: "checkmark.shield",
                description: Text("Select a finding to see what it means and how to fix it.")
            )
        }
    }

    private func footer(for fix: AuditFinding.Fix) -> String {
        switch fix {
        case .setPermissions: String(localized: "Changes the file mode right away. Nothing else is touched.")
        case .removeConfigLine: String(localized: "You see the change as a diff before it is saved. A backup is kept.")
        case .addPassphrase, .upgradeFormat: String(localized: "Opens the key's editing sheet.")
        case .rotate: String(localized: """
            Opens the rotation assistant: a new key replaces this one everywhere it is used.
            """)
        }
    }
}

/// The middle column for Security → Commit Signing.
struct SigningView: View {
    @Bindable var security: SecurityModel
    let library: LibraryModel
    let providers: ProvidersModel

    @State private var keyID: String?
    @State private var email = ""
    @State private var signTags = true
    @State private var plan: GitSigningPlan?
    @State private var error: SMPError?
    @State private var isUploading = false

    private var candidates: [LibraryItem] {
        library.items.filter {
            !$0.isArchived && !$0.isSecureEnclave && $0.key.privateKeyFile != nil && $0.key.publicKeyFile != nil
                && $0.key.publicKey?.isCertificate == false
        }
    }

    private var item: LibraryItem? { candidates.first { $0.id == keyID } }

    var body: some View {
        Form {
            Section("Current git settings") {
                if let state = security.gitState {
                    LabeledContent("Signs commits", value: state.signsCommits ? "Yes" : "No")
                    LabeledContent("Format", value: state.format ?? "openpgp (default)")
                    LabeledContent("Signing key", value: state.signingKey ?? "None")
                } else {
                    ProgressView().controlSize(.small)
                }
            }
            Section {
                Picker("Key", selection: $keyID) {
                    Text("Choose a key").tag(String?.none)
                    ForEach(candidates) { Text($0.displayName).tag(Optional($0.id)) }
                }
                TextField("Email you commit with", text: $email)
                Toggle("Also sign tags", isOn: $signTags)
                Button("Preview Changes…") { Task { await preview() } }
                    .disabled(item == nil || email.isEmpty)
            } header: {
                Text("Sign with an SSH key")
            } footer: {
                Text("""
                    SMP changes only your global git config (~/.gitconfig), after showing exactly what \
                    changes. Secure Enclave keys are not offered: git asks the macOS ssh-agent, not \
                    SMP Agent, for signatures.
                    """)
                    .foregroundStyle(.secondary)
            }
            if let plan {
                PlanSection(plan: plan) {
                    Task {
                        await security.applySigning(plan)
                        self.plan = nil
                    }
                }
            }
            if let item, security.gitState?.usesSSHKey(atPath: item.key.publicKeyFile?.url.path ?? "") == true,
               !providers.accounts.isEmpty {
                Section {
                    Button("Upload as Signing Key to a Provider…") { isUploading = true }
                } footer: {
                    Text("GitHub and GitLab show a “Verified” badge when they know your signing key.")
                        .foregroundStyle(.secondary)
                }
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Commit Signing")
        .navigationSplitViewColumnWidth(min: 340, ideal: 420)
        .sheet(isPresented: $isUploading) {
            UploadKeySheet(providers: providers, library: library, item: item, account: nil, signing: true)
        }
        .task {
            await security.loadGitState()
            if email.isEmpty, let current = security.gitState?.email {
                email = current
            }
        }
    }

    private func preview() async {
        guard let item else { return }
        error = nil
        do {
            plan = try await security.planSigning(with: item, email: email, signTags: signTags)
        } catch {
            self.error = error.asSMPError
        }
    }
}

/// Lists exactly what "Set up commit signing" changes.
struct PlanSection: View {
    let plan: GitSigningPlan
    let onApply: () -> Void

    var body: some View {
        Section {
            if plan.changes.isEmpty && plan.allowedSignersLine == nil {
                Text("git is already set up this way.").foregroundStyle(.secondary)
            }
            ForEach(plan.changes) { change in
                VStack(alignment: .leading, spacing: 2) {
                    Text(change.key).font(.system(.body, design: .monospaced))
                    Text("\(change.oldValue ?? "not set") → \(change.newValue)")
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            if let line = plan.allowedSignersLine {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Add to \(plan.allowedSignersFile.lastPathComponent)")
                        .font(.system(.body, design: .monospaced))
                    Text(line).font(.caption).foregroundStyle(.secondary).lineLimit(2).truncationMode(.middle)
                }
            }
            Button("Apply") { onApply() }
                .disabled(plan.changes.isEmpty && plan.allowedSignersLine == nil)
        } header: {
            Text("Changes")
        }
    }
}

/// The detail column for Security → Commit Signing.
struct SigningDetailView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Signing commits with SSH").font(.title2.weight(.semibold))
                Text("""
                    git 2.34 and later can sign commits and tags with an SSH key instead of GPG. \
                    SMP sets gpg.format to ssh, points user.signingkey at your public key, turns on \
                    commit.gpgsign, and lists your key in ~/.ssh/allowed_signers so \
                    “git log --show-signature” can verify your own commits.
                    """)
                Text("To get the “Verified” badge on GitHub or GitLab, upload the same key there as a signing key.")
                    .foregroundStyle(.secondary)
            }
            .padding(24)
            .frame(maxWidth: 560, alignment: .leading)
        }
    }
}

import AppKit
import SMPCore
import SMPServices
import SwiftUI
import UniformTypeIdentifiers

extension UTType {
    /// SMP's encrypted backup file.
    static var smpBackup: UTType { UTType(filenameExtension: BackupService.fileExtension) ?? .data }
}

/// Creates an encrypted backup of key files, SSH settings and SMP's metadata.
struct BackupSheet: View {
    let model: LibraryModel
    @Environment(\.dismiss) private var dismiss

    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var isWorking = false
    @State private var error: SMPError?

    private var sources: [(BackupFile.Kind, URL)] { model.backupSources() }

    var body: some View {
        Form {
            Section {
                LabeledContent("Keys", value: keySummary)
                LabeledContent("SSH settings", value: settingsSummary)
                LabeledContent("SMP data", value: "Tags, groups, notes, dates, host settings and tunnels")
            } header: {
                Text("Included")
            } footer: {
                Text("Not included: Secure Enclave keys (they can never leave this Mac), archived keys and "
                    + "provider tokens (add your accounts again after restoring).")
                    .foregroundStyle(.secondary)
            }
            Section {
                PassphraseFields(passphrase: $passphrase, confirmation: $confirmation, title: "Backup passphrase")
            } footer: {
                Text("The backup is encrypted with AES-256-GCM. Without this passphrase nobody can open it, "
                    + "including you: SMP does not store it.")
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
                Button("Save Backup…") { save() }
                    .disabled(passphrase.isEmpty || passphrase != confirmation || isWorking)
            }
        }
    }

    private var keySummary: String {
        let keys = sources.filter { $0.0 == .privateKey }.count
        let files = sources.filter { $0.0 != .config && $0.0 != .knownHosts }.count
        return "\(keys) keys (\(files) files)"
    }

    private var settingsSummary: String {
        let names = sources.compactMap { source -> String? in
            switch source.0 {
            case .config: return "~/.ssh/config"
            case .knownHosts: return "known_hosts"
            default: return nil
            }
        }
        return names.isEmpty ? "None found" : names.joined(separator: ", ")
    }

    private func save() {
        let panel = NSSavePanel()
        panel.title = "Save Backup"
        panel.allowedContentTypes = [.smpBackup]
        let date = Date().formatted(.iso8601.year().month().day())
        panel.nameFieldStringValue = "SMP Backup \(date).\(BackupService.fileExtension)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let secret = SecureBytes(utf8: passphrase)
        Task {
            isWorking = true
            error = nil
            defer {
                isWorking = false
                secret.wipe()
            }
            do {
                _ = try await model.createBackup(passphrase: secret, to: url)
                passphrase = ""
                confirmation = ""
                dismiss()
            } catch {
                self.error = error.asSMPError
            }
        }
    }
}

/// Restores a backup: choose the file, enter the passphrase, review, restore.
struct RestoreBackupSheet: View {
    let model: LibraryModel
    @Environment(\.dismiss) private var dismiss

    @State private var file: URL?
    @State private var passphrase = ""
    @State private var opened: OpenedBackup?
    @State private var plan: [RestoreStep] = []
    @State private var summary: RestoreSummary?
    @State private var isWorking = false
    @State private var error: SMPError?

    var body: some View {
        Form {
            if let summary {
                RestoreSummarySection(summary: summary)
            } else if let opened {
                RestorePlanSection(manifest: opened.manifest, plan: plan)
            } else {
                Section {
                    LabeledContent("Backup") {
                        HStack {
                            Text(file?.lastPathComponent ?? "None chosen").foregroundStyle(.secondary)
                            Button("Choose…") { choose() }
                        }
                    }
                    SecureField("Passphrase", text: $passphrase)
                } footer: {
                    Text("Nothing is changed until you have reviewed what the backup contains.")
                        .foregroundStyle(.secondary)
                }
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 600)
        .frame(minHeight: 320)
        .disabled(isWorking)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(summary == nil ? "Cancel" : "Done") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                if summary == nil {
                    if opened == nil {
                        Button("Open") { Task { await open() } }
                            .disabled(file == nil || passphrase.isEmpty || isWorking)
                    } else {
                        Button("Restore") { Task { await restore() } }
                            .disabled(isWorking)
                    }
                }
            }
        }
        .onDisappear {
            opened?.wipe()
            passphrase = ""
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.title = "Choose a Backup"
        panel.allowedContentTypes = [.smpBackup]
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK {
            file = panel.url
        }
    }

    private func open() async {
        guard let file else { return }
        isWorking = true
        error = nil
        let secret = SecureBytes(utf8: passphrase)
        defer {
            isWorking = false
            secret.wipe()
        }
        do {
            let result = try await model.openBackup(file, passphrase: secret)
            opened = result.0
            plan = result.1
            passphrase = ""
        } catch {
            self.error = error.asSMPError
        }
    }

    private func restore() async {
        guard let opened else { return }
        isWorking = true
        error = nil
        defer { isWorking = false }
        do {
            summary = try await model.restoreBackup(opened, plan: plan)
            opened.wipe()
        } catch {
            self.error = error.asSMPError
        }
    }
}

/// What restoring will do, file by file.
private struct RestorePlanSection: View {
    let manifest: BackupManifest
    let plan: [RestoreStep]

    var body: some View {
        Section {
            LabeledContent("Made", value: manifest.createdAt.formatted(date: .abbreviated, time: .shortened))
            LabeledContent("Keys", value: "\(manifest.keyCount)")
            LabeledContent(
                "SMP data",
                value: "\(manifest.metadata.tags.count) tags, \(manifest.metadata.groups.count) groups, "
                    + "\(manifest.metadata.tunnels.count) tunnels"
            )
        } header: {
            Text("Backup")
        } footer: {
            Text("Existing files are never overwritten. A different file with the same name is restored "
                + "next to it with “-restored” in its name. Tags, notes and settings you already have are kept.")
                .foregroundStyle(.secondary)
        }
        Section("Files") {
            ForEach(plan) { step in
                HStack(alignment: .firstTextBaseline) {
                    Image(systemName: symbol(for: step.action)).foregroundStyle(color(for: step.action))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(displayPath(step.destination ?? step.target)).font(.system(.body, design: .monospaced))
                        Text(description(of: step.action)).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private func symbol(for action: RestoreStep.Action) -> String {
        switch action {
        case .create: "plus.circle.fill"
        case .alreadyPresent: "checkmark.circle"
        case .writeAlongside: "doc.on.doc"
        case .skip: "exclamationmark.triangle.fill"
        }
    }

    private func color(for action: RestoreStep.Action) -> Color {
        switch action {
        case .create: .green
        case .alreadyPresent: .secondary
        case .writeAlongside: .orange
        case .skip: .red
        }
    }

    private func description(of action: RestoreStep.Action) -> String {
        switch action {
        case .create: "Will be restored"
        case .alreadyPresent: "Already here, unchanged"
        case .writeAlongside: "A different file has this name; the backup's version is saved next to it"
        case .skip(let reason): "Skipped: \(reason)"
        }
    }
}

private struct RestoreSummarySection: View {
    let summary: RestoreSummary

    var body: some View {
        Section("Restored") {
            LabeledContent("Files written", value: "\(summary.written.count)")
            LabeledContent("Already here", value: "\(summary.alreadyPresent)")
            if !summary.skipped.isEmpty {
                LabeledContent("Skipped", value: "\(summary.skipped.count)")
            }
            LabeledContent(
                "SMP data",
                value: "\(summary.tagsAdded) tags, \(summary.groupsAdded) groups, "
                    + "\(summary.notesRestored) key notes, \(summary.hostsRestored) host settings, "
                    + "\(summary.tunnelsAdded) tunnels added"
            )
            ForEach(summary.written, id: \.self) { url in
                Text(displayPath(url)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
            }
        }
    }
}

private func displayPath(_ url: URL) -> String {
    (url.path as NSString).abbreviatingWithTildeInPath
}

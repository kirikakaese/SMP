import SMPCore
import SMPServices
import SwiftUI

/// The safe deletion flow: impact report → archive (default) or permanent deletion.
struct DeleteKeySheet: View {
    enum Mode: Hashable {
        case archive, deletePermanently
    }

    enum ReferenceAction: String, CaseIterable, Identifiable {
        case keep, commentOut, remove
        var id: String { rawValue }
        var title: String {
            switch self {
            case .keep: "Keep"
            case .commentOut: "Comment out"
            case .remove: "Remove line"
            }
        }
    }

    let model: LibraryModel
    let items: [LibraryItem]
    @Environment(\.dismiss) private var dismiss

    @State private var mode: Mode = .archive
    @State private var reports: [String: KeyImpactReport] = [:]
    @State private var referenceActions: [String: ReferenceAction] = [:]
    @State private var confirmationText = ""
    @State private var isLoading = true
    @State private var isWorking = false
    @State private var error: SMPError?

    private var onlyArchived: Bool { items.allSatisfy(\.isArchived) }
    private var confirmationPhrase: String {
        items.count == 1 ? items[0].displayName : "delete \(items.count) keys"
    }

    var body: some View {
        Form {
            Section {
                Text(title).font(.headline)
                if !onlyArchived {
                    Picker("Action", selection: $mode) {
                        Text("Archive (recommended)").tag(Mode.archive)
                        Text("Delete permanently").tag(Mode.deletePermanently)
                    }
                    .pickerStyle(.radioGroup)
                    Text(mode == .archive
                         ? "The files move into SMP's encrypted archive and can be restored at any time."
                         : "The files are overwritten and deleted. This cannot be undone.")
                        .font(.callout)
                        .foregroundStyle(mode == .archive ? Color.secondary : Color.red)
                }
            }

            if isLoading {
                Section { ProgressView("Checking where the key is used…") }
            } else {
                ForEach(items.filter { !$0.isArchived }) { item in
                    impactSection(for: item)
                }
            }

            if mode == .deletePermanently || onlyArchived {
                Section {
                    TextField("Type “\(confirmationPhrase)” to confirm", text: $confirmationText)
                } footer: {
                    Text("You'll be asked for Touch ID or your password.").foregroundStyle(.secondary)
                }
            }

            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 540)
        .frame(minHeight: 360)
        .disabled(isWorking)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(confirmTitle, role: isPermanent ? .destructive : nil) { Task { await perform() } }
                    .disabled(!canConfirm)
            }
        }
        .task { await loadReports() }
    }

    private var title: String {
        items.count == 1 ? "Remove “\(items[0].displayName)”?" : "Remove \(items.count) keys?"
    }

    private var isPermanent: Bool { mode == .deletePermanently || onlyArchived }
    private var confirmTitle: String { isPermanent ? "Delete Permanently" : "Archive" }
    private var canConfirm: Bool {
        !isWorking && !isLoading && (!isPermanent || confirmationText == confirmationPhrase)
    }

    @ViewBuilder
    private func impactSection(for item: LibraryItem) -> some View {
        let report = reports[item.id]
        Section(items.count > 1 ? "Impact: \(item.displayName)" : "Impact") {
            if let report, report.isEmpty {
                Label("Not used in your SSH config, the agent or git signing.", systemImage: "checkmark.circle")
                    .foregroundStyle(.green)
            }
            if report?.isLoadedInAgent == true {
                Label("Loaded in ssh-agent: it will be removed from the agent.", systemImage: "person.badge.key")
            }
            ForEach(report?.configReferences ?? []) { reference in
                LabeledContent {
                    Picker("", selection: binding(for: reference)) {
                        ForEach(ReferenceAction.allCases) { Text($0.title).tag($0) }
                    }
                    .labelsHidden()
                    .fixedSize()
                    .disabled(!isPermanent)
                } label: {
                    Text("\(reference.file.lastPathComponent), line \(reference.lineNumber)")
                    Text("Host \(reference.hostPatterns.joined(separator: " ")) → \(reference.value)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            ForEach(report?.gitSigningReferences ?? [], id: \.self) { reference in
                Label(
                    "Used for git commit signing in \(reference.file.lastPathComponent). Update it after deleting.",
                    systemImage: "signature"
                )
                .foregroundStyle(.orange)
            }
            if let notChecked = report?.notChecked, !notChecked.isEmpty {
                DisclosureGroup("Not checked automatically") {
                    ForEach(notChecked, id: \.self) { Text("• \($0)").font(.caption) }
                }
                .font(.callout)
            }
        }
    }

    private func binding(for reference: ConfigReference) -> Binding<ReferenceAction> {
        Binding(
            get: { referenceActions[reference.id] ?? .keep },
            set: { referenceActions[reference.id] = $0 }
        )
    }

    private func loadReports() async {
        isLoading = true
        defer { isLoading = false }
        for item in items where !item.isArchived {
            do {
                reports[item.id] = try await model.impactReport(for: item)
            } catch {
                self.error = error.asSMPError
            }
        }
    }

    private func perform() async {
        isWorking = true
        error = nil
        defer { isWorking = false }
        if !isPermanent {
            await model.archive(items, undoManager: model.windowUndoManager)
            dismiss()
            return
        }
        var edits: [String: [ConfigReferenceEdit]] = [:]
        for item in items {
            let references = reports[item.id]?.configReferences ?? []
            edits[item.id] = references.compactMap { (reference: ConfigReference) -> ConfigReferenceEdit? in
                switch referenceActions[reference.id] ?? .keep {
                case .keep: nil
                case .commentOut: .commentOut(reference)
                case .remove: .remove(reference)
                }
            }
        }
        do {
            try await model.deletePermanently(items, configEdits: edits)
            dismiss()
        } catch {
            self.error = error.asSMPError
        }
    }
}

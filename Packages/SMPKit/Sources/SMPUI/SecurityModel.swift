import Foundation
import Observation
import SMPCore
import SMPServices
import SMPSSH

/// The sections of the Security sidebar group.
public enum SecuritySection: String, CaseIterable, Identifiable, Hashable, Sendable {
    case audit, signing

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .audit: "Audit"
        case .signing: "Commit Signing"
        }
    }

    public var systemImage: String {
        switch self {
        case .audit: "checkmark.shield"
        case .signing: "signature"
        }
    }
}

/// State behind Security → Audit and Security → Commit Signing.
@MainActor
@Observable
public final class SecurityModel {
    public private(set) var findings: [AuditFinding] = []
    public private(set) var score = 100
    public private(set) var lastRun: Date?
    public private(set) var rotations: [RotationJob] = []
    public private(set) var gitState: GitSigningState?
    public var selectedFindingID: String?
    public var lastError: SMPError?
    public var notice: String?

    @ObservationIgnored let services: ServiceContainer

    public init(services: ServiceContainer) {
        self.services = services
    }

    public var selectedFinding: AuditFinding? { findings.first { $0.id == selectedFindingID } }

    /// Findings of medium severity or worse, for the sidebar badge.
    public var importantCount: Int { findings.filter { $0.severity >= .medium }.count }

    public var unfinishedRotations: [RotationJob] { rotations.filter { !$0.isFinished } }

    // MARK: Audit

    public func runAudit(library: LibraryModel) {
        let onDisk = library.items.filter { !$0.isArchived && !$0.isVirtualSecureEnclaveEntry }
        var metadata: [String: KeyMetadata] = [:]
        for item in onDisk {
            if let fingerprint = item.key.fingerprint, let stored = item.metadata {
                metadata[fingerprint] = stored
            }
        }
        let configFiles = (try? services.hosts.loadFiles()) ?? []
        let input = AuditInput(keys: onDisk.map(\.key), metadata: metadata, configFiles: configFiles)
        findings = AuditEngine.findings(input)
        score = AuditEngine.score(findings)
        lastRun = Date()
        if let selectedFindingID, !findings.contains(where: { $0.id == selectedFindingID }) {
            self.selectedFindingID = nil
        }
        reloadRotations()
    }

    /// Starts the finding's fix. Fixes that change files show a sheet or diff first, except permissions.
    public func fix(_ finding: AuditFinding, library: LibraryModel, hosts: HostsModel) async {
        guard let fix = finding.fix else { return }
        let item = finding.keyID.flatMap { id in library.items.first { $0.key.id == id && !$0.isArchived } }
        switch fix {
        case .setPermissions(let path, let mode):
            do {
                try services.auditFixer.setPermissions(path: path, mode: mode, allowedRoots: library.watchedFolders)
                let name = URL(fileURLWithPath: path).lastPathComponent
                notice = "Permissions of \(name) set to \(String(mode, radix: 8))."
                await library.reload()
                runAudit(library: library)
            } catch {
                lastError = error.asSMPError
            }
        case .addPassphrase:
            if let item { library.activeSheet = .changePassphrase(item) }
        case .upgradeFormat:
            if let item { library.activeSheet = .upgradeFormat(item) }
        case .rotate:
            if let item { library.activeSheet = .rotate(item) }
        case .removeConfigLine(let path, let lineIndex):
            hosts.reload()
            guard let file = hosts.files.first(where: { $0.url.path == path }) else { return }
            var document = file.document
            document.removeLine(lineIndex)
            hosts.proposeRawText(document.render(), for: file)
        }
    }

    // MARK: Rotations

    public func reloadRotations() {
        rotations = (try? services.metadata.rotationJobs()) ?? []
    }

    public func discardRotation(_ job: RotationJob) {
        do {
            try services.metadata.deleteRotationJob(id: job.id)
            reloadRotations()
        } catch {
            lastError = error.asSMPError
        }
    }

    // MARK: Commit signing

    public func loadGitState() async {
        do {
            gitState = try await services.gitSigning.currentState()
        } catch {
            lastError = error.asSMPError
        }
    }

    public func planSigning(with item: LibraryItem, email: String, signTags: Bool) async throws -> GitSigningPlan {
        guard let publicKey = item.key.publicKey, let file = item.key.publicKeyFile?.url,
              !item.isVirtualSecureEnclaveEntry
        else {
            throw SMPError.invalidArgument("“\(item.displayName)” has no public key file git can use.")
        }
        return try await services.gitSigning.plan(
            publicKeyFile: file, publicKey: publicKey, email: email, signTags: signTags
        )
    }

    public func applySigning(_ plan: GitSigningPlan) async {
        do {
            try await services.gitSigning.apply(plan)
            notice = "git now signs your commits with SSH."
            await loadGitState()
        } catch {
            lastError = error.asSMPError
        }
    }
}

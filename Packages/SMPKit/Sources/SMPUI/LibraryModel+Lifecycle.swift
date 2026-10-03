import Foundation
import SMPCore
import SMPServices
import SMPSSH

/// Sheets and dialogs presented by the library window.
public enum LibrarySheet: Identifiable, Sendable {
    case newKey
    case newSecureEnclaveKey
    case downloadResidentKeys
    /// Import, optionally pre-filled with a dropped or chosen file.
    case importKey(URL?)
    case rename(LibraryItem)
    case changePassphrase(LibraryItem)
    case changeComment(LibraryItem)
    case upgradeFormat(LibraryItem)
    case delete([LibraryItem])
    case qrCode(LibraryItem)
    case deploy(LibraryItem)
    case rotate(LibraryItem)
    case resumeRotation(RotationJob)
    case backup
    case restoreBackup

    public var id: String {
        switch self {
        case .newKey: "new"
        case .newSecureEnclaveKey: "new-secure-enclave"
        case .downloadResidentKeys: "download-resident"
        case .importKey: "import"
        case .rename(let item): "rename-\(item.id)"
        case .changePassphrase(let item): "passphrase-\(item.id)"
        case .changeComment(let item): "comment-\(item.id)"
        case .upgradeFormat(let item): "upgrade-\(item.id)"
        case .delete(let items): "delete-" + items.map(\.id).joined(separator: ",")
        case .qrCode(let item): "qr-\(item.id)"
        case .deploy(let item): "deploy-\(item.id)"
        case .rotate(let item): "rotate-\(item.id)"
        case .resumeRotation(let job): "rotation-\(job.id.uuidString)"
        case .backup: "backup"
        case .restoreBackup: "restore-backup"
        }
    }
}

/// Optional follow-up steps after creating a key.
public struct NewKeyOptions: Sendable {
    public var tagIDs: Set<Int64> = []
    public var expiresAt: Date?
    public var addToAgent = false
    public var storePassphraseInKeychain = false
    /// When set, a `Host` block using the new key is appended to ~/.ssh/config.
    public var hostAlias = ""
    public var hostName = ""
    public var hostUser = ""

    public init() {}
}

extension LibraryModel {
    public var sshDirectory: URL { services.environment.sshDirectory }

    /// File names currently present in ~/.ssh, for suggesting free names.
    public func existingFileNames() -> Set<String> {
        Set((try? FileManager.default.contentsOfDirectory(atPath: sshDirectory.path)) ?? [])
    }

    // MARK: Create & import

    /// Creates a key and runs the requested follow-up steps. Follow-up failures are reported
    /// in the returned result's `warnings`; the key itself is kept.
    public func generate(
        _ request: KeyGenerationRequest,
        options: NewKeyOptions
    ) async throws -> (result: KeyOperationResult, warnings: [String]) {
        let result = try await services.keys.generate(request)
        var warnings: [String] = []
        let fingerprint = result.publicKey.fingerprintSHA256

        do {
            if options.expiresAt != nil {
                try services.metadata.save(KeyMetadata(
                    fingerprint: fingerprint,
                    expiresAt: options.expiresAt,
                    lastSeenPath: result.privateKeyURL?.path
                ))
            }
            if !options.tagIDs.isEmpty {
                try services.metadata.setTags(options.tagIDs, for: fingerprint)
            }
        } catch {
            warnings.append("Tags or expiry could not be saved: \(error.localizedDescription)")
        }

        if options.addToAgent || options.storePassphraseInKeychain, let privateKey = result.privateKeyURL {
            do {
                try await services.agent.add(
                    keyFile: privateKey,
                    passphrase: request.passphrase,
                    storeInKeychain: options.storePassphraseInKeychain,
                    lifetime: nil
                )
            } catch {
                warnings.append("The key could not be added to the agent: \(error.localizedDescription)")
            }
        }

        let alias = options.hostAlias.trimmingCharacters(in: .whitespaces)
        if !alias.isEmpty {
            do {
                var hostOptions: [(keyword: String, value: String)] = []
                let hostName = options.hostName.trimmingCharacters(in: .whitespaces)
                if !hostName.isEmpty { hostOptions.append(("HostName", hostName)) }
                let user = options.hostUser.trimmingCharacters(in: .whitespaces)
                if !user.isEmpty { hostOptions.append(("User", user)) }
                hostOptions.append(("IdentityFile", "~/.ssh/\(request.fileName)"))
                hostOptions.append(("IdentitiesOnly", "yes"))
                if options.storePassphraseInKeychain {
                    hostOptions.append(("UseKeychain", "yes"))
                    hostOptions.append(("AddKeysToAgent", "yes"))
                }
                try services.config.appendHost(alias: alias, options: hostOptions)
            } catch {
                warnings.append("~/.ssh/config could not be updated: \(error.localizedDescription)")
            }
        }
        await reload()
        selectedKeyIDs = [result.privateKeyURL?.path ?? result.publicKeyURL.path]
        return (result, warnings)
    }

    public func importKey(_ request: KeyImportRequest) async throws -> KeyOperationResult {
        let result = try await services.keys.importKey(request)
        await reload()
        selectedKeyIDs = [result.privateKeyURL?.path ?? result.publicKeyURL.path]
        return result
    }

    // MARK: Edit

    public func configReferences(for item: LibraryItem) async -> [ConfigReference] {
        let files = [item.key.privateKeyFile?.url, item.key.publicKeyFile?.url].compactMap { $0 }
        return (try? services.config.references(to: files)) ?? []
    }

    public func rename(_ item: LibraryItem, to newName: String, updateConfig: Bool) async throws -> RenameResult {
        let result = try await services.keys.rename(item.key, to: newName, updateConfig: updateConfig)
        await reload()
        if let path = result.privateKeyURL?.path ?? result.publicKeyURL?.path {
            selectedKeyIDs = [path]
        }
        return result
    }

    public func changePassphrase(
        _ item: LibraryItem,
        current: SecureBytes?,
        new: SecureBytes?,
        kdfRounds: Int
    ) async throws {
        try await services.keys.changePassphrase(of: item.key, current: current, new: new, kdfRounds: kdfRounds)
        await reload()
    }

    public func changeComment(_ item: LibraryItem, to comment: String, passphrase: SecureBytes?) async throws {
        try await services.keys.changeComment(of: item.key, to: comment, passphrase: passphrase)
        await reload()
    }

    public func upgradeFormat(_ item: LibraryItem, passphrase: SecureBytes?) async throws {
        try await services.keys.upgradeFormat(of: item.key, passphrase: passphrase)
        await reload()
    }

    // MARK: Archive

    /// Moves keys into the encrypted archive. Registers an undo action that restores them.
    public func archive(_ items: [LibraryItem], undoManager: UndoManager?) async {
        var archivedIDs: [UUID] = []
        if items.contains(where: \.isSecureEnclave) {
            notice = "Secure Enclave keys cannot be archived: they can never leave this Mac."
        }
        for item in items where item.archive == nil && !item.isSecureEnclave {
            do {
                if item.isLoadedInAgent, let file = item.key.publicKeyFile?.url ?? item.key.privateKeyFile?.url {
                    try? await services.agent.remove(keyFile: file, removeFromKeychain: false)
                }
                let archived = try services.archive.archive(item.key)
                archivedIDs.append(archived.id)
                if let fingerprint = item.key.fingerprint {
                    // Read the stored record: `item` may be an older snapshot.
                    let stored = try? services.metadata.metadata(for: fingerprint)
                    var metadata = stored ?? item.metadata ?? KeyMetadata(fingerprint: fingerprint)
                    metadata.archivedAt = archived.archivedAt
                    try? services.metadata.save(metadata)
                }
            } catch {
                report(error, whatHappened: "SMP could not archive “\(item.displayName)”.")
            }
        }
        guard !archivedIDs.isEmpty else { return }
        let undoManager = undoManager ?? windowUndoManager
        notice = archivedIDs.count == 1
            ? "Key archived. Choose Edit → Undo to restore it."
            : "\(archivedIDs.count) keys archived."
        if let undoManager {
            let ids = archivedIDs
            undoManager.registerUndo(withTarget: self) { model in
                Task { @MainActor in
                    for id in ids {
                        await model.restore(archiveID: id)
                    }
                }
            }
            undoManager.setActionName(archivedIDs.count == 1 ? "Archive Key" : "Archive Keys")
        }
        await reload()
    }

    /// Restores an archived key. If a key with the same name exists, restores as `<name>_restored`.
    public func restore(archiveID: UUID) async {
        guard let entry = try? services.archive.list().first(where: { $0.id == archiveID }) else { return }
        do {
            do {
                try services.archive.restore(id: archiveID, conflict: .fail)
                notice = "“\(entry.name)” restored."
            } catch let error as SMPError where error.code == .alreadyExists {
                let newName = entry.name + "_restored"
                try services.archive.restore(id: archiveID, conflict: .rename(to: newName))
                notice = "A key named “\(entry.name)” already exists, "
                    + "so the archived key was restored as “\(newName)”."
            }
            if let fingerprint = entry.fingerprint, var metadata = try services.metadata.metadata(for: fingerprint) {
                metadata.archivedAt = nil
                try services.metadata.save(metadata)
            }
        } catch {
            report(error, whatHappened: "SMP could not restore “\(entry.name)”.")
        }
        await reload()
    }

    // MARK: Delete

    public func impactReport(for item: LibraryItem) async throws -> KeyImpactReport {
        try await services.keys.impactReport(for: item.key, isLoadedInAgent: item.isLoadedInAgent)
    }

    /// Permanently deletes keys after Touch ID / password confirmation.
    /// - Parameter configEdits: per item ID, the config changes the user confirmed.
    public func deletePermanently(_ items: [LibraryItem], configEdits: [String: [ConfigReferenceEdit]]) async throws {
        let count = items.count
        try await services.authenticator.authenticate(
            reason: count == 1
                ? "permanently delete the key “\(items[0].displayName)”"
                : "permanently delete \(count) keys"
        )
        for item in items {
            if let archive = item.archive {
                try services.archive.deleteArchived(id: archive.id)
            } else if let enclaveKey = item.secureEnclave {
                try services.secureEnclave.delete(id: enclaveKey.id)
                if !item.isVirtualSecureEnclaveEntry {
                    try await services.keys.deletePermanently(item.key, configEdits: configEdits[item.id] ?? [])
                }
            } else {
                try await services.keys.deletePermanently(item.key, configEdits: configEdits[item.id] ?? [])
            }
            if let fingerprint = item.key.fingerprint {
                let stillPresent = self.items.contains {
                    $0.key.fingerprint == fingerprint && !items.map(\.id).contains($0.id)
                }
                if !stillPresent {
                    try? services.metadata.deleteMetadata(for: fingerprint)
                }
            }
        }
        notice = count == 1 ? "Key deleted permanently." : "\(count) keys deleted permanently."
        selectedKeyIDs = []
        await reload()
    }

    // MARK: Export

    public func exportPrivateKey(_ item: LibraryItem, to destination: URL) async throws {
        try await services.authenticator.authenticate(reason: "export the private key “\(item.displayName)”")
        try services.keys.exportPrivateKey(item.key, to: destination)
        notice = "Private key exported. Keep the copy somewhere safe."
    }

    public func exportPublicKey(_ item: LibraryItem, to destination: URL) throws {
        try services.keys.exportPublicKey(item.key, to: destination)
    }

    // MARK: Archived entries

    /// Builds a display-only `DiscoveredKey` from an archive manifest.
    nonisolated static func discoveredKey(fromArchived entry: ArchivedKey) -> DiscoveredKey {
        let directory = URL(fileURLWithPath: entry.originalDirectory, isDirectory: true)
        func info(_ file: ArchivedKey.File?) -> KeyFileInfo? {
            file.map {
                KeyFileInfo(
                    url: directory.appending(path: $0.name),
                    permissions: UInt16(truncatingIfNeeded: $0.mode),
                    isOwnedByCurrentUser: true,
                    isSymbolicLink: false,
                    size: 0,
                    createdAt: nil,
                    modifiedAt: entry.archivedAt
                )
            }
        }
        let privateFile = info(entry.files.first { $0.isPrivateKey })
        let publicFile = info(entry.files.first { $0.name == entry.name + ".pub" })
        let certificateFile = info(entry.files.first { $0.name == entry.name + "-cert.pub" })
        let kind: DiscoveredKey.Kind = privateFile == nil ? .publicOnly : (publicFile == nil ? .privateOnly : .pair)
        return DiscoveredKey(
            name: entry.name,
            kind: kind,
            publicKey: entry.publicKey,
            privateKeyFile: privateFile,
            privateKeyInfo: nil,
            publicKeyFile: publicFile,
            certificateFile: certificateFile,
            certificate: nil,
            issues: []
        )
    }
}

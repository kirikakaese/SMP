import Foundation
import SMPCore
import SMPServices

extension LibraryModel {
    // MARK: Backup and restore

    /// The files a backup contains: every key file in the key folders (not archived keys, not
    /// Secure Enclave keys, which cannot leave this Mac), plus `~/.ssh/config` and known_hosts.
    public func backupSources() -> [(BackupFile.Kind, URL)] {
        var sources: [(BackupFile.Kind, URL)] = []
        var seen = Set<String>()
        func add(_ kind: BackupFile.Kind, _ url: URL?) {
            guard let url, seen.insert(url.standardizedFileURL.path).inserted else { return }
            sources.append((kind, url))
        }
        for item in items where !item.isArchived && !item.isVirtualSecureEnclaveEntry {
            add(.privateKey, item.key.privateKeyFile?.url)
            add(.publicKey, item.key.publicKeyFile?.url)
            add(.certificate, item.key.certificateFile?.url)
        }
        let environment = services.environment
        let settings: [(BackupFile.Kind, URL)] = [
            (.config, environment.configFile), (.knownHosts, environment.knownHostsFile),
        ]
        for (kind, url) in settings where FileManager.default.fileExists(atPath: url.path) {
            add(kind, url)
        }
        return sources
    }

    /// Writes an encrypted backup to `url`.
    public func createBackup(passphrase: SecureBytes, to url: URL) async throws -> BackupManifest {
        let sources = backupSources()
        let backup = services.backup
        let manifest = try await Task.detached {
            try backup.createBackup(files: sources, passphrase: passphrase, to: url)
        }.value
        notice = String(localized: "Backup saved: \(manifest.keyCount) keys and your SSH settings.")
        return manifest
    }

    /// Decrypts a backup and works out what restoring it would do. Nothing is written yet.
    public func openBackup(_ url: URL, passphrase: SecureBytes) async throws -> (OpenedBackup, [RestoreStep]) {
        let backup = services.backup
        let folders = watchedFolders
        return try await Task.detached {
            let opened = try backup.open(url, passphrase: passphrase)
            return (opened, backup.restorePlan(for: opened, allowedFolders: folders))
        }.value
    }

    /// Restores the planned files (never overwriting anything) and merges SMP's metadata.
    public func restoreBackup(_ opened: OpenedBackup, plan: [RestoreStep]) async throws -> RestoreSummary {
        let summary = try services.backup.restore(opened, plan: plan)
        await reload()
        notice = summary.written.isEmpty
            ? "Nothing to restore: everything in the backup is already here."
            : "Restored \(summary.written.count) files from the backup."
        return summary
    }
}

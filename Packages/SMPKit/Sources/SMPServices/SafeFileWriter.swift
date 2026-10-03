import CryptoKit
import Foundation
import SMPCore

/// Identifies the exact on-disk state of a file when SMP read it.
public struct FileSnapshot: Sendable, Equatable {
    public let size: Int
    public let modificationDate: Date?
    public let sha256: Data

    /// Captures the current state of the file at `url`, or `nil` if it does not exist.
    public static func capture(_ url: URL) throws -> FileSnapshot? {
        let target = url.resolvingSymlinksInPath()
        guard FileManager.default.fileExists(atPath: target.path) else { return nil }
        let data = try Data(contentsOf: target)
        let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
        return FileSnapshot(
            size: data.count,
            modificationDate: attributes[.modificationDate] as? Date,
            sha256: Data(SHA256.hash(data: data))
        )
    }
}

/// Writes non-secret text files (config, known_hosts) safely:
/// lock → verify unchanged since read → timestamped backup → atomic replace.
public struct SafeFileWriter: Sendable {
    /// Where timestamped backups go (Application Support/Backups by default).
    public let backupDirectory: URL

    public init(backupDirectory: URL) {
        self.backupDirectory = backupDirectory
    }

    public static func live() throws -> SafeFileWriter {
        SafeFileWriter(backupDirectory: try AppPaths.applicationSupportDirectory().appending(path: "Backups"))
    }

    /// Replaces the file at `url` with `contents`.
    ///
    /// - Parameters:
    ///   - expected: the snapshot taken when the file was read; `nil` means "must not exist yet".
    ///   - mode: permissions for a newly created file. Existing files keep their permissions.
    /// - Returns: the backup's location, if a previous version existed.
    @discardableResult
    public func write(_ contents: Data, to url: URL, expected: FileSnapshot?, mode: Int = 0o600) throws -> URL? {
        // Follow symlinks (dotfile managers often link ~/.ssh/config) and replace the real file.
        let target = url.resolvingSymlinksInPath()
        let directory = target.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let lock = try FileLock(path: lockPath(for: target))
        defer { lock.release() }

        guard try FileSnapshot.capture(target) == expected else {
            throw SMPError.fileChangedOnDisk(target.lastPathComponent)
        }

        var backup: URL?
        var permissions = mode
        if expected != nil {
            backup = try makeBackup(of: target)
            let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
            permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? mode
        }

        let temporary = directory.appending(path: ".\(target.lastPathComponent).smp-\(UUID().uuidString)")
        do {
            guard FileManager.default.createFile(
                atPath: temporary.path,
                contents: contents,
                attributes: [.posixPermissions: permissions]
            ) else {
                throw SMPError(.fileSystem, whatHappened: String(localized: """
                    SMP could not write \(target.lastPathComponent).
                    """))
            }
            let handle = try FileHandle(forWritingTo: temporary)
            try handle.synchronize()
            try handle.close()
            guard rename(temporary.path, target.path) == 0 else {
                throw SMPError(
                    .fileSystem,
                    whatHappened: String(localized: "SMP could not replace \(target.lastPathComponent)."),
                    details: String(cString: strerror(errno))
                )
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
        return backup
    }

    /// Lock files live next to the backups (never in ~/.ssh), one per target path.
    private func lockPath(for target: URL) throws -> String {
        let locks = backupDirectory.deletingLastPathComponent().appending(path: "Locks")
        try FileManager.default.createDirectory(
            at: locks,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let digest = SHA256.hash(data: Data(target.path.utf8)).prefix(16).map { String(format: "%02x", $0) }.joined()
        return locks.appending(path: "\(digest).lock").path
    }

    private func makeBackup(of file: URL) throws -> URL {
        try FileManager.default.createDirectory(
            at: backupDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss-SSS"
        let stamp = formatter.string(from: Date())
        let backup = backupDirectory.appending(path: "\(file.lastPathComponent)-\(stamp).bak")
        try FileManager.default.copyItem(at: file, to: backup)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
        return backup
    }
}

/// An exclusive advisory lock (`flock`) held until `release()`. The lock file itself is kept,
/// because unlinking it would let a waiting process lock a stale inode.
final class FileLock {
    private var descriptor: Int32

    init(path: String, timeout: TimeInterval = 5) throws {
        let opened = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard opened >= 0 else {
            throw SMPError(.fileSystem, whatHappened: String(localized: "SMP could not lock a file for editing."))
        }
        let deadline = Date().addingTimeInterval(timeout)
        while flock(opened, LOCK_EX | LOCK_NB) != 0 {
            guard Date() < deadline else {
                close(opened)
                throw SMPError(
                    .fileSystem,
                    whatHappened: String(localized: "Another SMP window is editing this file."),
                    howToFix: String(localized: "Wait a moment, then try again.")
                )
            }
            usleep(50_000)
        }
        descriptor = opened
    }

    func release() {
        guard descriptor >= 0 else { return }
        flock(descriptor, LOCK_UN)
        close(descriptor)
        descriptor = -1
    }

    deinit {
        release()
    }
}

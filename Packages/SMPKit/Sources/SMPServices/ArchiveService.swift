import CryptoKit
import Foundation
import SMPCore
import SMPSSH

/// A key that was moved into SMP's encrypted archive. The manifest holds public information only.
public struct ArchivedKey: Sendable, Hashable, Codable, Identifiable {
    public struct File: Sendable, Hashable, Codable {
        public let name: String
        public let mode: Int
        public let isPrivateKey: Bool
    }

    public let id: UUID
    public let name: String
    public let originalDirectory: String
    public let files: [File]
    public let publicKeyLine: String?
    public let fingerprint: String?
    public let archivedAt: Date

    public var publicKey: SSHPublicKey? { publicKeyLine.flatMap { try? SSHPublicKey(line: $0) } }
}

/// What to do when restoring would overwrite an existing file.
public enum RestoreConflictResolution: Sendable, Hashable {
    /// Fail with `alreadyExists` (the default).
    case fail
    /// Restore under a different base name, e.g. `id_ed25519_restored`.
    case rename(to: String)
}

public protocol ArchiveServicing: Sendable {
    /// Encrypts the key's files into the archive, verifies the archive, then securely deletes the originals.
    func archive(_ key: DiscoveredKey) throws -> ArchivedKey
    func list() throws -> [ArchivedKey]
    /// Restores the files and removes the archive entry. Returns the restored file URLs.
    @discardableResult
    func restore(id: UUID, conflict: RestoreConflictResolution) throws -> [URL]
    /// Permanently deletes an archive entry.
    func deleteArchived(id: UUID) throws
}

/// `ArchiveServicing` storing AES-GCM sealed archives, keyed by a 256-bit key kept in the Keychain.
///
/// Layout: `<id>.json` (public manifest, mode 0600) and `<id>.sealed` (AES-GCM combined box over
/// the files' contents; the manifest's id is bound as associated data).
public struct ArchiveService: ArchiveServicing {
    private let directory: URL
    private let keychain: any KeychainServicing
    private static let keyItem = KeychainItem(
        service: KeychainItem.Service.archiveKey,
        account: "archive-v1",
        label: "SMP key archive"
    )

    public init(directory: URL, keychain: any KeychainServicing) {
        self.directory = directory
        self.keychain = keychain
    }

    public static func live(keychain: any KeychainServicing) throws -> ArchiveService {
        let directory = try AppPaths.applicationSupportDirectory().appending(path: "Archive")
        return ArchiveService(directory: directory, keychain: keychain)
    }

    // MARK: Archive

    public func archive(_ key: DiscoveredKey) throws -> ArchivedKey {
        try ensureDirectory()
        let files = [key.privateKeyFile, key.publicKeyFile, key.certificateFile].compactMap { $0 }
        guard let first = files.first else {
            throw SMPError.keyOperationFailed("There are no files to archive for “\(key.name)”.")
        }
        let manifest = ArchivedKey(
            id: UUID(),
            name: key.name,
            originalDirectory: first.url.deletingLastPathComponent().path,
            files: files.map {
                ArchivedKey.File(
                    name: $0.url.lastPathComponent,
                    mode: Int($0.permissions),
                    isPrivateKey: $0.url == key.privateKeyFile?.url
                )
            },
            publicKeyLine: key.publicKey?.openSSHLine,
            fingerprint: key.fingerprint,
            archivedAt: Date()
        )

        let payload = try buildPayload(files.map(\.url))
        defer { payload.wipe() }
        let sealed = try seal(payload, id: manifest.id)
        try write(Data(sealed), to: sealedURL(manifest.id))
        try write(try JSONEncoder.archive.encode(manifest), to: manifestURL(manifest.id))

        // Verify before deleting anything: the archive must decrypt to exactly what is on disk.
        let check = try open(manifest.id)
        defer { check.wipe() }
        guard check.constantTimeEquals(payload) else {
            try? deleteArchived(id: manifest.id)
            throw SMPError.keyOperationFailed("The archive could not be verified. Your key was not changed.")
        }
        for file in files {
            try SecureDelete.removeFile(at: file.url)
        }
        return manifest
    }

    // MARK: Listing & restoring

    public func list() throws -> [ArchivedKey] {
        guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        return names.filter { $0.hasSuffix(".json") }
            .compactMap { name in
                guard let data = try? Data(contentsOf: directory.appending(path: name)) else { return nil }
                return try? JSONDecoder.archive.decode(ArchivedKey.self, from: data)
            }
            .sorted { $0.archivedAt > $1.archivedAt }
    }

    @discardableResult
    public func restore(id: UUID, conflict: RestoreConflictResolution) throws -> [URL] {
        let manifest = try JSONDecoder.archive.decode(ArchivedKey.self, from: Data(contentsOf: manifestURL(id)))
        let payload = try open(id)
        defer { payload.wipe() }

        let destinationDirectory = URL(fileURLWithPath: manifest.originalDirectory, isDirectory: true)
        try FileManager.default.createDirectory(at: destinationDirectory, withIntermediateDirectories: true)
        let targetNames = manifest.files.map { file -> String in
            guard case .rename(let newBase) = conflict else { return file.name }
            return newBase + file.name.dropFirst(manifest.name.count)
        }
        for name in targetNames {
            if FileManager.default.fileExists(atPath: destinationDirectory.appending(path: name).path) {
                throw SMPError.alreadyExists(name)
            }
        }

        var written: [URL] = []
        do {
            try payload.withUnsafeBytes { bytes in
                var reader = SSHWireReader(bytes, maxFieldLength: 1_024 * 1_024)
                for (file, name) in zip(manifest.files, targetNames) {
                    let range = try reader.readStringRange()
                    let url = destinationDirectory.appending(path: name)
                    try SecureDelete.createFile(
                        at: url,
                        contents: UnsafeRawBufferPointer(rebasing: bytes[range]),
                        mode: file.mode
                    )
                    written.append(url)
                }
            }
        } catch {
            for url in written {
                try? FileManager.default.removeItem(at: url)
            }
            throw error
        }
        try deleteArchived(id: id)
        return written
    }

    public func deleteArchived(id: UUID) throws {
        if FileManager.default.fileExists(atPath: sealedURL(id).path) {
            try SecureDelete.removeFile(at: sealedURL(id))
        }
        if FileManager.default.fileExists(atPath: manifestURL(id).path) {
            try FileManager.default.removeItem(at: manifestURL(id))
        }
    }

    // MARK: Internals

    /// Payload: each file's contents as an SSH `string`, in manifest order.
    private func buildPayload(_ urls: [URL]) throws -> SecureBytes {
        let contents = try urls.map { try SecureFileReader.read($0, maxBytes: PrivateKeyInspector.maxFileSize) }
        defer { contents.forEach { $0.wipe() } }
        var writer = SecureWireWriter(capacity: contents.reduce(0) { $0 + $1.count + 4 })
        for file in contents {
            file.withUnsafeBytes { writer.appendString($0) }
        }
        return writer.finish()
    }

    private func seal(_ payload: SecureBytes, id: UUID) throws -> Data {
        let key = try archiveKey()
        let box = try payload.withUnsafeBytes { bytes in
            try AES.GCM.seal(bytes, using: key, authenticating: Data(id.uuidString.utf8))
        }
        guard let combined = box.combined else {
            throw SMPError.keyOperationFailed("SMP could not encrypt the archive.")
        }
        return combined
    }

    private func open(_ id: UUID) throws -> SecureBytes {
        let key = try archiveKey()
        let box = try AES.GCM.SealedBox(combined: Data(contentsOf: sealedURL(id)))
        do {
            var plaintext = try AES.GCM.open(box, using: key, authenticating: Data(id.uuidString.utf8))
            return SecureBytes(consuming: &plaintext)
        } catch {
            throw SMPError.keyOperationFailed(
                "The archived key could not be decrypted.",
                howToFix: "The archive key in your Keychain may have been removed or the archive was damaged."
            )
        }
    }

    /// Loads the archive key from the Keychain, creating it on first use.
    private func archiveKey() throws -> SymmetricKey {
        if let stored = try keychain.secret(for: Self.keyItem) {
            defer { stored.wipe() }
            return stored.withUnsafeBytes { SymmetricKey(data: $0) }
        }
        let key = SymmetricKey(size: .bits256)
        let bytes = key.withUnsafeBytes { SecureBytes($0) }
        defer { bytes.wipe() }
        try keychain.setSecret(bytes, for: Self.keyItem)
        return key
    }

    private func ensureDirectory() throws {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    private func write(_ data: Data, to url: URL) throws {
        let created = FileManager.default.createFile(
            atPath: url.path,
            contents: data,
            attributes: [.posixPermissions: 0o600]
        )
        guard created else {
            throw SMPError(.fileSystem, whatHappened: "SMP could not write to its archive folder.")
        }
    }

    private func manifestURL(_ id: UUID) -> URL { directory.appending(path: "\(id.uuidString).json") }
    private func sealedURL(_ id: UUID) -> URL { directory.appending(path: "\(id.uuidString).sealed") }
}

extension JSONEncoder {
    static var archive: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}

extension JSONDecoder {
    static var archive: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

/// File creation and deletion for key material.
public enum SecureDelete {
    /// Overwrites the file's contents with zeros, flushes, then unlinks it.
    ///
    /// On APFS (copy-on-write, SSD wear levelling) overwriting cannot guarantee the old blocks are
    /// gone; it still removes the data from the file's current extent. FileVault protects the rest.
    public static func removeFile(at url: URL) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { return }
        if (info.st_mode & S_IFMT) == S_IFREG, info.st_size > 0 {
            let descriptor = Darwin.open(url.path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW)
            if descriptor >= 0 {
                let zeros = [UInt8](repeating: 0, count: Int(info.st_size))
                _ = zeros.withUnsafeBytes { RawFileWriter.write(descriptor, $0) }
                fsync(descriptor)
                close(descriptor)
            }
        }
        guard unlink(url.path) == 0 else {
            throw SMPError(
                .fileSystem,
                whatHappened: "SMP could not delete \(url.lastPathComponent).",
                details: String(cString: strerror(errno))
            )
        }
    }

    /// Creates a new file (failing if it exists) with `mode`, writing `contents` directly from memory.
    public static func createFile(at url: URL, contents: UnsafeRawBufferPointer, mode: Int) throws {
        let flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW
        let descriptor = Darwin.open(url.path, flags, mode_t(mode))
        guard descriptor >= 0 else {
            if errno == EEXIST {
                throw SMPError.alreadyExists(url.lastPathComponent)
            }
            throw SMPError(
                .fileSystem,
                whatHappened: "SMP could not create \(url.lastPathComponent).",
                details: String(cString: strerror(errno))
            )
        }
        defer { close(descriptor) }
        // open() applies the umask; set the exact mode explicitly.
        fchmod(descriptor, mode_t(mode))
        guard RawFileWriter.write(descriptor, contents), fsync(descriptor) == 0 else {
            unlink(url.path)
            throw SMPError(.fileSystem, whatHappened: "SMP could not write \(url.lastPathComponent).")
        }
    }
}

enum RawFileWriter {
    static func write(_ descriptor: Int32, _ buffer: UnsafeRawBufferPointer) -> Bool {
        guard let base = buffer.baseAddress else { return true }
        var offset = 0
        while offset < buffer.count {
            let written = Darwin.write(descriptor, base + offset, buffer.count - offset)
            if written < 0 {
                if errno == EINTR { continue }
                return false
            }
            offset += written
        }
        return true
    }
}

import CommonCrypto
import CryptoKit
import Foundation
import SMPCore
import SMPPersistence
import SMPSSH

/// A decrypted backup, held in memory only while the user looks at the restore preview.
/// File contents live in `SecureBytes` and are wiped by `wipe()` or when the object goes away.
public final class OpenedBackup: @unchecked Sendable {
    // Safety: immutable after init; `SecureBytes` guards its own storage.
    public let manifest: BackupManifest
    let contents: [SecureBytes]

    init(manifest: BackupManifest, contents: [SecureBytes]) {
        self.manifest = manifest
        self.contents = contents
    }

    public func wipe() {
        contents.forEach { $0.wipe() }
    }
}

/// Creates and restores encrypted SMP backups (`.smpbackup`).
public protocol BackupServicing: Sendable {
    /// Encrypts the files and SMP's metadata with `passphrase` and writes the backup to `url`.
    func createBackup(files: [(BackupFile.Kind, URL)], passphrase: SecureBytes, to url: URL) throws -> BackupManifest
    /// Decrypts a backup. Fails with `passphraseRequired` for a wrong passphrase.
    func open(_ url: URL, passphrase: SecureBytes) throws -> OpenedBackup
    /// What restoring would do, without touching anything. Files may only go to `~/.ssh` or one
    /// of `allowedFolders`; anything else is restored into `~/.ssh`.
    func restorePlan(for backup: OpenedBackup, allowedFolders: [URL]) -> [RestoreStep]
    /// Writes the planned files (never overwriting anything) and merges the metadata.
    func restore(_ backup: OpenedBackup, plan: [RestoreStep]) throws -> RestoreSummary
}

/// File layout: `"SMPBACKUP" || version (1 byte) || PBKDF2 iterations (uint32) || salt length
/// (1 byte) || salt || AES-256-GCM combined box (nonce || ciphertext || tag)`. The header is
/// authenticated as associated data. The plaintext is the manifest JSON as an SSH `string`,
/// followed by each file's contents as an SSH `string`, in manifest order.
public struct BackupService: BackupServicing {
    public static let fileExtension = "smpbackup"
    static let magic = Data("SMPBACKUP".utf8)
    static let formatVersion: UInt8 = 1
    /// PBKDF2-HMAC-SHA256 rounds for new backups (OWASP 2023 guidance).
    public static let defaultIterations = 600_000
    static let iterationRange = 1_000...10_000_000
    /// Limits that keep a hostile or damaged file from exhausting memory.
    static let maxFileSize = 8 * 1024 * 1024
    static let maxBackupSize = 256 * 1024 * 1024

    private let environment: SSHEnvironment
    private let metadata: any MetadataStoring
    private let iterations: Int

    public init(environment: SSHEnvironment, metadata: any MetadataStoring, iterations: Int = defaultIterations) {
        self.environment = environment
        self.metadata = metadata
        self.iterations = iterations
    }

    // MARK: Creating

    public func createBackup(
        files sources: [(BackupFile.Kind, URL)],
        passphrase: SecureBytes,
        to url: URL
    ) throws -> BackupManifest {
        try Self.checkPassphrase(passphrase)
        var files: [BackupFile] = []
        var contents: [SecureBytes] = []
        defer { contents.forEach { $0.wipe() } }
        for (kind, source) in sources {
            let mode = (try? FileManager.default.attributesOfItem(atPath: source.path)[.posixPermissions] as? Int)
            contents.append(try SecureFileReader.read(source, maxBytes: Self.maxFileSize))
            files.append(BackupFile(
                kind: kind,
                path: BackupFile.storedPath(for: source, home: environment.homeDirectory),
                mode: mode ?? (kind == .privateKey ? 0o600 : 0o644)
            ))
        }
        let manifest = BackupManifest(files: files, metadata: try snapshot())
        let manifestData = try JSONEncoder.archive.encode(manifest)
        var writer = SecureWireWriter(capacity: contents.reduce(manifestData.count + 4) { $0 + $1.count + 4 })
        writer.appendString(manifestData)
        for file in contents {
            file.withUnsafeBytes { writer.appendString($0) }
        }
        let plaintext = writer.finish()
        defer { plaintext.wipe() }

        let salt = SymmetricKey(size: .init(bitCount: 128)).withUnsafeBytes { Data($0) }
        let header = Self.header(iterations: iterations, salt: salt)
        let key = try Self.deriveKey(passphrase: passphrase, salt: salt, iterations: iterations)
        let box = try plaintext.withUnsafeBytes { try AES.GCM.seal($0, using: key, authenticating: header) }
        guard let combined = box.combined else {
            throw SMPError(.keyOperationFailed, whatHappened: "SMP could not encrypt the backup.")
        }
        try write(header + combined, to: url)
        return manifest
    }

    private func write(_ data: Data, to url: URL) throws {
        do {
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            throw SMPError(
                .fileSystem,
                whatHappened: "SMP could not save the backup to \(url.lastPathComponent).",
                details: error.localizedDescription
            )
        }
    }

    /// Everything SMP keeps about keys, hosts and tunnels (no provider tokens, no rotation jobs).
    func snapshot() throws -> MetadataSnapshot {
        func lists(_ assignments: [String: Set<Int64>]) -> [String: [Int64]] {
            assignments.mapValues { $0.sorted() }
        }
        return MetadataSnapshot(
            keys: try metadata.allMetadata().values.sorted { $0.fingerprint < $1.fingerprint },
            tags: try metadata.allTags(),
            tagAssignments: lists(try metadata.tagAssignments()),
            groups: try metadata.allGroups(),
            groupAssignments: lists(try metadata.groupAssignments()),
            hosts: try metadata.allHostMetadata().values.sorted { $0.alias < $1.alias },
            hostTagAssignments: lists(try metadata.hostTagAssignments()),
            tunnels: try metadata.allTunnels()
        )
    }

    // MARK: Opening

    public func open(_ url: URL, passphrase: SecureBytes) throws -> OpenedBackup {
        try Self.checkPassphrase(passphrase)
        let data = try Self.readBackupFile(url)
        let (iterations, salt, headerLength) = try Self.parseHeader(data)
        let header = data.prefix(headerLength)
        let key = try Self.deriveKey(passphrase: passphrase, salt: salt, iterations: iterations)
        var plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: data.dropFirst(headerLength))
            plaintext = try AES.GCM.open(box, using: key, authenticating: header)
        } catch {
            throw SMPError(
                .passphraseRequired,
                whatHappened: "The backup could not be opened.",
                howToFix: "Check the passphrase. If it is right, the file is damaged or not an SMP backup."
            )
        }
        let secure = SecureBytes(consuming: &plaintext)
        defer { secure.wipe() }
        return try Self.parsePayload(secure)
    }

    static func readBackupFile(_ url: URL) throws -> Data {
        let size = try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int
        guard let size, size <= maxBackupSize else {
            throw SMPError.invalidArgument("\(url.lastPathComponent) is missing or too large to be an SMP backup.")
        }
        do {
            return try Data(contentsOf: url)
        } catch {
            throw SMPError(
                .fileSystem, whatHappened: "SMP could not read \(url.lastPathComponent).",
                details: error.localizedDescription
            )
        }
    }

    static let newerVersion = SMPError.invalidArgument(
        "This backup was made by a newer version of SMP. Update SMP to restore it."
    )

    static func header(iterations: Int, salt: Data) -> Data {
        var header = magic
        header.append(formatVersion)
        withUnsafeBytes(of: UInt32(iterations).bigEndian) { header.append(contentsOf: $0) }
        header.append(UInt8(salt.count))
        header.append(salt)
        return header
    }

    /// - Returns: iterations, salt and the header's length.
    static func parseHeader(_ data: Data) throws -> (Int, Data, Int) {
        let notABackup = SMPError.invalidArgument("This file is not an SMP backup.")
        let bytes = [UInt8](data.prefix(magic.count + 6 + 255))
        guard bytes.count > magic.count + 6, Data(bytes.prefix(magic.count)) == magic else { throw notABackup }
        var offset = magic.count
        guard bytes[offset] == formatVersion else { throw newerVersion }
        offset += 1
        let iterations = bytes[offset..<offset + 4].reduce(0) { ($0 << 8) | Int($1) }
        offset += 4
        let saltLength = Int(bytes[offset])
        offset += 1
        guard iterationRange.contains(iterations), (16...64).contains(saltLength),
              bytes.count >= offset + saltLength
        else { throw notABackup }
        let salt = Data(bytes[offset..<offset + saltLength])
        return (iterations, salt, offset + saltLength)
    }

    static func parsePayload(_ payload: SecureBytes) throws -> OpenedBackup {
        let damaged = SMPError.invalidArgument("The backup is damaged.")
        return try payload.withUnsafeBytes { buffer in
            var reader = SSHWireReader(buffer, maxFieldLength: maxBackupSize)
            guard let manifestRange = try? reader.readStringRange(),
                  let manifest = try? JSONDecoder.archive.decode(
                    BackupManifest.self, from: Data(buffer[manifestRange])
                  )
            else { throw damaged }
            guard manifest.version <= BackupManifest.currentVersion else {
                throw newerVersion
            }
            var contents: [SecureBytes] = []
            for _ in manifest.files {
                guard let range = try? reader.readStringRange(), range.count <= maxFileSize else {
                    contents.forEach { $0.wipe() }
                    throw damaged
                }
                contents.append(SecureBytes(UnsafeRawBufferPointer(rebasing: buffer[range])))
            }
            return OpenedBackup(manifest: manifest, contents: contents)
        }
    }

    // MARK: Restoring

    public func restorePlan(for backup: OpenedBackup, allowedFolders: [URL]) -> [RestoreStep] {
        let ssh = environment.sshDirectory.standardizedFileURL
        let roots = ([ssh] + allowedFolders).map(\.standardizedFileURL)
        var claimed = Set<String>()
        return backup.manifest.files.enumerated().map { index, file in
            let target = restoreTarget(for: file, roots: roots, ssh: ssh)
            let planned = action(for: target, contents: backup.contents[index], file: file, claimed: &claimed)
            let step = RestoreStep(index: index, file: file, target: target, action: planned)
            if let destination = step.destination {
                claimed.insert(destination.path)
            }
            return step
        }
    }

    /// Config files only ever go to their place in `~/.ssh`; key files to their folder if SMP
    /// watches it, otherwise into `~/.ssh`.
    func restoreTarget(for file: BackupFile, roots: [URL], ssh: URL) -> URL {
        let name = file.fileName
        switch file.kind {
        case .config: return environment.configFile
        case .knownHosts: return environment.knownHostsFile
        case .privateKey, .publicKey, .certificate:
            let stored = BackupFile.url(for: file.path, home: environment.homeDirectory).standardizedFileURL
            let folder = stored.deletingLastPathComponent().standardizedFileURL
            let isSafeName = !name.isEmpty && name != "." && name != ".." && !name.contains("/")
            guard isSafeName else { return ssh.appending(path: "restored-key") }
            if roots.contains(where: { $0.path == folder.path }) {
                return folder.appending(path: name)
            }
            return ssh.appending(path: name)
        }
    }

    private func action(
        for target: URL,
        contents: SecureBytes,
        file: BackupFile,
        claimed: inout Set<String>
    ) -> RestoreStep.Action {
        if !FileManager.default.fileExists(atPath: target.path), !claimed.contains(target.path) {
            return .create
        }
        if let existing = try? SecureFileReader.read(target, maxBytes: Self.maxFileSize) {
            defer { existing.wipe() }
            if existing.constantTimeEquals(contents) { return .alreadyPresent }
        }
        let alternative = target.deletingLastPathComponent().appending(path: Self.alternativeName(for: file))
        if FileManager.default.fileExists(atPath: alternative.path) || claimed.contains(alternative.path) {
            return .skip("Both \(target.lastPathComponent) and \(alternative.lastPathComponent) already exist.")
        }
        return .writeAlongside(alternative)
    }

    /// `id_ed25519` → `id_ed25519-restored`, keeping `.pub` / `-cert.pub` so pairs stay pairs.
    static func alternativeName(for file: BackupFile) -> String {
        let name = file.fileName
        for suffix in ["-cert.pub", ".pub"] where name.hasSuffix(suffix) {
            return String(name.dropLast(suffix.count)) + "-restored" + suffix
        }
        return name + "-restored"
    }

    public func restore(_ backup: OpenedBackup, plan: [RestoreStep]) throws -> RestoreSummary {
        var summary = RestoreSummary()
        for step in plan {
            switch step.action {
            case .alreadyPresent:
                summary.alreadyPresent += 1
            case .skip(let reason):
                summary.skipped.append(reason)
            case .create, .writeAlongside:
                guard let destination = step.destination, backup.contents.indices.contains(step.index) else {
                    continue
                }
                try FileManager.default.createDirectory(
                    at: destination.deletingLastPathComponent(),
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )
                let mode = step.file.kind == .privateKey ? 0o600 : (step.file.mode & 0o644)
                try backup.contents[step.index].withUnsafeBytes {
                    try SecureDelete.createFile(at: destination, contents: $0, mode: mode)
                }
                summary.written.append(destination)
            }
        }
        try merge(backup.manifest.metadata, into: &summary)
        return summary
    }

    // MARK: Metadata

    /// Adds what is missing; never overwrites notes, settings or tunnels that already exist.
    func merge(_ snapshot: MetadataSnapshot, into summary: inout RestoreSummary) throws {
        let tagIDs = try mergeTags(snapshot.tags, summary: &summary)
        let groupIDs = try mergeGroups(snapshot.groups, summary: &summary)
        let existingKeys = try metadata.allMetadata()
        for var key in snapshot.keys where existingKeys[key.fingerprint] == nil {
            key.archivedAt = nil
            try metadata.save(key)
            summary.notesRestored += 1
        }
        let currentTags = try metadata.tagAssignments()
        for (fingerprint, ids) in snapshot.tagAssignments {
            let mapped = Set(ids.compactMap { tagIDs[$0] })
            let merged = (currentTags[fingerprint] ?? []).union(mapped)
            if merged != currentTags[fingerprint] ?? [] { try metadata.setTags(merged, for: fingerprint) }
        }
        let currentGroups = try metadata.groupAssignments()
        for (fingerprint, ids) in snapshot.groupAssignments {
            let mapped = Set(ids.compactMap { groupIDs[$0] })
            let merged = (currentGroups[fingerprint] ?? []).union(mapped)
            if merged != currentGroups[fingerprint] ?? [] { try metadata.setGroups(merged, for: fingerprint) }
        }
        try mergeHostsAndTunnels(snapshot, tagIDs: tagIDs, summary: &summary)
    }

    private func mergeTags(_ tags: [KeyTag], summary: inout RestoreSummary) throws -> [Int64: Int64] {
        var existing = Dictionary(
            try metadata.allTags().map { ($0.name.lowercased(), $0.id) }, uniquingKeysWith: { first, _ in first }
        )
        var mapping: [Int64: Int64] = [:]
        for tag in tags {
            if let id = existing[tag.name.lowercased()] {
                mapping[tag.id] = id
            } else {
                let created = try metadata.createTag(named: tag.name, color: tag.color)
                existing[tag.name.lowercased()] = created.id
                mapping[tag.id] = created.id
                summary.tagsAdded += 1
            }
        }
        return mapping
    }

    private func mergeGroups(_ groups: [KeyGroup], summary: inout RestoreSummary) throws -> [Int64: Int64] {
        var existing = Dictionary(
            try metadata.allGroups().map { ($0.name.lowercased(), $0.id) }, uniquingKeysWith: { first, _ in first }
        )
        var mapping: [Int64: Int64] = [:]
        for group in groups {
            if let id = existing[group.name.lowercased()] {
                mapping[group.id] = id
            } else {
                let created = try metadata.createGroup(named: group.name)
                existing[group.name.lowercased()] = created.id
                mapping[group.id] = created.id
                summary.groupsAdded += 1
            }
        }
        return mapping
    }

    private func mergeHostsAndTunnels(
        _ snapshot: MetadataSnapshot,
        tagIDs: [Int64: Int64],
        summary: inout RestoreSummary
    ) throws {
        let existingHosts = try metadata.allHostMetadata()
        for host in snapshot.hosts where existingHosts[host.alias] == nil {
            try metadata.saveHostMetadata(host)
            summary.hostsRestored += 1
        }
        let currentHostTags = try metadata.hostTagAssignments()
        for (alias, ids) in snapshot.hostTagAssignments {
            let merged = (currentHostTags[alias] ?? []).union(ids.compactMap { tagIDs[$0] })
            if merged != currentHostTags[alias] ?? [] { try metadata.setHostTags(merged, forHost: alias) }
        }
        let existingTunnels = Set(try metadata.allTunnels().map(\.id))
        for tunnel in snapshot.tunnels where !existingTunnels.contains(tunnel.id) {
            try metadata.saveTunnel(tunnel)
            summary.tunnelsAdded += 1
        }
    }

    // MARK: Key derivation

    static func checkPassphrase(_ passphrase: SecureBytes) throws {
        guard passphrase.count >= 1 else {
            throw SMPError.invalidArgument("A backup needs a passphrase.")
        }
    }

    static func deriveKey(passphrase: SecureBytes, salt: Data, iterations: Int) throws -> SymmetricKey {
        var derived = [UInt8](repeating: 0, count: 32)
        defer {
            derived.withUnsafeMutableBytes { buffer in
                if let base = buffer.baseAddress { SecureMemory.zero(base, count: buffer.count) }
            }
        }
        let status = passphrase.withUnsafeBytes { password in
            salt.withUnsafeBytes { saltBytes in
                derived.withUnsafeMutableBytes { output in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        password.baseAddress?.assumingMemoryBound(to: CChar.self), password.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), saltBytes.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                        output.baseAddress?.assumingMemoryBound(to: UInt8.self), output.count
                    )
                }
            }
        }
        guard status == Int32(kCCSuccess) else {
            throw SMPError(.keyOperationFailed, whatHappened: "SMP could not derive the backup key.")
        }
        return SymmetricKey(data: derived)
    }
}

extension ServiceContainer {
    /// Encrypted backups of key files, `~/.ssh/config`, known_hosts and SMP's metadata.
    public var backup: any BackupServicing {
        BackupService(environment: environment, metadata: metadata)
    }
}

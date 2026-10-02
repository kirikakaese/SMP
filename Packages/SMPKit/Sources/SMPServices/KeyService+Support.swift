import Foundation
import SMPCore
import SMPSSH

extension KeyService {
    // MARK: Helpers

    /// Returns a copy of `contents` with a trailing newline, or `nil` if it already ends with one.
    static func newlineTerminated(_ contents: SecureBytes) -> SecureBytes? {
        guard contents.withUnsafeBytes({ $0.last }) != 0x0A else { return nil }
        let terminated = SecureBytes(count: contents.count + 1)
        terminated.withUnsafeMutableBytes { target in
            contents.withUnsafeBytes { source in
                if let base = target.baseAddress, let from = source.baseAddress, !source.isEmpty {
                    base.copyMemory(from: from, byteCount: source.count)
                }
            }
            target[target.count - 1] = 0x0A
        }
        return terminated
    }

    struct Destination {
        let privateKey: URL
        let publicKey: URL
        let existing: DiscoveredKey?
    }

    func prepareDestination(directory: URL, fileName: String, replaceExisting: Bool) throws -> Destination {
        try ensureDirectory(directory)
        let privateURL = directory.appending(path: fileName)
        let publicURL = directory.appending(path: fileName + ".pub")
        let exists = [privateURL, publicURL].contains { FileManager.default.fileExists(atPath: $0.path) }
        guard exists else { return Destination(privateKey: privateURL, publicKey: publicURL, existing: nil) }
        guard replaceExisting else { throw SMPError.alreadyExists(fileName) }
        let existing = try KeyDiscoveryService().scan(directory: directory).first { $0.name == fileName }
        return Destination(privateKey: privateURL, publicKey: publicURL, existing: existing)
    }

    func archiveExisting(_ destination: Destination) throws -> ArchivedKey? {
        guard let existing = destination.existing else { return nil }
        return try archive.archive(existing)
    }

    func ensureDirectory(_ directory: URL) throws {
        let isSSHDirectory = directory.standardizedFileURL.path == environment.sshDirectory.standardizedFileURL.path
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } else if isSSHDirectory {
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        }
    }

    /// Moves staged files into `directory`, rolling back if any move fails.
    func move(from staging: URL, names: [String], to directory: URL) throws {
        var moved: [String] = []
        do {
            for name in names {
                let target = directory.appending(path: name)
                if FileManager.default.fileExists(atPath: target.path) {
                    throw SMPError.alreadyExists(name)
                }
                guard Darwin.rename(staging.appending(path: name).path, target.path) == 0 else {
                    throw SMPError(.fileSystem, whatHappened: "SMP could not save \(name).",
                                   details: String(cString: strerror(errno)))
                }
                moved.append(name)
            }
        } catch {
            for name in moved {
                _ = Darwin.rename(directory.appending(path: name).path, staging.appending(path: name).path)
            }
            throw error
        }
    }

    func setModes(privateKey: URL, publicKey: URL) throws {
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: privateKey.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: publicKey.path)
    }

    func readPublicKey(_ url: URL) throws -> SSHPublicKey {
        guard let key = KeyDiscoveryService.readPublicKey(url) else {
            throw SMPError.keyOperationFailed("ssh-keygen did not produce a readable public key.")
        }
        return key
    }

    func writePublicKey(_ key: SSHPublicKey, to url: URL, replacing: Bool = false) throws {
        if replacing, FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        let line = Data((key.openSSHLine + "\n").utf8)
        try line.withUnsafeBytes { try SecureDelete.createFile(at: url, contents: $0, mode: 0o644) }
    }

    func privateKey(of key: DiscoveredKey) throws -> (URL, PrivateKeyInfo) {
        guard let url = key.privateKeyFile?.url, let info = try PrivateKeyInspector.inspect(fileAt: url) else {
            throw SMPError.keyOperationFailed("“\(key.name)” has no readable private key.")
        }
        return (url, info)
    }

    /// Guards against OpenSSH silently writing an unencrypted key when a passphrase prompt failed.
    func verifyEncryption(of url: URL, expected: Bool) throws {
        guard let info = try PrivateKeyInspector.inspect(fileAt: url), info.isEncrypted == expected else {
            if expected {
                // Never leave a key that the user believes is protected but is not.
                try? SecureDelete.removeFile(at: url)
            }
            throw SMPError.keyOperationFailed(
                expected
                    ? "The passphrase could not be applied, so the unprotected key was deleted."
                    : "The key's passphrase could not be removed.",
                howToFix: "Try again. If this keeps happening, please report it."
            )
        }
    }

    func validate(fileName: String) throws {
        if let problem = KeyFileName.problem(with: fileName) {
            throw SMPError.invalidArgument(problem)
        }
    }

    func validate(comment: String) throws {
        guard comment.count <= 1_024, !comment.contains(where: \.isNewline) else {
            throw SMPError.invalidArgument("The comment must be a single line of at most 1024 characters.")
        }
    }

    func gitSigningReferences(to key: DiscoveredKey) -> [GitSigningReference] {
        let home = environment.homeDirectory
        let files = [home.appending(path: ".gitconfig"), home.appending(path: ".config/git/config")]
        let paths = Set([key.privateKeyFile?.url.path, key.publicKeyFile?.url.path].compactMap { $0 })
        let blob = key.publicKey?.blob.base64EncodedString()
        var references: [GitSigningReference] = []
        for file in files {
            guard let text = try? String(contentsOf: file, encoding: .utf8) else { continue }
            for line in text.split(whereSeparator: \.isNewline) {
                let parts = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                guard parts.count == 2, parts[0].lowercased() == "signingkey" else { continue }
                var value = parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                if value.hasPrefix("key::") {
                    value.removeFirst("key::".count)
                }
                let expanded = value.hasPrefix("~/") ? home.path + value.dropFirst(1) : value
                if paths.contains(expanded) || (blob.map { value.contains($0) } ?? false) {
                    references.append(GitSigningReference(file: file, value: parts[1]))
                }
            }
        }
        return references
    }

    func failure(_ result: ToolResult, action: String, keyName: String) -> SMPError {
        let stderr = result.standardErrorString.trimmingCharacters(in: .whitespacesAndNewlines)
        let lowered = stderr.lowercased()
        if lowered.contains("incorrect passphrase") || lowered.contains("bad passphrase")
            || lowered.contains("wrong passphrase") {
            return SMPError.wrongPassphrase(keyName)
        }
        if lowered.contains("securitykeyprovider") || lowered.contains("fido") || lowered.contains("sk_") {
            return SMPError(
                .keyOperationFailed,
                whatHappened: "SMP could not talk to your security key.",
                howToFix: "The OpenSSH built into macOS needs a FIDO provider library for security keys. "
                    + "Install one (for example via Homebrew) and enter its path under Security key options, "
                    + "then plug in the key and touch it when it blinks.",
                details: stderr
            )
        }
        return SMPError.keyOperationFailed("SMP could not \(action).", details: stderr.isEmpty ? nil : stderr)
    }
}

/// A private (0700) folder inside the target directory, so final moves are atomic renames on
/// the same volume. Removed with all contents when done.
struct StagingDirectory {
    let url: URL

    init(in directory: URL) throws {
        var template = Array(directory.appending(path: ".smp-staging.XXXXXX").path.utf8CString)
        let created = template.withUnsafeMutableBufferPointer { buffer -> String? in
            guard let base = buffer.baseAddress, let result = mkdtemp(base) else { return nil }
            return String(cString: result)
        }
        guard let created else {
            throw SMPError(
                .fileSystem,
                whatHappened: "SMP could not create a temporary folder in \(directory.lastPathComponent)."
            )
        }
        url = URL(fileURLWithPath: created, isDirectory: true)
    }

    func remove() {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
        for name in names {
            try? SecureDelete.removeFile(at: url.appending(path: name))
        }
        try? FileManager.default.removeItem(at: url)
    }
}

import Foundation
import SMPCore
import SMPSSH

extension KeyService {
    // MARK: Passphrase, comment, format

    public func changePassphrase(
        of key: DiscoveredKey,
        current: SecureBytes?,
        new: SecureBytes?,
        kdfRounds: Int
    ) async throws {
        let (file, info) = try privateKey(of: key)
        guard info.format != .putty else {
            throw SMPError.keyOperationFailed(String(localized: """
                PuTTY keys must be imported before their passphrase can be changed.
                """))
        }
        var arguments = ["-p", "-a", String(max(16, kdfRounds)), "-f", file.path]
        var responses: [SecureBytes] = []
        if info.isEncrypted == true {
            guard let current, !current.isEmpty else { throw SMPError.wrongPassphrase(key.name) }
            responses.append(current)
        } else {
            arguments += ["-P", ""]
        }
        let setsPassphrase = !(new?.isEmpty ?? true)
        if let new, setsPassphrase {
            responses += [new, new]
        } else {
            arguments += ["-N", ""]
        }
        let result = try await runner.run(
            .sshKeygen,
            arguments: arguments,
            options: ToolRunOptions(passphrases: responses)
        )
        guard result.succeeded else {
            throw failure(result, action: "change the passphrase", keyName: key.name)
        }
        try verifyEncryption(of: file, expected: setsPassphrase)
    }

    public func changeComment(of key: DiscoveredKey, to comment: String, passphrase: SecureBytes?) async throws {
        try validate(comment: comment)
        let (file, info) = try privateKey(of: key)
        guard info.format == .openSSH else {
            throw SMPError.keyOperationFailed(
                "Comments can only be changed for keys in the OpenSSH format.",
                howToFix: String(localized: "Upgrade the key to the OpenSSH format first.")
            )
        }
        var arguments = ["-c", "-C", comment, "-f", file.path]
        var responses: [SecureBytes] = []
        if info.isEncrypted == true {
            guard let passphrase, !passphrase.isEmpty else { throw SMPError.wrongPassphrase(key.name) }
            responses.append(passphrase)
        } else {
            arguments.insert(contentsOf: ["-P", ""], at: 0)
        }
        let result = try await runner.run(
            .sshKeygen,
            arguments: arguments,
            options: ToolRunOptions(passphrases: responses)
        )
        guard result.succeeded else {
            throw failure(result, action: "change the comment", keyName: key.name)
        }
        // ssh-keygen rewrites the .pub file too; make sure it exists and carries the new comment.
        if let publicKey = key.publicKey {
            let updated = try SSHPublicKey(blob: publicKey.blob, comment: comment)
            let publicURL = key.publicKeyFile?.url
                ?? file.deletingLastPathComponent().appending(path: key.name + ".pub")
            try writePublicKey(updated, to: publicURL, replacing: true)
        }
    }

    public func upgradeFormat(of key: DiscoveredKey, passphrase: SecureBytes?) async throws {
        let (file, info) = try privateKey(of: key)
        guard info.format == .pem || info.format == .pkcs8 else { return }
        var arguments = ["-p", "-a", String(Self.defaultKDFRounds), "-f", file.path]
        var responses: [SecureBytes] = []
        let encrypted = info.isEncrypted == true
        if encrypted {
            guard let passphrase, !passphrase.isEmpty else { throw SMPError.wrongPassphrase(key.name) }
            responses = [passphrase, passphrase, passphrase]  // old, new, confirm: keep the same passphrase
        } else {
            arguments += ["-P", "", "-N", ""]
        }
        let result = try await runner.run(
            .sshKeygen,
            arguments: arguments,
            options: ToolRunOptions(passphrases: responses)
        )
        guard result.succeeded else {
            throw failure(result, action: "upgrade the key format", keyName: key.name)
        }
        guard let upgraded = try PrivateKeyInspector.inspect(fileAt: file), upgraded.format == .openSSH else {
            throw SMPError.keyOperationFailed(String(localized: "The key was not converted to the OpenSSH format."))
        }
        try verifyEncryption(of: file, expected: encrypted)
    }

    // MARK: Impact & deletion

    public func impactReport(for key: DiscoveredKey, isLoadedInAgent: Bool) async throws -> KeyImpactReport {
        let files = [key.privateKeyFile?.url, key.publicKeyFile?.url].compactMap { $0 }
        return KeyImpactReport(
            configReferences: try config.references(to: files),
            isLoadedInAgent: isLoadedInAgent,
            gitSigningReferences: gitSigningReferences(to: key),
            notChecked: [
                "Keys deployed to GitHub, GitLab and other providers (provider sync arrives in a later version).",
                "authorized_keys files on servers that accept this key.",
            ]
        )
    }

    public func deletePermanently(_ key: DiscoveredKey, configEdits: [ConfigReferenceEdit]) async throws {
        // Config first: if it can't be saved, nothing has been deleted yet.
        try config.apply(configEdits)
        if let agentFile = key.publicKeyFile?.url ?? key.privateKeyFile?.url {
            do {
                try await agent.remove(keyFile: agentFile, removeFromKeychain: key.privateKeyFile != nil)
            } catch {
                Log.app.error("Removing a deleted key from the agent failed")
            }
        }
        for file in [key.privateKeyFile, key.publicKeyFile, key.certificateFile].compactMap({ $0 }) {
            try SecureDelete.removeFile(at: file.url)
        }
    }

    // MARK: Export

    public func exportPrivateKey(_ key: DiscoveredKey, to destination: URL) throws {
        guard let source = key.privateKeyFile?.url else {
            throw SMPError.keyOperationFailed(String(localized: "“\(key.name)” has no private key to export."))
        }
        // The file is copied by the kernel; its contents never pass through SMP's memory.
        if FileManager.default.fileExists(atPath: destination.path) {
            try SecureDelete.removeFile(at: destination)
        }
        try FileManager.default.copyItem(at: source, to: destination)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
    }

    public func exportPublicKey(_ key: DiscoveredKey, to destination: URL) throws {
        guard let publicKey = key.publicKey else {
            throw SMPError.keyOperationFailed(String(localized: "The public key of “\(key.name)” is not available."))
        }
        try writePublicKey(publicKey, to: destination, replacing: true)
    }
}

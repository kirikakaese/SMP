import Foundation
import SMPCore
import SMPSSH

// MARK: - Implementation

public struct KeyService: KeyManaging {
    /// bcrypt KDF rounds for new passphrases (ssh-keygen's default is 16).
    public static let defaultKDFRounds = 100

    let runner: any SSHToolRunning
    let environment: SSHEnvironment
    let config: any ConfigServicing
    let archive: any ArchiveServicing
    let agent: any AgentServicing

    public init(
        runner: any SSHToolRunning,
        environment: SSHEnvironment,
        config: any ConfigServicing,
        archive: any ArchiveServicing,
        agent: any AgentServicing
    ) {
        self.runner = runner
        self.environment = environment
        self.config = config
        self.archive = archive
        self.agent = agent
    }

    // MARK: Generate

    public func generate(_ request: KeyGenerationRequest) async throws -> KeyOperationResult {
        try validate(fileName: request.fileName)
        try validate(comment: request.comment)
        let destination = try prepareDestination(directory: request.directory, fileName: request.fileName,
                                                 replaceExisting: request.replaceExisting)
        let staging = try StagingDirectory(in: request.directory)
        defer { staging.remove() }

        let stagedPrivate = staging.url.appending(path: request.fileName)
        var arguments = try typeArguments(for: request)
        arguments += ["-a", String(max(16, request.kdfRounds)), "-C", request.comment, "-f", stagedPrivate.path]

        var responses: [SecureBytes] = []
        if let pin = request.securityKeyPIN, !pin.isEmpty {
            responses.append(pin)
        }
        let wantsPassphrase = !(request.passphrase?.isEmpty ?? true)
        if let passphrase = request.passphrase, wantsPassphrase {
            responses += [passphrase, passphrase]
        } else {
            arguments += ["-N", ""]
        }

        let result = try await runner.run(
            .sshKeygen,
            arguments: arguments,
            options: ToolRunOptions(
                passphrases: responses,
                timeout: request.type.isSecurityKey ? .seconds(120) : .seconds(60)
            )
        )
        guard result.succeeded else {
            throw failure(result, action: "create the key", keyName: request.fileName)
        }

        let publicKey = try readPublicKey(staging.url.appending(path: request.fileName + ".pub"))
        try verifyEncryption(of: stagedPrivate, expected: wantsPassphrase)
        try setModes(privateKey: stagedPrivate, publicKey: staging.url.appending(path: request.fileName + ".pub"))
        let replaced = try archiveExisting(destination)
        try move(from: staging.url, names: [request.fileName, request.fileName + ".pub"], to: request.directory)
        return KeyOperationResult(
            privateKeyURL: destination.privateKey,
            publicKeyURL: destination.publicKey,
            publicKey: publicKey,
            replacedKey: replaced
        )
    }

    private func typeArguments(for request: KeyGenerationRequest) throws -> [String] {
        var arguments: [String]
        switch request.type {
        case .ed25519:
            arguments = ["-t", "ed25519"]
        case .ecdsa(let bits):
            guard [256, 384, 521].contains(bits) else {
                throw SMPError.invalidArgument("ECDSA keys use 256, 384 or 521 bits.")
            }
            arguments = ["-t", "ecdsa", "-b", String(bits)]
        case .rsa(let bits):
            guard bits >= 3072, bits <= 16384 else {
                throw SMPError.invalidArgument("RSA keys must have at least 3072 bits.")
            }
            arguments = ["-t", "rsa", "-b", String(bits)]
        case .ed25519SK:
            arguments = ["-t", "ed25519-sk"]
        case .ecdsaSK:
            arguments = ["-t", "ecdsa-sk"]
        }
        if request.type.isSecurityKey {
            let options = request.securityKey
            if options.resident { arguments += ["-O", "resident"] }
            if options.verifyRequired { arguments += ["-O", "verify-required"] }
            if !options.application.isEmpty {
                guard options.application.hasPrefix("ssh:") else {
                    throw SMPError.invalidArgument("The security key application must start with “ssh:”.")
                }
                arguments += ["-O", "application=\(options.application)"]
            }
            if !options.providerPath.isEmpty {
                arguments += ["-w", options.providerPath]
            }
        }
        return arguments
    }

    // MARK: Import

    public func importKey(_ request: KeyImportRequest) async throws -> KeyOperationResult {
        try validate(fileName: request.fileName)
        if let comment = request.comment {
            try validate(comment: comment)
        }
        guard let info = PrivateKeyInspector.inspect(contents: request.contents) else {
            return try importPublicKey(request)
        }
        let destination = try prepareDestination(directory: request.directory, fileName: request.fileName,
                                                 replaceExisting: request.replaceExisting)
        let staging = try StagingDirectory(in: request.directory)
        defer { staging.remove() }
        let stagedPrivate = staging.url.appending(path: request.fileName)

        var contents = request.contents
        var embeddedPublicKey = info.embeddedPublicKey
        if info.format == .putty {
            contents = try PuTTYKeyConverter.convert(request.contents)
            embeddedPublicKey = PrivateKeyInspector.inspect(contents: contents)?.embeddedPublicKey
        }
        defer { if contents !== request.contents { contents.wipe() } }
        try contents.withUnsafeBytes { try SecureDelete.createFile(at: stagedPrivate, contents: $0, mode: 0o600) }

        // Validate the key with ssh-keygen and derive its public half.
        let isEncrypted = info.format != .putty && info.isEncrypted == true
        var publicKey = try await derivePublicKey(
            of: stagedPrivate,
            isEncrypted: isEncrypted,
            embedded: embeddedPublicKey,
            passphrase: request.passphrase.flatMap { $0.isEmpty ? nil : $0 },
            keyName: request.fileName
        )

        let comment = [publicKey.comment, info.comment ?? "", request.comment ?? ""].first { !$0.isEmpty } ?? ""
        publicKey = try SSHPublicKey(blob: publicKey.blob, comment: comment)
        let stagedPublic = staging.url.appending(path: request.fileName + ".pub")
        try writePublicKey(publicKey, to: stagedPublic)
        try setModes(privateKey: stagedPrivate, publicKey: stagedPublic)

        let replaced = try archiveExisting(destination)
        try move(from: staging.url, names: [request.fileName, request.fileName + ".pub"], to: request.directory)
        return KeyOperationResult(
            privateKeyURL: destination.privateKey,
            publicKeyURL: destination.publicKey,
            publicKey: publicKey,
            replacedKey: replaced
        )
    }

    /// Runs `ssh-keygen -y` to prove the key is valid and get its public half. Without a passphrase,
    /// an encrypted OpenSSH key falls back to the public key stored in its header.
    private func derivePublicKey(
        of file: URL,
        isEncrypted: Bool,
        embedded: SSHPublicKey?,
        passphrase: SecureBytes?,
        keyName: String
    ) async throws -> SSHPublicKey {
        if isEncrypted, passphrase == nil {
            guard let embedded else {
                throw SMPError(
                    .passphraseRequired,
                    whatHappened: "This key is protected by a passphrase.",
                    howToFix: "Enter the key's passphrase so SMP can check it and derive the public key."
                )
            }
            return embedded
        }
        let derived = try await runner.run(
            .sshKeygen,
            arguments: isEncrypted ? ["-y", "-f", file.path] : ["-y", "-P", "", "-f", file.path],
            options: ToolRunOptions(passphrases: passphrase.map { [$0] } ?? [], timeout: .seconds(30))
        )
        guard derived.succeeded else {
            throw isEncrypted
                ? SMPError.wrongPassphrase(keyName)
                : failure(derived, action: "read the key", keyName: keyName)
        }
        let publicKey = try SSHPublicKey(line: derived.standardOutputString)
        if let embedded, embedded.blob != publicKey.blob {
            throw SMPError.keyOperationFailed("The key file is inconsistent: its public and private parts don't match.")
        }
        return publicKey
    }

    private func importPublicKey(_ request: KeyImportRequest) throws -> KeyOperationResult {
        let text = request.contents.withUnsafeBytes { String(bytes: $0, encoding: .utf8) } ?? ""
        let firstLine = text.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        guard var publicKey = try? SSHPublicKey(line: firstLine) else {
            throw SMPError.keyOperationFailed(
                "This doesn't look like an SSH key.",
                howToFix: "SMP imports OpenSSH, PEM, PKCS#8 and PuTTY private keys, and OpenSSH public keys."
            )
        }
        if publicKey.comment.isEmpty, let comment = request.comment {
            publicKey = try SSHPublicKey(blob: publicKey.blob, declaredType: publicKey.wireType, comment: comment)
        }
        let target = request.directory.appending(path: request.fileName + ".pub")
        try ensureDirectory(request.directory)
        guard !FileManager.default.fileExists(atPath: target.path) else {
            throw SMPError.alreadyExists(target.lastPathComponent)
        }
        try writePublicKey(publicKey, to: target)
        return KeyOperationResult(privateKeyURL: nil, publicKeyURL: target, publicKey: publicKey, replacedKey: nil)
    }

    // MARK: Rename

    public func rename(_ key: DiscoveredKey, to newName: String, updateConfig: Bool) async throws -> RenameResult {
        try validate(fileName: newName)
        guard newName != key.name else {
            return RenameResult(privateKeyURL: key.privateKeyFile?.url, publicKeyURL: key.publicKeyFile?.url,
                                updatedConfigReferences: 0)
        }
        let suffixes = [
            (key.privateKeyFile?.url, ""),
            (key.publicKeyFile?.url, ".pub"),
            (key.certificateFile?.url, "-cert.pub"),
        ]
        let moves = suffixes.compactMap { url, suffix in
            url.map { ($0, $0.deletingLastPathComponent().appending(path: newName + suffix)) }
        }
        for (_, target) in moves where FileManager.default.fileExists(atPath: target.path) {
            throw SMPError.alreadyExists(target.lastPathComponent)
        }

        var edits: [ConfigReferenceEdit] = []
        if updateConfig {
            edits = try config.references(to: moves.map(\.0)).map { reference in
                .replaceValue(reference, newValue: reference.renamedValue(from: key.name, to: newName))
            }
        }

        var done: [(URL, URL)] = []
        do {
            for (source, target) in moves {
                guard Darwin.rename(source.path, target.path) == 0 else {
                    throw SMPError(.fileSystem, whatHappened: "SMP could not rename \(source.lastPathComponent).",
                                   details: String(cString: strerror(errno)))
                }
                done.append((source, target))
            }
            try config.apply(edits)
        } catch {
            for (source, target) in done.reversed() {
                _ = Darwin.rename(target.path, source.path)
            }
            throw error
        }
        let byPath = Dictionary(uniqueKeysWithValues: moves.map { ($0.0.path, $0.1) })
        return RenameResult(
            privateKeyURL: key.privateKeyFile.flatMap { byPath[$0.url.path] },
            publicKeyURL: key.publicKeyFile.flatMap { byPath[$0.url.path] },
            updatedConfigReferences: edits.count
        )
    }
}

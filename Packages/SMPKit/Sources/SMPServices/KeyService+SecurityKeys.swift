import Darwin
import Foundation
import SMPCore
import SMPSSH

extension KeyService {
    /// Downloads resident keys from a FIDO2 security key (`ssh-keygen -K`) into `~/.ssh`.
    ///
    /// The downloaded files are key handles: they only work with the security key plugged in.
    /// Keys already present in `~/.ssh` (same fingerprint) are skipped; name clashes get a suffix.
    public func downloadResidentKeys(pin: SecureBytes?, providerPath: String) async throws -> [KeyOperationResult] {
        let directory = environment.sshDirectory
        try ensureDirectory(directory)
        let staging = try StagingDirectory(in: directory)
        defer { staging.remove() }

        // -N "" answers the "protect with a passphrase?" prompt with no passphrase: the handles are
        // useless without the security key. The PIN goes through askpass, never argv.
        var arguments = ["-K", "-N", ""]
        if !providerPath.isEmpty {
            arguments += ["-w", providerPath]
        }
        let pins = pin.flatMap { $0.isEmpty ? nil : [$0] } ?? []
        let result = try await runner.run(
            .sshKeygen,
            arguments: arguments,
            options: ToolRunOptions(passphrases: pins, timeout: .seconds(120), workingDirectory: staging.url)
        )
        guard result.succeeded else {
            throw failure(result, action: "download keys from the security key", keyName: "security key")
        }

        let existing = Set(Self.publicKeyFingerprints(in: directory))
        let staged = (try? FileManager.default.contentsOfDirectory(atPath: staging.url.path)) ?? []
        var results: [KeyOperationResult] = []
        for name in staged.sorted() where !name.hasSuffix(".pub") && staged.contains(name + ".pub") {
            let publicKey = try readPublicKey(staging.url.appending(path: name + ".pub"))
            guard !existing.contains(publicKey.fingerprintSHA256) else { continue }
            let target = Self.unusedName(for: name, in: directory)
            if target != name {
                for suffix in ["", ".pub"] {
                    let from = staging.url.appending(path: name + suffix).path
                    guard Darwin.rename(from, staging.url.appending(path: target + suffix).path) == 0 else {
                        throw SMPError(.fileSystem, whatHappened: String(localized: """
                            SMP could not name the downloaded key.
                            """))
                    }
                }
            }
            try setModes(
                privateKey: staging.url.appending(path: target),
                publicKey: staging.url.appending(path: target + ".pub")
            )
            try move(from: staging.url, names: [target, target + ".pub"], to: directory)
            results.append(KeyOperationResult(
                privateKeyURL: directory.appending(path: target),
                publicKeyURL: directory.appending(path: target + ".pub"),
                publicKey: publicKey,
                replacedKey: nil
            ))
        }
        return results
    }

    /// Writes a public key to `~/.ssh/<fileName>.pub`; never overwrites an existing file.
    public func installPublicKey(_ key: SSHPublicKey, fileName: String) throws -> URL {
        try validate(fileName: fileName)
        try ensureDirectory(environment.sshDirectory)
        let url = environment.sshDirectory.appending(path: fileName + ".pub")
        guard !FileManager.default.fileExists(atPath: url.path) else {
            throw SMPError.alreadyExists(fileName + ".pub")
        }
        try writePublicKey(key, to: url)
        return url
    }

    static func publicKeyFingerprints(in directory: URL) -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        return names.filter { $0.hasSuffix(".pub") }.compactMap {
            KeyDiscoveryService.readPublicKey(directory.appending(path: $0))?.fingerprintSHA256
        }
    }

    /// `name`, or `name-2`, `name-3`, … if a private or public key file with that name exists.
    static func unusedName(for name: String, in directory: URL) -> String {
        func taken(_ candidate: String) -> Bool {
            FileManager.default.fileExists(atPath: directory.appending(path: candidate).path)
                || FileManager.default.fileExists(atPath: directory.appending(path: candidate + ".pub").path)
        }
        var candidate = name
        var counter = 2
        while taken(candidate) {
            candidate = "\(name)-\(counter)"
            counter += 1
        }
        return candidate
    }
}

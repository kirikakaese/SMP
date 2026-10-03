import Foundation
import SMPCore
import SMPSSH

/// Runs the steps of a key rotation. Each step updates the job (per-target results and a log line);
/// the caller persists the job after every step so an interrupted rotation can be resumed.
public struct RotationService: Sendable {
    private let services: RotationDependencies

    public init(services: RotationDependencies) {
        self.services = services
    }

    // MARK: Planning

    /// Finds where the old key is used: provider accounts (from the cached key lists) and `Host`
    /// aliases whose `IdentityFile` points at it.
    public func plan(for key: DiscoveredKey) throws -> RotationJob {
        guard let fingerprint = key.fingerprint else {
            throw SMPError.invalidArgument(String(localized: "SMP cannot rotate a key whose public key is unknown."))
        }
        guard key.privateKeyFile != nil else {
            throw SMPError.invalidArgument(String(localized: """
                Only keys with a private key file on this Mac can be rotated here.
                """))
        }
        var targets: [RotationJob.Target] = []
        let accounts = try services.providers.accounts()
        let remote = try services.providers.cachedKeys().filter { $0.fingerprint == fingerprint }
        for account in accounts {
            let entries = remote.filter { $0.accountID == account.id }
            guard !entries.isEmpty else { continue }
            let usages = entries.reduce(into: Set<RemoteKeyUsage>()) { $0.formUnion($1.usages) }
            targets.append(RotationJob.Target(
                kind: .provider(accountID: account.id, usages: usages, oldRemoteIDs: entries.map(\.remoteID)),
                label: account.displayName
            ))
        }
        for alias in try hostAliases(using: key) {
            targets.append(RotationJob.Target(kind: .host(alias: alias), label: alias))
        }
        let directory = (key.privateKeyFile?.url ?? key.primaryFile.url).deletingLastPathComponent()
        return RotationJob(
            oldKeyName: key.name,
            oldFingerprint: fingerprint,
            oldPrivateKeyPath: key.privateKeyFile?.url.path,
            oldPublicKeyPath: key.publicKeyFile?.url.path,
            oldComment: key.comment,
            directoryPath: directory.path,
            newKeyName: Self.suggestedName(for: key.name, in: directory),
            targets: targets
        )
    }

    /// Concrete `Host` aliases (no wildcards, no `Match` blocks) that use the key.
    func hostAliases(using key: DiscoveredKey) throws -> [String] {
        let files = [key.privateKeyFile?.url, key.publicKeyFile?.url].compactMap { $0 }
        var seen = Set<String>()
        return try services.config.references(to: files)
            .filter { !$0.isInMatchBlock }
            .flatMap(\.hostPatterns)
            .filter { pattern in
                HostAlias.problem(with: pattern) == nil && !pattern.contains { "*?!".contains($0) }
            }
            .filter { seen.insert($0).inserted }
    }

    /// `id_ed25519` → `id_ed25519_2026` (or `_2026-2` …), never an existing file.
    static func suggestedName(for name: String, in directory: URL, now: Date = Date()) -> String {
        let year = Calendar(identifier: .gregorian).component(.year, from: now)
        var base = name
        if let range = base.range(of: #"_\d{4}(-\d+)?$"#, options: .regularExpression) {
            base.removeSubrange(range)
        }
        var candidate = "\(base)_\(year)"
        var counter = 2
        while FileManager.default.fileExists(atPath: directory.appending(path: candidate).path)
            || FileManager.default.fileExists(atPath: directory.appending(path: candidate + ".pub").path)
            || candidate == name {
            candidate = "\(base)_\(year)-\(counter)"
            counter += 1
        }
        return candidate
    }

    // MARK: Steps

    /// Step 1: creates the new key next to the old one (Ed25519 unless a type is given).
    public func generate(
        _ job: RotationJob,
        type: KeyGenerationRequest.KeyType = .ed25519,
        passphrase: SecureBytes?
    ) async throws -> RotationJob {
        var job = job
        let result = try await services.keys.generate(KeyGenerationRequest(
            type: type,
            fileName: job.newKeyName,
            directory: URL(fileURLWithPath: job.directoryPath, isDirectory: true),
            comment: job.oldComment,
            passphrase: passphrase
        ))
        job.newPrivateKeyPath = result.privateKeyURL?.path
        job.newPublicKeyLine = result.publicKey.openSSHLine
        job.newFingerprint = result.publicKey.fingerprintSHA256
        job.complete(.generate, "Created \(job.newKeyName) (\(result.publicKey.fingerprintSHA256)).")
        return job
    }

    /// Step 2: uploads the new key to each provider and installs it on each server
    /// (connecting with the old key, which still works at this point).
    public func deploy(_ job: RotationJob) async -> RotationJob {
        var job = job
        guard let newKey = newPublicKey(of: job) else {
            job.note("The new key is missing; create it first.")
            return job
        }
        let accounts = (try? services.providers.accounts()) ?? []
        for index in job.targets.indices where !job.targets[index].skipped && !job.targets[index].deployed {
            do {
                switch job.targets[index].kind {
                case .provider(let accountID, let usages, _):
                    guard let account = accounts.first(where: { $0.id == accountID }) else {
                        throw SMPError.invalidArgument(String(localized: "The provider account was removed from SMP."))
                    }
                    let title = job.newKeyName + (job.oldComment.isEmpty ? "" : " (\(job.oldComment))")
                    _ = try await services.providers.upload(newKey, title: title, usages: usages, to: account)
                case .host(let alias):
                    _ = try await services.deploy.install(newKey, on: alias, password: nil)
                }
                job.targets[index].deployed = true
                job.targets[index].lastError = nil
                job.note("Added the new key to \(job.targets[index].label).")
            } catch {
                job.targets[index].lastError = Self.message(error)
                job.note("Could not add the new key to \(job.targets[index].label).")
            }
        }
        if job.activeTargets.allSatisfy(\.deployed) {
            job.complete(.deploy, "The new key is on every provider and server.")
        }
        return job
    }

    /// Step 3: points every `IdentityFile` that used the old key at the new one (with backups).
    public func updateConfig(_ job: RotationJob) throws -> RotationJob {
        var job = job
        let oldFiles = [job.oldPrivateKeyPath, job.oldPublicKeyPath].compactMap { $0 }.map(URL.init(fileURLWithPath:))
        let edits = try services.config.references(to: oldFiles).map { reference in
            ConfigReferenceEdit.replaceValue(
                reference, newValue: reference.renamedValue(from: job.oldKeyName, to: job.newKeyName)
            )
        }
        try services.config.apply(edits)
        job.complete(.updateConfig, edits.isEmpty
            ? "No IdentityFile lines referred to the old key."
            : "Updated \(edits.count) IdentityFile line(s); backups were kept.")
        return job
    }

    /// Step 4: logs in to each server with only the new key. Providers are checked with
    /// `ssh -T git@<host>` where the key is used for authentication.
    public func verify(_ job: RotationJob, passphrase: SecureBytes?) async -> RotationJob {
        var job = job
        guard let keyPath = job.newPrivateKeyPath else {
            job.note("The new key is missing; create it first.")
            return job
        }
        let keyFile = URL(fileURLWithPath: keyPath)
        let accounts = (try? services.providers.accounts()) ?? []
        for index in job.targets.indices where !job.targets[index].skipped && !job.targets[index].verified {
            let destination: String?
            switch job.targets[index].kind {
            case .host(let alias):
                destination = alias
            case .provider(let accountID, let usages, _):
                // Signing-only keys cannot be tested with a login.
                let host = accounts.first { $0.id == accountID }.flatMap { Self.gitHost(for: $0) }
                destination = usages.contains(.authentication) ? host : nil
            }
            guard let destination else {
                job.targets[index].verified = true
                continue
            }
            let result = await services.deploy.verifyLogin(
                on: destination, keyFile: keyFile, passphrase: passphrase
            )
            if case .failure(let problem, let details) = result {
                job.targets[index].lastError = "\(problem.title) \(details)"
                job.note("Login to \(job.targets[index].label) with the new key failed.")
            } else {
                job.targets[index].verified = true
                job.targets[index].lastError = nil
                job.note("Logged in to \(job.targets[index].label) with the new key.")
            }
        }
        if job.activeTargets.allSatisfy(\.verified) {
            job.complete(.verify, "The new key works everywhere.")
        }
        return job
    }

    /// Step 5 (after the user confirmed): removes the old key from providers and servers. The caller
    /// archives the old key files locally afterwards.
    public func retire(_ job: RotationJob) async -> RotationJob {
        var job = job
        let accounts = (try? services.providers.accounts()) ?? []
        let cached = (try? services.providers.cachedKeys()) ?? []
        for index in job.targets.indices where !job.targets[index].skipped && !job.targets[index].retired {
            do {
                switch job.targets[index].kind {
                case .provider(let accountID, _, let oldIDs):
                    guard let account = accounts.first(where: { $0.id == accountID }) else {
                        throw SMPError.invalidArgument(String(localized: "The provider account was removed from SMP."))
                    }
                    for key in cached where key.accountID == accountID && oldIDs.contains(key.remoteID) {
                        try await services.providers.delete(key, from: account)
                    }
                case .host(let alias):
                    let entries = try await services.deploy.authorizedKeys(on: alias, password: nil)
                    for entry in entries where entry.publicKey.fingerprintSHA256 == job.oldFingerprint {
                        try await services.deploy.remove(entry, from: alias, password: nil)
                    }
                }
                job.targets[index].retired = true
                job.targets[index].lastError = nil
                job.note("Removed the old key from \(job.targets[index].label).")
            } catch {
                job.targets[index].lastError = Self.message(error)
                job.note("Could not remove the old key from \(job.targets[index].label).")
            }
        }
        if job.activeTargets.allSatisfy(\.retired) {
            job.complete(.retire, "The old key was removed from every provider and server.")
        }
        return job
    }

    // MARK: Helpers

    private func newPublicKey(of job: RotationJob) -> SSHPublicKey? {
        job.newPublicKeyLine.flatMap { try? SSHPublicKey(line: $0) }
    }

    /// `git@github.com` for an account, used to test authentication keys.
    static func gitHost(for account: ProviderAccount) -> String? {
        let host: String? = switch account.kind {
        case .bitbucket: "bitbucket.org"
        default: account.serverURL.host()
        }
        return host.map { "git@\($0)" }
    }

    static func message(_ error: Error) -> String {
        guard let error = error as? SMPError else { return error.localizedDescription }
        return [error.whatHappened, error.howToFix].compactMap { $0 }.joined(separator: " ")
    }
}

/// The services a rotation uses.
public struct RotationDependencies: Sendable {
    public var keys: any KeyManaging
    public var config: any ConfigServicing
    public var providers: any ProviderServicing
    public var deploy: any DeployServicing

    public init(
        keys: any KeyManaging,
        config: any ConfigServicing,
        providers: any ProviderServicing,
        deploy: any DeployServicing
    ) {
        self.keys = keys
        self.config = config
        self.providers = providers
        self.deploy = deploy
    }
}

extension ServiceContainer {
    public var rotation: RotationService {
        RotationService(
            services: RotationDependencies(keys: keys, config: config, providers: providers, deploy: deploy)
        )
    }
}

import Foundation
import SMPCore
import SMPServices
import SMPSSH

extension LibraryModel {
    // MARK: Secure Enclave keys

    func secureEnclaveKeys() -> [SecureEnclaveKeyInfo] {
        do {
            return try services.secureEnclave.keys()
        } catch {
            // Unsigned development builds cannot reach the shared Keychain group.
            Log.keychain.error("Secure Enclave keys could not be listed")
            return []
        }
    }

    /// Marks items whose public key belongs to a Secure Enclave key, and adds an item for each
    /// Secure Enclave key whose `.pub` file is not on disk.
    nonisolated static func attachSecureEnclaveKeys(
        _ keys: [SecureEnclaveKeyInfo],
        to items: [LibraryItem]
    ) -> [LibraryItem] {
        var byFingerprint: [String: SecureEnclaveKeyInfo] = [:]
        for key in keys {
            if let fingerprint = try? key.publicKey().fingerprintSHA256 {
                byFingerprint[fingerprint] = key
            }
        }
        var matched = Set<UUID>()
        var result = items.map { item -> LibraryItem in
            guard let fingerprint = item.key.fingerprint, let key = byFingerprint[fingerprint] else { return item }
            matched.insert(key.id)
            var copy = item
            copy.secureEnclave = key
            return copy
        }
        for key in keys where !matched.contains(key.id) {
            result.append(LibraryItem(key: discoveredKey(fromSecureEnclave: key), secureEnclave: key))
        }
        return result
    }

    nonisolated static func discoveredKey(fromSecureEnclave key: SecureEnclaveKeyInfo) -> DiscoveredKey {
        // A virtual path keeps the item's identity unique; no file is ever read or written there.
        let placeholder = KeyFileInfo(
            url: URL(fileURLWithPath: "/secure-enclave/\(key.id.uuidString)"),
            permissions: 0o644,
            isOwnedByCurrentUser: true,
            isSymbolicLink: false,
            size: 0,
            createdAt: key.createdAt,
            modifiedAt: key.createdAt
        )
        return DiscoveredKey(
            name: key.name,
            kind: .publicOnly,
            publicKey: try? key.publicKey(),
            privateKeyFile: nil,
            privateKeyInfo: nil,
            publicKeyFile: placeholder,
            certificateFile: nil,
            certificate: nil,
            issues: []
        )
    }

    /// Creates a key in the Secure Enclave and (optionally) saves its public key as `~/.ssh/<name>.pub`,
    /// so `IdentityFile` can point at it.
    public func createSecureEnclaveKey(
        name: String,
        comment: String,
        policy: SigningPolicy,
        savePublicKey: Bool
    ) async throws {
        if let problem = KeyFileName.problem(with: name) {
            throw SMPError.invalidArgument(problem)
        }
        let publicFile = services.environment.sshDirectory.appending(path: name + ".pub")
        if savePublicKey, FileManager.default.fileExists(atPath: publicFile.path) {
            throw SMPError.alreadyExists(name + ".pub")
        }
        let key = try services.secureEnclave.create(name: name, comment: comment, policy: policy)
        if savePublicKey {
            do {
                _ = try services.keys.installPublicKey(try key.publicKey(), fileName: name)
            } catch {
                try? services.secureEnclave.delete(id: key.id)
                throw error
            }
        }
        notice = "Secure Enclave key “\(name)” created. It can only be used through SMP's agent."
        await reload()
        selectedKeyIDs = Set(items.filter { $0.secureEnclave?.id == key.id }.map(\.id))
    }

    /// Changes when the agent asks for Touch ID. Keys created without a Touch ID requirement keep it.
    public func setSigningPolicy(_ policy: SigningPolicy, for item: LibraryItem) {
        guard var key = item.secureEnclave else { return }
        guard policy.requiresUserPresence == key.policy.requiresUserPresence else {
            lastError = SMPError.invalidArgument(
                "Whether a key needs Touch ID is fixed when it is created. Create a new key to change it."
            )
            return
        }
        key.policy = policy
        do {
            try services.secureEnclave.update(key)
            if let index = items.firstIndex(where: { $0.id == item.id }) {
                items[index].secureEnclave = key
            }
        } catch {
            report(error, whatHappened: "SMP could not change the key's Touch ID setting.")
        }
    }

    // MARK: Security keys (FIDO2)

    /// Downloads resident keys from a plugged-in security key into `~/.ssh`.
    /// - Returns: the number of new keys.
    public func downloadResidentKeys(pin: SecureBytes?, providerPath: String) async throws -> Int {
        let results = try await services.keys.downloadResidentKeys(pin: pin, providerPath: providerPath)
        notice = switch results.count {
        case 0: "The security key holds no keys that are not already in ~/.ssh."
        case 1: "1 key was downloaded from the security key."
        default: "\(results.count) keys were downloaded from the security key."
        }
        await reload()
        return results.count
    }
}

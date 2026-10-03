import Foundation
import SMPCore
import SMPSSH

/// File-system facts about one key file.
public struct KeyFileInfo: Sendable, Hashable {
    public let url: URL
    /// POSIX permission bits (for example `0o600`).
    public let permissions: UInt16
    public let isOwnedByCurrentUser: Bool
    public let isSymbolicLink: Bool
    public let size: Int
    public let createdAt: Date?
    public let modifiedAt: Date?

    public init(
        url: URL,
        permissions: UInt16,
        isOwnedByCurrentUser: Bool,
        isSymbolicLink: Bool,
        size: Int,
        createdAt: Date?,
        modifiedAt: Date?
    ) {
        self.url = url
        self.permissions = permissions
        self.isOwnedByCurrentUser = isOwnedByCurrentUser
        self.isSymbolicLink = isSymbolicLink
        self.size = size
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
    }

    /// Permissions as `ls -l` shows them, e.g. `rw-------`.
    public var symbolicPermissions: String {
        let symbols: [Character] = ["r", "w", "x"]
        return (0..<9).reduce(into: "") { result, index in
            let bit = UInt16(1) << UInt16(8 - index)
            result.append(permissions & bit != 0 ? symbols[index % 3] : "-")
        }
    }
}

/// Something about a key that deserves the user's attention.
public enum KeyIssue: Sendable, Hashable {
    /// The private key is readable or writable by group/others; `ssh` refuses to use it.
    case privateKeyPermissionsTooOpen(UInt16)
    /// The public key is writable by group/others.
    case publicKeyWritableByOthers(UInt16)
    /// The folder holding the key is accessible by group/others.
    case directoryPermissionsTooOpen(UInt16)
    case notOwnedByCurrentUser
    case noPassphrase
    case weakAlgorithm(String)
    /// Only the public half exists.
    case orphanedPublicKey
    /// The private key uses a legacy container format.
    case legacyFormat(PrivateKeyFormat)
    /// The `.pub` file does not belong to the private key next to it.
    case publicKeyMismatch

    public var summary: String {
        switch self {
        case .privateKeyPermissionsTooOpen(let mode):
            String(localized: """
                Private key permissions are too open (\(String(mode, radix: 8))). SSH refuses such keys; use 600.
                """)
        case .publicKeyWritableByOthers(let mode):
            String(localized: "Public key can be modified by other users (\(String(mode, radix: 8))). Use 644.")
        case .directoryPermissionsTooOpen(let mode):
            String(localized: "The key's folder is accessible by other users (\(String(mode, radix: 8))). Use 700.")
        case .notOwnedByCurrentUser:
            String(localized: "The key file belongs to another user.")
        case .noPassphrase:
            String(localized: "The private key has no passphrase.")
        case .weakAlgorithm(let reason):
            reason
        case .orphanedPublicKey:
            String(localized: "Only the public key was found; the private key is missing.")
        case .legacyFormat(let format):
            String(localized: "The private key uses the legacy \(format.displayName) format.")
        case .publicKeyMismatch:
            String(localized: "The .pub file does not match its private key.")
        }
    }
}

/// A key found on disk: a private/public pair, a lone private key, or an orphaned public key.
public struct DiscoveredKey: Sendable, Hashable, Identifiable {
    public enum Kind: String, Sendable, Hashable {
        case pair
        case privateOnly
        case publicOnly
    }

    /// Path of the primary file (the private key, or the public key for orphans). Unique.
    public var id: String { primaryFile.url.path }
    /// File name without `.pub`, e.g. `id_ed25519`.
    public let name: String
    public let kind: Kind
    public let publicKey: SSHPublicKey?
    public let privateKeyFile: KeyFileInfo?
    public let privateKeyInfo: PrivateKeyInfo?
    public let publicKeyFile: KeyFileInfo?
    public let certificateFile: KeyFileInfo?
    public let certificate: SSHPublicKey?
    public let issues: [KeyIssue]

    public var primaryFile: KeyFileInfo {
        // Every discovered key has at least one of the two files.
        privateKeyFile ?? publicKeyFile ?? certificateFile ?? KeyFileInfo(
            url: URL(fileURLWithPath: "/"), permissions: 0, isOwnedByCurrentUser: false,
            isSymbolicLink: false, size: 0, createdAt: nil, modifiedAt: nil
        )
    }

    public var fingerprint: String? { publicKey?.fingerprintSHA256 }
    public var algorithm: KeyAlgorithm { publicKey?.algorithm ?? .unknown }
    public var comment: String { publicKey?.comment ?? privateKeyInfo?.comment ?? "" }
    public var isPassphraseProtected: Bool? { privateKeyInfo?.isEncrypted }

    public init(
        name: String,
        kind: Kind,
        publicKey: SSHPublicKey?,
        privateKeyFile: KeyFileInfo?,
        privateKeyInfo: PrivateKeyInfo?,
        publicKeyFile: KeyFileInfo?,
        certificateFile: KeyFileInfo?,
        certificate: SSHPublicKey?,
        issues: [KeyIssue]
    ) {
        self.name = name
        self.kind = kind
        self.publicKey = publicKey
        self.privateKeyFile = privateKeyFile
        self.privateKeyInfo = privateKeyInfo
        self.publicKeyFile = publicKeyFile
        self.certificateFile = certificateFile
        self.certificate = certificate
        self.issues = issues
    }
}

public protocol KeyDiscovering: Sendable {
    /// Scans `directories` (non-recursively) and returns the keys found, sorted by name.
    func discoverKeys(in directories: [URL]) async throws -> [DiscoveredKey]
}

/// Scans folders for SSH keys. Files are classified by content, not by name.
public struct KeyDiscoveryService: KeyDiscovering {
    /// Files in `~/.ssh` that are never keys; skipped without reading.
    static let ignoredNames: Set<String> = [
        "config", "known_hosts", "known_hosts.old", "authorized_keys", "authorized_keys2",
        "environment", "rc", "allowed_signers", ".DS_Store",
    ]

    public init() {}

    public func discoverKeys(in directories: [URL]) async throws -> [DiscoveredKey] {
        var keys: [DiscoveredKey] = []
        var seenDirectories = Set<String>()
        for directory in directories {
            let resolved = directory.resolvingSymlinksInPath().standardizedFileURL
            guard seenDirectories.insert(resolved.path).inserted else { continue }
            keys += try scan(directory: resolved)
        }
        return keys.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    func scan(directory: URL) throws -> [DiscoveredKey] {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: directory.path) else { return [] }
        let names = try fileManager.contentsOfDirectory(atPath: directory.path)
        let directoryMode = Self.fileInfo(for: directory)?.permissions ?? 0o700

        var privateKeys: [String: (KeyFileInfo, PrivateKeyInfo)] = [:]
        var publicKeys: [String: (KeyFileInfo, SSHPublicKey)] = [:]
        var certificates: [String: (KeyFileInfo, SSHPublicKey)] = [:]

        for name in names where !name.hasPrefix(".") && !Self.ignoredNames.contains(name) {
            let url = directory.appending(path: name, directoryHint: .notDirectory)
            guard let info = Self.fileInfo(for: url), info.size > 0, info.size <= PrivateKeyInspector.maxFileSize else {
                continue
            }
            if name.hasSuffix("-cert.pub") {
                if let key = Self.readPublicKey(url), key.isCertificate {
                    certificates[String(name.dropLast("-cert.pub".count))] = (info, key)
                }
            } else if name.hasSuffix(".pub") {
                if let key = Self.readPublicKey(url), !key.isCertificate {
                    publicKeys[String(name.dropLast(".pub".count))] = (info, key)
                }
            } else if let prefix = try? SecureFileReader.readPrefix(url, maxBytes: 64),
                      PrivateKeyInspector.looksLikePrivateKey(prefix: prefix),
                      let privateInfo = try? PrivateKeyInspector.inspect(fileAt: url) {
                privateKeys[name] = (info, privateInfo)
            }
        }

        var keys: [DiscoveredKey] = []
        for (base, (file, privateInfo)) in privateKeys {
            let publicEntry = publicKeys.removeValue(forKey: base)
            let certificateEntry = certificates.removeValue(forKey: base)
            keys.append(makeKey(
                name: base, privateFile: file, privateInfo: privateInfo,
                publicEntry: publicEntry, certificateEntry: certificateEntry, directoryMode: directoryMode
            ))
        }
        for (base, (file, publicKey)) in publicKeys {
            let certificateEntry = certificates.removeValue(forKey: base)
            keys.append(makeKey(
                name: base, privateFile: nil, privateInfo: nil,
                publicEntry: (file, publicKey), certificateEntry: certificateEntry, directoryMode: directoryMode
            ))
        }
        return keys
    }

    private func makeKey(
        name: String,
        privateFile: KeyFileInfo?,
        privateInfo: PrivateKeyInfo?,
        publicEntry: (KeyFileInfo, SSHPublicKey)?,
        certificateEntry: (KeyFileInfo, SSHPublicKey)?,
        directoryMode: UInt16
    ) -> DiscoveredKey {
        let embedded = privateInfo?.embeddedPublicKey
        let filePublicKey = publicEntry?.1
        // The key embedded in the private file is authoritative; the .pub file adds the comment.
        let publicKey: SSHPublicKey? = {
            guard let embedded else { return filePublicKey }
            guard let filePublicKey, filePublicKey.blob == embedded.blob else { return embedded }
            return filePublicKey
        }()
        let mismatch = embedded != nil && filePublicKey != nil && embedded?.blob != filePublicKey?.blob

        let kind: DiscoveredKey.Kind =
            privateFile == nil ? .publicOnly : (publicEntry == nil ? .privateOnly : .pair)
        let issues = Self.issues(
            kind: kind,
            algorithm: publicKey?.algorithm,
            bits: publicKey?.bitLength,
            privateFile: privateFile,
            privateInfo: privateInfo,
            publicFile: publicEntry?.0,
            directoryMode: directoryMode,
            mismatch: mismatch
        )
        return DiscoveredKey(
            name: name,
            kind: kind,
            publicKey: publicKey,
            privateKeyFile: privateFile,
            privateKeyInfo: privateInfo,
            publicKeyFile: publicEntry?.0,
            certificateFile: certificateEntry?.0,
            certificate: certificateEntry?.1,
            issues: issues
        )
    }

    // swiftlint:disable:next function_parameter_count
    static func issues(
        kind: DiscoveredKey.Kind,
        algorithm: KeyAlgorithm?,
        bits: Int?,
        privateFile: KeyFileInfo?,
        privateInfo: PrivateKeyInfo?,
        publicFile: KeyFileInfo?,
        directoryMode: UInt16,
        mismatch: Bool
    ) -> [KeyIssue] {
        var issues: [KeyIssue] = []
        if let privateFile {
            if privateFile.permissions & 0o077 != 0 {
                issues.append(.privateKeyPermissionsTooOpen(privateFile.permissions))
            }
            if !privateFile.isOwnedByCurrentUser {
                issues.append(.notOwnedByCurrentUser)
            }
        }
        if let publicFile, publicFile.permissions & 0o022 != 0 {
            issues.append(.publicKeyWritableByOthers(publicFile.permissions))
        }
        if directoryMode & 0o077 != 0, privateFile != nil {
            issues.append(.directoryPermissionsTooOpen(directoryMode))
        }
        if let privateInfo {
            if privateInfo.isEncrypted == false, algorithm?.isSecurityKey != true {
                issues.append(.noPassphrase)
            }
            if privateInfo.format.isLegacy {
                issues.append(.legacyFormat(privateInfo.format))
            }
        }
        switch algorithm {
        case .dsa:
            issues.append(.weakAlgorithm("DSA keys are obsolete and disabled in current OpenSSH."))
        case .rsa:
            if let bits, bits < 3072 {
                issues.append(.weakAlgorithm("RSA keys shorter than 3072 bits are considered weak (\(bits) bits)."))
            }
        default:
            break
        }
        if kind == .publicOnly {
            issues.append(.orphanedPublicKey)
        }
        if mismatch {
            issues.append(.publicKeyMismatch)
        }
        return issues
    }

    static func readPublicKey(_ url: URL) -> SSHPublicKey? {
        guard let bytes = try? SecureFileReader.readPrefix(url, maxBytes: 16 * 1024),
              let text = String(bytes: bytes, encoding: .utf8),
              let line = text.split(whereSeparator: \.isNewline).first
        else { return nil }
        return try? SSHPublicKey(line: String(line))
    }

    static func fileInfo(for url: URL) -> KeyFileInfo? {
        guard let linkAttributes = try? FileManager.default.attributesOfItem(atPath: url.path) else { return nil }
        let isLink = (linkAttributes[.type] as? FileAttributeType) == .typeSymbolicLink
        let resolvedPath = isLink ? url.resolvingSymlinksInPath().path : url.path
        guard let attributes = isLink ? try? FileManager.default.attributesOfItem(atPath: resolvedPath) : linkAttributes
        else { return nil }
        let type = attributes[.type] as? FileAttributeType
        guard type == .typeRegular || type == .typeDirectory else { return nil }
        let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
        return KeyFileInfo(
            url: url,
            permissions: UInt16(truncatingIfNeeded: (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0),
            isOwnedByCurrentUser: owner == getuid(),
            isSymbolicLink: isLink,
            size: (attributes[.size] as? NSNumber)?.intValue ?? 0,
            createdAt: attributes[.creationDate] as? Date,
            modifiedAt: attributes[.modificationDate] as? Date
        )
    }
}

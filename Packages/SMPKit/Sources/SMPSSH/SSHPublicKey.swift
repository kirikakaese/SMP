import CryptoKit
import Foundation
import SMPCore

/// Why a public key line could not be parsed. Never carries the input itself.
public enum PublicKeyParseError: Error, Sendable, Equatable {
    case empty
    case tooLong
    case missingKeyData
    case invalidBase64
    case malformedBlob
    case typeMismatch
}

/// A parsed OpenSSH public key or certificate (one line of a `.pub` file).
public struct SSHPublicKey: Sendable, Hashable {
    /// The key type as written in the line, e.g. `ssh-ed25519` or `ssh-ed25519-cert-v01@openssh.com`.
    public let wireType: String
    public let algorithm: KeyAlgorithm
    /// The decoded key blob.
    public let blob: Data
    public let comment: String
    /// Key size in bits, if known (not computed for certificates).
    public let bitLength: Int?

    public var isCertificate: Bool { KeyAlgorithm.isCertificateWireName(wireType) }

    /// `SHA256:<base64 without padding>`, exactly as printed by `ssh-keygen -l`.
    public var fingerprintSHA256: String {
        "SHA256:" + Self.unpaddedBase64(Data(SHA256.hash(data: blob)))
    }

    /// `MD5:aa:bb:…`, exactly as printed by `ssh-keygen -l -E md5`.
    public var fingerprintMD5: String {
        let digest = Insecure.MD5.hash(data: blob)
        return "MD5:" + digest.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    /// The raw SHA256 digest of the blob (input for randomart).
    public var sha256Digest: [UInt8] {
        Array(SHA256.hash(data: blob))
    }

    /// The key as a single line suitable for `authorized_keys` or a `.pub` file.
    public var openSSHLine: String {
        let base = wireType + " " + blob.base64EncodedString()
        return comment.isEmpty ? base : base + " " + comment
    }

    /// Parses one public key line: `type base64 [comment]`.
    ///
    /// The blob's embedded type must match the declared type, and the structure is validated
    /// for the algorithms SMP knows, so malformed or tampered input is rejected.
    public init(line: String) throws {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw PublicKeyParseError.empty }
        guard trimmed.utf8.count <= 16 * 1024 else { throw PublicKeyParseError.tooLong }

        let fields = trimmed.split(maxSplits: 2, omittingEmptySubsequences: true) { $0 == " " || $0 == "\t" }
        guard fields.count >= 2 else { throw PublicKeyParseError.missingKeyData }
        let declaredType = String(fields[0])
        guard let blob = Data(base64Encoded: String(fields[1])) else {
            throw PublicKeyParseError.invalidBase64
        }
        let comment = fields.count > 2 ? String(fields[2]).trimmingCharacters(in: .whitespaces) : ""
        try self.init(blob: blob, declaredType: declaredType, comment: comment)
    }

    /// Builds a key from a raw blob (for example from a private key header or the agent).
    public init(blob: Data, declaredType: String? = nil, comment: String = "") throws {
        let parsed = try Self.inspectBlob(blob)
        if let declaredType, declaredType != parsed.type {
            throw PublicKeyParseError.typeMismatch
        }
        self.wireType = parsed.type
        self.algorithm = KeyAlgorithm(wireName: parsed.type)
        self.blob = blob
        self.comment = comment
        self.bitLength = parsed.bits
    }

    private static func inspectBlob(_ blob: Data) throws -> (type: String, bits: Int?) {
        try blob.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) throws -> (type: String, bits: Int?) in
            var reader = SSHWireReader(buffer)
            do {
                let type = try reader.readUTF8()
                guard !type.isEmpty, type.count <= 64 else { throw PublicKeyParseError.malformedBlob }
                if KeyAlgorithm.isCertificateWireName(type) {
                    return (type, nil)
                }
                let bits = try bitLength(of: KeyAlgorithm(wireName: type), reader: &reader)
                return (type, bits)
            } catch is SSHWireError {
                throw PublicKeyParseError.malformedBlob
            }
        }
    }

    private static func bitLength(of algorithm: KeyAlgorithm, reader: inout SSHWireReader) throws -> Int? {
        switch algorithm {
        case .ed25519:
            guard try reader.readBytes().count == 32, reader.isAtEnd else { throw PublicKeyParseError.malformedBlob }
            return 256
        case .ed25519SK:
            guard try reader.readBytes().count == 32 else { throw PublicKeyParseError.malformedBlob }
            try reader.skipString()  // application, e.g. "ssh:"
            return 256
        case .ecdsaP256, .ecdsaP384, .ecdsaP521, .ecdsaSK:
            let curve = try reader.readUTF8()
            let expectedCurve: String =
                switch algorithm {
                case .ecdsaP384: "nistp384"
                case .ecdsaP521: "nistp521"
                default: "nistp256"
                }
            guard curve == expectedCurve else { throw PublicKeyParseError.malformedBlob }
            try reader.skipString()  // EC point
            if algorithm == .ecdsaSK {
                try reader.skipString()  // application
            }
            return algorithm.fixedBitLength
        case .rsa:
            _ = try reader.readMPIntBitLength()  // public exponent
            return try reader.readMPIntBitLength()
        case .dsa:
            return try reader.readMPIntBitLength()  // p
        case .unknown:
            return nil
        }
    }

    static func unpaddedBase64(_ data: Data) -> String {
        var encoded = data.base64EncodedString()
        while encoded.hasSuffix("=") {
            encoded.removeLast()
        }
        return encoded
    }
}

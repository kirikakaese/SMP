import CryptoKit
import Foundation
import SMPCore

/// Converts unencrypted PuTTY `.ppk` files (versions 2 and 3) to OpenSSH private keys.
///
/// The file's MAC is verified before anything is converted. All private material stays in
/// `SecureBytes`. Callers should additionally confirm the result with `ssh-keygen -y`.
public enum PuTTYKeyConverter {
    public static func convert(_ contents: SecureBytes) throws -> SecureBytes {
        try contents.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) throws -> SecureBytes in
            let file = try PuTTYFile(bytes)
            guard file.encryption == "none" else {
                throw SMPError.keyOperationFailed(
                    "Passphrase-protected PuTTY keys can't be imported directly.",
                    howToFix: "Open the key in PuTTYgen and choose Conversions → Export OpenSSH key, "
                        + "then import the exported file."
                )
            }
            guard let publicBlob = Data(base64Encoded: file.publicBase64),
                  let publicKey = try? SSHPublicKey(blob: publicBlob, comment: file.comment),
                  publicKey.wireType == file.algorithm
            else {
                throw invalid("The public key inside the PuTTY file is damaged.")
            }
            guard let privateBlob = SecureBase64.decode(bytes, ranges: file.privateRanges) else {
                throw invalid("The private key inside the PuTTY file is damaged.")
            }
            defer { privateBlob.wipe() }
            try verifyMAC(file: file, publicBlob: publicBlob, privateBlob: privateBlob)
            return try OpenSSHPrivateKeyBuilder.build(
                publicKey: publicKey,
                puttyPrivateBlob: privateBlob,
                comment: file.comment
            )
        }
    }

    private static func verifyMAC(file: PuTTYFile, publicBlob: Data, privateBlob: SecureBytes) throws {
        var macData = Data()
        for text in [file.algorithm, file.encryption, file.comment] {
            appendString(Data(text.utf8), to: &macData)
        }
        appendString(publicBlob, to: &macData)
        // The private blob is MACed without being copied into `macData`.
        let lengthPrefix = withUnsafeBytes(of: UInt32(privateBlob.count).bigEndian) { Data($0) }

        let computed: String = privateBlob.withUnsafeBytes { privateBytes in
            if file.version == 3 {
                // Version 3, unencrypted: HMAC-SHA-256 with an empty key.
                var mac = HMAC<SHA256>(key: SymmetricKey(data: Data()))
                mac.update(data: macData)
                mac.update(data: lengthPrefix)
                mac.update(data: privateBytes)
                return hex(mac.finalize())
            } else {
                // Version 2, unencrypted: HMAC-SHA-1 keyed with SHA-1 of the fixed string.
                let key = Insecure.SHA1.hash(data: Data("putty-private-key-file-mac-key".utf8))
                var mac = HMAC<Insecure.SHA1>(key: SymmetricKey(data: Data(key)))
                mac.update(data: macData)
                mac.update(data: lengthPrefix)
                mac.update(data: privateBytes)
                return hex(mac.finalize())
            }
        }
        guard computed == file.mac.lowercased() else {
            throw invalid("The PuTTY file failed its integrity check. It may be damaged or modified.")
        }
    }

    private static func appendString(_ data: Data, to target: inout Data) {
        withUnsafeBytes(of: UInt32(data.count).bigEndian) { target.append(contentsOf: $0) }
        target.append(data)
    }

    private static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }

    static func invalid(_ message: String) -> SMPError {
        SMPError.keyOperationFailed(message, howToFix: "Export the key again from PuTTYgen and retry.")
    }
}

/// The public header of a `.ppk` file plus the location of its private lines.
private struct PuTTYFile {
    var version = 2
    var algorithm = ""
    var encryption = ""
    var comment = ""
    var publicBase64 = ""
    var privateRanges: [Range<Int>] = []
    var mac = ""

    init(_ bytes: UnsafeRawBufferPointer) throws {
        let scanner = LineScanner(bytes)
        let ranges = scanner.allRanges
        var index = 0

        func text(_ range: Range<Int>) -> String {
            String(bytes: bytes[range], encoding: .utf8) ?? ""
        }
        func value(_ line: String) -> String {
            guard let colon = line.firstIndex(of: ":") else { return "" }
            return line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }

        while index < ranges.count {
            let line = text(ranges[index])
            index += 1
            if line.hasPrefix("PuTTY-User-Key-File-") {
                version = line.hasPrefix("PuTTY-User-Key-File-3:") ? 3 : 2
                algorithm = value(line)
            } else if line.hasPrefix("Encryption:") {
                encryption = value(line)
            } else if line.hasPrefix("Comment:") {
                comment = value(line)
            } else if line.hasPrefix("Public-Lines:") {
                let count = Int(value(line)) ?? 0
                guard count > 0, count <= 64, index + count <= ranges.count else {
                    throw PuTTYKeyConverter.invalid("The PuTTY file's public key section is malformed.")
                }
                publicBase64 = ranges[index..<(index + count)].map(text).joined()
                index += count
            } else if line.hasPrefix("Private-Lines:") {
                let count = Int(value(line)) ?? 0
                guard count > 0, count <= 256, index + count <= ranges.count else {
                    throw PuTTYKeyConverter.invalid("The PuTTY file's private key section is malformed.")
                }
                // Private lines are never turned into strings.
                privateRanges = Array(ranges[index..<(index + count)])
                index += count
            } else if line.hasPrefix("Private-MAC:") {
                mac = value(line)
            }
        }
        guard !algorithm.isEmpty, !publicBase64.isEmpty, !privateRanges.isEmpty, !mac.isEmpty else {
            throw PuTTYKeyConverter.invalid("The file is not a complete PuTTY private key.")
        }
    }
}

/// Assembles OpenSSH-format (`openssh-key-v1`) unencrypted private key files in secure memory.
enum OpenSSHPrivateKeyBuilder {
    static func build(
        publicKey: SSHPublicKey,
        puttyPrivateBlob: SecureBytes,
        comment: String
    ) throws -> SecureBytes {
        let section = try puttyPrivateBlob.withUnsafeBytes { privateBytes in
            try Self.privateSection(publicKey: publicKey, puttyPrivate: privateBytes, comment: comment)
        }
        defer { section.wipe() }

        var writer = SecureWireWriter(capacity: 128 + publicKey.blob.count + section.count)
        writer.append(Array("openssh-key-v1".utf8) + [0])
        writer.appendString("none")  // cipher
        writer.appendString("none")  // KDF
        writer.appendString("")  // KDF options
        writer.appendUInt32(1)  // number of keys
        writer.appendString(publicKey.blob)
        section.withUnsafeBytes { writer.appendString($0) }
        let binary = writer.finish()
        defer { binary.wipe() }
        return SecureBase64.armor(binary, label: "OPENSSH PRIVATE KEY")
    }

    private static func privateSection(
        publicKey: SSHPublicKey,
        puttyPrivate: UnsafeRawBufferPointer,
        comment: String
    ) throws -> SecureBytes {
        var putty = SSHWireReader(puttyPrivate)
        let capacity = 256 + publicKey.blob.count * 2 + puttyPrivate.count + comment.utf8.count
        var writer = SecureWireWriter(capacity: capacity)
        let check = UInt32.random(in: .min ... .max)
        writer.appendUInt32(check)
        writer.appendUInt32(check)

        try publicKey.blob.withUnsafeBytes { publicBytes in
            var pub = SSHWireReader(publicBytes)
            do {
                let type = try pub.readStringRange()
                writer.appendString(UnsafeRawBufferPointer(rebasing: publicBytes[type]))
                try appendKeyFields(
                    algorithm: publicKey.algorithm,
                    publicBytes: publicBytes,
                    publicReader: &pub,
                    puttyPrivate: puttyPrivate,
                    puttyReader: &putty,
                    writer: &writer
                )
            } catch is SSHWireError {
                throw PuTTYKeyConverter.invalid("The PuTTY private key data is malformed.")
            }
        }

        writer.appendString(comment)
        var padding: UInt8 = 1
        while writer.count % 8 != 0 {
            writer.append([padding])
            padding += 1
        }
        return writer.finish()
    }

    /// Appends the algorithm-specific private fields in OpenSSH order.
    private static func appendKeyFields(
        algorithm: KeyAlgorithm,
        publicBytes: UnsafeRawBufferPointer,
        publicReader pub: inout SSHWireReader,
        puttyPrivate: UnsafeRawBufferPointer,
        puttyReader putty: inout SSHWireReader,
        writer: inout SecureWireWriter
    ) throws {
        switch algorithm {
        case .ed25519:
            let point = try pub.readStringRange()
            guard point.count == 32 else { throw PuTTYKeyConverter.invalid("Unexpected Ed25519 key size.") }
            // PuTTY stores the 32-byte seed as a little-endian integer without trailing zero bytes.
            let seed = try putty.readStringRange()
            guard seed.count <= 32 else { throw PuTTYKeyConverter.invalid("Unexpected Ed25519 key size.") }
            try verifyEd25519(
                seed: UnsafeRawBufferPointer(rebasing: puttyPrivate[seed]),
                publicKey: UnsafeRawBufferPointer(rebasing: publicBytes[point])
            )
            writer.appendString(UnsafeRawBufferPointer(rebasing: publicBytes[point]))
            writer.appendUInt32(64)
            writer.append(UnsafeRawBufferPointer(rebasing: puttyPrivate[seed]))
            writer.append([UInt8](repeating: 0, count: 32 - seed.count))
            writer.append(UnsafeRawBufferPointer(rebasing: publicBytes[point]))
        case .ecdsaP256, .ecdsaP384, .ecdsaP521:
            let curve = try pub.readStringRange()
            let point = try pub.readStringRange()
            let scalar = try putty.readStringRange()
            writer.appendString(UnsafeRawBufferPointer(rebasing: publicBytes[curve]))
            writer.appendString(UnsafeRawBufferPointer(rebasing: publicBytes[point]))
            writer.appendString(UnsafeRawBufferPointer(rebasing: puttyPrivate[scalar]))
        case .rsa:
            let exponent = try pub.readStringRange()
            let modulus = try pub.readStringRange()
            let privateExponent = try putty.readStringRange()
            let primeP = try putty.readStringRange()
            let primeQ = try putty.readStringRange()
            let inverseQ = try putty.readStringRange()
            // OpenSSH order: n, e, d, iqmp, p, q.
            writer.appendString(UnsafeRawBufferPointer(rebasing: publicBytes[modulus]))
            writer.appendString(UnsafeRawBufferPointer(rebasing: publicBytes[exponent]))
            for range in [privateExponent, inverseQ, primeP, primeQ] {
                writer.appendString(UnsafeRawBufferPointer(rebasing: puttyPrivate[range]))
            }
        default:
            throw SMPError.keyOperationFailed(
                "\(algorithm.displayName) keys can't be converted from PuTTY.",
                howToFix: "Export the key from PuTTYgen with Conversions → Export OpenSSH key."
            )
        }
    }
}

extension OpenSSHPrivateKeyBuilder {
    /// Derives the public key from the seed and checks it against the stored public key.
    static func verifyEd25519(seed: UnsafeRawBufferPointer, publicKey: UnsafeRawBufferPointer) throws {
        let padded = SecureBytes(count: 32)
        padded.withUnsafeMutableBytes { target in
            if let base = target.baseAddress, let source = seed.baseAddress, !seed.isEmpty {
                base.copyMemory(from: source, byteCount: seed.count)
            }
        }
        let derived = try padded.withUnsafeBytes { try Curve25519.Signing.PrivateKey(rawRepresentation: $0) }
        guard derived.publicKey.rawRepresentation.elementsEqual(publicKey) else {
            throw PuTTYKeyConverter.invalid("The PuTTY private key does not match its public key.")
        }
    }
}

/// Builds SSH wire-format data inside a fixed-capacity `SecureBytes` buffer.
public struct SecureWireWriter {
    private let buffer: SecureBytes
    public private(set) var count = 0

    public init(capacity: Int) {
        buffer = SecureBytes(count: capacity)
    }

    public mutating func append(_ bytes: UnsafeRawBufferPointer) {
        let offset = count
        precondition(offset + bytes.count <= buffer.count, "SecureWireWriter capacity exceeded")
        buffer.withUnsafeMutableBytes { target in
            guard let base = target.baseAddress, let source = bytes.baseAddress, !bytes.isEmpty else { return }
            (base + offset).copyMemory(from: source, byteCount: bytes.count)
        }
        count += bytes.count
    }

    public mutating func append(_ bytes: [UInt8]) {
        bytes.withUnsafeBytes { append($0) }
    }

    public mutating func appendUInt32(_ value: UInt32) {
        withUnsafeBytes(of: value.bigEndian) { append($0) }
    }

    public mutating func appendString(_ bytes: UnsafeRawBufferPointer) {
        appendUInt32(UInt32(bytes.count))
        append(bytes)
    }

    public mutating func appendString(_ data: Data) {
        data.withUnsafeBytes { appendString($0) }
    }

    public mutating func appendString(_ text: String) {
        appendString(Data(text.utf8))
    }

    /// Returns an exactly sized copy; the working buffer is zeroed when the writer goes away.
    public func finish() -> SecureBytes {
        buffer.withUnsafeBytes { SecureBytes(UnsafeRawBufferPointer(rebasing: $0[0..<count])) }
    }
}

extension SecureBase64 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
    /// Characters per line. OpenSSH accepts any wrapping; a multiple of 4 keeps groups intact.
    private static let lineWidth = 68

    /// Base64-encodes `data` into PEM-style armor (`-----BEGIN label-----`, 70-character lines).
    static func armor(_ data: SecureBytes, label: String) -> SecureBytes {
        let header = Array("-----BEGIN \(label)-----\n".utf8)
        let footer = Array("-----END \(label)-----\n".utf8)
        let encodedLength = (data.count + 2) / 3 * 4
        let capacity = header.count + encodedLength + encodedLength / lineWidth + 1 + footer.count
        var writer = SecureWireWriter(capacity: capacity)
        writer.append(header)
        data.withUnsafeBytes { input in
            var lineLength = 0
            var index = 0
            while index < input.count {
                let byte0 = input[index]
                let byte1 = index + 1 < input.count ? input[index + 1] : 0
                let byte2 = index + 2 < input.count ? input[index + 2] : 0
                var quad: [UInt8] = [
                    alphabet[Int(byte0 >> 2)],
                    alphabet[Int((byte0 & 0x03) << 4 | byte1 >> 4)],
                    alphabet[Int((byte1 & 0x0F) << 2 | byte2 >> 6)],
                    alphabet[Int(byte2 & 0x3F)],
                ]
                if index + 1 >= input.count { quad[2] = UInt8(ascii: "=") }
                if index + 2 >= input.count { quad[3] = UInt8(ascii: "=") }
                writer.append(quad)
                quad = [0, 0, 0, 0]
                lineLength += 4
                index += 3
                if lineLength == lineWidth {
                    writer.append([0x0A])
                    lineLength = 0
                }
            }
            if lineLength > 0 {
                writer.append([0x0A])
            }
        }
        writer.append(footer)
        return writer.finish()
    }
}

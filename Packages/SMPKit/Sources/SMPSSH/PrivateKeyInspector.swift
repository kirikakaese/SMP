import Foundation
import SMPCore

/// On-disk formats of private key files.
public enum PrivateKeyFormat: String, Sendable, Codable, Hashable {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----` (the modern default).
    case openSSH
    /// Traditional PEM: `BEGIN RSA/EC/DSA PRIVATE KEY`.
    case pem
    /// PKCS#8: `BEGIN PRIVATE KEY` or `BEGIN ENCRYPTED PRIVATE KEY`.
    case pkcs8
    /// PuTTY `.ppk` (version 2 or 3).
    case putty

    public var displayName: String {
        switch self {
        case .openSSH: "OpenSSH"
        case .pem: "PEM (legacy)"
        case .pkcs8: "PKCS#8"
        case .putty: "PuTTY"
        }
    }

    /// Formats `ssh-keygen -p -o` can upgrade to the OpenSSH format.
    public var isLegacy: Bool { self != .openSSH }
}

/// What can be learned about a private key file without decrypting it.
public struct PrivateKeyInfo: Sendable, Hashable {
    public let format: PrivateKeyFormat
    /// `nil` when the format does not say.
    public let isEncrypted: Bool?
    /// The public key stored in the clear inside the file (OpenSSH and PuTTY formats).
    public let embeddedPublicKey: SSHPublicKey?
    /// Cipher name (OpenSSH: `none`, `aes256-ctr`, …; PuTTY: `none`, `aes256-cbc`).
    public let cipherName: String?
    /// bcrypt KDF rounds for encrypted OpenSSH keys.
    public let kdfRounds: Int?
    /// Comment stored in the clear (PuTTY only).
    public let comment: String?
}

/// Inspects private key files.
///
/// Security: the file is read into `SecureBytes` and decoded into `SecureBytes`, which are
/// zeroed afterwards. Only the unencrypted header (format, cipher, KDF parameters and public
/// key) is parsed; the private section is never interpreted, copied or logged.
public enum PrivateKeyInspector {
    /// Private key files larger than this are not considered.
    public static let maxFileSize = 64 * 1024

    /// Returns `true` if `prefix` (the first bytes of a file) looks like a private key.
    public static func looksLikePrivateKey(prefix: [UInt8]) -> Bool {
        let text = String(decoding: prefix.prefix(64), as: UTF8.self)
        return Marker.allCases.contains { text.hasPrefix($0.rawValue) }
    }

    /// Inspects the file at `url`. Returns `nil` if it is not a recognized private key.
    public static func inspect(fileAt url: URL) throws -> PrivateKeyInfo? {
        let contents = try SecureFileReader.read(url, maxBytes: maxFileSize)
        defer { contents.wipe() }
        return inspect(contents: contents)
    }

    /// Inspects private key file contents held in a secure buffer.
    public static func inspect(contents: SecureBytes) -> PrivateKeyInfo? {
        contents.withUnsafeBytes { bytes -> PrivateKeyInfo? in
            let lines = LineScanner(bytes)
            guard let first = lines.firstLine else { return nil }
            switch Marker(rawValue: first) {
            case .openSSH:
                return inspectOpenSSH(bytes, lines: lines)
            case .rsa, .ec, .dsa:
                let encrypted = lines.headerLines(limit: 4).contains {
                    $0.hasPrefix("Proc-Type:") && $0.contains("ENCRYPTED")
                }
                return PrivateKeyInfo(
                    format: .pem, isEncrypted: encrypted, embeddedPublicKey: nil,
                    cipherName: nil, kdfRounds: nil, comment: nil
                )
            case .pkcs8:
                return PrivateKeyInfo(
                    format: .pkcs8, isEncrypted: false, embeddedPublicKey: nil,
                    cipherName: nil, kdfRounds: nil, comment: nil
                )
            case .pkcs8Encrypted:
                return PrivateKeyInfo(
                    format: .pkcs8, isEncrypted: true, embeddedPublicKey: nil,
                    cipherName: nil, kdfRounds: nil, comment: nil
                )
            case .none:
                if first.hasPrefix(Marker.puttyV2.rawValue) || first.hasPrefix(Marker.puttyV3.rawValue) {
                    return inspectPuTTY(lines: lines)
                }
                return nil
            case .puttyV2, .puttyV3:
                return inspectPuTTY(lines: lines)
            }
        }
    }

    private enum Marker: String, CaseIterable {
        case openSSH = "-----BEGIN OPENSSH PRIVATE KEY-----"
        case rsa = "-----BEGIN RSA PRIVATE KEY-----"
        case ec = "-----BEGIN EC PRIVATE KEY-----"
        case dsa = "-----BEGIN DSA PRIVATE KEY-----"
        case pkcs8 = "-----BEGIN PRIVATE KEY-----"
        case pkcs8Encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        case puttyV2 = "PuTTY-User-Key-File-2:"
        case puttyV3 = "PuTTY-User-Key-File-3:"
    }

    // MARK: OpenSSH

    private static let openSSHMagic = Array("openssh-key-v1".utf8) + [0]

    private static func inspectOpenSSH(_ bytes: UnsafeRawBufferPointer, lines: LineScanner) -> PrivateKeyInfo? {
        let body = lines.base64Body(of: bytes)
        let decoded = SecureBase64.decode(bytes, ranges: body)
        defer { decoded?.wipe() }
        guard let decoded else { return nil }

        return decoded.withUnsafeBytes { buffer -> PrivateKeyInfo? in
            guard buffer.count > openSSHMagic.count,
                  zip(buffer.prefix(openSSHMagic.count), openSSHMagic).allSatisfy({ $0 == $1 })
            else { return nil }
            var reader = SSHWireReader(UnsafeRawBufferPointer(rebasing: buffer[openSSHMagic.count...]))
            do {
                let cipher = try reader.readUTF8()
                let kdf = try reader.readUTF8()
                let kdfOptions = try reader.readBytes()
                let rounds = kdf == "bcrypt" ? bcryptRounds(kdfOptions) : nil
                let keyCount = try reader.readUInt32()
                var publicKey: SSHPublicKey?
                if keyCount >= 1 {
                    publicKey = try? SSHPublicKey(blob: Data(try reader.readBytes()))
                }
                // The private section that follows is deliberately left untouched.
                return PrivateKeyInfo(
                    format: .openSSH, isEncrypted: cipher != "none", embeddedPublicKey: publicKey,
                    cipherName: cipher, kdfRounds: rounds, comment: nil
                )
            } catch {
                return nil
            }
        }
    }

    private static func bcryptRounds(_ options: [UInt8]) -> Int? {
        options.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Int? in
            var reader = SSHWireReader(buffer)
            guard (try? reader.skipString()) != nil, let rounds = try? reader.readUInt32() else { return nil }
            return Int(rounds)
        }
    }

    // MARK: PuTTY

    private static func inspectPuTTY(lines: LineScanner) -> PrivateKeyInfo? {
        var encryption: String?
        var comment: String?
        var publicLineCount = 0
        var publicBase64 = ""
        var collectingPublic = false

        // Only the header and the public lines are read; "Private-Lines" and everything after
        // it are never touched.
        for line in lines.textLines(until: { $0.hasPrefix("Private-Lines:") }) {
            if collectingPublic {
                publicBase64 += line
                publicLineCount -= 1
                collectingPublic = publicLineCount > 0
            } else if line.hasPrefix("Encryption:") {
                encryption = value(of: line)
            } else if line.hasPrefix("Comment:") {
                comment = value(of: line)
            } else if line.hasPrefix("Public-Lines:") {
                publicLineCount = Int(value(of: line)) ?? 0
                collectingPublic = publicLineCount > 0 && publicLineCount <= 64
            }
        }
        let publicKey = Data(base64Encoded: publicBase64).flatMap {
            try? SSHPublicKey(blob: $0, comment: comment ?? "")
        }
        return PrivateKeyInfo(
            format: .putty,
            isEncrypted: encryption.map { $0 != "none" },
            embeddedPublicKey: publicKey,
            cipherName: encryption,
            kdfRounds: nil,
            comment: comment
        )
    }

    private static func value(of line: String) -> String {
        guard let colon = line.firstIndex(of: ":") else { return "" }
        return line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
    }
}

/// Splits a borrowed buffer into lines without copying the content.
struct LineScanner {
    private let ranges: [Range<Int>]
    private let bytes: UnsafeRawBufferPointer

    init(_ bytes: UnsafeRawBufferPointer) {
        self.bytes = bytes
        var ranges: [Range<Int>] = []
        var start = 0
        for index in 0..<bytes.count where bytes[index] == 0x0A {
            ranges.append(start..<index)
            start = index + 1
        }
        if start < bytes.count {
            ranges.append(start..<bytes.count)
        }
        // Drop a trailing carriage return from CRLF files.
        self.ranges = ranges.map { range in
            if let last = range.last, bytes[last] == 0x0D {
                return range.lowerBound..<last
            }
            return range
        }
    }

    var allRanges: [Range<Int>] { ranges }

    /// The first line, which is always a public marker such as `-----BEGIN … -----`.
    var firstLine: String? {
        guard let range = ranges.first, range.count <= 128 else { return nil }
        return String(bytes: bytes[range], encoding: .utf8)
    }

    /// The `Key: value` header lines directly after the first line (PEM `Proc-Type`, `DEK-Info`).
    func headerLines(limit: Int) -> [String] {
        ranges.dropFirst().prefix(limit).compactMap { range in
            guard range.count <= 128, let line = String(bytes: bytes[range], encoding: .utf8),
                  line.contains(":")
            else { return nil }
            return line
        }
    }

    /// Text lines from the start up to (not including) the first line matching `stop`.
    func textLines(until stop: (String) -> Bool) -> [String] {
        var result: [String] = []
        for range in ranges {
            guard let line = String(bytes: bytes[range], encoding: .utf8) else { break }
            if stop(line) { break }
            result.append(line)
        }
        return result
    }

    /// The ranges of base64 lines between the BEGIN and END markers.
    func base64Body(of bytes: UnsafeRawBufferPointer) -> [Range<Int>] {
        var body: [Range<Int>] = []
        for range in ranges.dropFirst() {
            if range.count >= 5, bytes[range.lowerBound] == UInt8(ascii: "-") {
                break
            }
            body.append(range)
        }
        return body
    }
}

/// Base64 decoding into `SecureBytes`, for data that may contain private key material.
enum SecureBase64 {
    static func decode(_ source: UnsafeRawBufferPointer, ranges: [Range<Int>]) -> SecureBytes? {
        let characterCount = ranges.reduce(0) { $0 + $1.count }
        let output = SecureBytes(count: characterCount / 4 * 3 + 3)
        let written = output.withUnsafeMutableBytes { out -> Int? in
            var accumulator: UInt32 = 0
            var bits = 0
            var count = 0
            for range in ranges {
                for index in range {
                    let character = source[index]
                    if character == UInt8(ascii: "=") { return count }
                    if character == UInt8(ascii: " ") || character == UInt8(ascii: "\t") { continue }
                    guard let value = sextet(character) else { return nil }
                    accumulator = (accumulator << 6) | UInt32(value)
                    bits += 6
                    if bits >= 8 {
                        bits -= 8
                        out[count] = UInt8(truncatingIfNeeded: accumulator >> UInt32(bits))
                        count += 1
                    }
                }
            }
            accumulator = 0
            return count
        }
        guard let written else {
            output.wipe()
            return nil
        }
        let result = output.withUnsafeBytes { SecureBytes(UnsafeRawBufferPointer(rebasing: $0[0..<written])) }
        output.wipe()
        return result
    }

    private static func sextet(_ character: UInt8) -> UInt8? {
        switch character {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): character - UInt8(ascii: "A")
        case UInt8(ascii: "a")...UInt8(ascii: "z"): character - UInt8(ascii: "a") + 26
        case UInt8(ascii: "0")...UInt8(ascii: "9"): character - UInt8(ascii: "0") + 52
        case UInt8(ascii: "+"): 62
        case UInt8(ascii: "/"): 63
        default: nil
        }
    }
}

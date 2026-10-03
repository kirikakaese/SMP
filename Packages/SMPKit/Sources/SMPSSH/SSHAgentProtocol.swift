import Foundation

/// Message numbers of the SSH agent protocol (draft-miller-ssh-agent).
public enum SSHAgentMessageType: UInt8, Sendable {
    case failure = 5
    case success = 6
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case addIdentity = 17
    case removeIdentity = 18
    case removeAllIdentities = 19
    case addSmartcardKey = 20
    case removeSmartcardKey = 21
    case lock = 22
    case unlock = 23
    case addIdentityConstrained = 25
    case addSmartcardKeyConstrained = 26
    case `extension` = 27
    case extensionFailure = 28

    /// Requests that carry secrets (private keys, PINs, lock passphrases). SMP's agent never
    /// relays these; users load file keys into the system agent directly.
    public var carriesSecrets: Bool {
        switch self {
        case .addIdentity, .addIdentityConstrained, .addSmartcardKey, .addSmartcardKeyConstrained, .lock, .unlock:
            true
        default:
            false
        }
    }
}

/// A public key the agent offers, with its comment.
public struct SSHAgentIdentity: Sendable, Hashable {
    public let keyBlob: Data
    public let comment: String

    public init(keyBlob: Data, comment: String) {
        self.keyBlob = keyBlob
        self.comment = comment
    }
}

/// An `SSH_AGENTC_SIGN_REQUEST`.
public struct SSHAgentSignRequest: Sendable, Hashable {
    public static let flagRSASHA256: UInt32 = 0x02
    public static let flagRSASHA512: UInt32 = 0x04

    public let keyBlob: Data
    public let data: Data
    public let flags: UInt32

    public init(keyBlob: Data, data: Data, flags: UInt32) {
        self.keyBlob = keyBlob
        self.data = data
        self.flags = flags
    }
}

/// Encodes and decodes agent protocol messages. A message is `uint32 length || byte type || body`;
/// the functions here work on the payload (type byte plus body) unless noted otherwise.
public enum SSHAgentCodec {
    /// Upper bound for one message, as a guard against hostile length prefixes (OpenSSH uses 256 KiB).
    public static let maxMessageLength = 256 * 1024

    public static let failure = Data([SSHAgentMessageType.failure.rawValue])
    public static let success = Data([SSHAgentMessageType.success.rawValue])
    public static let requestIdentities = Data([SSHAgentMessageType.requestIdentities.rawValue])

    /// Prefixes a payload with its length.
    public static func frame(_ payload: Data) -> Data {
        var framed = Data()
        framed.appendUInt32(UInt32(payload.count))
        framed.append(payload)
        return framed
    }

    /// The message type of a payload, if known.
    public static func type(of payload: Data) -> SSHAgentMessageType? {
        payload.first.flatMap(SSHAgentMessageType.init(rawValue:))
    }

    public static func identitiesAnswer(_ identities: [SSHAgentIdentity]) -> Data {
        var payload = Data([SSHAgentMessageType.identitiesAnswer.rawValue])
        payload.appendUInt32(UInt32(identities.count))
        for identity in identities {
            payload.appendSSHString(identity.keyBlob)
            payload.appendSSHString(Data(identity.comment.utf8))
        }
        return payload
    }

    public static func parseIdentitiesAnswer(_ payload: Data) throws -> [SSHAgentIdentity] {
        try payload.withUnsafeBytes { buffer in
            var reader = SSHWireReader(buffer, maxFieldLength: maxMessageLength)
            guard try reader.readByte() == SSHAgentMessageType.identitiesAnswer.rawValue else {
                throw SSHWireError.invalidEncoding
            }
            let count = Int(try reader.readUInt32())
            // Each identity needs at least two length prefixes.
            guard count <= reader.remaining / 8 else { throw SSHWireError.truncated }
            return try (0..<count).map { _ in
                let blob = Data(try reader.readBytes())
                let comment = String(decoding: try reader.readBytes(), as: UTF8.self)
                return SSHAgentIdentity(keyBlob: blob, comment: comment)
            }
        }
    }

    public static func signRequest(_ request: SSHAgentSignRequest) -> Data {
        var payload = Data([SSHAgentMessageType.signRequest.rawValue])
        payload.appendSSHString(request.keyBlob)
        payload.appendSSHString(request.data)
        payload.appendUInt32(request.flags)
        return payload
    }

    public static func parseSignRequest(_ payload: Data) throws -> SSHAgentSignRequest {
        try payload.withUnsafeBytes { buffer in
            var reader = SSHWireReader(buffer, maxFieldLength: maxMessageLength)
            guard try reader.readByte() == SSHAgentMessageType.signRequest.rawValue else {
                throw SSHWireError.invalidEncoding
            }
            let blob = Data(try reader.readBytes())
            let data = Data(try reader.readBytes())
            let flags = try reader.readUInt32()
            return SSHAgentSignRequest(keyBlob: blob, data: data, flags: flags)
        }
    }

    public static func signResponse(signature: Data) -> Data {
        var payload = Data([SSHAgentMessageType.signResponse.rawValue])
        payload.appendSSHString(signature)
        return payload
    }

    public static func parseSignResponse(_ payload: Data) throws -> Data {
        try payload.withUnsafeBytes { buffer in
            var reader = SSHWireReader(buffer, maxFieldLength: maxMessageLength)
            guard try reader.readByte() == SSHAgentMessageType.signResponse.rawValue else {
                throw SSHWireError.invalidEncoding
            }
            return Data(try reader.readBytes())
        }
    }

    // MARK: Extensions

    /// An `SSH_AGENTC_EXTENSION` request: `byte 27 || string name || contents`.
    public static func extensionRequest(name: String, contents: Data) -> Data {
        var payload = Data([SSHAgentMessageType.extension.rawValue])
        payload.appendSSHString(Data(name.utf8))
        payload.append(contents)
        return payload
    }

    /// The extension name and the extension-specific contents that follow it.
    public static func parseExtensionRequest(_ payload: Data) throws -> (name: String, contents: Data) {
        try payload.withUnsafeBytes { buffer in
            var reader = SSHWireReader(buffer, maxFieldLength: maxMessageLength)
            guard try reader.readByte() == SSHAgentMessageType.extension.rawValue else {
                throw SSHWireError.invalidEncoding
            }
            let name = try reader.readUTF8()
            return (name, Data(buffer[reader.offset...]))
        }
    }

    /// A successful extension reply: `byte SSH_AGENT_SUCCESS || contents`.
    public static func extensionResponse(_ contents: Data) -> Data {
        success + contents
    }

    /// The contents of a successful extension reply.
    public static func parseExtensionResponse(_ payload: Data) throws -> Data {
        guard type(of: payload) == .success else { throw SSHWireError.invalidEncoding }
        return Data(payload.dropFirst())
    }

    // MARK: ECDSA P-256 (Secure Enclave keys)

    public static let ecdsaP256KeyType = "ecdsa-sha2-nistp256"

    /// The public key blob for an uncompressed P-256 point (`04 || X || Y`, 65 bytes).
    public static func ecdsaP256PublicKeyBlob(x963 point: Data) -> Data {
        var blob = Data()
        blob.appendSSHString(Data(ecdsaP256KeyType.utf8))
        blob.appendSSHString(Data("nistp256".utf8))
        blob.appendSSHString(point)
        return blob
    }

    /// Wraps a raw `r || s` signature (64 bytes) the way SSH expects:
    /// `string "ecdsa-sha2-nistp256" || string (mpint r || mpint s)`.
    public static func ecdsaP256SignatureBlob(raw: Data) throws -> Data {
        guard raw.count == 64 else { throw SSHWireError.invalidEncoding }
        let bytes = [UInt8](raw)
        var inner = Data()
        inner.appendSSHMPInt(bytes[0..<32])
        inner.appendSSHMPInt(bytes[32..<64])
        var blob = Data()
        blob.appendSSHString(Data(ecdsaP256KeyType.utf8))
        blob.appendSSHString(inner)
        return blob
    }
}

extension Data {
    mutating func appendUInt32(_ value: UInt32) {
        append(contentsOf: [
            UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value),
        ])
    }

    mutating func appendSSHString(_ bytes: Data) {
        appendUInt32(UInt32(bytes.count))
        append(bytes)
    }

    /// Appends a positive big-endian integer as an SSH `mpint` (minimal length, sign-safe).
    mutating func appendSSHMPInt(_ bytes: ArraySlice<UInt8>) {
        var trimmed = Array(bytes.drop { $0 == 0 })
        if let first = trimmed.first, first & 0x80 != 0 {
            trimmed.insert(0, at: 0)
        }
        appendUInt32(UInt32(trimmed.count))
        append(contentsOf: trimmed)
    }
}

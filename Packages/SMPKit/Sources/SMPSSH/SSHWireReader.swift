import Foundation

/// Errors from parsing SSH wire-format data. Messages never include the data itself.
public enum SSHWireError: Error, Sendable, Equatable {
    case truncated
    case fieldTooLarge
    case invalidEncoding
}

/// Reads RFC 4251 wire-format values (`uint32`, `string`, `mpint`) from a borrowed buffer.
///
/// The reader does not own its bytes: use it only inside the `withUnsafeBytes` scope that
/// produced the buffer.
public struct SSHWireReader {
    private let bytes: UnsafeRawBufferPointer
    public private(set) var offset = 0
    /// Upper bound for a single `string` field, as a guard against hostile length prefixes.
    private let maxFieldLength: Int

    public init(_ bytes: UnsafeRawBufferPointer, maxFieldLength: Int = 64 * 1024) {
        self.bytes = bytes
        self.maxFieldLength = maxFieldLength
    }

    public var isAtEnd: Bool { offset >= bytes.count }
    public var remaining: Int { bytes.count - offset }

    public mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else { throw SSHWireError.truncated }
        var value: UInt32 = 0
        for index in 0..<4 {
            value = (value << 8) | UInt32(bytes[offset + index])
        }
        offset += 4
        return value
    }

    public mutating func readByte() throws -> UInt8 {
        guard remaining >= 1 else { throw SSHWireError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    /// Reads a length-prefixed `string` and returns a copy of its bytes. Use only for public data.
    public mutating func readBytes() throws -> [UInt8] {
        let range = try readStringRange()
        return Array(bytes[range])
    }

    /// Reads a length-prefixed `string` as UTF-8 text.
    public mutating func readUTF8() throws -> String {
        let range = try readStringRange()
        guard let text = String(bytes: bytes[range], encoding: .utf8) else {
            throw SSHWireError.invalidEncoding
        }
        return text
    }

    /// Skips a length-prefixed `string` without copying it.
    public mutating func skipString() throws {
        _ = try readStringRange()
    }

    /// Reads an `mpint` and returns its size in bits (ignoring leading zero bytes).
    public mutating func readMPIntBitLength() throws -> Int {
        let range = try readStringRange()
        var index = range.lowerBound
        while index < range.upperBound, bytes[index] == 0 {
            index += 1
        }
        guard index < range.upperBound else { return 0 }
        let leading = bytes[index]
        let leadingBits = UInt8.bitWidth - leading.leadingZeroBitCount
        return (range.upperBound - index - 1) * 8 + leadingBits
    }

    /// Reads a length-prefixed `string` and returns its byte range without copying it.
    public mutating func readStringRange() throws -> Range<Int> {
        let length = Int(try readUInt32())
        guard length <= maxFieldLength else { throw SSHWireError.fieldTooLarge }
        guard remaining >= length else { throw SSHWireError.truncated }
        let range = offset..<(offset + length)
        offset += length
        return range
    }
}

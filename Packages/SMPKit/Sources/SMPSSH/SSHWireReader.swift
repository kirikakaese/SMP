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
struct SSHWireReader {
    private let bytes: UnsafeRawBufferPointer
    private(set) var offset = 0
    /// Upper bound for a single `string` field, as a guard against hostile length prefixes.
    private let maxFieldLength: Int

    init(_ bytes: UnsafeRawBufferPointer, maxFieldLength: Int = 64 * 1024) {
        self.bytes = bytes
        self.maxFieldLength = maxFieldLength
    }

    var isAtEnd: Bool { offset >= bytes.count }
    var remaining: Int { bytes.count - offset }

    mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else { throw SSHWireError.truncated }
        var value: UInt32 = 0
        for index in 0..<4 {
            value = (value << 8) | UInt32(bytes[offset + index])
        }
        offset += 4
        return value
    }

    /// Reads a length-prefixed `string` and returns a copy of its bytes. Use only for public data.
    mutating func readBytes() throws -> [UInt8] {
        let range = try readStringRange()
        return Array(bytes[range])
    }

    /// Reads a length-prefixed `string` as UTF-8 text.
    mutating func readUTF8() throws -> String {
        let range = try readStringRange()
        guard let text = String(bytes: bytes[range], encoding: .utf8) else {
            throw SSHWireError.invalidEncoding
        }
        return text
    }

    /// Skips a length-prefixed `string` without copying it.
    mutating func skipString() throws {
        _ = try readStringRange()
    }

    /// Reads an `mpint` and returns its size in bits (ignoring leading zero bytes).
    mutating func readMPIntBitLength() throws -> Int {
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

    private mutating func readStringRange() throws -> Range<Int> {
        let length = Int(try readUInt32())
        guard length <= maxFieldLength else { throw SSHWireError.fieldTooLarge }
        guard remaining >= length else { throw SSHWireError.truncated }
        let range = offset..<(offset + length)
        offset += length
        return range
    }
}

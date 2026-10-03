import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// Reads small files that may contain secrets straight into `SecureBytes`, without passing
/// through `Data` or `String`.
public enum SecureFileReader {
    /// Reads at most `maxBytes` from the start of the file at `url`.
    ///
    /// - Returns: the bytes read (fewer than `maxBytes` if the file is shorter).
    public static func read(_ url: URL, maxBytes: Int) throws -> SecureBytes {
        let descriptor = open(url.path, O_RDONLY | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw fileError(url, errno: errno)
        }
        defer { close(descriptor) }

        var info = stat()
        guard fstat(descriptor, &info) == 0 else {
            throw fileError(url, errno: errno)
        }
        guard (info.st_mode & S_IFMT) == S_IFREG else {
            throw SMPError(.fileSystem, whatHappened: String(localized: """
                \(url.lastPathComponent) is not a regular file.
                """))
        }

        let capacity = max(0, min(Int(info.st_size), maxBytes))
        let buffer = SecureBytes(count: capacity)
        let total = buffer.withUnsafeMutableBytes { bytes -> Int in
            guard let base = bytes.baseAddress else { return 0 }
            var offset = 0
            while offset < bytes.count {
                let result = Darwin.read(descriptor, base + offset, bytes.count - offset)
                if result < 0 {
                    if errno == EINTR { continue }
                    return -1
                }
                if result == 0 { break }
                offset += result
            }
            return offset
        }
        guard total >= 0 else {
            throw fileError(url, errno: errno)
        }
        if total == capacity {
            return buffer
        }
        // The file shrank while reading; copy the part we got into an exactly sized buffer.
        return buffer.withUnsafeBytes { SecureBytes(UnsafeRawBufferPointer(rebasing: $0[0..<total])) }
    }

    /// Reads at most `maxBytes` from the start of a file that holds no secrets (for sniffing headers).
    public static func readPrefix(_ url: URL, maxBytes: Int) throws -> [UInt8] {
        let secure = try read(url, maxBytes: maxBytes)
        return secure.withUnsafeBytes { Array($0) }
    }

    private static func fileError(_ url: URL, errno code: Int32) -> SMPError {
        SMPError(
            .fileSystem,
            whatHappened: String(localized: "SMP could not read \(url.lastPathComponent)."),
            howToFix: code == EACCES ? "Check the file's permissions in Finder or with “ls -l”." : nil,
            details: String(cString: strerror(code))
        )
    }
}

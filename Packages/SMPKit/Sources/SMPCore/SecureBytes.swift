import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// A fixed-size heap buffer for secret material (passphrases, tokens, decrypted key bytes).
///
/// The memory is locked against swapping where the OS allows it and is overwritten with zeros
/// when the buffer is wiped or released. Prefer passing `SecureBytes` around instead of `String`
/// or `Data`, which can be copied freely by the runtime and are never zeroed.
public final class SecureBytes: @unchecked Sendable {
    // Safety: `storage` is allocated once in `init` and only mutated by `wipe()`, which takes
    // `lock`. Readers also take `lock`, so concurrent access is serialized.
    private let storage: UnsafeMutableRawBufferPointer
    private let isLocked: Bool
    private let lock = NSLock()

    /// Number of bytes held by the buffer.
    public var count: Int { storage.count }

    /// `true` if the buffer holds zero bytes.
    public var isEmpty: Bool { storage.isEmpty }

    /// Creates a zero-filled buffer of the given size.
    public init(count: Int) {
        precondition(count >= 0, "SecureBytes count must not be negative")
        storage = .allocate(byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
        storage.initializeMemory(as: UInt8.self, repeating: 0)
        if let base = storage.baseAddress, count > 0 {
            isLocked = mlock(base, count) == 0
        } else {
            isLocked = false
        }
    }

    /// Copies `bytes` into a new secure buffer. The caller remains responsible for wiping the source.
    public convenience init(_ bytes: some Collection<UInt8>) {
        self.init(count: bytes.count)
        storage.copyBytes(from: bytes)
    }

    /// Copies the UTF-8 encoding of `string` into a new secure buffer.
    ///
    /// Use this only at the boundary where a secret arrives as a `String` (for example from a
    /// `SecureField`), and drop the `String` as soon as possible afterwards.
    public convenience init(utf8 string: String) {
        self.init(Array(string.utf8))
    }

    /// Moves the contents of `data` into a new secure buffer and zeroes `data`.
    public convenience init(consuming data: inout Data) {
        self.init(data)
        data.secureWipe()
        data = Data()
    }

    deinit {
        zeroMemory()
        if isLocked, let base = storage.baseAddress {
            munlock(base, storage.count)
        }
        storage.deallocate()
    }

    /// Gives read-only access to the secret bytes for the duration of `body`.
    ///
    /// Do not let the pointer escape `body`.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        return try body(UnsafeRawBufferPointer(storage))
    }

    /// Overwrites the buffer with zeros. The buffer keeps its size.
    public func wipe() {
        lock.lock()
        defer { lock.unlock() }
        zeroMemory()
    }

    /// Returns `true` if both buffers hold the same bytes. Runs in time that depends only on the length.
    public func constantTimeEquals(_ other: SecureBytes) -> Bool {
        guard count == other.count else { return false }
        return withUnsafeBytes { lhs in
            other.withUnsafeBytes { rhs in
                var difference: UInt8 = 0
                for index in 0..<lhs.count {
                    difference |= lhs[index] ^ rhs[index]
                }
                return difference == 0
            }
        }
    }

    private func zeroMemory() {
        guard let base = storage.baseAddress, storage.count > 0 else { return }
        SecureMemory.zero(base, count: storage.count)
    }
}

extension SecureBytes: CustomStringConvertible, CustomDebugStringConvertible {
    // Never print secret contents, not even in debug builds.
    public var description: String { "SecureBytes(\(count) bytes, redacted)" }
    public var debugDescription: String { description }
}

/// Helpers for zeroing memory in a way the optimizer cannot remove.
public enum SecureMemory {
    /// Overwrites `count` bytes at `pointer` with zeros.
    public static func zero(_ pointer: UnsafeMutableRawPointer, count: Int) {
        guard count > 0 else { return }
        #if canImport(Darwin)
        _ = memset_s(pointer, count, 0, count)
        #else
        let bytes = pointer.assumingMemoryBound(to: UInt8.self)
        for index in 0..<count {
            bytes[index] = 0
        }
        #endif
    }
}

extension Data {
    /// Overwrites the bytes currently owned by this value with zeros.
    ///
    /// `Data` is copy-on-write, so copies made earlier are not affected. Use this as a best-effort
    /// clean-up for buffers that had to pass through Foundation APIs, and prefer `SecureBytes`.
    public mutating func secureWipe() {
        guard !isEmpty else { return }
        withUnsafeMutableBytes { buffer in
            if let base = buffer.baseAddress {
                SecureMemory.zero(base, count: buffer.count)
            }
        }
    }
}

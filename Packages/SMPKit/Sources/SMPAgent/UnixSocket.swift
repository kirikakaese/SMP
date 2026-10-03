import Darwin
import Foundation
import SMPCore
import SMPSSH

/// Blocking Unix domain socket helpers for the agent protocol.
enum UnixSocket {
    static func address(for path: String) throws -> sockaddr_un {
        let bytes = Array(path.utf8)
        guard bytes.count <= AgentPaths.maxSocketPathLength else {
            throw SMPError.invalidArgument("The socket path is too long for macOS (\(bytes.count) bytes).")
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: bytes)
        }
        return address
    }

    static func makeSocket() throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw posixError("create a socket") }
        var one: Int32 = 1
        // Writing to a closed peer must fail with EPIPE instead of killing the process.
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        return fd
    }

    /// Connects to the socket at `path`. The caller closes the descriptor.
    static func connect(to path: String, timeoutSeconds: Int) throws -> Int32 {
        var address = try address(for: path)
        let fd = try makeSocket()
        var timeout = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let error = posixError("connect to the agent")
            close(fd)
            throw error
        }
        return fd
    }

    static func readFully(_ fd: Int32, count: Int) -> Data? {
        var buffer = [UInt8](repeating: 0, count: count)
        var received = 0
        while received < count {
            let result = buffer.withUnsafeMutableBytes { raw in
                Darwin.read(fd, raw.baseAddress?.advanced(by: received), count - received)
            }
            if result < 0, errno == EINTR { continue }
            guard result > 0 else { return nil }
            received += result
        }
        return Data(buffer)
    }

    static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let result = Darwin.write(fd, raw.baseAddress?.advanced(by: sent), raw.count - sent)
                if result < 0, errno == EINTR { continue }
                guard result > 0 else { return false }
                sent += result
            }
            return true
        }
    }

    /// Reads one length-prefixed agent message and returns its payload, or `nil` at end of stream
    /// or for an oversized or empty message.
    static func readMessage(_ fd: Int32) -> Data? {
        guard let header = readFully(fd, count: 4) else { return nil }
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length <= SSHAgentCodec.maxMessageLength else { return nil }
        return readFully(fd, count: length)
    }

    static func writeMessage(_ fd: Int32, _ payload: Data) -> Bool {
        writeAll(fd, SSHAgentCodec.frame(payload))
    }

    static func posixError(_ action: String) -> SMPError {
        let reason = String(cString: strerror(errno))
        return SMPError(.fileSystem, whatHappened: "SMP's agent could not \(action).", details: reason)
    }
}

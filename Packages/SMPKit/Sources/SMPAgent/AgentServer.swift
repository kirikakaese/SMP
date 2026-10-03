import Darwin
import Foundation
import SMPCore
import SMPSSH

/// Serves the SSH agent protocol on a Unix domain socket (mode 0600, in a 0700 folder).
/// Each connection is handled on its own thread with blocking I/O.
public final class AgentServer: @unchecked Sendable {
    // Safety: `listener` is only accessed while holding `lock`.
    public let socketURL: URL
    private let handler: AgentRequestHandler
    private let lock = NSLock()
    private var listener: Int32 = -1

    public init(socketURL: URL, handler: AgentRequestHandler) {
        self.socketURL = socketURL
        self.handler = handler
    }

    public var isRunning: Bool { lock.withLock { listener >= 0 } }

    /// Binds the socket and starts accepting connections.
    /// - Throws: if another agent already listens on the socket, or the socket cannot be created.
    public func start() throws {
        guard !isRunning else { return }
        let path = socketURL.path
        try removeStaleSocket(at: path)
        var address = try UnixSocket.address(for: path)
        let fd = try UnixSocket.makeSocket()
        // Create the socket with no permissions for others from the first moment.
        let previousMask = umask(0o177)
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(previousMask)
        guard bound == 0, chmod(path, 0o600) == 0, listen(fd, 16) == 0 else {
            let error = UnixSocket.posixError("listen on its socket")
            close(fd)
            throw error
        }
        lock.withLock { listener = fd }
        let thread = Thread { [weak self] in self?.acceptLoop(fd) }
        thread.name = "SMP agent listener"
        thread.start()
    }

    /// Stops accepting connections and removes the socket.
    public func stop() {
        let fd = lock.withLock { () -> Int32 in
            defer { listener = -1 }
            return listener
        }
        guard fd >= 0 else { return }
        // Closing the listener makes the blocked accept() return.
        shutdown(fd, SHUT_RDWR)
        close(fd)
        unlink(socketURL.path)
    }

    private func acceptLoop(_ fd: Int32) {
        while true {
            let client = accept(fd, nil, nil)
            if client < 0 {
                if errno == EINTR || errno == ECONNABORTED { continue }
                return
            }
            let thread = Thread { [handler] in
                Self.serve(client, handler: handler)
            }
            thread.name = "SMP agent connection"
            thread.start()
        }
    }

    private static func serve(_ fd: Int32, handler: AgentRequestHandler) {
        defer { close(fd) }
        let peer = PeerProcess.of(socket: fd)
        while let request = UnixSocket.readMessage(fd) {
            let response = handler.handle(request, from: peer)
            guard UnixSocket.writeMessage(fd, response) else { return }
        }
    }

    /// Removes a socket file left behind by a crashed agent. Refuses to touch anything that is not
    /// a socket, or a socket another agent still answers on.
    private func removeStaleSocket(at path: String) throws {
        var info = stat()
        guard lstat(path, &info) == 0 else { return }
        guard info.st_mode & S_IFMT == S_IFSOCK else {
            throw SMPError(
                .fileSystem,
                whatHappened: String(localized: "SMP's agent could not start because a file is in the way."),
                howToFix: String(localized: "Remove \(path) and try again.")
            )
        }
        if let fd = try? UnixSocket.connect(to: path, timeoutSeconds: 1) {
            close(fd)
            throw SMPError(
                .alreadyExists,
                whatHappened: String(localized: "Another copy of SMP's agent is already running."),
                howToFix: String(localized: "Quit the other copy, or keep using it.")
            )
        }
        unlink(path)
    }
}

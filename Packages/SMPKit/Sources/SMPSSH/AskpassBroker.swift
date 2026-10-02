import Foundation
import SMPCore

#if canImport(Darwin)
import Darwin
#endif

/// Hands passphrases to OpenSSH tools without putting them in argv, the environment or a file.
///
/// OpenSSH reads passphrases from the controlling TTY, or from the program named by `SSH_ASKPASS`
/// when `SSH_ASKPASS_REQUIRE=force` is set. The broker creates a private directory (mode 0700)
/// containing a named pipe and a two-line askpass script that reads one line from the pipe.
/// Each time the tool runs the script, the broker writes the next queued response into the pipe.
///
/// Important: when OpenSSH asks more often than there are responses, the extra prompt fails and
/// OpenSSH treats it as an *empty* passphrase. Callers that set a passphrase must therefore
/// supply the exact number of responses the tool asks for and verify the result afterwards
/// (for example by checking that the new private key really is encrypted).
final class AskpassBroker: @unchecked Sendable {
    // Safety: mutable state (`isStopped`, `servedCount`) is guarded by `lock`; the worker thread
    // only reads `responses`, which are immutable `SecureBytes` references.
    private let directory: URL
    private let fifoPath: String
    private let scriptPath: String
    private let responses: [SecureBytes]
    private let lock = NSLock()
    private var isStopped = false
    private var servedCount = 0
    private let finished = DispatchSemaphore(value: 0)
    private var didStart = false

    init(responses: [SecureBytes], temporaryDirectory: URL) throws {
        self.responses = responses

        var template = Array(
            temporaryDirectory.appending(path: "smp-askpass.XXXXXX", directoryHint: .notDirectory).path.utf8CString
        )
        // mkdtemp creates the directory with mode 0700 and writes the final name into `template`.
        let createdPath = template.withUnsafeMutableBufferPointer { buffer -> String? in
            guard let base = buffer.baseAddress, let result = mkdtemp(base) else { return nil }
            return String(cString: result)
        }
        guard let directoryPath = createdPath else {
            throw SMPError(
                .fileSystem,
                whatHappened: "SMP could not create a private temporary folder.",
                howToFix: "Check that your disk is not full, then try again."
            )
        }
        directory = URL(fileURLWithPath: directoryPath, isDirectory: true)
        fifoPath = directoryPath + "/pipe"
        scriptPath = directoryPath + "/askpass"

        do {
            guard mkfifo(fifoPath, 0o600) == 0 else {
                throw SMPError(.fileSystem, whatHappened: "SMP could not create a private pipe for the passphrase.")
            }
            let script = "#!/bin/sh\nexec /bin/cat \(Self.shellQuoted(fifoPath))\n"
            guard FileManager.default.createFile(
                atPath: scriptPath,
                contents: Data(script.utf8),
                attributes: [.posixPermissions: 0o700]
            ) else {
                throw SMPError(.fileSystem, whatHappened: "SMP could not create the passphrase helper.")
            }
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    deinit {
        stop()
    }

    /// Environment variables that make OpenSSH use the broker instead of a TTY.
    var environment: [String: String] {
        ["SSH_ASKPASS": scriptPath, "SSH_ASKPASS_REQUIRE": "force"]
    }

    /// Number of responses the tool has read so far.
    var responsesServed: Int {
        lock.withLock { servedCount }
    }

    /// Starts serving responses on a background thread.
    func start() {
        lock.withLock { didStart = true }
        let thread = Thread { [self] in
            serveAll()
            finished.signal()
        }
        thread.name = "SMP askpass broker"
        thread.start()
    }

    /// Stops serving, waits for the worker to finish and removes the private directory.
    func stop() {
        let wasStarted = lock.withLock { () -> Bool in
            let started = didStart && !isStopped
            isStopped = true
            return started
        }
        if wasStarted {
            finished.wait()
        }
        try? FileManager.default.removeItem(at: directory)
    }

    private var shouldStop: Bool {
        lock.withLock { isStopped }
    }

    private func serveAll() {
        for (index, response) in responses.enumerated() {
            guard serve(response, isLast: index == responses.count - 1) else { return }
            lock.withLock { servedCount += 1 }
        }
    }

    /// Waits for a reader on the FIFO and writes `response` followed by a newline.
    ///
    /// For the last response the pipe is unlinked as soon as the reader is connected, so any
    /// further prompt fails immediately instead of blocking until the timeout.
    private func serve(_ response: SecureBytes, isLast: Bool) -> Bool {
        while !shouldStop {
            // O_NONBLOCK makes open() fail with ENXIO while nobody has the pipe open for reading.
            let descriptor = open(fifoPath, O_WRONLY | O_NONBLOCK | O_CLOEXEC)
            if descriptor < 0 {
                if errno == ENXIO || errno == EINTR {
                    usleep(10_000)
                    continue
                }
                return false
            }
            defer { close(descriptor) }
            if isLast {
                unlink(fifoPath)
            }
            let flags = fcntl(descriptor, F_GETFL)
            _ = fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK)
            #if os(macOS)
            _ = fcntl(descriptor, F_SETNOSIGPIPE, 1)
            #endif
            let wroteSecret = response.withUnsafeBytes { FileDescriptorIO.writeAll(descriptor, $0) }
            let newline: [UInt8] = [0x0A]
            let wroteNewline = newline.withUnsafeBytes { FileDescriptorIO.writeAll(descriptor, $0) }
            return wroteSecret && wroteNewline
        }
        return false
    }

    static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

enum FileDescriptorIO {
    /// Writes the whole buffer, retrying on `EINTR`. Returns `false` on any other error.
    static func writeAll(_ descriptor: Int32, _ buffer: UnsafeRawBufferPointer) -> Bool {
        guard let base = buffer.baseAddress else { return true }
        var offset = 0
        while offset < buffer.count {
            let written = write(descriptor, base + offset, buffer.count - offset)
            if written < 0 {
                if errno == EINTR { continue }
                return false
            }
            offset += written
        }
        return true
    }
}

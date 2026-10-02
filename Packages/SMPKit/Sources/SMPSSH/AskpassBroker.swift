import Foundation
import SMPCore

#if canImport(Darwin)
import Darwin
#endif

/// Hands passphrases to OpenSSH tools without putting them in argv, the environment or a file.
///
/// OpenSSH reads passphrases from the controlling TTY, or from the program named by `SSH_ASKPASS`
/// when `SSH_ASKPASS_REQUIRE=force` is set. The broker creates a private directory (mode 0700)
/// containing one named pipe per queued response (`a.00`, `a.01`, …) and a small askpass script.
/// Each run of the script atomically claims the next unclaimed pipe by renaming it (`a.NN` →
/// `t.NN`) and reads from it; the broker writes response `NN` into `t.NN` once a reader is
/// attached. Because every pipe is used exactly once, a response can never reach the wrong
/// prompt, even if an earlier reader is still draining its pipe.
///
/// Important: when OpenSSH asks more often than there are responses, the extra prompt fails and
/// OpenSSH treats it as an *empty* passphrase. Callers that set a passphrase must therefore
/// supply the exact number of responses the tool asks for and verify the result afterwards
/// (for example by checking that the new private key really is encrypted).
final class AskpassBroker: @unchecked Sendable {
    // Safety: mutable state (`isStopped`, `servedCount`, `didStart`) is guarded by `lock`; the
    // worker thread only reads `responses`, which are immutable `SecureBytes` references.
    private let directory: URL
    private let directoryPath: String
    private let scriptPath: String
    private let responses: [SecureBytes]
    private let lock = NSLock()
    private var isStopped = false
    private var servedCount = 0
    private let finished = DispatchSemaphore(value: 0)
    private var didStart = false

    init(responses: [SecureBytes], temporaryDirectory: URL) throws {
        guard responses.count <= 100 else {
            throw SMPError.invalidArgument("Too many passphrase responses were queued.")
        }
        self.responses = responses

        var template = Array(
            temporaryDirectory.appending(path: "smp-askpass.XXXXXX", directoryHint: .notDirectory).path.utf8CString
        )
        // mkdtemp creates the directory with mode 0700 and writes the final name into `template`.
        let createdPath = template.withUnsafeMutableBufferPointer { buffer -> String? in
            guard let base = buffer.baseAddress, let result = mkdtemp(base) else { return nil }
            return String(cString: result)
        }
        guard let createdPath else {
            throw SMPError(
                .fileSystem,
                whatHappened: "SMP could not create a private temporary folder.",
                howToFix: "Check that your disk is not full, then try again."
            )
        }
        directoryPath = createdPath
        directory = URL(fileURLWithPath: createdPath, isDirectory: true)
        scriptPath = createdPath + "/askpass"

        do {
            for index in responses.indices {
                guard mkfifo(Self.pipePath(in: createdPath, prefix: "a", index: index), 0o600) == 0 else {
                    throw SMPError(.fileSystem, whatHappened: "SMP could not create a private pipe for the passphrase.")
                }
            }
            guard FileManager.default.createFile(
                atPath: scriptPath,
                contents: Data(Self.script(directoryPath: createdPath).utf8),
                attributes: [.posixPermissions: 0o700]
            ) else {
                throw SMPError(.fileSystem, whatHappened: "SMP could not create the passphrase helper.")
            }
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    /// The askpass program: claim the lowest unclaimed pipe atomically, then read it.
    /// Exits with status 1 (a failed prompt) when no pipe is left.
    static func script(directoryPath: String) -> String {
        """
        #!/bin/sh
        cd \(shellQuoted(directoryPath)) || exit 1
        for f in a.*; do
          n="${f#a.}"
          if /bin/mv "$f" "t.$n" 2>/dev/null; then
            exec /bin/cat "t.$n"
          fi
        done
        exit 1

        """
    }

    static func pipePath(in directoryPath: String, prefix: String, index: Int) -> String {
        directoryPath + "/" + prefix + "." + (index < 10 ? "0" : "") + String(index)
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
            guard serve(response, at: Self.pipePath(in: directoryPath, prefix: "t", index: index)) else { return }
            lock.withLock { servedCount += 1 }
        }
    }

    /// Waits until a script run has claimed the pipe at `path` and opened it, then writes
    /// `response` followed by a newline and closes the pipe (the reader sees EOF).
    private func serve(_ response: SecureBytes, at path: String) -> Bool {
        while !shouldStop {
            // ENOENT: not claimed yet. ENXIO: claimed, but the reader has not opened it yet.
            let descriptor = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC)
            if descriptor < 0 {
                if errno == ENOENT || errno == ENXIO || errno == EINTR {
                    usleep(10_000)
                    continue
                }
                return false
            }
            defer { close(descriptor) }
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

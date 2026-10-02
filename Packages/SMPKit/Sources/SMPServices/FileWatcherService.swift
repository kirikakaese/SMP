import CoreServices
import Foundation

public protocol FileWatching: Sendable {
    /// Emits a value (coalesced) whenever something changes inside `directories`.
    /// The stream ends when the consuming task is cancelled.
    func changes(in directories: [URL]) -> AsyncStream<Void>
}

/// Watches folders with FSEvents.
public struct FileWatcherService: FileWatching {
    /// Delay FSEvents uses to coalesce bursts of changes.
    public var latency: TimeInterval

    public init(latency: TimeInterval = 0.3) {
        self.latency = latency
    }

    public func changes(in directories: [URL]) -> AsyncStream<Void> {
        let paths = directories.map(\.path)
        let latency = latency
        return AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            let watcher = FSEventsWatcher(paths: paths, latency: latency) {
                continuation.yield(())
            }
            continuation.onTermination = { _ in
                watcher.stop()
            }
            if !watcher.start() {
                continuation.finish()
            }
        }
    }
}

/// Owns one FSEvents stream. All stream calls happen on `queue`.
private final class FSEventsWatcher: @unchecked Sendable {
    // Safety: `stream` is only read and written on `queue`.
    private let paths: [String]
    private let latency: TimeInterval
    private let handler: @Sendable () -> Void
    private let queue = DispatchQueue(label: "com.kirikakaese.smp.fsevents")
    private var stream: FSEventStreamRef?

    init(paths: [String], latency: TimeInterval, handler: @escaping @Sendable () -> Void) {
        self.paths = paths
        self.latency = latency
        self.handler = handler
    }

    func start() -> Bool {
        queue.sync {
            guard stream == nil, !paths.isEmpty else { return false }
            var context = FSEventStreamContext(
                version: 0,
                info: Unmanaged.passUnretained(self).toOpaque(),
                retain: nil,
                release: nil,
                copyDescription: nil
            )
            let callback: FSEventStreamCallback = { _, info, _, _, _, _ in
                guard let info else { return }
                Unmanaged<FSEventsWatcher>.fromOpaque(info).takeUnretainedValue().handler()
            }
            let flags = FSEventStreamCreateFlags(
                kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer | kFSEventStreamCreateFlagWatchRoot
            )
            guard let created = FSEventStreamCreate(
                kCFAllocatorDefault,
                callback,
                &context,
                paths as CFArray,
                FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
                latency,
                flags
            ) else {
                return false
            }
            FSEventStreamSetDispatchQueue(created, queue)
            guard FSEventStreamStart(created) else {
                FSEventStreamInvalidate(created)
                FSEventStreamRelease(created)
                return false
            }
            stream = created
            return true
        }
    }

    func stop() {
        queue.async { [self] in
            guard let stream else { return }
            FSEventStreamStop(stream)
            FSEventStreamInvalidate(stream)
            FSEventStreamRelease(stream)
            self.stream = nil
        }
    }
}

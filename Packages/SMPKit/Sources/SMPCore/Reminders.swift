import Foundation

/// Expiry and rotation dates the app shares with SMP Agent, which shows the reminders even when the
/// app is closed. Contains key names, fingerprints and dates only.
public struct ReminderSchedule: Sendable, Hashable, Codable {
    public struct Entry: Sendable, Hashable, Codable {
        public enum Kind: String, Sendable, Hashable, Codable {
            case expiry, rotation
        }

        public let fingerprint: String
        public let keyName: String
        public let kind: Kind
        public let date: Date

        public init(fingerprint: String, keyName: String, kind: Kind, date: Date) {
            self.fingerprint = fingerprint
            self.keyName = keyName
            self.kind = kind
            self.date = date
        }
    }

    public var entries: [Entry]

    public init(entries: [Entry]) {
        self.entries = entries
    }

    /// `~/Library/Application Support/com.kirikakaese.smp/reminders.json`.
    public static func fileURL() throws -> URL {
        try AppPaths.applicationSupportDirectory().appending(path: "reminders.json")
    }

    public static func load(from url: URL) -> ReminderSchedule {
        guard let data = try? Data(contentsOf: url),
              let schedule = try? JSONDecoder().decode(ReminderSchedule.self, from: data)
        else { return ReminderSchedule(entries: []) }
        return schedule
    }

    /// Writes atomically with mode 0600. Unchanged schedules are not rewritten.
    public func save(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        if (try? Data(contentsOf: url)) == data { return }
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// A notification to show.
    public struct Reminder: Sendable, Hashable, Identifiable {
        /// Stable per entry and threshold, so each reminder is shown once.
        public let id: String
        public let title: String
        public let body: String
    }

    /// Reminders 14 days and 1 day before, and on the date. Already shown IDs are skipped.
    public func dueReminders(now: Date = Date(), alreadyShown: Set<String>) -> [Reminder] {
        let day: TimeInterval = 24 * 3600
        let thresholds: [(id: String, before: TimeInterval)] = [("14d", 14 * day), ("1d", day), ("0d", 0)]
        var result: [Reminder] = []
        for entry in entries {
            let remaining = entry.date.timeIntervalSince(now)
            // The closest threshold that has been reached; older ones are not repeated.
            guard let threshold = thresholds.last(where: { remaining <= $0.before }) else { continue }
            let stamp = Int(entry.date.timeIntervalSince1970)
            let id = "\(entry.fingerprint)|\(entry.kind.rawValue)|\(stamp)|\(threshold.id)"
            guard !alreadyShown.contains(id) else { continue }
            let title = Self.title(for: entry, remaining: remaining)
            result.append(Reminder(id: id, title: title, body: Self.body(for: entry)))
        }
        return result
    }

    static func title(for entry: Entry, remaining: TimeInterval) -> String {
        let days = Int((remaining / (24 * 3600)).rounded(.up))
        switch (entry.kind, remaining <= 0) {
        case (.expiry, true): return "“\(entry.keyName)” has expired"
        case (.expiry, false): return "“\(entry.keyName)” expires in \(days == 1 ? "1 day" : "\(days) days")"
        case (.rotation, true): return "Time to rotate “\(entry.keyName)”"
        case (.rotation, false): return "Rotate “\(entry.keyName)” in \(days == 1 ? "1 day" : "\(days) days")"
        }
    }

    static func body(for entry: Entry) -> String {
        "Open SMP and choose Rotate Key… to replace it everywhere it is used."
    }
}

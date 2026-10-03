import Foundation
import Testing

@testable import SMPCore

@Suite("ReminderSchedule")
struct RemindersTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let day: TimeInterval = 86_400

    private func entry(
        _ name: String,
        _ kind: ReminderSchedule.Entry.Kind,
        inDays days: Double
    ) -> ReminderSchedule.Entry {
        let date = now.addingTimeInterval(days * day)
        return ReminderSchedule.Entry(fingerprint: "SHA256:\(name)", keyName: name, kind: kind, date: date)
    }

    @Test func remindsAtFourteenDaysOneDayAndOnTheDate() {
        let schedule = ReminderSchedule(entries: [
            entry("far", .expiry, inDays: 30),
            entry("soon", .expiry, inDays: 10),
            entry("tomorrow", .rotation, inDays: 0.5),
            entry("past", .expiry, inDays: -2),
        ])
        let due = schedule.dueReminders(now: now, alreadyShown: [])
        #expect(due.map(\.title) == [
            "“soon” expires in 10 days",
            "Rotate “tomorrow” in 1 day",
            "“past” has expired",
        ])
        #expect(due[0].id.hasSuffix("|14d"))
        #expect(due[1].id.hasSuffix("|1d"))
        #expect(due[2].id.hasSuffix("|0d"))

        // Shown reminders are not repeated; a later threshold is a new reminder.
        let shown = Set(due.map(\.id))
        #expect(schedule.dueReminders(now: now, alreadyShown: shown).isEmpty)
        let later = schedule.dueReminders(now: now.addingTimeInterval(9.5 * day), alreadyShown: shown)
        #expect(later.map(\.title) == ["“soon” expires in 1 day", "Time to rotate “tomorrow”"])
    }

    @Test func savesAndLoadsWithPrivatePermissions() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "smp-reminders-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let schedule = ReminderSchedule(entries: [entry("key", .expiry, inDays: 3)])
        try schedule.save(to: url)
        #expect(ReminderSchedule.load(from: url) == schedule)
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)
        #expect(ReminderSchedule.load(from: url.appending(path: "missing")).entries.isEmpty)
    }
}

import AppKit
import Foundation
import Observation
import SMPCore
import SMPServices

/// The app lock's settings, stored in `UserDefaults`.
public struct AppLockSettings: Sendable, Hashable {
    /// Ask for Touch ID or the login password when SMP opens and after it was idle. On by default.
    public var isEnabled: Bool
    /// Minutes without input before SMP locks; 0 locks only at launch, on screen lock and on sleep.
    public var idleMinutes: Int

    public static let idleChoices = [1, 5, 15, 60, 0]

    public init(isEnabled: Bool = true, idleMinutes: Int = 5) {
        self.isEnabled = isEnabled
        self.idleMinutes = idleMinutes
    }

    private enum Key {
        static let enabled = "appLock.enabled"
        static let idleMinutes = "appLock.idleMinutes"
    }

    public static func load(from defaults: UserDefaults) -> AppLockSettings {
        AppLockSettings(
            isEnabled: defaults.object(forKey: Key.enabled) as? Bool ?? true,
            idleMinutes: max(0, defaults.object(forKey: Key.idleMinutes) as? Int ?? 5)
        )
    }

    public func save(to defaults: UserDefaults) {
        defaults.set(isEnabled, forKey: Key.enabled)
        defaults.set(idleMinutes, forKey: Key.idleMinutes)
    }
}

/// Covers the main window until the user proves presence with Touch ID or the login password:
/// at launch, after `idleMinutes` without input, when the screen locks and when the Mac sleeps.
/// Individual actions (deleting, exporting, …) keep their own prompts either way.
@MainActor
@Observable
public final class AppLockModel {
    public private(set) var isLocked: Bool
    public private(set) var isUnlocking = false
    /// Shown on the lock screen, e.g. after a cancelled prompt.
    public private(set) var message: String?
    /// `false` on a Mac without a login password: the lock cannot work there and stays off.
    public let isAvailable: Bool
    public var settings: AppLockSettings {
        didSet {
            settings.save(to: defaults)
            if !settings.isEnabled { isLocked = false }
        }
    }

    @ObservationIgnored private let authenticator: any DeviceAuthenticating
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private var lastActivity: Date
    @ObservationIgnored private var observers: [Any] = []
    @ObservationIgnored private var idleTimer: Timer?

    public init(
        authenticator: any DeviceAuthenticating,
        defaults: UserDefaults = .standard,
        isAvailable: Bool = true,
        startsLocked: Bool = true,
        now: @escaping () -> Date = Date.init
    ) {
        self.authenticator = authenticator
        self.defaults = defaults
        self.isAvailable = isAvailable
        self.now = now
        self.lastActivity = now()
        let settings = AppLockSettings.load(from: defaults)
        self.settings = settings
        self.isLocked = isAvailable && settings.isEnabled && startsLocked
    }

    private var isActive: Bool { isAvailable && settings.isEnabled }

    public func lock() {
        guard isActive else { return }
        isLocked = true
        message = nil
    }

    public func unlock() async {
        guard isLocked, !isUnlocking else { return }
        isUnlocking = true
        defer { isUnlocking = false }
        do {
            try await authenticator.authenticate(reason: "unlock SMP")
            isLocked = false
            message = nil
            lastActivity = now()
        } catch {
            message = "SMP stays locked until you confirm with Touch ID or your password."
        }
    }

    /// Call on user input; postpones the idle lock.
    public func noteActivity() {
        lastActivity = now()
    }

    /// Locks if SMP has been idle for longer than the setting allows.
    public func checkIdle() {
        guard isActive, !isLocked, settings.idleMinutes > 0 else { return }
        if now().timeIntervalSince(lastActivity) >= TimeInterval(settings.idleMinutes * 60) {
            lock()
        }
    }

    /// Watches input, screen lock and sleep. Call once, from the app.
    public func startMonitoring() {
        guard observers.isEmpty else { return }
        let input: NSEvent.EventTypeMask = [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel]
        if let monitor = NSEvent.addLocalMonitorForEvents(matching: input, handler: { [weak self] event in
            MainActor.assumeIsolated { self?.noteActivity() }
            return event
        }) {
            observers.append(monitor)
        }
        let lockNow: @Sendable (Notification) -> Void = { [weak self] _ in
            MainActor.assumeIsolated { self?.lock() }
        }
        observers.append(DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main, using: lockNow
        ))
        observers.append(NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main, using: lockNow
        ))
        idleTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.checkIdle() }
        }
    }
}

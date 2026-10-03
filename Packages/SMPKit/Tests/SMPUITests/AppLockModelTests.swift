import Foundation
import SMPCore
import SMPServices
import Testing

@testable import SMPUI

/// A clock the test moves forward by hand.
@MainActor
private final class TestClock {
    var current = Date(timeIntervalSince1970: 1_800_000_000)

    func advance(minutes: Double) {
        current = current.addingTimeInterval(minutes * 60)
    }
}

@MainActor
@Suite("App lock")
struct AppLockModelTests {
    private func defaults() -> UserDefaults {
        UserDefaults(suiteName: "smp-lock-\(UUID().uuidString)") ?? .standard
    }

    @Test func isOnByDefaultAndUnlocksAfterAuthentication() async {
        let store = defaults()
        let lock = AppLockModel(authenticator: FakeAuthenticator(succeeds: true), defaults: store)
        #expect(lock.settings == AppLockSettings(isEnabled: true, idleMinutes: 5))
        #expect(lock.isLocked)
        await lock.unlock()
        #expect(!lock.isLocked)
    }

    @Test func staysLockedWhenAuthenticationFails() async {
        let lock = AppLockModel(authenticator: FakeAuthenticator(succeeds: false), defaults: defaults())
        await lock.unlock()
        #expect(lock.isLocked)
        #expect(lock.message != nil)
    }

    @Test func locksAfterTheIdleTimeOnly() async {
        let clock = TestClock()
        let lock = AppLockModel(
            authenticator: FakeAuthenticator(), defaults: defaults(), startsLocked: false, now: { clock.current }
        )
        clock.advance(minutes: 4)
        lock.checkIdle()
        #expect(!lock.isLocked)
        lock.noteActivity()
        clock.advance(minutes: 4.9)
        lock.checkIdle()
        #expect(!lock.isLocked)
        clock.advance(minutes: 0.2)
        lock.checkIdle()
        #expect(lock.isLocked)

        await lock.unlock()
        lock.settings.idleMinutes = 0
        clock.advance(minutes: 600)
        lock.checkIdle()
        #expect(!lock.isLocked)
    }

    @Test func neverLocksWhenDisabledOrUnavailable() {
        let store = defaults()
        AppLockSettings(isEnabled: false, idleMinutes: 1).save(to: store)
        let disabled = AppLockModel(authenticator: FakeAuthenticator(), defaults: store)
        #expect(!disabled.isLocked)
        disabled.lock()
        #expect(!disabled.isLocked)

        let unavailable = AppLockModel(authenticator: FakeAuthenticator(), defaults: defaults(), isAvailable: false)
        #expect(!unavailable.isLocked)
        unavailable.lock()
        #expect(!unavailable.isLocked)
    }

    @Test func savesSettingsAndUnlocksWhenTurnedOff() {
        let store = defaults()
        let lock = AppLockModel(authenticator: FakeAuthenticator(), defaults: store)
        lock.settings.idleMinutes = 15
        #expect(AppLockSettings.load(from: store).idleMinutes == 15)
        #expect(lock.isLocked)
        lock.settings.isEnabled = false
        #expect(!lock.isLocked)
        #expect(!AppLockSettings.load(from: store).isEnabled)
    }

    @Test func remembersTheIntroduction() {
        let store = defaults()
        #expect(!OnboardingState.isCompleted(in: store))
        OnboardingState.setCompleted(true, in: store)
        #expect(OnboardingState.isCompleted(in: store))
    }
}

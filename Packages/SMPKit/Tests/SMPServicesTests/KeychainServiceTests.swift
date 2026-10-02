import Foundation
import SMPCore
import SMPServices
import Testing

/// Shared behaviour every `KeychainServicing` implementation must satisfy.
private func exerciseRoundTrip(_ keychain: any KeychainServicing) throws {
    let item = KeychainItem(service: "com.kirikakaese.smp.tests", account: "roundtrip-\(UUID().uuidString)")
    defer { try? keychain.deleteSecret(for: item) }

    #expect(try keychain.secret(for: item) == nil)
    #expect(try !keychain.containsSecret(for: item))

    try keychain.setSecret(SecureBytes(utf8: "first"), for: item)
    #expect(try keychain.containsSecret(for: item))
    let first = try #require(try keychain.secret(for: item))
    #expect(first.constantTimeEquals(SecureBytes(utf8: "first")))

    // Saving again replaces the value instead of failing with a duplicate-item error.
    try keychain.setSecret(SecureBytes(utf8: "second"), for: item)
    let second = try #require(try keychain.secret(for: item))
    #expect(second.constantTimeEquals(SecureBytes(utf8: "second")))

    try keychain.deleteSecret(for: item)
    #expect(try keychain.secret(for: item) == nil)
    // Deleting a missing item is not an error.
    try keychain.deleteSecret(for: item)
}

@Suite("KeychainService")
struct KeychainServiceTests {
    @Test func inMemoryRoundTrip() throws {
        try exerciseRoundTrip(InMemoryKeychainService())
    }

    @Test func inMemoryStoresIndependentCopies() throws {
        let keychain = InMemoryKeychainService()
        let item = KeychainItem(service: "s", account: "a")
        let original = SecureBytes(utf8: "value")
        try keychain.setSecret(original, for: item)
        original.wipe()
        let stored = try #require(try keychain.secret(for: item))
        #expect(stored.constantTimeEquals(SecureBytes(utf8: "value")))
    }

    @Test func providerTokenItemsUseDedicatedService() {
        let item = KeychainItem.providerToken(accountID: "github:alice")
        #expect(item.service == KeychainItem.Service.providerToken)
        #expect(item.account == "github:alice")
        #expect(item.accessibility == .whenUnlockedThisDeviceOnly)
    }

    /// Touches the real login keychain, so it only runs when explicitly requested
    /// (`SMP_RUN_KEYCHAIN_TESTS=1 swift test`).
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SMP_RUN_KEYCHAIN_TESTS"] == "1"))
    func systemKeychainRoundTrip() throws {
        try exerciseRoundTrip(KeychainService())
    }
}

@Suite("ServiceContainer")
struct ServiceContainerTests {
    @Test func previewServicesNeverUseTheRealHomeDirectory() {
        let services = ServiceContainer.preview()
        #expect(services.environment.homeDirectory != FileManager.default.homeDirectoryForCurrentUser)
        #expect(services.keychain is InMemoryKeychainService)
    }
}

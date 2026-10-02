import Foundation
import SMPCore
import Testing

@Suite("SecureBytes")
struct SecureBytesTests {
    @Test func storesCopiedBytes() {
        let secret = SecureBytes([1, 2, 3])
        #expect(secret.count == 3)
        secret.withUnsafeBytes { #expect(Array($0) == [1, 2, 3]) }
    }

    @Test func utf8InitializerEncodesString() {
        let secret = SecureBytes(utf8: "pässword")
        secret.withUnsafeBytes { #expect(Array($0) == Array("pässword".utf8)) }
    }

    @Test func wipeZeroesButKeepsSize() {
        let secret = SecureBytes(utf8: "hunter2")
        secret.wipe()
        #expect(secret.count == 7)
        secret.withUnsafeBytes { #expect($0.allSatisfy { $0 == 0 }) }
    }

    @Test func emptyBufferIsSupported() {
        let secret = SecureBytes(count: 0)
        #expect(secret.isEmpty)
        secret.wipe()
    }

    @Test func constantTimeEquality() {
        #expect(SecureBytes(utf8: "abc").constantTimeEquals(SecureBytes(utf8: "abc")))
        #expect(!SecureBytes(utf8: "abc").constantTimeEquals(SecureBytes(utf8: "abd")))
        #expect(!SecureBytes(utf8: "abc").constantTimeEquals(SecureBytes(utf8: "abcd")))
    }

    @Test func descriptionNeverRevealsContents() {
        let secret = SecureBytes(utf8: "top-secret")
        #expect(!secret.description.contains("top-secret"))
        #expect(!String(describing: secret).contains("top-secret"))
        #expect(!String(reflecting: secret).contains("top-secret"))
    }

    @Test func consumingInitializerClearsSource() {
        var data = Data("token".utf8)
        let secret = SecureBytes(consuming: &data)
        #expect(data.isEmpty)
        secret.withUnsafeBytes { #expect(Array($0) == Array("token".utf8)) }
    }

    @Test func dataSecureWipeZeroesBytes() {
        var data = Data("secret".utf8)
        data.secureWipe()
        #expect(data.count == 6)
        #expect(data.allSatisfy { $0 == 0 })
    }
}

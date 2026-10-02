import Foundation
import SMPCore
import SMPTestFixtures
import Testing

@testable import SMPSSH

@Suite("PuTTYKeyConverter")
struct PuTTYConverterTests {
    private func convert(_ text: String) throws -> PrivateKeyInfo {
        let converted = try PuTTYKeyConverter.convert(SecureBytes(utf8: text))
        return try #require(PrivateKeyInspector.inspect(contents: converted))
    }

    @Test(arguments: [Fixtures.ed25519PuTTYv2, Fixtures.ed25519PuTTYv3])
    func convertsEd25519(text: String) throws {
        let info = try convert(text)
        #expect(info.format == .openSSH)
        #expect(info.isEncrypted == false)
        let expected = try SSHPublicKey(line: Fixtures.ed25519Public)
        #expect(info.embeddedPublicKey?.fingerprintSHA256 == expected.fingerprintSHA256)
    }

    @Test func convertsRSA() throws {
        let info = try convert(Fixtures.rsa2048PuTTYv2)
        let expected = try SSHPublicKey(line: Fixtures.rsa2048Public)
        #expect(info.embeddedPublicKey?.fingerprintSHA256 == expected.fingerprintSHA256)
    }

    @Test func rejectsTamperedFiles() {
        let tampered = Fixtures.ed25519PuTTYv2.replacingOccurrences(of: "Comment: putty-v2", with: "Comment: evil")
        #expect(throws: SMPError.self) { try PuTTYKeyConverter.convert(SecureBytes(utf8: tampered)) }
        // The older placeholder fixture has a dummy MAC.
        #expect(throws: SMPError.self) { try PuTTYKeyConverter.convert(SecureBytes(utf8: Fixtures.ed25519PuTTY)) }
    }

    @Test func rejectsEncryptedFiles() {
        let encrypted = Fixtures.ed25519PuTTYv3
            .replacingOccurrences(of: "Encryption: none", with: "Encryption: aes256-cbc")
        do {
            _ = try PuTTYKeyConverter.convert(SecureBytes(utf8: encrypted))
            Issue.record("Expected an error for an encrypted PuTTY file")
        } catch {
            #expect((error as? SMPError)?.whatHappened.contains("Passphrase-protected") == true)
        }
    }

    @Test func armorWrapsBase64() {
        let armored = SecureBase64.armor(SecureBytes(Array(repeating: 0xAB, count: 100)), label: "TEST")
        let text = armored.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
        let lines = text.split(separator: "\n")
        #expect(lines.first == "-----BEGIN TEST-----")
        #expect(lines.last == "-----END TEST-----")
        #expect(lines.dropFirst().dropLast().allSatisfy { $0.count <= 68 })
        let body = lines.dropFirst().dropLast().joined()
        #expect(Data(base64Encoded: body) == Data(repeating: 0xAB, count: 100))
    }
}

import Foundation
import SMPCore
import SMPTestFixtures
import Testing

@testable import SMPSSH

@Suite("PrivateKeyInspector")
struct PrivateKeyInspectorTests {
    private func inspect(_ text: String) -> PrivateKeyInfo? {
        PrivateKeyInspector.inspect(contents: SecureBytes(utf8: text))
    }

    @Test func unencryptedOpenSSHKeyExposesItsPublicKey() throws {
        let info = try #require(inspect(Fixtures.ed25519Private))
        #expect(info.format == .openSSH)
        #expect(info.isEncrypted == false)
        #expect(info.cipherName == "none")
        #expect(info.kdfRounds == nil)
        let publicKey = try SSHPublicKey(line: Fixtures.ed25519Public)
        #expect(info.embeddedPublicKey?.fingerprintSHA256 == publicKey.fingerprintSHA256)
    }

    @Test func encryptedOpenSSHKeyIsDetectedWithoutPassphrase() throws {
        let info = try #require(inspect(Fixtures.ed25519EncryptedPrivate))
        #expect(info.format == .openSSH)
        #expect(info.isEncrypted == true)
        #expect(info.cipherName == "aes256-ctr")
        #expect(info.kdfRounds == 16)
        let publicKey = try SSHPublicKey(line: Fixtures.ed25519EncryptedPublic)
        #expect(info.embeddedPublicKey?.fingerprintSHA256 == publicKey.fingerprintSHA256)
    }

    @Test func toleratesCRLFLineEndings() throws {
        let crlf = Fixtures.ed25519Private.replacingOccurrences(of: "\n", with: "\r\n")
        let info = try #require(inspect(crlf))
        #expect(info.embeddedPublicKey != nil)
    }

    @Test func legacyPEMFormats() throws {
        let plain = try #require(inspect(Fixtures.rsa2048PEMPrivate))
        #expect(plain.format == .pem)
        #expect(plain.isEncrypted == false)
        #expect(plain.format.isLegacy)

        let encrypted = try #require(inspect(Fixtures.rsa2048PEMEncryptedPrivate))
        #expect(encrypted.format == .pem)
        #expect(encrypted.isEncrypted == true)
    }

    @Test func pkcs8Formats() throws {
        #expect(inspect(Fixtures.rsa2048PKCS8Private)?.isEncrypted == false)
        #expect(inspect(Fixtures.rsa2048PKCS8EncryptedPrivate)?.isEncrypted == true)
        #expect(inspect(Fixtures.rsa2048PKCS8Private)?.format == .pkcs8)
    }

    @Test func puttyKeyExposesPublicKeyAndComment() throws {
        let info = try #require(inspect(Fixtures.ed25519PuTTY))
        #expect(info.format == .putty)
        #expect(info.isEncrypted == false)
        #expect(info.comment == "putty-key")
        let publicKey = try SSHPublicKey(line: Fixtures.ed25519Public)
        #expect(info.embeddedPublicKey?.fingerprintSHA256 == publicKey.fingerprintSHA256)
    }

    @Test func rejectsNonKeys() {
        #expect(inspect("Host example\n  HostName example.com\n") == nil)
        #expect(inspect(Fixtures.ed25519Public) == nil)
        #expect(inspect("") == nil)
        #expect(inspect("-----BEGIN OPENSSH PRIVATE KEY-----\n!!!!\n-----END OPENSSH PRIVATE KEY-----\n") == nil)
    }

    @Test func sniffsPrivateKeyHeaders() {
        #expect(PrivateKeyInspector.looksLikePrivateKey(prefix: Array(Fixtures.ed25519Private.utf8)))
        #expect(PrivateKeyInspector.looksLikePrivateKey(prefix: Array(Fixtures.ed25519PuTTY.utf8)))
        #expect(!PrivateKeyInspector.looksLikePrivateKey(prefix: Array(Fixtures.ed25519Public.utf8)))
    }

    @Test func secureBase64MatchesFoundation() throws {
        let sample = Data((0..<200).map { UInt8($0) })
        let encoded = sample.base64EncodedString(options: .lineLength64Characters)
        let decoded = try #require(SecureBytes(utf8: encoded).withUnsafeBytes { bytes in
            SecureBase64.decode(bytes, ranges: LineScanner(bytes).allRanges)
        })
        decoded.withUnsafeBytes { #expect(Data($0) == sample) }
    }
}

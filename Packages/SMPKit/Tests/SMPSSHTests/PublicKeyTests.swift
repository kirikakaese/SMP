import Foundation
import SMPCore
import SMPTestFixtures
import Testing

@testable import SMPSSH

@Suite("SSHPublicKey")
struct PublicKeyTests {
    struct Case: Sendable {
        let fixture: String
        let line: String
        let algorithm: KeyAlgorithm
        let bits: Int
    }

    static let cases: [Case] = [
        Case(fixture: "ed25519Public", line: Fixtures.ed25519Public, algorithm: .ed25519, bits: 256),
        Case(fixture: "ecdsaP256Public", line: Fixtures.ecdsaP256Public, algorithm: .ecdsaP256, bits: 256),
        Case(fixture: "ecdsaP384Public", line: Fixtures.ecdsaP384Public, algorithm: .ecdsaP384, bits: 384),
        Case(fixture: "ecdsaP521Public", line: Fixtures.ecdsaP521Public, algorithm: .ecdsaP521, bits: 521),
        Case(fixture: "rsa3072Public", line: Fixtures.rsa3072Public, algorithm: .rsa, bits: 3072),
        Case(fixture: "rsa2048Public", line: Fixtures.rsa2048Public, algorithm: .rsa, bits: 2048),
        Case(fixture: "dsaPublic", line: Fixtures.dsaPublic, algorithm: .dsa, bits: Fixtures.dsaBits),
        Case(fixture: "ed25519SKPublic", line: Fixtures.ed25519SKPublic, algorithm: .ed25519SK, bits: 256),
    ]

    @Test(arguments: PublicKeyTests.cases.map(\.fixture))
    func parsesAlgorithmBitsAndFingerprints(fixture: String) throws {
        let entry = try #require(Self.cases.first { $0.fixture == fixture })
        let key = try SSHPublicKey(line: entry.line)
        #expect(key.algorithm == entry.algorithm)
        #expect(key.bitLength == entry.bits)
        #expect(!key.isCertificate)
        let expected = try #require(Fixtures.expectedFingerprints[fixture])
        #expect(key.fingerprintSHA256 == expected.sha256)
        #expect(key.fingerprintMD5 == expected.md5)
    }

    @Test func keepsCommentWithSpaces() throws {
        let line = Fixtures.ed25519Public + " and more words"
        let key = try SSHPublicKey(line: line)
        #expect(key.comment == "alice@example.com and more words")
        #expect(key.openSSHLine == line)
    }

    @Test func acceptsLinesWithoutComment() throws {
        let parts = Fixtures.ed25519Public.split(separator: " ")
        let key = try SSHPublicKey(line: "\(parts[0]) \(parts[1])\n")
        #expect(key.comment.isEmpty)
        #expect(key.openSSHLine == "\(parts[0]) \(parts[1])")
    }

    @Test func detectsCertificates() throws {
        let certificate = try SSHPublicKey(line: Fixtures.ed25519Certificate)
        #expect(certificate.isCertificate)
        #expect(certificate.algorithm == .ed25519)
        #expect(certificate.bitLength == nil)
    }

    @Test func rejectsMalformedInput() {
        #expect(throws: PublicKeyParseError.empty) { try SSHPublicKey(line: "  \n") }
        #expect(throws: PublicKeyParseError.missingKeyData) { try SSHPublicKey(line: "ssh-ed25519") }
        #expect(throws: PublicKeyParseError.invalidBase64) { try SSHPublicKey(line: "ssh-ed25519 not*base64") }
        #expect(throws: PublicKeyParseError.malformedBlob) { try SSHPublicKey(line: "ssh-ed25519 AAAA") }
    }

    @Test func rejectsTypeMismatch() {
        let parts = Fixtures.ed25519Public.split(separator: " ")
        #expect(throws: PublicKeyParseError.typeMismatch) { try SSHPublicKey(line: "ssh-rsa \(parts[1])") }
    }

    @Test func rejectsTruncatedBlob() {
        let parts = Fixtures.ed25519Public.split(separator: " ")
        var blob = Data(base64Encoded: String(parts[1])) ?? Data()
        blob.removeLast(5)
        #expect(throws: PublicKeyParseError.malformedBlob) {
            try SSHPublicKey(line: "ssh-ed25519 \(blob.base64EncodedString())")
        }
    }

    @Test func certificateWireNamesMapToPlainAlgorithms() {
        #expect(KeyAlgorithm(wireName: "ssh-rsa-cert-v01@openssh.com") == .rsa)
        #expect(KeyAlgorithm(wireName: "sk-ssh-ed25519-cert-v01@openssh.com") == .ed25519SK)
        #expect(KeyAlgorithm(wireName: "ecdsa-sha2-nistp384-cert-v01@openssh.com") == .ecdsaP384)
        #expect(KeyAlgorithm(wireName: "ssh-unknown") == .unknown)
    }
}

@Suite("Randomart")
struct RandomartTests {
    @Test func hasOpenSSHShape() throws {
        let key = try SSHPublicKey(line: Fixtures.ed25519Public)
        let lines = Randomart.render(key).split(separator: "\n").map(String.init)
        #expect(lines.count == 11)
        #expect(lines.allSatisfy { $0.count == 19 })
        #expect(lines.first == "+--[ED25519 256]--+")
        #expect(lines.last == "+----[SHA256]-----+")
        let body = lines[1...9].joined()
        #expect(body.contains("S"))
        #expect(body.contains("E"))
    }

    @Test func usesRSABitsInTitle() throws {
        let key = try SSHPublicKey(line: Fixtures.rsa3072Public)
        #expect(Randomart.render(key).hasPrefix("+---[RSA 3072]----+"))
    }

    @Test func fallsBackToTypeWhenTitleIsTooLong() {
        let art = Randomart.render(
            digest: Array(repeating: 0, count: 32),
            title: "[ED25519-SK-CERT 256]",
            fallbackTitle: "[ED25519-SK-CERT]",
            hashName: "SHA256"
        )
        // Like OpenSSH, the 17-byte title buffer cuts the closing bracket.
        #expect(art.hasPrefix("+[ED25519-SK-CERT-+"))
    }
}

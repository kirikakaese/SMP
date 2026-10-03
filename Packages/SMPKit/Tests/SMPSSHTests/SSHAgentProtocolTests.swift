import Foundation
import SMPTestFixtures
import Testing

@testable import SMPSSH

@Suite("SSHAgentCodec")
struct SSHAgentProtocolTests {
    @Test func framesWithABigEndianLength() {
        #expect(SSHAgentCodec.frame(Data([11])) == Data([0, 0, 0, 1, 11]))
        #expect(SSHAgentCodec.type(of: Data([12, 0])) == .identitiesAnswer)
        #expect(SSHAgentCodec.type(of: Data()) == nil)
        #expect(SSHAgentCodec.type(of: Data([200])) == nil)
    }

    @Test func roundTripsIdentities() throws {
        let key = try SSHPublicKey(line: Fixtures.ed25519Public)
        let identities = [
            SSHAgentIdentity(keyBlob: key.blob, comment: "alice@example.com"),
            SSHAgentIdentity(keyBlob: Data([1, 2, 3]), comment: ""),
        ]
        let payload = SSHAgentCodec.identitiesAnswer(identities)
        #expect(payload.first == SSHAgentMessageType.identitiesAnswer.rawValue)
        #expect(try SSHAgentCodec.parseIdentitiesAnswer(payload) == identities)
        #expect(try SSHAgentCodec.parseIdentitiesAnswer(SSHAgentCodec.identitiesAnswer([])).isEmpty)
    }

    @Test func roundTripsSignRequestsAndResponses() throws {
        let request = SSHAgentSignRequest(keyBlob: Data([9, 9]), data: Data("session".utf8), flags: 4)
        #expect(try SSHAgentCodec.parseSignRequest(SSHAgentCodec.signRequest(request)) == request)
        let signature = Data([1, 2, 3, 4])
        #expect(try SSHAgentCodec.parseSignResponse(SSHAgentCodec.signResponse(signature: signature)) == signature)
    }

    @Test func rejectsMalformedMessages() {
        #expect(throws: (any Error).self) { try SSHAgentCodec.parseSignRequest(Data([13, 0, 0])) }
        #expect(throws: (any Error).self) { try SSHAgentCodec.parseIdentitiesAnswer(Data([5])) }
        // A huge identity count with no data must not allocate or loop.
        #expect(throws: (any Error).self) {
            try SSHAgentCodec.parseIdentitiesAnswer(Data([12, 0xFF, 0xFF, 0xFF, 0xFF]))
        }
    }

    @Test func buildsECDSAPublicKeyBlobsOpenSSHUnderstands() throws {
        // The P-256 point from Fixtures.ecdsaP256Public, re-encoded from its blob.
        let fixture = try SSHPublicKey(line: Fixtures.ecdsaP256Public)
        let point = fixture.blob.suffix(65)
        let blob = SSHAgentCodec.ecdsaP256PublicKeyBlob(x963: Data(point))
        #expect(blob == fixture.blob)
        let line = "ecdsa-sha2-nistp256 " + blob.base64EncodedString()
        #expect(try SSHPublicKey(line: line).fingerprintSHA256 == fixture.fingerprintSHA256)
    }

    @Test func encodesSignaturesAsMinimalMPInts() throws {
        // r has a leading zero byte, s has its high bit set (needs a 0x00 prefix).
        var raw = Data([0x00]) + Data(repeating: 0x11, count: 31)
        raw += Data([0x80]) + Data(repeating: 0x22, count: 31)
        let blob = try SSHAgentCodec.ecdsaP256SignatureBlob(raw: raw)
        var expected = Data([0, 0, 0, 19]) + Data("ecdsa-sha2-nistp256".utf8)
        var inner = Data([0, 0, 0, 31]) + Data(repeating: 0x11, count: 31)
        inner += Data([0, 0, 0, 33, 0x00, 0x80]) + Data(repeating: 0x22, count: 31)
        expected += Data([0, 0, 0, UInt8(inner.count)]) + inner
        #expect(blob == expected)
        #expect(throws: (any Error).self) { try SSHAgentCodec.ecdsaP256SignatureBlob(raw: Data(count: 63)) }
    }

    @Test func secretBearingRequestsAreFlagged() {
        #expect(SSHAgentMessageType.addIdentity.carriesSecrets)
        #expect(SSHAgentMessageType.addIdentityConstrained.carriesSecrets)
        #expect(SSHAgentMessageType.lock.carriesSecrets)
        #expect(!SSHAgentMessageType.removeIdentity.carriesSecrets)
        #expect(!SSHAgentMessageType.extension.carriesSecrets)
    }
}

import Foundation
import SMPTestFixtures
import Testing

@testable import SMPSSH

/// The key part of a fixture line, without its comment.
private func keyPart(_ line: String) -> String {
    line.split(separator: " ").prefix(2).joined(separator: " ")
}

@Suite("KnownHostsDocument")
struct KnownHostsDocumentTests {
    // Hashed entries generated independently (Python hmac/sha1) with salt bytes 1...20.
    static let hashedExample = "|1|AQIDBAUGBwgJCgsMDQ4PEBESExQ=|qvtG0DaqrsqPDhV2Ni+wmYohchA="
    static let hashedExamplePort = "|1|AQIDBAUGBwgJCgsMDQ4PEBESExQ=|uVLj+YL3GsbtNOcCoC7AMM/WVh0="

    static var sample: String {
        """
        # managed by hand
        example.com,192.0.2.1 \(keyPart(Fixtures.ed25519Public))
        [git.example.com]:2222 \(keyPart(Fixtures.rsa2048Public)) old server
        \(hashedExample) \(keyPart(Fixtures.ecdsaP256Public))
        @cert-authority *.corp,!secret.corp \(keyPart(Fixtures.ed25519Public))
        garbage

        """
    }

    @Test func parsesEntriesAndSkipsCommentsAndGarbage() throws {
        let entries = KnownHostsDocument(text: Self.sample).entries()
        #expect(entries.map(\.lineIndex) == [1, 2, 3, 4])
        #expect(entries[0].hostPatterns == ["example.com", "192.0.2.1"])
        #expect(entries[0].publicKey?.wireType == "ssh-ed25519")
        #expect(entries[1].comment == "old server")
        #expect(entries[2].isHashed)
        #expect(entries[2].hostPatterns.isEmpty)
        #expect(entries[3].marker == .certAuthority)
        #expect(entries[3].hostPatterns == ["*.corp", "!secret.corp"])
    }

    @Test func matchesHostsLikeOpenSSH() {
        let document = KnownHostsDocument(text: Self.sample)
        #expect(document.entries(matching: "EXAMPLE.com").map(\.lineIndex) == [1, 3])
        #expect(document.entries(matching: "192.0.2.1").map(\.lineIndex) == [1])
        #expect(document.entries(matching: "git.example.com", port: 2222).map(\.lineIndex) == [2])
        #expect(document.entries(matching: "git.example.com").isEmpty)
        #expect(document.entries(matching: "build.corp").map(\.lineIndex) == [4])
        #expect(document.entries(matching: "secret.corp").isEmpty)
    }

    @Test func hashesHostNamesLikeHashKnownHosts() {
        let salt = Data((1...20).map { UInt8($0) })
        #expect(KnownHostsDocument.hash("example.com", salt: salt) == Self.hashedExample)
        #expect(KnownHostsDocument.hash("[example.com]:2222", salt: salt) == Self.hashedExamplePort)
        #expect(KnownHostsDocument.hashedMatch(field: Self.hashedExamplePort, candidate: "[example.com]:2222"))
        #expect(!KnownHostsDocument.hashedMatch(field: Self.hashedExample, candidate: "example.org"))
        #expect(!KnownHostsDocument.hashedMatch(field: "|1|not base64|x", candidate: "example.com"))
    }

    @Test func hostKeysUseBracketsForNonDefaultPorts() {
        #expect(KnownHostsDocument.hostKey(host: "Example.COM", port: 22) == "example.com")
        #expect(KnownHostsDocument.hostKey(host: "example.com", port: 2222) == "[example.com]:2222")
    }

    @Test func globSupportsStarAndQuestionMark() {
        #expect(KnownHostsDocument.glob("*.example.com", matches: "a.b.example.com"))
        #expect(KnownHostsDocument.glob("web-??", matches: "web-01"))
        #expect(!KnownHostsDocument.glob("web-??", matches: "web-1"))
        #expect(KnownHostsDocument.glob("*", matches: ""))
        #expect(!KnownHostsDocument.glob("*.example.com", matches: "example.com"))
    }

    @Test func removesAndAppendsWithoutTouchingOtherLines() throws {
        var document = KnownHostsDocument(text: Self.sample)
        document.removeLines([2, 3])
        let key = try SSHPublicKey(line: Fixtures.ecdsaP384Public)
        document.append(host: "new.example.com", port: 2200, key: key, hashed: false)
        document.append(host: "hidden.example.com", port: 22, key: key, hashed: true)

        let lines = document.render().components(separatedBy: "\n")
        #expect(lines[0] == "# managed by hand")
        #expect(lines[3] == "garbage")
        #expect(lines[4] == "[new.example.com]:2200 \(keyPart(Fixtures.ecdsaP384Public))")
        #expect(lines[5].hasPrefix("|1|"))
        #expect(!lines[5].contains("hidden"))
        #expect(document.entries(matching: "hidden.example.com").count == 1)
        #expect(document.render().hasSuffix("\n"))
    }

    @Test func roundTripsUnchangedFiles() {
        for text in [Self.sample, "", "example.com \(keyPart(Fixtures.ed25519Public))"] {
            #expect(KnownHostsDocument(text: text).render() == text)
        }
    }
}

@Suite("AuthorizedKeysEntry")
struct AuthorizedKeysEntryTests {
    @Test func parsesKeysWithAndWithoutOptions() throws {
        let options = #"from="10.0.0.0/8,192.168.0.1",command="echo \"hi there\"",no-pty"#
        let text = """
            # keys
            \(Fixtures.ed25519Public)
            \(options) \(Fixtures.rsa2048Public)

            garbage line
            """
        let entries = AuthorizedKeysEntry.parse(text)
        #expect(entries.count == 2)
        #expect(entries[0].lineIndex == 1)
        #expect(entries[0].options == nil)
        #expect(entries[0].publicKey.comment == "alice@example.com")
        #expect(entries[1].lineIndex == 2)
        #expect(entries[1].options == options)
        #expect(entries[1].publicKey.wireType == "ssh-rsa")
        #expect(entries[1].line == "\(options) \(Fixtures.rsa2048Public)")
    }
}

@Suite("ShellQuoting")
struct ShellQuotingTests {
    @Test func quotesForPOSIXShells() {
        #expect(ShellQuoting.quote("it's") == #"'it'\''s'"#)
        #expect(ShellQuoting.quoteIfNeeded("web-prod") == "web-prod")
        #expect(ShellQuoting.quoteIfNeeded("deploy@10.0.0.1") == "deploy@10.0.0.1")
        #expect(ShellQuoting.quoteIfNeeded("my host") == "'my host'")
        #expect(ShellQuoting.quoteIfNeeded("") == "''")
        #expect(ShellQuoting.quoteIfNeeded("$(rm -rf ~)") == "'$(rm -rf ~)'")
    }

    @Test func shellReceivesTheExactString() throws {
        let tricky = #"a 'b' "c" $HOME `id` \n; | & *"#
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "printf '%s' " + ShellQuoting.quote(tricky)]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        #expect(String(decoding: output, as: UTF8.self) == tricky)
    }

    @Test func escapesAppleScriptStrings() {
        #expect(ShellQuoting.appleScriptString(#"a"b\c"#) == #""a\"b\\c""#)
    }
}

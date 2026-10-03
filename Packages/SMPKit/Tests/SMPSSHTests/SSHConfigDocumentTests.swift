import Foundation
import Testing

@testable import SMPSSH

@Suite("SSHConfigDocument")
struct SSHConfigDocumentTests {
    static let sample = """
        # Global defaults
        Include ~/.ssh/config.d/*

        Host *
            AddKeysToAgent yes
            UseKeychain yes

        Host github.com gh
          HostName github.com
          User git
          IdentityFile ~/.ssh/id_ed25519
          IdentitiesOnly=yes

        Match host *.internal exec "test -f /tmp/vpn"
        \tIdentityFile = "~/.ssh/work key"
        UnknownFutureOption whatever
        """

    static let roundTripInputs = [
        sample,
        sample + "\n",
        sample.replacingOccurrences(of: "\n", with: "\r\n") + "\r\n",
        "",
        "\n\n",
    ]

    @Test(arguments: SSHConfigDocumentTests.roundTripInputs)
    func rendersInputUnchanged(text: String) {
        #expect(SSHConfigDocument(text: text).render() == text)
    }

    @Test func parsesDirectivesWithTheirBlocks() throws {
        let document = SSHConfigDocument(text: Self.sample)
        let identities = document.directives(named: "identityfile")
        #expect(identities.count == 2)
        #expect(identities[0].arguments == ["~/.ssh/id_ed25519"])
        #expect(identities[0].blockPatterns == ["github.com", "gh"])
        #expect(!identities[0].isInMatchBlock)
        #expect(identities[1].arguments == ["~/.ssh/work key"])
        #expect(identities[1].rawValue == "\"~/.ssh/work key\"")
        #expect(identities[1].isInMatchBlock)
        #expect(document.directives(named: "IdentitiesOnly").first?.arguments == ["yes"])
        #expect(document.directives(named: "include").first?.blockPatterns == ["*"])
        #expect(document.directives(named: "UnknownFutureOption").count == 1)
    }

    @Test func replacesOnlyTheValue() throws {
        var document = SSHConfigDocument(text: Self.sample)
        let line = try #require(document.directives(named: "IdentityFile").first).lineIndex
        document.replaceValue(atLine: line, with: "~/.ssh/renamed")
        #expect(document.lines[line] == "  IdentityFile ~/.ssh/renamed")

        let equalsLine = try #require(document.directives(named: "IdentityFile").last).lineIndex
        document.replaceValue(atLine: equalsLine, with: "\"~/.ssh/other key\"")
        #expect(document.lines[equalsLine] == "\tIdentityFile = \"~/.ssh/other key\"")
    }

    @Test func commentsOutAndRemovesLines() throws {
        var document = SSHConfigDocument(text: Self.sample)
        let line = try #require(document.directives(named: "IdentityFile").first).lineIndex
        document.commentOutLine(line)
        #expect(document.lines[line] == "  # IdentityFile ~/.ssh/id_ed25519")
        #expect(document.directives(named: "IdentityFile").count == 1)
        let count = document.lines.count
        document.removeLine(line)
        #expect(document.lines.count == count - 1)
    }

    @Test func appendsHostBlocks() {
        var document = SSHConfigDocument(text: "Host a\n  User x\n")
        document.appendHostBlock(
            patterns: ["new host"],
            options: [("HostName", "example.com"), ("IdentitiesOnly", "yes")]
        )
        let expected = "Host a\n  User x\n\nHost \"new host\"\n    HostName example.com\n    IdentitiesOnly yes\n"
        #expect(document.render() == expected)

        var empty = SSHConfigDocument(text: "")
        empty.appendHostBlock(patterns: ["b"], options: [])
        #expect(empty.render() == "Host b\n")
    }

    @Test func splitsQuotedArguments() {
        #expect(SSHConfigDocument.splitArguments(#"a "b c"  d"#) == ["a", "b c", "d"])
        #expect(SSHConfigDocument.splitArguments(#""""#) == [""])
    }
}

import Foundation
import Testing

@testable import SMPSSH

@Suite("SSHConfigDocument host blocks")
struct SSHConfigHostsTests {
    static let sample = """
        # global
        Host web
            HostName 10.0.0.1
            IdentityFile ~/.ssh/a
            IdentityFile ~/.ssh/b

        Host db
          User root

        """

    @Test func findsBlocksWithTheirOptions() throws {
        let document = SSHConfigDocument(text: Self.sample + "Host *.corp !secret.corp\n    User me\nMatch host x\n")
        let blocks = document.blocks()
        #expect(blocks.map(\.alias) == ["web", "db", "*.corp", "host"])
        #expect(blocks.map(\.headerLine) == [1, 6, 8, 10])
        #expect(blocks[0].endLine == 6)
        #expect(blocks[0].value(of: "hostname") == "10.0.0.1")
        #expect(blocks[0].values(of: "IdentityFile") == ["~/.ssh/a", "~/.ssh/b"])
        #expect(blocks[1].value(of: "User") == "root")
        #expect(!blocks[0].isWildcard)
        #expect(blocks[2].isWildcard)
        #expect(blocks[3].isMatch && blocks[3].isWildcard)
        #expect(document.block(at: 6)?.alias == "db")
        #expect(document.block(at: 2) == nil)
    }

    @Test func setValuesReplacesRemovesAndInserts() throws {
        var document = SSHConfigDocument(text: Self.sample)
        document.setValues(["~/.ssh/c"], for: "IdentityFile", inBlockAt: 1)
        document.setValues(["admin"], for: "User", inBlockAt: 1)
        document.setValues([], for: "HostName", inBlockAt: 1)
        let db = try #require(document.blocks().first { $0.alias == "db" })
        document.setValues(["2222"], for: "Port", inBlockAt: db.headerLine)
        #expect(document.render() == """
            # global
            Host web
                IdentityFile ~/.ssh/c
                User admin

            Host db
              User root
              Port 2222

            """)
    }

    @Test func setValuesWithUnchangedValuesKeepsTheFileIdentical() {
        var document = SSHConfigDocument(text: Self.sample)
        document.setValues(["~/.ssh/a", "~/.ssh/b"], for: "identityfile", inBlockAt: 1)
        #expect(document.render() == Self.sample)
    }

    @Test func addsValuesToAnEmptyBlock() {
        var document = SSHConfigDocument(text: "Host empty\n")
        document.setValues(["example.com"], for: "HostName", inBlockAt: 0)
        #expect(document.render() == "Host empty\n    HostName example.com\n")
    }

    @Test func removesBlocksWithoutLeavingDoubleGaps() {
        var first = SSHConfigDocument(text: Self.sample)
        first.removeBlock(at: 1)
        #expect(first.render() == "# global\nHost db\n  User root\n")

        var last = SSHConfigDocument(text: Self.sample)
        last.removeBlock(at: 6)
        #expect(last.render() == """
            # global
            Host web
                HostName 10.0.0.1
                IdentityFile ~/.ssh/a
                IdentityFile ~/.ssh/b

            """)
    }

    @Test func duplicatesAndRenamesBlocks() throws {
        var document = SSHConfigDocument(text: Self.sample)
        let copy = document.duplicateBlock(at: 1, as: ["web-staging"])
        let header = try #require(copy)
        #expect(document.block(at: header)?.alias == "web-staging")
        #expect(document.block(at: header)?.values(of: "IdentityFile") == ["~/.ssh/a", "~/.ssh/b"])
        #expect(document.render().hasSuffix("""
              User root

            Host web-staging
                HostName 10.0.0.1
                IdentityFile ~/.ssh/a
                IdentityFile ~/.ssh/b

            """))

        document.setPatterns(["api", "api.example.com"], forBlockAt: 1)
        #expect(document.lines[1] == "Host api api.example.com")
        #expect(document.blocks().map(\.alias) == ["api", "db", "web-staging"])
    }

    @Test func knownKeywordsCoverTheCommonFields() {
        for keyword in SSHConfigKeywords.common {
            #expect(SSHConfigKeywords.known.contains(keyword.lowercased()), "\(keyword)")
        }
        #expect(!SSHConfigKeywords.known.contains("hostnmae"))
    }
}

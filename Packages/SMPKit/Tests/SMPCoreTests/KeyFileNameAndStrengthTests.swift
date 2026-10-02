import Foundation
import SMPCore
import Testing

@Suite("KeyFileName")
struct KeyFileNameTests {
    @Test(arguments: ["id_ed25519", "work-laptop", "deploy@prod", "key.2026", "a+b"])
    func acceptsValidNames(name: String) {
        #expect(KeyFileName.problem(with: name) == nil)
    }

    @Test(arguments: ["", ".hidden", "key.pub", "config", "known_hosts", "a/b", "with space", "ümlaut", "x\0y"])
    func rejectsInvalidNames(name: String) {
        #expect(KeyFileName.problem(with: name) != nil)
    }

    @Test func suggestsFreeNames() {
        #expect(KeyFileName.suggestion(base: "id_ed25519", existing: []) == "id_ed25519")
        let existing: Set = ["id_ed25519", "id_ed25519_2.pub"]
        #expect(KeyFileName.suggestion(base: "id_ed25519", existing: existing) == "id_ed25519_3")
    }

    @Test func defaultCommentLooksLikeUserAtHost() {
        let comment = KeyFileName.defaultComment()
        #expect(comment.contains("@"))
        #expect(!comment.hasSuffix(".local"))
    }
}

@Suite("PassphraseStrength")
struct PassphraseStrengthTests {
    @Test func ordersPassphrasesSensibly() {
        let empty = PassphraseStrength.evaluate("")
        let weak = PassphraseStrength.evaluate("password1")
        let repeated = PassphraseStrength.evaluate("aaaaaaaaaaaaaaaaaaaa")
        let strong = PassphraseStrength.evaluate("correct horse battery staple ladder")
        #expect(empty.level == .empty)
        #expect(weak.level <= .weak)
        #expect(repeated.level <= .weak)
        #expect(strong.level >= .strong)
        #expect(strong.suggestion == nil)
        #expect(weak.suggestion != nil)
    }
}

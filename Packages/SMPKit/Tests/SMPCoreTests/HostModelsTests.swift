import Foundation
import Testing

@testable import SMPCore

@Suite("TextDiff")
struct TextDiffTests {
    @Test func reportsChangedLinesInOrder() {
        let diff = TextDiff.lines(from: "a\nb\nc", to: "a\nx\nc\nd")
        #expect(diff == [.same("a"), .removed("b"), .added("x"), .same("c"), .added("d")])
        #expect(TextDiff.hasChanges(diff))
    }

    @Test func identicalTextHasNoChanges() {
        let diff = TextDiff.lines(from: "Host a\n    User b\n", to: "Host a\n    User b\n")
        #expect(!TextDiff.hasChanges(diff))
        #expect(diff.count == 3)
    }

    @Test func handlesEmptyInput() {
        #expect(TextDiff.lines(from: "", to: "new") == [.removed(""), .added("new")])
    }
}

@Suite("Host models")
struct HostModelsTests {
    @Test func forwardsProduceSSHArguments() {
        #expect(TunnelForward(bindPort: 8080, targetPort: 80).arguments == ["-L", "127.0.0.1:8080:localhost:80"])
        let remote = TunnelForward(
            kind: .remote, bindAddress: "0.0.0.0", bindPort: 9000, targetHost: "db", targetPort: 5432
        )
        #expect(remote.arguments == ["-R", "0.0.0.0:9000:db:5432"])
        #expect(TunnelForward(kind: .dynamic, bindPort: 1080).arguments == ["-D", "127.0.0.1:1080"])
    }

    @Test func rejectsInvalidForwards() {
        #expect(TunnelForward(bindPort: 0, targetPort: 80).problem != nil)
        #expect(TunnelForward(bindPort: 8080, targetPort: 70_000).problem != nil)
        #expect(TunnelForward(bindPort: 8080, targetHost: "-oProxyCommand=x", targetPort: 80).problem != nil)
        #expect(TunnelForward(bindPort: 8080, targetHost: "a b", targetPort: 80).problem != nil)
        #expect(TunnelForward(bindAddress: "", bindPort: 8080, targetPort: 80).problem != nil)
        #expect(TunnelForward(kind: .dynamic, bindPort: 1080).problem == nil)
        #expect(TunnelForward(bindPort: 8080, targetHost: "[::1]", targetPort: 80).problem == nil)
    }

    @Test func validatesHostAliases() {
        #expect(HostAlias.problem(with: "web-prod") == nil)
        #expect(HostAlias.problem(with: "deploy@10.0.0.1") == nil)
        #expect(HostAlias.problem(with: "") != nil)
        #expect(HostAlias.problem(with: "-oProxyCommand=evil") != nil)
        #expect(HostAlias.problem(with: "two words") != nil)
        #expect(HostAlias.problem(with: "quote\"d") != nil)
        #expect(HostAlias.problem(with: String(repeating: "a", count: 256)) != nil)
    }

    @Test func tunnelProfilesRoundTripThroughJSON() throws {
        let forward = TunnelForward(bindPort: 5432, targetPort: 5432)
        let tunnel = TunnelProfile(name: "DB", hostAlias: "bastion", forwards: [forward])
        let decoded = try JSONDecoder().decode(TunnelProfile.self, from: JSONEncoder().encode(tunnel))
        #expect(decoded == tunnel)
    }
}

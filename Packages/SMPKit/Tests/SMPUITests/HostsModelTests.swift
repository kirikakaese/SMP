import Foundation
import SMPCore
import SMPPersistence
import SMPServices
import SMPSSH
import Testing

@testable import SMPUI

@MainActor
@Suite("HostsModel")
struct HostsModelTests {
    let home: URL
    let services: ServiceContainer

    init() throws {
        home = FileManager.default.temporaryDirectory.appending(path: "smp-hosts-\(UUID().uuidString)")
        let ssh = home.appending(path: ".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ssh.path)
        services = ServiceContainer.make(
            environment: SSHEnvironment(homeDirectory: home, userName: "test", agentSocketPath: "/nonexistent.sock"),
            supportDirectory: home.appending(path: "support"),
            keychain: InMemoryKeychainService(),
            metadata: try GRDBMetadataStore.inMemory(),
            authenticator: FakeAuthenticator()
        )
    }

    private var configURL: URL { home.appending(path: ".ssh/config") }

    private func writeConfig(_ text: String) throws {
        try Data(text.utf8).write(to: configURL)
    }

    private func readConfig() throws -> String {
        try String(contentsOf: configURL, encoding: .utf8)
    }

    @Test func addsTheFirstHostToAMissingConfig() async throws {
        defer { try? FileManager.default.removeItem(at: home) }
        let model = HostsModel(services: services)
        model.reload()
        #expect(model.hosts.isEmpty)

        model.proposeNewHost(alias: "web", options: [("HostName", "10.0.0.1"), ("User", "")])
        let change = try #require(model.pendingChange)
        #expect(change.diff.contains(.added("Host web")))
        #expect(await model.applyPendingChange())
        #expect(try readConfig() == "Host web\n    HostName 10.0.0.1\n")
        #expect(model.hosts.map(\.alias) == ["web"])
        #expect(model.pendingChange == nil)
    }

    @Test func editsGoThroughTheReviewedChange() async throws {
        defer { try? FileManager.default.removeItem(at: home) }
        try writeConfig("Host web\n    HostName 10.0.0.1\n\nHost *\n    ServerAliveInterval 30\n")
        let model = HostsModel(services: services)
        model.reload()
        let web = try #require(model.hosts.first { $0.alias == "web" })
        #expect(model.connectableAliases == ["web"])

        model.proposeEdits([("User", ["deploy"]), ("HostName", ["web.example.com"])], on: web)
        #expect(try readConfig().contains("10.0.0.1"))  // Nothing is written before review.
        #expect(await model.applyPendingChange())
        #expect(try readConfig() == "Host web\n    HostName web.example.com\n    User deploy\n\nHost *\n"
            + "    ServerAliveInterval 30\n")
    }

    @Test func renameAndDeleteCarryHostMetadata() async throws {
        defer { try? FileManager.default.removeItem(at: home) }
        try writeConfig("Host web\n    HostName 10.0.0.1\n")
        let model = HostsModel(services: services)
        model.reload()
        let web = try #require(model.hosts.first)
        model.setFavorite(true, for: web)
        model.setNotes("frontend", for: web)

        model.proposeRename(web, to: "frontend")
        #expect(await model.applyPendingChange())
        #expect(model.metadata["web"] == nil)
        #expect(model.metadata["frontend"]?.notes == "frontend")
        #expect(model.visibleHosts.first?.alias == "frontend")

        let renamed = try #require(model.hosts.first)
        model.proposeDelete(renamed)
        #expect(await model.applyPendingChange())
        #expect(model.hosts.isEmpty)
        #expect(model.metadata.isEmpty)
    }

    @Test func refusesToOverwriteAConfigChangedElsewhere() async throws {
        defer { try? FileManager.default.removeItem(at: home) }
        try writeConfig("Host web\n")
        let model = HostsModel(services: services)
        model.reload()
        let web = try #require(model.hosts.first)
        model.proposeSet("User", to: ["deploy"], on: web)
        try writeConfig("Host web\n    User someone-else\n")

        #expect(await model.applyPendingChange() == false)
        #expect(model.lastError?.code == .fileChangedOnDisk)
        #expect(try readConfig() == "Host web\n    User someone-else\n")
    }

    @Test func rejectsInvalidAliases() {
        defer { try? FileManager.default.removeItem(at: home) }
        let model = HostsModel(services: services)
        model.reload()
        model.proposeNewHost(alias: "-oProxyCommand=x", options: [])
        #expect(model.pendingChange == nil)
        #expect(model.lastError?.code == .invalidArgument)
    }

    @Test func favoritesSortFirstAndSearchFilters() throws {
        defer { try? FileManager.default.removeItem(at: home) }
        try writeConfig("Host alpha\n    User a\nHost beta\n    HostName beta.example.com\nHost *\n    User x\n")
        let model = HostsModel(services: services)
        model.reload()
        let beta = try #require(model.hosts.first { $0.alias == "beta" })
        model.setFavorite(true, for: beta)
        #expect(model.visibleHosts.map(\.alias) == ["beta", "alpha", "*"])
        model.searchText = "example.com"
        #expect(model.visibleHosts.map(\.alias) == ["beta"])
    }
}

@Suite("KnownHostsModel")
struct KnownHostsModelTests {
    @Test func splitsHostAndPort() {
        let cases: [String: HostKeyRequest] = [
            "example.com": HostKeyRequest(host: "example.com"),
            "example.com:2222": HostKeyRequest(host: "example.com", port: 2222),
            "[example.com]:2200": HostKeyRequest(host: "example.com", port: 2200),
            "[example.com]": HostKeyRequest(host: "example.com"),
            "fe80::1": HostKeyRequest(host: "fe80::1"),
        ]
        for (input, expected) in cases {
            let (host, port) = KnownHostsModel.split(input)
            #expect(HostKeyRequest(host: host, port: port) == expected, "\(input)")
        }
    }
}

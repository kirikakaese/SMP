import Foundation
import SMPCore
import SMPSSH
import Testing

@testable import SMPServices

/// A temporary HOME with ~/.ssh and a support folder for backups and archives.
final class TestHome: Sendable {
    let root: URL

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "smp-home-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ssh.path)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
    }

    deinit {
        try? FileManager.default.removeItem(at: root)
    }

    var home: URL { root.appending(path: "home", directoryHint: .isDirectory) }
    var ssh: URL { home.appending(path: ".ssh", directoryHint: .isDirectory) }
    var support: URL { root.appending(path: "support", directoryHint: .isDirectory) }
    var environment: SSHEnvironment { SSHEnvironment(homeDirectory: home, userName: "tester") }
    var writer: SafeFileWriter { SafeFileWriter(backupDirectory: support.appending(path: "Backups")) }
    var config: ConfigService { ConfigService(environment: environment, writer: writer) }

    @discardableResult
    func write(_ relativePath: String, _ text: String, mode: Int = 0o600) throws -> URL {
        let url = ssh.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url
    }

    func read(_ relativePath: String) throws -> String {
        try String(contentsOf: ssh.appending(path: relativePath), encoding: .utf8)
    }

    func backups() -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: support.appending(path: "Backups").path)) ?? []
    }
}

/// Runs `body` and returns the `SMPError.Code` it threw, or `nil`.
func errorCode(_ body: () throws -> Void) -> SMPError.Code? {
    do {
        try body()
        return nil
    } catch {
        return (error as? SMPError)?.code
    }
}

/// Async variant of `errorCode`.
func asyncErrorCode(_ body: () async throws -> Void) async -> SMPError.Code? {
    do {
        try await body()
        return nil
    } catch {
        return (error as? SMPError)?.code
    }
}

@Suite("SafeFileWriter")
struct SafeFileWriterTests {
    @Test func createsNewFilesWithRequestedMode() throws {
        let home = try TestHome()
        let url = home.ssh.appending(path: "config")
        let backup = try home.writer.write(Data("Host a\n".utf8), to: url, expected: nil, mode: 0o600)
        #expect(backup == nil)
        #expect(try home.read("config") == "Host a\n")
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)
    }

    @Test func backsUpAndKeepsPermissions() throws {
        let home = try TestHome()
        let url = try home.write("config", "old\n", mode: 0o640)
        let snapshot = try FileSnapshot.capture(url)
        let backup = try #require(try home.writer.write(Data("new\n".utf8), to: url, expected: snapshot))
        #expect(try home.read("config") == "new\n")
        #expect(try String(contentsOf: backup, encoding: .utf8) == "old\n")
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o640)
    }

    @Test func refusesWhenFileChangedSinceRead() throws {
        let home = try TestHome()
        let url = try home.write("config", "original\n")
        let snapshot = try FileSnapshot.capture(url)
        try Data("edited elsewhere\n".utf8).write(to: url)
        let code = errorCode { try home.writer.write(Data("mine\n".utf8), to: url, expected: snapshot) }
        #expect(code == .fileChangedOnDisk)
        #expect(try home.read("config") == "edited elsewhere\n")
    }

    @Test func writesThroughSymlinks() throws {
        let home = try TestHome()
        let real = try home.write("dotfiles/ssh_config", "real\n")
        let link = home.ssh.appending(path: "config")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        try home.writer.write(Data("updated\n".utf8), to: link, expected: try FileSnapshot.capture(link))
        let attributes = try FileManager.default.attributesOfItem(atPath: link.path)
        #expect(attributes[.type] as? FileAttributeType == .typeSymbolicLink)
        #expect(try String(contentsOf: real, encoding: .utf8) == "updated\n")
    }
}

@Suite("ConfigService")
struct ConfigServiceTests {
    static let config = """
        Include config.d/*.conf
        Host github.com
          IdentityFile ~/.ssh/id_ed25519
        Host relative
          IdentityFile .ssh/id_ed25519
        Host other
          IdentityFile ~/.ssh/other_key
        Match host *.corp
          IdentityFile "%d/.ssh/id_ed25519.pub"

        """

    @Test func findsReferencesIncludingIncludedFiles() throws {
        let home = try TestHome()
        try home.write("config", Self.config)
        try home.write("config.d/work.conf", "Host work\n  IdentityFile ~/.ssh/id_ed25519\n")
        let key = home.ssh.appending(path: "id_ed25519")
        let references = try home.config.references(to: [key, home.ssh.appending(path: "id_ed25519.pub")])
        #expect(references.count == 4)
        #expect(references.map(\.hostPatterns.first) == ["github.com", "relative", "host", "work"])
        #expect(references.last?.file.lastPathComponent == "work.conf")
        #expect(references[2].isInMatchBlock)
    }

    @Test func renamesReferencesKeepingStyle() throws {
        let home = try TestHome()
        try home.write("config", Self.config)
        let keyFiles = [home.ssh.appending(path: "id_ed25519"), home.ssh.appending(path: "id_ed25519.pub")]
        let references = try home.config.references(to: keyFiles)
        try home.config.apply(references.map {
            .replaceValue($0, newValue: $0.renamedValue(from: "id_ed25519", to: "work_ed25519"))
        })
        let text = try home.read("config")
        #expect(text.contains("  IdentityFile ~/.ssh/work_ed25519\n"))
        #expect(text.contains("  IdentityFile .ssh/work_ed25519\n"))
        #expect(text.contains(#"IdentityFile "%d/.ssh/work_ed25519.pub""#))
        #expect(text.contains("~/.ssh/other_key"))
        #expect(home.backups().count == 1)
    }

    @Test func commentsOutAndRemovesReferences() throws {
        let home = try TestHome()
        try home.write("config", Self.config)
        let references = try home.config.references(to: [home.ssh.appending(path: "id_ed25519")])
        try home.config.apply([.commentOut(references[0]), .remove(references[1])])
        let text = try home.read("config")
        #expect(text.contains("  # IdentityFile ~/.ssh/id_ed25519\n"))
        #expect(!text.contains("IdentityFile .ssh/id_ed25519\n"))
        #expect(text.contains("Host relative\nHost other"))
    }

    @Test func detectsStaleReferences() throws {
        let home = try TestHome()
        try home.write("config", Self.config)
        let references = try home.config.references(to: [home.ssh.appending(path: "id_ed25519")])
        try home.write("config", "Host changed\n")
        #expect(throws: SMPError.self) { try home.config.apply([.remove(references[0])]) }
        #expect(try home.read("config") == "Host changed\n")
    }

    @Test func appendsHostToNewOrExistingConfig() throws {
        let home = try TestHome()
        try home.config.appendHost(alias: "srv", options: [("HostName", "srv.example.com")])
        #expect(try home.read("config") == "Host srv\n    HostName srv.example.com\n")
        try home.config.appendHost(alias: "two", options: [])
        #expect(try home.read("config") == "Host srv\n    HostName srv.example.com\n\nHost two\n")
    }

    @Test func renamedValueHandlesQuotesAndPublicKeys() {
        func reference(_ value: String) -> ConfigReference {
            ConfigReference(
                file: URL(fileURLWithPath: "/c"),
                lineIndex: 0,
                hostPatterns: [],
                isInMatchBlock: false,
                value: value
            )
        }
        #expect(reference("~/.ssh/a").renamedValue(from: "a", to: "b") == "~/.ssh/b")
        #expect(reference("\"~/my keys/a.pub\"").renamedValue(from: "a", to: "b") == "\"~/my keys/b.pub\"")
        #expect(reference("a").renamedValue(from: "a", to: "b") == "b")
    }
}

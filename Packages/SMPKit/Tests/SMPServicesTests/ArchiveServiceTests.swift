import Foundation
import SMPCore
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

@Suite("ArchiveService")
struct ArchiveServiceTests {
    private func makeArchive(
        _ home: TestHome,
        keychain: InMemoryKeychainService = InMemoryKeychainService()
    ) -> ArchiveService {
        ArchiveService(directory: home.support.appending(path: "Archive"), keychain: keychain)
    }

    private func discover(_ home: TestHome, _ name: String) throws -> DiscoveredKey {
        try #require(try KeyDiscoveryService().scan(directory: home.ssh).first { $0.name == name })
    }

    @Test func archivesVerifiesAndRestoresExactly() throws {
        let home = try TestHome()
        try home.write("id_ed25519", Fixtures.ed25519Private, mode: 0o600)
        try home.write("id_ed25519.pub", Fixtures.ed25519Public + "\n", mode: 0o644)
        let archive = makeArchive(home)

        let archived = try archive.archive(try discover(home, "id_ed25519"))
        #expect(!FileManager.default.fileExists(atPath: home.ssh.appending(path: "id_ed25519").path))
        #expect(!FileManager.default.fileExists(atPath: home.ssh.appending(path: "id_ed25519.pub").path))
        #expect(try archive.list().map(\.id) == [archived.id])
        #expect(archived.fingerprint == Fixtures.expectedFingerprints["ed25519Public"]?.sha256)

        // The archive never contains the private key in the clear.
        let archiveFolder = home.support.appending(path: "Archive").path
        let archiveFiles = try FileManager.default.contentsOfDirectory(atPath: archiveFolder)
        for name in archiveFiles {
            let data = try Data(contentsOf: home.support.appending(path: "Archive/\(name)"))
            #expect(String(decoding: data, as: UTF8.self).contains("PRIVATE KEY") == false)
        }

        let restored = try archive.restore(id: archived.id, conflict: .fail)
        #expect(restored.count == 2)
        #expect(try home.read("id_ed25519") == Fixtures.ed25519Private)
        let mode = try FileManager.default.attributesOfItem(atPath: home.ssh.appending(path: "id_ed25519").path)
        #expect((mode[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(try archive.list().isEmpty)
    }

    @Test func restoresUnderNewNameOnConflict() throws {
        let home = try TestHome()
        try home.write("id_ed25519", Fixtures.ed25519Private)
        try home.write("id_ed25519.pub", Fixtures.ed25519Public + "\n", mode: 0o644)
        let archive = makeArchive(home)
        let archived = try archive.archive(try discover(home, "id_ed25519"))
        try home.write("id_ed25519", "newer key\n")

        #expect(errorCode { try archive.restore(id: archived.id, conflict: .fail) } == .alreadyExists)
        try archive.restore(id: archived.id, conflict: .rename(to: "id_ed25519_restored"))
        #expect(try home.read("id_ed25519_restored") == Fixtures.ed25519Private)
        #expect(try home.read("id_ed25519_restored.pub").hasPrefix("ssh-ed25519 "))
        #expect(try home.read("id_ed25519") == "newer key\n")
    }

    @Test func cannotOpenWithoutTheKeychainKey() throws {
        let home = try TestHome()
        try home.write("solo", Fixtures.ed25519Private)
        let archived = try makeArchive(home).archive(try discover(home, "solo"))
        // A different Keychain (e.g. the key was removed) cannot decrypt the archive.
        let other = makeArchive(home, keychain: InMemoryKeychainService())
        #expect(errorCode { try other.restore(id: archived.id, conflict: .fail) } == .keyOperationFailed)
    }

    @Test func detectsTampering() throws {
        let home = try TestHome()
        try home.write("solo", Fixtures.ed25519Private)
        let keychain = InMemoryKeychainService()
        let archive = makeArchive(home, keychain: keychain)
        let archived = try archive.archive(try discover(home, "solo"))
        let sealed = home.support.appending(path: "Archive/\(archived.id.uuidString).sealed")
        var bytes = try Data(contentsOf: sealed)
        bytes[bytes.count - 1] ^= 0xFF
        try bytes.write(to: sealed)
        #expect(errorCode { try archive.restore(id: archived.id, conflict: .fail) } == .keyOperationFailed)
    }

    @Test func deletesArchivedEntries() throws {
        let home = try TestHome()
        try home.write("solo", Fixtures.ed25519Private)
        let archive = makeArchive(home)
        let archived = try archive.archive(try discover(home, "solo"))
        try archive.deleteArchived(id: archived.id)
        #expect(try archive.list().isEmpty)
    }
}

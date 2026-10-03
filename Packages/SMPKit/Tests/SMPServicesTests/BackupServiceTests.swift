import Foundation
import SMPCore
import SMPPersistence
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

private let privateText = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot a real key\n-----END OPENSSH PRIVATE KEY-----\n"

@Suite("BackupService")
struct BackupServiceTests {
    /// A home with one key pair, a config and known_hosts, and a store with some metadata.
    private func source() throws -> (TestHome, GRDBMetadataStore, [(BackupFile.Kind, URL)]) {
        let home = try TestHome()
        let store = try GRDBMetadataStore.inMemory()
        let key = try home.write("id_work", privateText, mode: 0o600)
        let pub = try home.write("id_work.pub", Fixtures.ed25519Public + "\n", mode: 0o644)
        let config = try home.write("config", "Host web\n    IdentityFile ~/.ssh/id_work\n", mode: 0o600)
        let known = try home.write("known_hosts", "web ssh-ed25519 AAAA\n", mode: 0o644)

        let tag = try store.createTag(named: "Work", color: .blue)
        let group = try store.createGroup(named: "Servers")
        let fingerprint = try SSHPublicKey(line: Fixtures.ed25519Public).fingerprintSHA256
        try store.save(KeyMetadata(fingerprint: fingerprint, notes: "laptop key"))
        try store.setTags([tag.id], for: fingerprint)
        try store.setGroups([group.id], for: fingerprint)
        try store.saveHostMetadata(HostMetadata(alias: "web", isFavorite: true))
        try store.setHostTags([tag.id], forHost: "web")
        try store.saveTunnel(TunnelProfile(name: "db", hostAlias: "web", forwards: []))
        return (home, store, [(.privateKey, key), (.publicKey, pub), (.config, config), (.knownHosts, known)])
    }

    private func service(_ home: TestHome, _ store: GRDBMetadataStore) -> BackupService {
        BackupService(environment: home.environment, metadata: store, iterations: 1_000)
    }

    private func passphrase(_ text: String = "correct horse battery staple") -> SecureBytes {
        SecureBytes(utf8: text)
    }

    @Test func roundTripsFilesAndMetadataIntoAnEmptyHome() throws {
        let (home, store, files) = try source()
        let url = home.support.appending(path: "test.smpbackup")
        let manifest = try service(home, store).createBackup(files: files, passphrase: passphrase(), to: url)
        #expect(manifest.keyCount == 1)
        #expect(manifest.files.map(\.path) == [
            "~/.ssh/id_work", "~/.ssh/id_work.pub", "~/.ssh/config", "~/.ssh/known_hosts",
        ])

        // Nothing readable on disk: not the key, not even the file names.
        let raw = try Data(contentsOf: url)
        #expect(raw.starts(with: Data("SMPBACKUP".utf8)))
        #expect(raw.range(of: Data("OPENSSH PRIVATE KEY".utf8)) == nil)
        #expect(raw.range(of: Data("id_work".utf8)) == nil)
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)

        let target = try TestHome()
        let targetStore = try GRDBMetadataStore.inMemory()
        let restorer = service(target, targetStore)
        let opened = try restorer.open(url, passphrase: passphrase())
        let plan = restorer.restorePlan(for: opened, allowedFolders: [])
        #expect(plan.allSatisfy { $0.action == .create })
        let summary = try restorer.restore(opened, plan: plan)

        #expect(summary.written.count == 4)
        #expect(try target.read("id_work") == privateText)
        #expect(try target.read("config") == "Host web\n    IdentityFile ~/.ssh/id_work\n")
        let keyMode = try FileManager.default.attributesOfItem(atPath: target.ssh.appending(path: "id_work").path)
        #expect((keyMode[.posixPermissions] as? NSNumber)?.intValue == 0o600)

        let fingerprint = try SSHPublicKey(line: Fixtures.ed25519Public).fingerprintSHA256
        #expect(try targetStore.metadata(for: fingerprint)?.notes == "laptop key")
        let tag = try #require(try targetStore.allTags().first)
        #expect(tag.name == "Work")
        #expect(try targetStore.tagAssignments()[fingerprint] == [tag.id])
        #expect(try targetStore.groupAssignments()[fingerprint]?.count == 1)
        #expect(try targetStore.allHostMetadata()["web"]?.isFavorite == true)
        #expect(try targetStore.hostTagAssignments()["web"] == [tag.id])
        #expect(try targetStore.allTunnels().map(\.name) == ["db"])
        #expect(summary.tagsAdded == 1 && summary.tunnelsAdded == 1)
    }

    @Test func refusesWrongPassphrasesAndTamperedFiles() throws {
        let (home, store, files) = try source()
        let url = home.support.appending(path: "test.smpbackup")
        let backup = service(home, store)
        _ = try backup.createBackup(files: files, passphrase: passphrase(), to: url)

        #expect(errorCode { _ = try backup.open(url, passphrase: passphrase("wrong")) } == .passphraseRequired)
        #expect(errorCode { _ = try backup.open(url, passphrase: SecureBytes(count: 0)) } == .invalidArgument)

        var raw = try Data(contentsOf: url)
        raw[raw.count - 20] ^= 0x01
        try raw.write(to: url)
        #expect(errorCode { _ = try backup.open(url, passphrase: passphrase()) } == .passphraseRequired)

        // A changed header (here: fewer iterations) breaks authentication as well.
        _ = try backup.createBackup(files: files, passphrase: passphrase(), to: url)
        raw = try Data(contentsOf: url)
        raw[12] ^= 0x01
        try raw.write(to: url)
        #expect(errorCode { _ = try backup.open(url, passphrase: passphrase()) } != nil)

        try Data("not a backup at all".utf8).write(to: url)
        #expect(errorCode { _ = try backup.open(url, passphrase: passphrase()) } == .invalidArgument)
    }

    @Test func neverOverwritesAndKeepsPairsTogether() throws {
        let (home, store, files) = try source()
        let url = home.support.appending(path: "test.smpbackup")
        let backup = service(home, store)
        _ = try backup.createBackup(files: files, passphrase: passphrase(), to: url)
        try home.write("id_work.pub", "ssh-ed25519 AAAAdifferent other\n", mode: 0o644)
        try home.write("config", "Host other\n", mode: 0o600)

        let opened = try backup.open(url, passphrase: passphrase())
        let plan = backup.restorePlan(for: opened, allowedFolders: [])
        let actions = Dictionary(uniqueKeysWithValues: plan.map { ($0.file.fileName, $0.action) })
        #expect(actions["id_work"] == .alreadyPresent)
        #expect(actions["known_hosts"] == .alreadyPresent)
        let destinations = Dictionary(uniqueKeysWithValues: plan.map { ($0.file.fileName, $0.destination?.path) })
        #expect(destinations["id_work.pub"] == home.ssh.appending(path: "id_work-restored.pub").path)
        #expect(destinations["config"] == home.ssh.appending(path: "config-restored").path)

        let summary = try backup.restore(opened, plan: plan)
        #expect(summary.alreadyPresent == 2)
        #expect(try home.read("config") == "Host other\n")
        #expect(try home.read("config-restored") == "Host web\n    IdentityFile ~/.ssh/id_work\n")
        // Existing metadata is kept, tags are matched by name rather than duplicated.
        #expect(try store.allTags().count == 1)
        #expect(summary.tagsAdded == 0 && summary.notesRestored == 0 && summary.tunnelsAdded == 0)

        // Restoring again finds both names taken.
        let again = backup.restorePlan(for: opened, allowedFolders: [])
        #expect(again.contains { if case .skip = $0.action { true } else { false } })
    }

    @Test func restoresOnlyIntoKeyFolders() throws {
        let home = try TestHome()
        let store = try GRDBMetadataStore.inMemory()
        let backup = service(home, store)
        let extra = home.home.appending(path: "keys")
        let manifest = BackupManifest(
            files: [
                BackupFile(kind: .privateKey, path: "~/Library/LaunchAgents/evil.plist", mode: 0o644),
                BackupFile(kind: .config, path: "/etc/ssh/ssh_config", mode: 0o644),
                BackupFile(kind: .publicKey, path: "~/keys/team.pub", mode: 0o644),
                BackupFile(kind: .privateKey, path: "~/.ssh/..", mode: 0o600),
            ],
            metadata: MetadataSnapshot()
        )
        let opened = OpenedBackup(manifest: manifest, contents: (0..<4).map { _ in SecureBytes(utf8: "x") })
        let targets = backup.restorePlan(for: opened, allowedFolders: [extra]).map(\.target.path)
        #expect(targets == [
            home.ssh.appending(path: "evil.plist").path,
            home.environment.configFile.path,
            extra.appending(path: "team.pub").path,
            home.ssh.appending(path: "restored-key").path,
        ])
    }

    @Test func namesAlternativesSoPairsStayPairs() {
        func name(_ path: String) -> String {
            BackupService.alternativeName(for: BackupFile(kind: .publicKey, path: path, mode: 0o644))
        }
        #expect(name("~/.ssh/id_ed25519") == "id_ed25519-restored")
        #expect(name("~/.ssh/id_ed25519.pub") == "id_ed25519-restored.pub")
        #expect(name("~/.ssh/id_ed25519-cert.pub") == "id_ed25519-restored-cert.pub")
        let home = URL(fileURLWithPath: "/Users/a")
        #expect(BackupFile.storedPath(for: URL(fileURLWithPath: "/Users/a/.ssh/x"), home: home) == "~/.ssh/x")
        #expect(BackupFile.storedPath(for: URL(fileURLWithPath: "/Volumes/k/x"), home: home) == "/Volumes/k/x")
    }
}

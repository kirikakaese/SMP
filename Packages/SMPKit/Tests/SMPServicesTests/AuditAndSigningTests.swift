import Foundation
import SMPCore
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

private func key(
    _ name: String,
    line: String = Fixtures.ed25519Public,
    folder: String = "/keys",
    issues: [KeyIssue] = [],
    hasPrivateKey: Bool = true
) throws -> DiscoveredKey {
    func file(_ fileName: String) -> KeyFileInfo {
        KeyFileInfo(
            url: URL(fileURLWithPath: "\(folder)/\(fileName)"), permissions: 0o600, isOwnedByCurrentUser: true,
            isSymbolicLink: false, size: 100, createdAt: nil, modifiedAt: nil
        )
    }
    return DiscoveredKey(
        name: name, kind: hasPrivateKey ? .pair : .publicOnly, publicKey: try SSHPublicKey(line: line),
        privateKeyFile: hasPrivateKey ? file(name) : nil, privateKeyInfo: nil, publicKeyFile: file(name + ".pub"),
        certificateFile: nil, certificate: nil, issues: issues
    )
}

@Suite("AuditEngine")
struct AuditEngineTests {
    @Test func turnsKeyIssuesIntoFindingsWithFixes() throws {
        let keys = [
            try key("open", issues: [.privateKeyPermissionsTooOpen(0o644), .directoryPermissionsTooOpen(0o755)]),
            try key("plain", issues: [.noPassphrase, .directoryPermissionsTooOpen(0o755)]),
            try key("old", line: Fixtures.dsaPublic, issues: [.weakAlgorithm("DSA keys are deprecated.")]),
            try key("orphan", issues: [.orphanedPublicKey], hasPrivateKey: false),
        ]
        let findings = AuditEngine.findings(AuditInput(keys: keys, metadata: [:], configFiles: []))
        // Most severe first; within a severity, by subject.
        #expect(findings.map(\.rule) == [
            "weak-algorithm", "private-key-permissions", "folder-permissions", "no-passphrase",
        ])
        #expect(findings[0].severity == .critical)
        #expect(findings[0].fix == .rotate(keyID: keys[2].id))
        #expect(findings[1].fix == .setPermissions(path: "/keys/open", mode: 0o600))
        #expect(findings[2].fix == .setPermissions(path: "/keys", mode: 0o700))  // Reported once for two keys.
        #expect(findings[3].fix == .addPassphrase(keyID: keys[1].id))
        #expect(AuditEngine.score(findings) == 100 - 25 - 25 - 15 - 15)
        #expect(AuditEngine.score([]) == 100)
    }

    @Test func warnsAboutExpiryAndRotationDates() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let soon = try key("soon")
        let expired = try key("expired", line: Fixtures.rsa3072Public)
        let due = try key("due", line: Fixtures.ecdsaP256Public)
        let metadata = [
            soon.fingerprint ?? "": KeyMetadata(fingerprint: "a", expiresAt: now.addingTimeInterval(3 * 86_400)),
            expired.fingerprint ?? "": KeyMetadata(fingerprint: "b", expiresAt: now.addingTimeInterval(-60)),
            due.fingerprint ?? "": KeyMetadata(fingerprint: "c", rotateAt: now.addingTimeInterval(-60)),
        ]
        let findings = AuditEngine.findings(
            AuditInput(keys: [soon, expired, due], metadata: metadata, configFiles: [], now: now)
        )
        #expect(Set(findings.map(\.rule)) == ["expiring", "expired", "rotation-due"])
        #expect(findings.first?.rule == "expired")
        #expect(findings.allSatisfy { if case .rotate = $0.fix { true } else { false } })
    }

    @Test func flagsRiskyConfigOnlyWhereItAppliesBroadly() {
        let text = """
            ForwardAgent yes
            Host bastion
                ForwardAgent yes
            Host *
                StrictHostKeyChecking no
                UserKnownHostsFile /dev/null
                ForwardX11Trusted yes
            """
        let file = LoadedConfigFile(
            url: URL(fileURLWithPath: "/home/.ssh/config"), document: SSHConfigDocument(text: text), snapshot: nil
        )
        let findings = AuditEngine.findings(AuditInput(keys: [], metadata: [:], configFiles: [file]))
        #expect(Set(findings.map(\.rule)) == [
            "forward-agent-everywhere", "no-host-key-checking", "known-hosts-discarded", "trusted-x11",
        ])
        let forward = findings.first { $0.rule == "forward-agent-everywhere" }
        #expect(forward?.subject == "config, line 1")
        #expect(forward?.fix == .removeConfigLine(file: "/home/.ssh/config", lineIndex: 0))
    }
}

@Suite("AuditFixer")
struct AuditFixerTests {
    @Test func setsPermissionsOnlyInsideKeyFoldersAndNotThroughLinks() throws {
        let home = try TestHome()
        let file = try home.write("id_test", "x", mode: 0o644)
        try AuditFixer().setPermissions(path: file.path, mode: 0o600, allowedRoots: [home.ssh])
        let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)

        #expect(errorCode {
            try AuditFixer().setPermissions(path: "/etc/hosts", mode: 0o600, allowedRoots: [home.ssh])
        } == .invalidArgument)
        let link = home.ssh.appending(path: "link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        #expect(errorCode {
            try AuditFixer().setPermissions(path: link.path, mode: 0o644, allowedRoots: [home.ssh])
        } == .invalidArgument)
    }
}

@Suite("GitSigningService (real git)")
struct GitSigningServiceTests {
    private func service(_ home: TestHome) -> GitSigningService {
        GitSigningService(
            runner: SSHToolRunner(environment: home.environment),
            environment: home.environment,
            writer: home.writer
        )
    }

    @Test func plansAppliesAndIsIdempotent() async throws {
        let home = try TestHome()
        let signing = service(home)
        let publicKey = try SSHPublicKey(line: Fixtures.ed25519Public)
        let publicFile = try home.write("id_ed25519.pub", Fixtures.ed25519Public + "\n", mode: 0o644)

        #expect(try await signing.currentState().values.isEmpty)
        let plan = try await signing.plan(
            publicKeyFile: publicFile, publicKey: publicKey, email: "alice@example.com", signTags: false
        )
        #expect(plan.changes.map(\.key) == [
            "gpg.format", "user.signingkey", "commit.gpgsign", "gpg.ssh.allowedsignersfile", "user.email",
        ])
        try await signing.apply(plan)

        let state = try await signing.currentState()
        #expect(state.usesSSHKey(atPath: publicFile.path))
        #expect(state.email == "alice@example.com")
        let gitconfig = try String(contentsOf: home.home.appending(path: ".gitconfig"), encoding: .utf8)
        #expect(gitconfig.contains("gpgsign = true"))
        let signers = try home.read("allowed_signers")
        #expect(signers == "alice@example.com namespaces=\"git\" \(keyBase(Fixtures.ed25519Public))\n")

        let again = try await signing.plan(
            publicKeyFile: publicFile, publicKey: publicKey, email: "alice@example.com", signTags: true
        )
        #expect(again.changes.map(\.key) == ["tag.gpgsign"])
        #expect(again.allowedSignersLine == nil)
    }

    @Test func keepsAnExistingEmailAndRejectsBadInput() async throws {
        let home = try TestHome()
        try Data("[user]\n\temail = work@example.com\n".utf8).write(to: home.home.appending(path: ".gitconfig"))
        let signing = service(home)
        let publicKey = try SSHPublicKey(line: Fixtures.ed25519Public)
        let file = home.ssh.appending(path: "id_ed25519.pub")
        let plan = try await signing.plan(
            publicKeyFile: file, publicKey: publicKey, email: "me@example.com", signTags: false
        )
        #expect(!plan.changes.contains { $0.key == "user.email" })
        #expect(plan.allowedSignersLine?.hasPrefix("me@example.com ") == true)
        await #expect(throws: SMPError.self) {
            _ = try await signing.plan(publicKeyFile: file, publicKey: publicKey, email: "a b", signTags: false)
        }
    }
}

private func keyBase(_ line: String) -> String {
    line.split(separator: " ").prefix(2).joined(separator: " ")
}

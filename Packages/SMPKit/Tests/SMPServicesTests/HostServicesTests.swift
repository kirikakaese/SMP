import Foundation
import SMPCore
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPServices

@Suite("ConnectionTestResult")
struct ConnectionTestResultTests {
    @Test func classifiesCommonFailures() {
        let cases: [(String, ConnectionProblem)] = [
            ("deploy@web: Permission denied (publickey).", .authenticationFailed),
            ("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.",
             .hostKeyChanged),
            ("No ED25519 host key is known for web and you have requested strict checking.\n"
                + "Host key verification failed.", .unknownHostKey),
            ("ssh: Could not resolve hostname nope: nodename nor servname provided", .hostNotFound),
            ("ssh: connect to host 10.0.0.1 port 22: Connection refused", .connectionRefused),
            ("ssh: connect to host 10.0.0.1 port 22: Operation timed out", .timedOut),
            ("ssh: connect to host 10.0.0.1 port 22: No route to host", .networkUnreachable),
            ("something unexpected", .other),
        ]
        for (stderr, problem) in cases {
            #expect(ConnectionTestResult.classify(exitCode: 255, stderr: stderr) == .failure(problem, details: stderr))
        }
    }

    @Test func treatsGitHostGreetingsAsSuccess() {
        let github = "Hi alice! You've successfully authenticated, but GitHub does not provide shell access."
        #expect(ConnectionTestResult.classify(exitCode: 1, stderr: github) == .success(github))
        #expect(ConnectionTestResult.classify(exitCode: 0, stderr: "") == .success("Connected and authenticated."))
    }

    @Test func everyProblemExplainsHowToFixIt() {
        let all: [ConnectionProblem] = [
            .authenticationFailed, .unknownHostKey, .hostKeyChanged, .hostNotFound,
            .connectionRefused, .timedOut, .networkUnreachable, .other,
        ]
        for problem in all {
            #expect(!problem.title.isEmpty)
            #expect(!problem.howToFix.isEmpty)
        }
    }

    @Test func buildsReadableSSHCommands() {
        #expect(HostService.sshCommand(for: "web") == "ssh web")
        #expect(HostService.sshCommand(for: "it's") == #"ssh 'it'\''s'"#)
    }
}

@Suite("HostService")
struct HostServiceTests {
    private func hostService(_ home: TestHome) -> HostService {
        HostService(
            runner: SSHToolRunner(environment: home.environment),
            environment: home.environment,
            writer: home.writer
        )
    }

    @Test func listsHostBlocksFromConfigAndIncludes() throws {
        let home = try TestHome()
        try home.write("config", "Include config.d/*\n\nHost web\n    HostName 10.0.0.1\n\nMatch host x\n    User y\n")
        try home.write("config.d/work", "Host db\n    User root\n")
        let service = hostService(home)
        let hosts = try service.hosts()
        #expect(hosts.map(\.alias).sorted() == ["db", "web"])
        #expect(Set(hosts.map(\.id)).count == 2)
    }

    @Test func validatesConfigTextWithSSH() async throws {
        let home = try TestHome()
        let service = hostService(home)
        #expect(try await service.validate("Host web\n    HostName 10.0.0.1\n    Port 2222\n").isEmpty)
        let problems = try await service.validate("Host web\n    HostNmae 10.0.0.1\n")
        #expect(!problems.isEmpty)
        #expect(problems.contains { $0.contains("line 2") })
        #expect(!problems.contains { $0.contains(home.root.path) })
    }

    @Test func savesWithBackupAndRefusesStaleWrites() throws {
        let home = try TestHome()
        try home.write("config", "Host a\n")
        let service = hostService(home)
        let file = try #require(service.loadFiles().first)
        try service.save("Host b\n", to: file)
        #expect(try home.read("config") == "Host b\n")
        #expect(home.backups().count == 1)
        #expect(errorCode { try service.save("Host c\n", to: file) } == .fileChangedOnDisk)
    }
}

@Suite("KnownHostsService")
struct KnownHostsServiceTests {
    private func makeService(_ home: TestHome) -> KnownHostsService {
        KnownHostsService(
            runner: SSHToolRunner(environment: home.environment),
            environment: home.environment,
            writer: home.writer
        )
    }

    @Test func parsesKeyscanOutputAndDropsDuplicates() {
        let output = """
            # example.com:22 SSH-2.0-OpenSSH_9.6
            example.com \(Fixtures.ed25519Public)
            example.com \(Fixtures.ed25519Public)
            example.com \(Fixtures.rsa2048Public)
            """
        let keys = KnownHostsService.parseScan(output)
        #expect(keys.map(\.wireType) == ["ssh-ed25519", "ssh-rsa"])
    }

    @Test func matchesPastedFingerprints() throws {
        let key = try SSHPublicKey(line: Fixtures.ed25519Public)
        let sha = "SHA256:b2JQ767rAoCayskafj+doabfNUumtrSAaU6SMWLC6uA"
        #expect(KnownHostsService.fingerprint(sha, matches: key))
        #expect(KnownHostsService.fingerprint("  b2JQ767rAoCayskafj+doabfNUumtrSAaU6SMWLC6uA=\n", matches: key))
        #expect(KnownHostsService.fingerprint("MD5:e2:b7:65:bf:6f:43:4c:e8:75:52:2f:16:63:5e:2a:dc", matches: key))
        #expect(KnownHostsService.fingerprint("E2:B7:65:BF:6F:43:4C:E8:75:52:2F:16:63:5E:2A:DC", matches: key))
        #expect(!KnownHostsService.fingerprint("SHA256:AAAA", matches: key))
        #expect(!KnownHostsService.fingerprint("", matches: key))
    }

    @Test func addsEntriesFollowingTheFileStyle() throws {
        let home = try TestHome()
        let service = makeService(home)
        let key = try SSHPublicKey(line: Fixtures.ed25519Public)
        try service.add(host: "example.com", port: 22, keys: [key])
        let plain = try home.read("known_hosts")
        #expect(plain.hasPrefix("example.com ssh-ed25519 "))

        // Once most entries are hashed, new ones are hashed too.
        try home.write("known_hosts", "|1|AQIDBAUGBwgJCgsMDQ4PEBESExQ=|qvtG0DaqrsqPDhV2Ni+wmYohchA= "
            + Fixtures.rsa2048Public + "\n", mode: 0o644)
        try service.add(host: "secret.example.com", port: 2222, keys: [key])
        let hashed = try home.read("known_hosts")
        #expect(!hashed.contains("secret"))
        #expect(try service.load().document.entries(matching: "secret.example.com", port: 2222).count == 1)
    }

    @Test func replacesOnlyTheChangedHost() throws {
        let home = try TestHome()
        try home.write("known_hosts", """
            example.com \(Fixtures.ed25519Public)
            other.example.com \(Fixtures.ed25519Public)
            example.com \(Fixtures.rsa2048Public)

            """, mode: 0o644)
        let service = makeService(home)
        let newKey = try SSHPublicKey(line: Fixtures.ecdsaP256Public)
        try service.replace(host: "example.com", port: 22, with: [newKey])

        let entries = try service.load().entries
        #expect(entries.count == 2)
        #expect(entries.first?.hostPatterns == ["other.example.com"])
        #expect(try service.load().document.entries(matching: "example.com").map(\.publicKey?.wireType)
            == ["ecdsa-sha2-nistp256"])
        #expect(home.backups().count == 1)
    }

    @Test func removesLinesUnlessTheFileChanged() throws {
        let home = try TestHome()
        let text = "a.example.com \(Fixtures.ed25519Public)\nb.example.com \(Fixtures.rsa2048Public)\n"
        try home.write("known_hosts", text, mode: 0o644)
        let service = makeService(home)
        try service.remove(lines: [0], from: service.load())
        #expect(try home.read("known_hosts") == "b.example.com \(Fixtures.rsa2048Public)\n")

        let stale = try service.load()
        try home.write("known_hosts", "changed elsewhere\n", mode: 0o644)
        #expect(errorCode { try service.remove(lines: [0], from: stale) } == .fileChangedOnDisk)
    }

    @Test func rejectsUnsafeScanTargets() async throws {
        let home = try TestHome()
        let service = makeService(home)
        let unsafeHost = await asyncErrorCode { _ = try await service.scan(host: "-oProxyCommand=x", port: 22) }
        #expect(unsafeHost == .invalidArgument)
        let badPort = await asyncErrorCode { _ = try await service.scan(host: "example.com", port: 0) }
        #expect(badPort == .invalidArgument)
    }
}

/// A launcher that records arguments and lets tests end the "process".
private final class FakeLauncher: SSHToolLaunching, @unchecked Sendable {
    final class Tool: RunningTool, @unchecked Sendable {
        var isRunning = true
        var exitCode: Int32?
        var errorOutput = ""
        let onExit: @Sendable (Int32, String) -> Void

        init(onExit: @escaping @Sendable (Int32, String) -> Void) {
            self.onExit = onExit
        }

        func terminate() {
            end(code: 15, stderr: "")
        }

        func end(code: Int32, stderr: String) {
            guard isRunning else { return }
            isRunning = false
            exitCode = code
            onExit(code, stderr)
        }
    }

    var launched: [[String]] = []
    var tools: [Tool] = []
    var failImmediately: String?

    func launch(
        _ tool: SSHTool,
        arguments: [String],
        onExit: @escaping @Sendable (Int32, String) -> Void
    ) throws -> any RunningTool {
        launched.append(arguments)
        let handle = Tool(onExit: onExit)
        tools.append(handle)
        if let failImmediately {
            handle.end(code: 255, stderr: failImmediately)
        }
        return handle
    }
}

@Suite("TunnelService")
struct TunnelServiceTests {
    let tunnel = TunnelProfile(name: "DB", hostAlias: "bastion", forwards: [
        TunnelForward(bindPort: 15432, targetHost: "db.internal", targetPort: 5432),
        TunnelForward(kind: .dynamic, bindPort: 1080),
    ])

    @Test func buildsNonInteractiveArguments() throws {
        #expect(try TunnelService.arguments(for: tunnel) == [
            "-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
            "-L", "127.0.0.1:15432:db.internal:5432", "-D", "127.0.0.1:1080", "bastion",
        ])
    }

    @Test func rejectsInvalidTunnels() {
        var badHost = tunnel
        badHost.hostAlias = "-oProxyCommand=evil"
        #expect(errorCode { _ = try TunnelService.arguments(for: badHost) } == .invalidArgument)
        var noForwards = tunnel
        noForwards.forwards = []
        #expect(errorCode { _ = try TunnelService.arguments(for: noForwards) } == .invalidArgument)
        var badForward = tunnel
        badForward.forwards[0].targetHost = "x;rm"
        #expect(errorCode { _ = try TunnelService.arguments(for: badForward) } == .invalidArgument)
    }

    @Test func tracksRunningStoppedAndFailedTunnels() throws {
        let launcher = FakeLauncher()
        let service = TunnelService(launcher: launcher)
        try service.start(tunnel)
        #expect(service.state(of: tunnel.id) == .running)
        try service.start(tunnel)
        #expect(launcher.launched.count == 1)

        service.stop(id: tunnel.id)
        #expect(service.state(of: tunnel.id) == .stopped)

        try service.start(tunnel)
        launcher.tools.last?.end(code: 255, stderr: "bind [127.0.0.1]:15432: Address already in use\n")
        #expect(service.state(of: tunnel.id) == .failed("bind [127.0.0.1]:15432: Address already in use"))

        try service.start(tunnel)
        service.stopAll()
        #expect(service.state(of: tunnel.id) == .stopped)
    }

    @Test func keepsFailuresThatHappenWhileStarting() throws {
        let launcher = FakeLauncher()
        launcher.failImmediately = "Permission denied (publickey)."
        let service = TunnelService(launcher: launcher)
        try service.start(tunnel)
        #expect(service.state(of: tunnel.id) == .failed("Permission denied (publickey)."))
    }
}

@Suite("DeployService")
struct DeployServiceTests {
    @Test func usesStrictHostKeysAndNoPromptsWithoutPassword() throws {
        let arguments = try DeployService.arguments(script: "true", host: "deploy@web", usesPassword: false)
        #expect(arguments == [
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "-o", "BatchMode=yes",
            "-T", "deploy@web", "exec sh -c 'true'",
        ])
    }

    @Test func passwordModeDisablesPublicKeys() throws {
        let arguments = try DeployService.arguments(script: "true", host: "web", usesPassword: true)
        #expect(arguments.contains("PubkeyAuthentication=no"))
        #expect(arguments.contains("NumberOfPasswordPrompts=1"))
        #expect(!arguments.contains("BatchMode=yes"))
        #expect(errorCode { _ = try DeployService.arguments(script: "true", host: "-x", usesPassword: false) }
            == .invalidArgument)
    }

    /// Runs a deploy script locally with `HOME` pointed at a temporary folder.
    private func runScript(_ script: String, home: URL, input: String) throws -> (status: Int32, output: String) {
        // Input comes from a file so an early exit can't cause SIGPIPE in the test process.
        let inputFile = home.appending(path: "input-\(UUID().uuidString)")
        try Data(input.utf8).write(to: inputFile)
        defer { try? FileManager.default.removeItem(at: inputFile) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", script]
        process.environment = ["HOME": home.path, "PATH": "/usr/bin:/bin"]
        let stdout = Pipe()
        process.standardInput = try FileHandle(forReadingFrom: inputFile)
        process.standardOutput = stdout
        try process.run()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: output, as: UTF8.self))
    }

    @Test func remoteScriptsInstallIdempotentlyAndRemoveExactLines() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: "smp-remote-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let file = home.appending(path: ".ssh/authorized_keys")

        #expect(try runScript(DeployService.installScript, home: home, input: Fixtures.ed25519Public + "\n").output
            == "SMP_ADDED\n")
        #expect(try runScript(DeployService.installScript, home: home, input: Fixtures.ed25519Public + "\n").output
            == "SMP_PRESENT\n")
        // A file without a trailing newline gets one before the next key.
        try Data((try String(contentsOf: file, encoding: .utf8) + "# no newline").utf8).write(to: file)
        _ = try runScript(DeployService.installScript, home: home, input: Fixtures.rsa2048Public + "\n")
        let installed = try String(contentsOf: file, encoding: .utf8)
        #expect(installed == "\(Fixtures.ed25519Public)\n# no newline\n\(Fixtures.rsa2048Public)\n")
        let sshMode = try FileManager.default.attributesOfItem(atPath: file.deletingLastPathComponent().path)
        #expect((sshMode[.posixPermissions] as? NSNumber)?.intValue == 0o700)
        let fileMode = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect((fileMode[.posixPermissions] as? NSNumber)?.intValue == 0o600)

        let listed = try runScript(DeployService.listScript, home: home, input: "").output
        #expect(AuthorizedKeysEntry.parse(listed).count == 2)

        let removed = try runScript(DeployService.removeScript, home: home, input: Fixtures.ed25519Public + "\n")
        #expect(removed.output == "SMP_REMOVED\n")
        #expect(try String(contentsOf: file, encoding: .utf8) == "# no newline\n\(Fixtures.rsa2048Public)\n")
        #expect(FileManager.default.fileExists(atPath: file.path + ".smp-backup"))
    }

    @Test func removeScriptFailsWithoutAuthorizedKeys() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: "smp-remote-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        #expect(try runScript(DeployService.removeScript, home: home, input: "x\n").status == 5)
    }
}

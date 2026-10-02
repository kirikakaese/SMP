import Foundation
import SMPCore
import Testing

@testable import SMPSSH

@Suite("ProcessExecutor")
struct ProcessExecutorTests {
    let executor = ProcessExecutor()

    private func invocation(
        _ path: String,
        _ arguments: [String] = [],
        timeout: Duration = .seconds(10)
    ) -> ToolInvocation {
        ToolInvocation(executable: URL(fileURLWithPath: path), arguments: arguments, timeout: timeout)
    }

    @Test func capturesStandardOutput() async throws {
        let result = try await executor.execute(invocation("/bin/echo", ["hello", "world"]))
        #expect(result.succeeded)
        #expect(result.standardOutputString == "hello world\n")
        #expect(result.toolName == "echo")
    }

    @Test func passesArgumentsVerbatimWithoutShell() async throws {
        let tricky = "$(touch /tmp/smp-should-not-exist); `id` | ; && *"
        let result = try await executor.execute(invocation("/bin/echo", [tricky]))
        #expect(result.standardOutputString == tricky + "\n")
        #expect(!FileManager.default.fileExists(atPath: "/tmp/smp-should-not-exist"))
    }

    @Test func reportsNonZeroExitCode() async throws {
        let result = try await executor.execute(invocation("/usr/bin/false"))
        #expect(result.exitCode == 1)
        #expect(!result.succeeded)
        #expect(throws: SMPError.self) { try result.requireSuccess() }
    }

    @Test func capturesStandardError() async throws {
        let result = try await executor.execute(invocation("/bin/sh", ["-c", "echo oops >&2; exit 3"]))
        #expect(result.exitCode == 3)
        #expect(result.standardErrorString == "oops\n")
    }

    @Test func writesStandardInputAndClosesIt() async throws {
        var call = invocation("/bin/cat")
        call.standardInput = SecureBytes(utf8: "from stdin")
        let result = try await executor.execute(call)
        #expect(result.standardOutputString == "from stdin")
    }

    @Test func stdinDefaultsToNullDevice() async throws {
        // Without explicit input, `cat` must see EOF immediately instead of blocking.
        let result = try await executor.execute(invocation("/bin/cat", timeout: .seconds(5)))
        #expect(result.succeeded)
        #expect(result.standardOutput.isEmpty)
    }

    @Test func usesOnlyTheGivenEnvironment() async throws {
        var call = invocation("/usr/bin/env")
        call.environment = ["SMP_TEST_VALUE": "42"]
        let result = try await executor.execute(call)
        let lines = result.standardOutputString.split(separator: "\n")
        #expect(lines.contains("SMP_TEST_VALUE=42"))
        #expect(!lines.contains { $0.hasPrefix("HOME=") })
    }

    @Test func truncatesOversizedOutput() async throws {
        let limited = ProcessExecutor(maxOutputBytes: 10)
        let result = try await limited.execute(invocation("/bin/echo", [String(repeating: "x", count: 100)]))
        #expect(result.outputTruncated)
        #expect(result.standardOutput.count == 10)
    }

    @Test func timesOutLongRunningProcess() async throws {
        let clock = ContinuousClock()
        let start = clock.now
        let code = await errorCode {
            try await executor.execute(invocation("/bin/sleep", ["30"], timeout: .milliseconds(300)))
        }
        #expect(code == .toolTimedOut)
        #expect(clock.now - start < .seconds(10))
    }

    @Test func cancellationStopsTheProcess() async throws {
        let executor = executor
        let call = invocation("/bin/sleep", ["30"], timeout: .seconds(60))
        let task = Task { try await executor.execute(call) }
        try await Task.sleep(for: .milliseconds(300))
        task.cancel()
        let code = await errorCode { try await task.value }
        #expect(code == .toolCancelled)
    }

    @Test func rejectsNulBytesInArguments() async throws {
        await #expect(throws: SMPError.self) {
            try await executor.execute(invocation("/bin/echo", ["a\0b"]))
        }
    }

    @Test func reportsMissingExecutable() async throws {
        let code = await errorCode { try await executor.execute(invocation("/nonexistent/tool")) }
        #expect(code == .toolNotFound)
    }
}

/// Runs `body` and returns the `SMPError.Code` it threw, or `nil` if it did not throw an `SMPError`.
func errorCode<T>(_ body: () async throws -> T) async -> SMPError.Code? {
    do {
        _ = try await body()
        return nil
    } catch {
        return (error as? SMPError)?.code
    }
}

@Suite("AskpassBroker")
struct AskpassBrokerTests {
    let executor = ProcessExecutor()

    @Test func servesResponsesInOrder() async throws {
        let script = #"a=$("$SSH_ASKPASS" first); b=$("$SSH_ASKPASS" second); "#
            + #"printf '%s|%s|%s' "$a" "$b" "$SSH_ASKPASS_REQUIRE""#
        let call = ToolInvocation(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", script],
            askpassResponses: [SecureBytes(utf8: "alpha"), SecureBytes(utf8: "beta gamma")],
            timeout: .seconds(10)
        )
        let result = try await executor.execute(call)
        #expect(result.standardOutputString == "alpha|beta gamma|force")
    }

    @Test func extraPromptFailsFastInsteadOfHanging() async throws {
        let script = #"a=$("$SSH_ASKPASS" first); "$SSH_ASKPASS" second >/dev/null 2>&1; "#
            + #"printf '%s|%s' "$a" "$?""#
        let call = ToolInvocation(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", script],
            askpassResponses: [SecureBytes(utf8: "only")],
            timeout: .seconds(10)
        )
        let result = try await executor.execute(call)
        #expect(result.standardOutputString.hasPrefix("only|"))
        #expect(result.standardOutputString != "only|0")
    }

    @Test func removesItsPrivateDirectoryAfterwards() async throws {
        let temporary = FileManager.default.temporaryDirectory
            .appending(path: "smp-broker-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }

        let executor = ProcessExecutor(temporaryDirectory: temporary)
        let call = ToolInvocation(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", #""$SSH_ASKPASS" prompt"#],
            askpassResponses: [SecureBytes(utf8: "x")],
            timeout: .seconds(10)
        )
        _ = try await executor.execute(call)
        #expect(try FileManager.default.contentsOfDirectory(atPath: temporary.path).isEmpty)
    }

    @Test func eachPromptReceivesExactlyOneResponse() async throws {
        // A slow reader must not receive the next response as well (regression test).
        let script = #"a=$("$SSH_ASKPASS" one | wc -l | tr -d ' '); b=$("$SSH_ASKPASS" two); "#
            + #"printf '%s|%s' "$a" "$b""#
        let call = ToolInvocation(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", script],
            askpassResponses: [SecureBytes(utf8: "first"), SecureBytes(utf8: "second")],
            timeout: .seconds(10)
        )
        let result = try await executor.execute(call)
        #expect(result.standardOutputString == "1|second")
    }

    @Test func pipeNamesAreZeroPadded() {
        #expect(AskpassBroker.pipePath(in: "/d", prefix: "a", index: 3) == "/d/a.03")
        #expect(AskpassBroker.pipePath(in: "/d", prefix: "t", index: 42) == "/d/t.42")
    }

    @Test func shellQuotingHandlesSingleQuotes() {
        #expect(AskpassBroker.shellQuoted("/tmp/a'b") == #"'/tmp/a'\''b'"#)
    }
}

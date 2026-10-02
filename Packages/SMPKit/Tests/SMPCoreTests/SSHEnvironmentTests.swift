import Foundation
import SMPCore
import Testing

@Suite("SSHEnvironment")
struct SSHEnvironmentTests {
    @Test func derivesPathsFromHomeDirectory() {
        let home = URL(fileURLWithPath: "/tmp/smp-home", isDirectory: true)
        let environment = SSHEnvironment(homeDirectory: home, userName: "alice")
        #expect(environment.sshDirectory.path == "/tmp/smp-home/.ssh")
        #expect(environment.configFile.path == "/tmp/smp-home/.ssh/config")
        #expect(environment.knownHostsFile.path == "/tmp/smp-home/.ssh/known_hosts")
    }

    @Test func errorsExplainWhatHappenedAndHowToFix() {
        let error = SMPError.toolNotFound("ssh-keygen", path: "/usr/bin/ssh-keygen")
        #expect(error.errorDescription?.contains("ssh-keygen") == true)
        #expect(error.recoverySuggestion != nil)
    }
}

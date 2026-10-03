import AppKit
import Foundation
import SMPCore
import SMPSSH

public protocol TerminalLaunching: Sendable {
    /// Opens a new window in `app` running `ssh <alias>`.
    @MainActor func connect(to alias: String, in app: TerminalApp) throws
    /// Terminal apps installed on this Mac.
    @MainActor func installedApps() -> [TerminalApp]
}

/// Opens SSH sessions in the user's terminal app.
///
/// Terminal and iTerm2 are driven through AppleScript (requires the Apple Events entitlement and
/// the user's permission on first use); Ghostty and WezTerm get the command as launch arguments;
/// Warp uses a launch configuration file and its URL scheme.
public struct TerminalLauncher: TerminalLaunching {
    private let homeDirectory: URL

    public init(homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) {
        self.homeDirectory = homeDirectory
    }

    @MainActor
    public func installedApps() -> [TerminalApp] {
        TerminalApp.allCases.filter { appURL($0) != nil }
    }

    @MainActor
    public func connect(to alias: String, in app: TerminalApp) throws {
        if let problem = HostAlias.problem(with: alias) {
            throw SMPError.invalidArgument(problem)
        }
        guard let url = appURL(app) else {
            throw SMPError(
                .toolNotFound,
                whatHappened: String(localized: "\(app.displayName) is not installed."),
                howToFix: String(localized: "Install it, or choose another terminal in SMP's settings.")
            )
        }
        let command = HostService.sshCommand(for: alias)
        switch app {
        case .terminal:
            try runAppleScript("""
                tell application "Terminal"
                    activate
                    do script \(ShellQuoting.appleScriptString(command))
                end tell
                """)
        case .iTerm2:
            try runAppleScript("""
                tell application "iTerm"
                    activate
                    create window with default profile command \(ShellQuoting.appleScriptString(command))
                end tell
                """)
        case .ghostty:
            open(url, arguments: ["-e", "ssh", alias])
        case .wezTerm:
            try launchWezTerm(at: url, alias: alias)
        case .warp:
            try openInWarp(alias: alias)
        }
    }

    @MainActor
    private func appURL(_ app: TerminalApp) -> URL? {
        NSWorkspace.shared.urlForApplication(withBundleIdentifier: app.bundleIdentifier)
    }

    @MainActor
    private func runAppleScript(_ source: String) throws {
        var errorInfo: NSDictionary?
        guard let script = NSAppleScript(source: source) else {
            throw SMPError(.toolLaunchFailed, whatHappened: String(localized: """
                SMP could not prepare the terminal command.
                """))
        }
        _ = script.executeAndReturnError(&errorInfo)
        if let errorInfo {
            let message = errorInfo[NSAppleScript.errorMessage] as? String ?? "Unknown AppleScript error"
            throw SMPError(
                .toolLaunchFailed,
                whatHappened: String(localized: "SMP could not open the terminal."),
                howToFix: String(localized: """
                    Allow SMP to control your terminal in \
                    System Settings → Privacy & Security → Automation.
                    """),
                details: message
            )
        }
    }

    @MainActor
    private func open(_ app: URL, arguments: [String]) {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.arguments = arguments
        configuration.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: app, configuration: configuration)
    }

    private func launchWezTerm(at app: URL, alias: String) throws {
        let process = Process()
        process.executableURL = app.appending(path: "Contents/MacOS/wezterm")
        process.arguments = ["start", "--", "ssh", alias]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            throw SMPError.toolLaunchFailed("WezTerm", reason: error.localizedDescription)
        }
    }

    /// Writes `~/.warp/launch_configurations/smp-<alias>.yaml` and opens it with `warp://launch/…`.
    @MainActor
    private func openInWarp(alias: String) throws {
        let folder = homeDirectory.appending(path: ".warp/launch_configurations", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let safeName = alias.map { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." ? $0 : "_" }
        let fileName = "smp-\(String(safeName)).yaml"
        let yamlCommand = "'" + HostService.sshCommand(for: alias).replacingOccurrences(of: "'", with: "''") + "'"
        let yaml = """
            ---
            name: SMP \(String(safeName))
            windows:
              - tabs:
                  - layout:
                      commands:
                        - exec: \(yamlCommand)

            """
        try Data(yaml.utf8).write(to: folder.appending(path: fileName), options: .atomic)
        guard let url = URL(string: "warp://launch/\(fileName)") else { return }
        NSWorkspace.shared.open(url)
    }
}

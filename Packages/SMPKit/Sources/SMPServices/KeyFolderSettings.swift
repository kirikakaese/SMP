import Foundation
import SMPCore

/// The folders SMP scans for keys: always `~/.ssh`, plus folders the user adds in Settings.
public enum KeyFolderSettings {
    public static let defaultsKey = "additionalKeyFolders"

    public static func additionalFolders(in defaults: UserDefaults = .standard) -> [URL] {
        (defaults.stringArray(forKey: defaultsKey) ?? []).map { URL(fileURLWithPath: $0, isDirectory: true) }
    }

    public static func setAdditionalFolders(_ folders: [URL], in defaults: UserDefaults = .standard) {
        var seen = Set<String>()
        let paths = folders.map(\.standardizedFileURL.path).filter { seen.insert($0).inserted }
        defaults.set(paths, forKey: defaultsKey)
    }

    public static func allFolders(environment: SSHEnvironment, defaults: UserDefaults = .standard) -> [URL] {
        [environment.sshDirectory] + additionalFolders(in: defaults)
    }
}

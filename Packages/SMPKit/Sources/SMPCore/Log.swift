import os

/// Unified-logging categories.
///
/// Rules: never log secret material. Interpolate paths, hosts and user names with
/// `privacy: .private` so they are redacted in collected logs.
public enum Log {
    public static let subsystem = "com.kirikakaese.smp"

    public static let tools = Logger(subsystem: subsystem, category: "tools")
    public static let keychain = Logger(subsystem: subsystem, category: "keychain")
    public static let app = Logger(subsystem: subsystem, category: "app")
}

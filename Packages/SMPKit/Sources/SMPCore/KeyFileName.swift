import Foundation

/// Validation rules for key file names chosen by the user.
public enum KeyFileName {
    /// Names that belong to other OpenSSH files and must never be used for keys.
    public static let reservedNames: Set<String> = [
        "config", "known_hosts", "known_hosts.old", "authorized_keys", "authorized_keys2",
        "environment", "rc", "allowed_signers",
    ]

    /// Returns `nil` if `name` is acceptable, otherwise a message explaining the problem.
    public static func problem(with name: String) -> String? {
        if name.isEmpty {
            return "Enter a file name."
        }
        if name.count > 128 {
            return "The file name is too long (128 characters at most)."
        }
        if name.hasPrefix(".") {
            return "The file name must not start with a dot."
        }
        if name.hasSuffix(".pub") {
            return "Leave out “.pub”; SMP adds it to the public key automatically."
        }
        if reservedNames.contains(name) {
            return "“\(name)” is used by OpenSSH for another purpose."
        }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@+")
        if name.unicodeScalars.contains(where: { !allowed.contains($0) }) {
            return "Use only letters, digits and . _ - @ +"
        }
        return nil
    }

    /// A safe default file name for a key type, e.g. `id_ed25519`, avoiding names in `existing`.
    public static func suggestion(base: String, existing: Set<String>) -> String {
        guard existing.contains(base) || existing.contains(base + ".pub") else { return base }
        var counter = 2
        while existing.contains("\(base)_\(counter)") || existing.contains("\(base)_\(counter).pub") {
            counter += 1
        }
        return "\(base)_\(counter)"
    }

    /// `user@host` as OpenSSH would default the comment.
    public static func defaultComment() -> String {
        var host = ProcessInfo.processInfo.hostName
        if host.hasSuffix(".local") {
            host.removeLast(".local".count)
        }
        return "\(NSUserName())@\(host)"
    }
}

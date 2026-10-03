import CryptoKit
import Foundation

/// One host key line in a `known_hosts` file.
public struct KnownHostsEntry: Sendable, Hashable, Identifiable {
    public enum Marker: String, Sendable, Hashable {
        case certAuthority = "@cert-authority"
        case revoked = "@revoked"
    }

    public let lineIndex: Int
    public let marker: Marker?
    /// The host field as written (comma-separated patterns, or a hashed `|1|salt|hash`).
    public let hostField: String
    public let publicKey: SSHPublicKey?
    public let comment: String

    public var id: Int { lineIndex }
    public var isHashed: Bool { hostField.hasPrefix("|1|") }

    /// Readable host patterns; empty for hashed entries.
    public var hostPatterns: [String] {
        isHashed ? [] : hostField.split(separator: ",").map(String.init)
    }

    /// Whether this entry applies to `host` on `port`, the way OpenSSH matches it.
    public func matches(host: String, port: Int = 22) -> Bool {
        let candidate = KnownHostsDocument.hostKey(host: host, port: port)
        if isHashed {
            return KnownHostsDocument.hashedMatch(field: hostField, candidate: candidate)
        }
        var matched = false
        for pattern in hostPatterns {
            if pattern.hasPrefix("!") {
                if KnownHostsDocument.glob(String(pattern.dropFirst()), matches: candidate) { return false }
            } else if KnownHostsDocument.glob(pattern, matches: candidate) {
                matched = true
            }
        }
        return matched
    }
}

/// A lossless model of a `known_hosts` file.
public struct KnownHostsDocument: Sendable, Equatable {
    public private(set) var lines: [String]
    private let hasTrailingNewline: Bool

    public init(text: String) {
        hasTrailingNewline = text.isEmpty || text.hasSuffix("\n")
        var parts = text.components(separatedBy: "\n")
        if hasTrailingNewline, parts.last == "" {
            parts.removeLast()
        }
        lines = parts
    }

    public func render() -> String {
        guard !lines.isEmpty else { return "" }
        return lines.joined(separator: "\n") + (hasTrailingNewline ? "\n" : "")
    }

    public func entries() -> [KnownHostsEntry] {
        lines.enumerated().compactMap { index, line in Self.parse(line, at: index) }
    }

    public func entries(matching host: String, port: Int = 22) -> [KnownHostsEntry] {
        entries().filter { $0.matches(host: host, port: port) }
    }

    /// Removes the given lines (by index).
    public mutating func removeLines(_ indices: Set<Int>) {
        for index in indices.sorted(by: >) where lines.indices.contains(index) {
            lines.remove(at: index)
        }
    }

    /// Appends an entry for `host`/`port`. With `hashed`, the host name is stored as `|1|salt|hash`
    /// like `HashKnownHosts yes` does, so the file does not reveal which hosts you visit.
    public mutating func append(host: String, port: Int, key: SSHPublicKey, hashed: Bool) {
        let hostKey = Self.hostKey(host: host, port: port)
        let salt = Data((0..<20).map { _ in UInt8.random(in: .min ... .max) })
        let field = hashed ? Self.hash(hostKey, salt: salt) : hostKey
        lines.append("\(field) \(key.wireType) \(key.blob.base64EncodedString())")
    }

    // MARK: Helpers

    /// `host` for port 22, otherwise `[host]:port`.
    public static func hostKey(host: String, port: Int) -> String {
        port == 22 ? host.lowercased() : "[\(host.lowercased())]:\(port)"
    }

    static func parse(_ line: String, at index: Int) -> KnownHostsEntry? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
        var rest = Substring(trimmed)
        var marker: KnownHostsEntry.Marker?
        if trimmed.hasPrefix("@") {
            let parts = trimmed.split(maxSplits: 1, omittingEmptySubsequences: true) { $0 == " " || $0 == "\t" }
            marker = KnownHostsEntry.Marker(rawValue: String(parts[0]))
            rest = parts.count > 1 ? parts[1] : ""
        }
        let fields = rest.split(maxSplits: 3, omittingEmptySubsequences: true) { $0 == " " || $0 == "\t" }
            .map(String.init)
        guard fields.count >= 3 else { return nil }
        let comment = fields.count > 3 ? fields[3] : ""
        let key = try? SSHPublicKey(line: "\(fields[1]) \(fields[2])")
        return KnownHostsEntry(
            lineIndex: index,
            marker: marker,
            hostField: fields[0],
            publicKey: key,
            comment: comment
        )
    }

    static func hash(_ host: String, salt: Data) -> String {
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(host.utf8), using: SymmetricKey(data: salt))
        return "|1|\(salt.base64EncodedString())|\(Data(mac).base64EncodedString())"
    }

    static func hashedMatch(field: String, candidate: String) -> Bool {
        let parts = field.split(separator: "|", omittingEmptySubsequences: true)
        guard parts.count == 3, parts[0] == "1",
              let salt = Data(base64Encoded: String(parts[1])),
              let expected = Data(base64Encoded: String(parts[2]))
        else { return false }
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(candidate.utf8), using: SymmetricKey(data: salt))
        return Data(mac) == expected
    }

    /// OpenSSH-style glob: `*` matches any run of characters, `?` exactly one. Case-insensitive.
    static func glob(_ pattern: String, matches text: String) -> Bool {
        let pattern = Array(pattern.lowercased())
        let text = Array(text.lowercased())
        var patternIndex = 0
        var textIndex = 0
        var starIndex: Int?
        var matchIndex = 0
        while textIndex < text.count {
            let current = patternIndex < pattern.count ? pattern[patternIndex] : nil
            if current == "?" || current == text[textIndex] {
                patternIndex += 1
                textIndex += 1
            } else if current == "*" {
                starIndex = patternIndex
                matchIndex = textIndex
                patternIndex += 1
            } else if let star = starIndex {
                patternIndex = star + 1
                matchIndex += 1
                textIndex = matchIndex
            } else {
                return false
            }
        }
        while patternIndex < pattern.count, pattern[patternIndex] == "*" {
            patternIndex += 1
        }
        return patternIndex == pattern.count
    }
}

/// One line of an `authorized_keys` file: optional options, then a public key.
public struct AuthorizedKeysEntry: Sendable, Hashable, Identifiable {
    public let lineIndex: Int
    /// The complete line, used to remove exactly this entry.
    public let line: String
    /// Options such as `from="10.0.0.0/8",no-agent-forwarding`, if present.
    public let options: String?
    public let publicKey: SSHPublicKey

    public var id: Int { lineIndex }

    /// Parses every key line; comments, blank lines and unreadable lines are skipped.
    public static func parse(_ text: String) -> [AuthorizedKeysEntry] {
        text.components(separatedBy: "\n").enumerated().compactMap { index, rawLine in
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
            if let key = try? SSHPublicKey(line: line) {
                return AuthorizedKeysEntry(lineIndex: index, line: line, options: nil, publicKey: key)
            }
            guard let split = optionsEnd(in: line) else { return nil }
            let options = String(line[..<split])
            let rest = String(line[split...]).trimmingCharacters(in: .whitespaces)
            guard let key = try? SSHPublicKey(line: rest) else { return nil }
            return AuthorizedKeysEntry(lineIndex: index, line: line, options: options, publicKey: key)
        }
    }

    /// The index of the first unquoted whitespace, which ends the options field.
    static func optionsEnd(in line: String) -> String.Index? {
        var inQuotes = false
        var index = line.startIndex
        while index < line.endIndex {
            let character = line[index]
            if character == "\\", inQuotes {
                index = line.index(after: index)
            } else if character == "\"" {
                inQuotes.toggle()
            } else if !inQuotes, character == " " || character == "\t" {
                return index
            }
            if index < line.endIndex {
                index = line.index(after: index)
            }
        }
        return nil
    }
}

/// Quoting for the few places where text must pass through a shell or AppleScript.
public enum ShellQuoting {
    /// POSIX single-quoting: safe for any string.
    public static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Quotes only when needed, so commands stay readable (`ssh myhost` rather than `ssh 'myhost'`).
    public static func quoteIfNeeded(_ value: String) -> String {
        let safe = CharacterSet(
            charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./-_"
        )
        return !value.isEmpty && value.unicodeScalars.allSatisfy(safe.contains) ? value : quote(value)
    }

    /// A double-quoted AppleScript string literal.
    public static func appleScriptString(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"" + escaped + "\""
    }
}

import Foundation

/// A `Host` or `Match` section of an SSH config file.
public struct SSHConfigBlock: Sendable, Hashable, Identifiable {
    /// Index of the `Host` / `Match` line.
    public let headerLine: Int
    /// Index one past the block's last line (the next block's header, or the end of the file).
    public let endLine: Int
    /// Host patterns (`Host`) or criteria (`Match`).
    public let patterns: [String]
    public let isMatch: Bool
    /// The directives inside the block, in file order.
    public let options: [SSHConfigDocument.Directive]

    public var id: Int { headerLine }

    /// The first pattern, used as the block's display name and as the `ssh` argument.
    public var alias: String { patterns.first ?? "" }

    /// `true` for blocks that cannot be connected to directly (`Host *`, `Host *.corp`, `Match …`).
    public var isWildcard: Bool {
        isMatch || patterns.allSatisfy { $0.contains("*") || $0.contains("?") || $0.hasPrefix("!") }
    }

    /// The first value of `keyword` (case-insensitive), as written.
    public func value(of keyword: String) -> String? {
        values(of: keyword).first
    }

    /// All values of `keyword` (some keywords such as `IdentityFile` may repeat).
    public func values(of keyword: String) -> [String] {
        let wanted = keyword.lowercased()
        return options.filter { $0.normalizedKeyword == wanted }.map(\.rawValue)
    }
}

extension SSHConfigDocument {
    /// The `Host` and `Match` blocks in file order.
    public func blocks() -> [SSHConfigBlock] {
        let all = directives()
        let headers = all.filter { ["host", "match"].contains($0.normalizedKeyword) }
        return headers.enumerated().map { index, header in
            let end = index + 1 < headers.count ? headers[index + 1].lineIndex : lines.count
            let options = all.filter { $0.lineIndex > header.lineIndex && $0.lineIndex < end }
            return SSHConfigBlock(
                headerLine: header.lineIndex,
                endLine: end,
                patterns: header.arguments,
                isMatch: header.normalizedKeyword == "match",
                options: options
            )
        }
    }

    /// The block whose header is on `headerLine`.
    public func block(at headerLine: Int) -> SSHConfigBlock? {
        blocks().first { $0.headerLine == headerLine }
    }

    /// Sets `keyword` in a block to exactly `values`: existing lines are reused in place, extra
    /// lines are removed, and missing ones are inserted after the block's last directive using the
    /// block's indentation. An empty `values` removes the keyword from the block.
    public mutating func setValues(_ values: [String], for keyword: String, inBlockAt headerLine: Int) {
        guard let block = block(at: headerLine) else { return }
        let wanted = keyword.lowercased()
        let existing = block.options.filter { $0.normalizedKeyword == wanted }.map(\.lineIndex)

        for (lineIndex, value) in zip(existing, values) {
            replaceValue(atLine: lineIndex, with: value)
        }
        if existing.count > values.count {
            for lineIndex in existing[values.count...].reversed() {
                removeLine(lineIndex)
            }
            return
        }
        guard values.count > existing.count else { return }
        let insertAt = (existing.last ?? block.options.last?.lineIndex ?? headerLine) + 1
        let indentation = block.options.first.map { Self.indentation(of: lines[$0.lineIndex]) } ?? "    "
        let newLines = values[existing.count...].map { "\(indentation)\(keyword) \($0)" }
        lines.insert(contentsOf: newLines, at: insertAt)
    }

    /// Replaces a block's host patterns, keeping the rest of the header line.
    public mutating func setPatterns(_ patterns: [String], forBlockAt headerLine: Int) {
        replaceValue(atLine: headerLine, with: patterns.map(Self.quotedIfNeeded).joined(separator: " "))
    }

    /// Removes a whole block, plus one surrounding blank line so no double gap remains.
    public mutating func removeBlock(at headerLine: Int) {
        guard let block = block(at: headerLine) else { return }
        lines.removeSubrange(block.headerLine..<block.endLine)
        let before = block.headerLine - 1
        let followedByGap = block.headerLine >= lines.count || Self.isBlank(lines[block.headerLine])
        if before >= 0, Self.isBlank(lines[before]), followedByGap {
            lines.remove(at: before)
        }
    }

    /// Appends a copy of a block (without its trailing blank lines) under new patterns.
    /// - Returns: the header line of the copy.
    @discardableResult
    public mutating func duplicateBlock(at headerLine: Int, as patterns: [String]) -> Int? {
        guard let block = block(at: headerLine) else { return nil }
        var copied = Array(lines[block.headerLine..<block.endLine])
        while let last = copied.last, Self.isBlank(last) {
            copied.removeLast()
        }
        if let last = lines.last, !Self.isBlank(last) {
            lines.append("")
        }
        let newHeader = lines.count
        lines.append(contentsOf: copied)
        setPatterns(patterns, forBlockAt: newHeader)
        return newHeader
    }

    static func indentation(of line: String) -> String {
        String(line.prefix { $0 == " " || $0 == "\t" })
    }

    static func isBlank(_ line: String) -> Bool {
        line.trimmingCharacters(in: .whitespaces).isEmpty
    }
}

/// Keywords SMP knows, for highlighting and the visual editor.
public enum SSHConfigKeywords {
    /// The fields shown on host cards, in display order.
    public static let common = [
        "HostName", "User", "Port", "IdentityFile", "IdentitiesOnly", "ProxyJump", "ForwardAgent",
        "LocalForward", "RemoteForward", "UseKeychain", "AddKeysToAgent",
    ]

    /// Keywords that may appear several times in one block.
    public static let repeatable: Set<String> = [
        "identityfile", "localforward", "remoteforward", "dynamicforward", "certificatefile", "sendenv", "setenv",
    ]

    /// A broad list of OpenSSH client keywords (lowercased), used to flag likely typos.
    public static let known: Set<String> = [
        "host", "match", "include", "hostname", "user", "port", "identityfile", "identitiesonly", "identityagent",
        "proxyjump", "proxycommand", "forwardagent", "forwardx11", "forwardx11trusted", "localforward",
        "remoteforward", "dynamicforward", "usekeychain", "addkeystoagent", "stricthostkeychecking",
        "userknownhostsfile", "globalknownhostsfile", "hashknownhosts", "serveraliveinterval",
        "serveralivecountmax", "connecttimeout", "connectionattempts", "controlmaster", "controlpath",
        "controlpersist", "compression", "loglevel", "preferredauthentications", "pubkeyauthentication",
        "passwordauthentication", "kbdinteractiveauthentication", "certificatefile", "hostkeyalgorithms",
        "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes", "kexalgorithms", "ciphers", "macs",
        "requesttty", "remotecommand", "sendenv", "setenv", "batchmode", "canonicalizehostname",
        "canonicaldomains", "updatehostkeys", "verifyhostkeydns", "visualhostkey", "tcpkeepalive",
        "exitonforwardfailure", "gatewayports", "clearallforwardings", "securitykeyprovider", "tag",
        "addressfamily", "bindaddress", "bindinterface", "escapechar", "permitlocalcommand", "localcommand",
        "nohostauthenticationforlocalhost", "rekeylimit", "revokedhostkeys", "streamlocalbindunlink",
        "streamlocalbindmask", "tunnel", "tunneldevice", "xauthlocation", "logverbose", "syslogfacility",
        "knownhostscommand", "obscurekeystroketiming", "enableescapecommandline", "requiredrsasize",
        "sessiontype", "stdinnull", "forkafterauthentication", "channeltimeout", "casignaturealgorithms",
        "fingerprinthash", "gssapiauthentication", "gssapidelegatecredentials", "ignoreunknown",
        "hostbasedauthentication", "hostbasedacceptedalgorithms", "hostkeyalias", "checkhostip",
        "ipqos", "numberofpasswordprompts", "pkcs11provider", "proxyusefdpass", "refuseconnection",
    ]
}

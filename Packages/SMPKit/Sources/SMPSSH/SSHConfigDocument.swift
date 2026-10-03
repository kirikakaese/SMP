import Foundation

/// A lossless, line-based model of an OpenSSH client config file (`~/.ssh/config`).
///
/// Every line is kept verbatim, so `render()` reproduces the input exactly, including comments,
/// indentation, ordering, `Include` and unknown directives. Edits touch only the lines they change.
/// The full visual editor (milestone 4) builds on this type.
public struct SSHConfigDocument: Sendable, Equatable {
    /// One `Keyword value` line.
    public struct Directive: Sendable, Equatable {
        public let lineIndex: Int
        /// The keyword as written (OpenSSH keywords are case-insensitive).
        public let keyword: String
        /// The text after the keyword and its separator, with surrounding whitespace removed.
        public let rawValue: String
        /// `rawValue` split into arguments, honoring double quotes.
        public let arguments: [String]
        /// Host patterns of the enclosing `Host` block, `["*"]` before the first block, or the
        /// `Match` criteria for `Match` blocks.
        public let blockPatterns: [String]
        public let isInMatchBlock: Bool

        public var normalizedKeyword: String { keyword.lowercased() }
    }

    public private(set) var lines: [String]
    private let lineSeparator: String
    private let hasTrailingNewline: Bool

    public init(text: String) {
        lineSeparator = text.contains("\r\n") ? "\r\n" : "\n"
        hasTrailingNewline = text.isEmpty || text.hasSuffix("\n")
        var parts = text.components(separatedBy: lineSeparator)
        if hasTrailingNewline, parts.last == "" {
            parts.removeLast()
        }
        lines = parts
    }

    /// The document as text. Unchanged documents render byte-for-byte identical to the input.
    public func render() -> String {
        guard !lines.isEmpty else { return "" }
        return lines.joined(separator: lineSeparator) + (hasTrailingNewline ? lineSeparator : "")
    }

    // MARK: Reading

    public func directives() -> [Directive] {
        var result: [Directive] = []
        var patterns = ["*"]
        var inMatch = false
        for (index, line) in lines.enumerated() {
            guard let parsed = Self.parse(line) else { continue }
            let keyword = parsed.keyword.lowercased()
            if keyword == "host" {
                patterns = Self.splitArguments(parsed.value)
                inMatch = false
            } else if keyword == "match" {
                patterns = Self.splitArguments(parsed.value)
                inMatch = true
            }
            result.append(Directive(
                lineIndex: index,
                keyword: parsed.keyword,
                rawValue: parsed.value,
                arguments: Self.splitArguments(parsed.value),
                blockPatterns: patterns,
                isInMatchBlock: inMatch
            ))
        }
        return result
    }

    /// All directives with the given keyword (case-insensitive).
    public func directives(named keyword: String) -> [Directive] {
        let wanted = keyword.lowercased()
        return directives().filter { $0.normalizedKeyword == wanted }
    }

    // MARK: Editing

    /// Replaces the value of the directive on `lineIndex`, keeping indentation, keyword and separator.
    public mutating func replaceValue(atLine lineIndex: Int, with newValue: String) {
        guard lines.indices.contains(lineIndex), let parsed = Self.parse(lines[lineIndex]) else { return }
        lines[lineIndex] = parsed.prefix + newValue
    }

    /// Turns the line into a comment, keeping its text so it can be restored by hand.
    public mutating func commentOutLine(_ lineIndex: Int) {
        guard lines.indices.contains(lineIndex) else { return }
        let line = lines[lineIndex]
        let indentation = line.prefix { $0 == " " || $0 == "\t" }
        lines[lineIndex] = String(indentation) + "# " + String(line.dropFirst(indentation.count))
    }

    public mutating func removeLine(_ lineIndex: Int) {
        guard lines.indices.contains(lineIndex) else { return }
        lines.remove(at: lineIndex)
    }

    /// Appends a `Host` block at the end of the file, separated by a blank line.
    public mutating func appendHostBlock(patterns: [String], options: [(keyword: String, value: String)]) {
        if let last = lines.last, !last.trimmingCharacters(in: .whitespaces).isEmpty {
            lines.append("")
        }
        lines.append("Host " + patterns.map(Self.quotedIfNeeded).joined(separator: " "))
        for option in options {
            lines.append("    \(option.keyword) \(option.value)")
        }
    }

    // MARK: Parsing helpers

    struct ParsedLine {
        /// Indentation + keyword + separator, i.e. everything before the value.
        let prefix: String
        let keyword: String
        let value: String
    }

    /// Parses `Keyword value`, `Keyword=value` or `Keyword = value`. Returns `nil` for blank and comment lines.
    static func parse(_ line: String) -> ParsedLine? {
        let trimmedLeading = line.drop { $0 == " " || $0 == "\t" }
        guard let first = trimmedLeading.first, first != "#" else { return nil }
        let keywordEnd =
            trimmedLeading.firstIndex { $0 == " " || $0 == "\t" || $0 == "=" } ?? trimmedLeading.endIndex
        let keyword = String(trimmedLeading[..<keywordEnd])
        var valueStart = keywordEnd
        var sawEquals = false
        while valueStart < trimmedLeading.endIndex {
            let character = trimmedLeading[valueStart]
            if character == " " || character == "\t" {
                valueStart = trimmedLeading.index(after: valueStart)
            } else if character == "=", !sawEquals {
                sawEquals = true
                valueStart = trimmedLeading.index(after: valueStart)
            } else {
                break
            }
        }
        let prefix = String(line[..<valueStart])
        let value = String(trimmedLeading[valueStart...]).trimmingCharacters(in: .whitespaces)
        return ParsedLine(prefix: prefix, keyword: keyword, value: value)
    }

    /// Splits arguments on whitespace, treating double-quoted strings as one argument.
    static func splitArguments(_ value: String) -> [String] {
        var arguments: [String] = []
        var current = ""
        var inQuotes = false
        var hasToken = false
        for character in value {
            if character == "\"" {
                inQuotes.toggle()
                hasToken = true
            } else if !inQuotes, character == " " || character == "\t" {
                if hasToken {
                    arguments.append(current)
                    current = ""
                    hasToken = false
                }
            } else {
                current.append(character)
                hasToken = true
            }
        }
        if hasToken {
            arguments.append(current)
        }
        return arguments
    }

    static func quotedIfNeeded(_ value: String) -> String {
        value.contains(where: { $0 == " " || $0 == "\t" }) ? "\"\(value)\"" : value
    }
}

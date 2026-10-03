import Foundation

/// A rough, offline estimate of passphrase strength for the strength meter.
///
/// The estimate works on the characters while the user types; nothing is stored or logged.
public struct PassphraseStrength: Sendable, Equatable {
    public enum Level: Int, Sendable, Comparable, CaseIterable {
        case empty, veryWeak, weak, fair, strong, veryStrong

        public static func < (lhs: Level, rhs: Level) -> Bool { lhs.rawValue < rhs.rawValue }

        public var title: String {
            switch self {
            case .empty: "No passphrase"
            case .veryWeak: "Very weak"
            case .weak: "Weak"
            case .fair: "Fair"
            case .strong: "Strong"
            case .veryStrong: "Very strong"
            }
        }
    }

    public let level: Level
    /// Estimated entropy in bits.
    public let bits: Double
    /// A hint for improving the passphrase, if any.
    public let suggestion: String?

    private static let commonWords: Set<String> = [
        "password", "passwort", "passphrase", "qwerty", "letmein", "welcome", "admin", "secret",
        "123456", "12345678", "iloveyou", "monkey", "dragon", "sunshine", "github", "ssh",
    ]

    public static func evaluate(_ passphrase: String) -> PassphraseStrength {
        guard !passphrase.isEmpty else {
            return PassphraseStrength(
                level: .empty,
                bits: 0,
                suggestion: "Without a passphrase, anyone who copies the file can use the key."
            )
        }
        var pool = 0
        if passphrase.contains(where: \.isLowercase) { pool += 26 }
        if passphrase.contains(where: \.isUppercase) { pool += 26 }
        if passphrase.contains(where: \.isNumber) { pool += 10 }
        if passphrase.contains(where: { !$0.isLetter && !$0.isNumber }) { pool += 33 }
        if passphrase.unicodeScalars.contains(where: { !$0.isASCII }) { pool += 100 }

        // Count only "fresh" characters: long runs of the same character add little.
        var effectiveLength = 0.0
        var previous: Character?
        for character in passphrase {
            effectiveLength += character == previous ? 0.25 : 1
            previous = character
        }
        var bits = effectiveLength * log2(Double(max(pool, 2)))

        let lowered = passphrase.lowercased()
        var suggestion: String?
        if commonWords.contains(where: { lowered.contains($0) }) {
            bits -= 20
            suggestion = "Avoid common words such as “password”."
        }
        if Set(passphrase).count <= 3 {
            bits = min(bits, 15)
            suggestion = "Use more different characters."
        }
        bits = max(bits, 0)

        let level: Level
        switch bits {
        case ..<28: level = .veryWeak
        case ..<40: level = .weak
        case ..<60: level = .fair
        case ..<80: level = .strong
        default: level = .veryStrong
        }
        if suggestion == nil, level < .strong {
            suggestion = "Longer is better: try four or more random words."
        }
        return PassphraseStrength(level: level, bits: bits, suggestion: suggestion)
    }
}

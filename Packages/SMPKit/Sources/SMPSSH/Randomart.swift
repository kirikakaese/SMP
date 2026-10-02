import Foundation
import SMPCore

/// OpenSSH's "drunken bishop" fingerprint visualization, byte-for-byte compatible with
/// `ssh-keygen -lv` (SHA256 digest).
public enum Randomart {
    private static let fieldWidth = 17
    private static let fieldHeight = 9
    private static let symbols = Array(" .o+=*BOX@%&#/^SE")

    /// Renders the randomart for `key`, including the borders, as nine-plus-two lines.
    public static func render(_ key: SSHPublicKey) -> String {
        let size = key.bitLength.map { " \($0)" } ?? ""
        return render(
            digest: key.sha256Digest,
            title: "[\(key.algorithm.openSSHTypeLabel)\(size)]",
            fallbackTitle: "[\(key.algorithm.openSSHTypeLabel)]",
            hashName: "SHA256"
        )
    }

    static func render(digest: [UInt8], title: String, fallbackTitle: String, hashName: String) -> String {
        let maxSymbol = symbols.count - 1
        var field = Array(repeating: Array(repeating: 0, count: fieldHeight), count: fieldWidth)
        var x = fieldWidth / 2
        var y = fieldHeight / 2

        for byte in digest {
            var input = byte
            for _ in 0..<4 {
                x += (input & 0x1) != 0 ? 1 : -1
                y += (input & 0x2) != 0 ? 1 : -1
                x = min(max(x, 0), fieldWidth - 1)
                y = min(max(y, 0), fieldHeight - 1)
                if field[x][y] < maxSymbol - 2 {
                    field[x][y] += 1
                }
                input >>= 2
            }
        }
        field[fieldWidth / 2][fieldHeight / 2] = maxSymbol - 1
        field[x][y] = maxSymbol

        // OpenSSH formats into a 17-byte buffer: at most 16 visible characters.
        let headline = title.count > fieldWidth ? fallbackTitle : title
        var lines = [border(label: String(headline.prefix(fieldWidth - 1)))]
        for row in 0..<fieldHeight {
            var line = "|"
            for column in 0..<fieldWidth {
                line.append(symbols[min(field[column][row], maxSymbol)])
            }
            line.append("|")
            lines.append(line)
        }
        lines.append(border(label: String("[\(hashName)]".prefix(fieldWidth - 1))))
        return lines.joined(separator: "\n")
    }

    private static func border(label: String) -> String {
        let leading = (fieldWidth - label.count) / 2
        let trailing = fieldWidth - leading - label.count
        return "+" + String(repeating: "-", count: leading) + label + String(repeating: "-", count: trailing) + "+"
    }
}

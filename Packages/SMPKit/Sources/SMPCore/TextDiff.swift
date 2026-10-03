import Foundation

/// A minimal line diff (longest common subsequence), for previewing file changes before saving.
public enum TextDiff {
    public enum Line: Sendable, Equatable {
        case same(String)
        case added(String)
        case removed(String)
    }

    /// Computes the line-level differences between `old` and `new`.
    public static func lines(from old: String, to new: String) -> [Line] {
        let before = old.components(separatedBy: "\n")
        let after = new.components(separatedBy: "\n")
        // Very large files: fall back to "everything changed" instead of an O(n·m) table.
        guard before.count * after.count <= 4_000_000 else {
            return before.map(Line.removed) + after.map(Line.added)
        }
        var table = Array(repeating: Array(repeating: 0, count: after.count + 1), count: before.count + 1)
        for i in stride(from: before.count - 1, through: 0, by: -1) {
            for j in stride(from: after.count - 1, through: 0, by: -1) {
                table[i][j] = before[i] == after[j] ? table[i + 1][j + 1] + 1 : max(table[i + 1][j], table[i][j + 1])
            }
        }
        var result: [Line] = []
        var i = 0
        var j = 0
        while i < before.count, j < after.count {
            if before[i] == after[j] {
                result.append(.same(before[i]))
                i += 1
                j += 1
            } else if table[i + 1][j] >= table[i][j + 1] {
                result.append(.removed(before[i]))
                i += 1
            } else {
                result.append(.added(after[j]))
                j += 1
            }
        }
        result += before[i...].map(Line.removed) + after[j...].map(Line.added)
        return result
    }

    /// `true` if the diff contains any change.
    public static func hasChanges(_ lines: [Line]) -> Bool {
        lines.contains { if case .same = $0 { false } else { true } }
    }
}

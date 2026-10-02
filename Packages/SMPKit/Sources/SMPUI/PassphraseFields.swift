import SMPCore
import SwiftUI

/// New-passphrase entry with confirmation and a strength meter.
struct PassphraseFields: View {
    @Binding var passphrase: String
    @Binding var confirmation: String
    var title = "Passphrase"

    var body: some View {
        SecureField(title, text: $passphrase)
            .textContentType(.newPassword)
        SecureField("Confirm \(title.lowercased())", text: $confirmation)
            .textContentType(.newPassword)
        StrengthMeter(strength: PassphraseStrength.evaluate(passphrase))
        if mismatch {
            Label("The passphrases don't match.", systemImage: "xmark.circle.fill")
                .foregroundStyle(.red)
                .font(.callout)
        }
    }

    private var mismatch: Bool { !confirmation.isEmpty && confirmation != passphrase }

    /// `true` when both fields agree (both empty counts as "no passphrase").
    static func isConsistent(_ passphrase: String, _ confirmation: String) -> Bool {
        passphrase == confirmation
    }
}

struct StrengthMeter: View {
    let strength: PassphraseStrength

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                ProgressView(value: Double(strength.level.rawValue), total: 5)
                    .tint(color)
                Text(strength.level.title)
                    .font(.caption)
                    .foregroundStyle(color)
                    .frame(minWidth: 80, alignment: .leading)
            }
            if let suggestion = strength.suggestion {
                Text(suggestion)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Passphrase strength: \(strength.level.title)")
        .accessibilityHint(strength.suggestion ?? "")
    }

    private var color: Color {
        switch strength.level {
        case .empty, .veryWeak: .red
        case .weak: .orange
        case .fair: .yellow
        case .strong, .veryStrong: .green
        }
    }
}

/// An inline error box with "what happened / how to fix".
struct ErrorBanner: View {
    let error: SMPError

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(error.whatHappened, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            if let fix = error.howToFix {
                Text(fix).font(.callout).foregroundStyle(.secondary)
            }
            if let details = error.details {
                DisclosureGroup("Details") {
                    Text(details).font(.caption.monospaced()).textSelection(.enabled)
                }
                .font(.caption)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}

extension SecureBytes {
    /// Converts a passphrase typed into a `SecureField`; returns `nil` for an empty string.
    static func passphrase(_ text: String) -> SecureBytes? {
        text.isEmpty ? nil : SecureBytes(utf8: text)
    }
}

extension Error {
    /// The error as an `SMPError`, wrapping unexpected errors with a generic message.
    var asSMPError: SMPError {
        (self as? SMPError)
            ?? SMPError(.keyOperationFailed, whatHappened: "Something went wrong.", details: localizedDescription)
    }
}

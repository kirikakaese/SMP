import AppKit
import SMPCore
import SMPServices
import SMPSSH
import SwiftUI

/// Shows exactly what will change in a config file, plus validation results, before saving.
struct ConfigDiffSheet: View {
    let model: HostsModel
    let change: ConfigChange
    @Environment(\.dismiss) private var dismiss
    @State private var isSaving = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(change.summary).font(.headline)
            Text(change.file.url.path(percentEncoded: false)).font(.caption).foregroundStyle(.secondary)
            DiffView(lines: change.diff)
                .frame(minHeight: 220)
            if !change.problems.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Label(
                        "ssh reports problems with the new configuration:",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(.orange)
                    ForEach(change.problems, id: \.self) { problem in
                        Text(problem).font(.system(.caption, design: .monospaced))
                    }
                }
            }
            Text("""
                A timestamped backup of the current file is saved first. \
                If the file was changed by another program since it was loaded, nothing is written.
                """)
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") {
                    model.pendingChange = nil
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Button(change.problems.isEmpty ? String(localized: "Save") : String(localized: "Save Anyway")) {
                    Task {
                        isSaving = true
                        if await model.applyPendingChange() {
                            dismiss()
                        }
                        isSaving = false
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(isSaving || !TextDiff.hasChanges(change.diff))
            }
        }
        .padding(20)
        .frame(width: 640)
    }
}

/// A unified diff with added lines in green and removed lines in red.
struct DiffView: View {
    let lines: [TextDiff.Line]

    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(visibleLines.enumerated()), id: \.offset) { _, line in
                    row(line)
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
        .accessibilityLabel("Changes")
    }

    /// Unchanged lines far from any change are collapsed to keep the diff readable.
    private var visibleLines: [TextDiff.Line?] {
        let changed = lines.indices.filter { if case .same = lines[$0] { false } else { true } }
        guard !changed.isEmpty else { return [] }
        var result: [TextDiff.Line?] = []
        var lastShown = -1
        for index in lines.indices where changed.contains(where: { abs($0 - index) <= 3 }) {
            if lastShown >= 0, index > lastShown + 1 {
                result.append(nil)
            }
            result.append(lines[index])
            lastShown = index
        }
        return result
    }

    @ViewBuilder
    private func row(_ line: TextDiff.Line?) -> some View {
        switch line {
        case .same(let text): lineText("  " + text).foregroundStyle(.secondary)
        case .added(let text): lineText("+ " + text).foregroundStyle(.green).background(.green.opacity(0.08))
        case .removed(let text): lineText("- " + text).foregroundStyle(.red).background(.red.opacity(0.08))
        case nil: lineText("  …").foregroundStyle(.tertiary)
        }
    }

    private func lineText(_ text: String) -> some View {
        Text(text)
            .font(.system(.body, design: .monospaced))
            .frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
    }
}

/// Edits a config file as text, with syntax highlighting. Saving goes through the diff review.
struct RawConfigEditorSheet: View {
    let model: HostsModel
    let file: LoadedConfigFile
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(file.url.path(percentEncoded: false)).font(.headline)
            HighlightedConfigEditor(text: $text)
                .frame(minWidth: 640, minHeight: 420)
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
            HStack {
                Text("Unknown options are underlined in orange.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Review Changes…") {
                    model.proposeRawText(text, for: file)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(text == file.document.render())
            }
        }
        .padding(20)
        .onAppear { text = file.document.render() }
    }
}

/// An `NSTextView` that highlights SSH config syntax: comments, `Host`/`Match` lines, keywords
/// and unknown keywords.
struct HighlightedConfigEditor: NSViewRepresentable {
    @Binding var text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSTextView.scrollableTextView()
        guard let textView = scrollView.documentView as? NSTextView else { return scrollView }
        textView.delegate = context.coordinator
        textView.isRichText = false
        textView.allowsUndo = true
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.isAutomaticSpellingCorrectionEnabled = false
        textView.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        textView.string = text
        textView.setAccessibilityLabel("SSH config text")
        Self.highlight(textView)
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let textView = scrollView.documentView as? NSTextView, textView.string != text else { return }
        textView.string = text
        Self.highlight(textView)
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject, NSTextViewDelegate {
        var text: Binding<String>

        init(text: Binding<String>) {
            self.text = text
        }

        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            text.wrappedValue = textView.string
            HighlightedConfigEditor.highlight(textView)
        }
    }

    static func highlight(_ textView: NSTextView) {
        guard let storage = textView.textStorage else { return }
        let text = storage.string as NSString
        let font = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        let bold = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .semibold)
        storage.beginEditing()
        let whole = NSRange(location: 0, length: text.length)
        storage.setAttributes([.font: font, .foregroundColor: NSColor.textColor], range: whole)
        text.enumerateSubstrings(in: whole, options: .byLines) { line, range, _, _ in
            guard let line else { return }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#") {
                storage.addAttribute(.foregroundColor, value: NSColor.secondaryLabelColor, range: range)
                return
            }
            let leading = line.prefix { $0 == " " || $0 == "\t" }.utf16.count
            let keyword = trimmed.prefix { $0 != " " && $0 != "\t" && $0 != "=" }
            guard !keyword.isEmpty else { return }
            let keywordRange = NSRange(location: range.location + leading, length: keyword.utf16.count)
            let lowered = keyword.lowercased()
            if lowered == "host" || lowered == "match" {
                storage.addAttributes([.font: bold, .foregroundColor: NSColor.controlAccentColor], range: range)
            } else if SSHConfigKeywords.known.contains(lowered) {
                storage.addAttribute(.foregroundColor, value: NSColor.systemPurple, range: keywordRange)
            } else {
                storage.addAttributes([
                    .underlineStyle: NSUnderlineStyle.thick.rawValue,
                    .underlineColor: NSColor.systemOrange,
                ], range: keywordRange)
            }
        }
        storage.endEditing()
    }
}

/// Adds a new host with the common fields.
struct NewHostSheet: View {
    let model: HostsModel
    @Environment(\.dismiss) private var dismiss
    @State private var alias = ""
    @State private var hostName = ""
    @State private var user = ""
    @State private var port = ""
    @State private var identityFile = ""
    @State private var identitiesOnly = true

    var body: some View {
        Form {
            TextField("Alias", text: $alias, prompt: Text("e.g. web-prod"))
            if let problem = HostAlias.problem(with: alias), !alias.isEmpty {
                Text(problem).font(.callout).foregroundStyle(.red)
            }
            TextField("HostName", text: $hostName, prompt: Text("server.example.com"))
            TextField("User", text: $user)
            TextField("Port", text: $port, prompt: Text("22"))
            TextField("IdentityFile", text: $identityFile, prompt: Text("~/.ssh/id_ed25519"))
            Toggle("Only use this key (IdentitiesOnly)", isOn: $identitiesOnly)
        }
        .formStyle(.grouped)
        .frame(width: 440)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Review…") {
                    var options: [(keyword: String, value: String)] = [
                        ("HostName", hostName), ("User", user), ("Port", port), ("IdentityFile", identityFile),
                    ]
                    if identitiesOnly, !identityFile.isEmpty {
                        options.append(("IdentitiesOnly", "yes"))
                    }
                    model.proposeNewHost(alias: alias, options: options)
                    dismiss()
                }
                .disabled(HostAlias.problem(with: alias) != nil || model.hosts.contains { $0.alias == alias })
            }
        }
    }
}

/// Asks for a host alias (duplicate, rename).
struct AliasPromptSheet: View {
    let title: String
    let initial: String
    let onSubmit: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var alias = ""

    var body: some View {
        Form {
            TextField("Alias", text: $alias)
            if let problem = HostAlias.problem(with: alias) {
                Text(problem).font(.callout).foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .frame(width: 360)
        .navigationTitle(title)
        .onAppear { alias = initial }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Review…") {
                    onSubmit(alias)
                    dismiss()
                }
                .disabled(HostAlias.problem(with: alias) != nil)
            }
        }
    }
}

import AppKit

/// Shows the standard About panel with SMP's full product name and license.
@MainActor
public enum AboutPanel {
    public static let productName = "SSH Management Platform"
    public static let shortName = "SMP"

    public static func show() {
        let credits = NSAttributedString(
            string: """
                \(shortName) — create, organize, deploy, audit and delete SSH keys.\n\
                Released under the MIT License.
                """,
            attributes: [
                .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
                .foregroundColor: NSColor.secondaryLabelColor,
            ]
        )
        NSApplication.shared.orderFrontStandardAboutPanel(options: [
            .applicationName: productName,
            .credits: credits,
        ])
        NSApplication.shared.activate()
    }
}

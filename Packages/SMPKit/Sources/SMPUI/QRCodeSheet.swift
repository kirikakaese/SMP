import AppKit
import CoreImage.CIFilterBuiltins
import SwiftUI

/// Shows the public key as a QR code, for copying it to a phone or another machine.
struct QRCodeSheet: View {
    let item: LibraryItem
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 16) {
            Text(item.displayName).font(.headline)
            if let line = item.key.publicKey?.openSSHLine, let image = Self.qrImage(for: line) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 280, height: 280)
                    .accessibilityLabel("QR code of the public key")
                Text("Public key only. Never share the private key.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("The public key is not available.").foregroundStyle(.secondary)
            }
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(24)
    }

    static func qrImage(for text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else {
            return nil
        }
        let representation = NSCIImageRep(ciImage: output)
        let image = NSImage(size: representation.size)
        image.addRepresentation(representation)
        return image
    }
}

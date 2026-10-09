import SwiftUI

/// SMP's app icon, drawn in code so every key and style is available without shipping images.
/// The geometry matches `design/app-icon/icons.py`, which renders the bundle's default icon.
public struct AppIconArtwork: View {
    private let choice: AppIconChoice

    public init(choice: AppIconChoice) {
        self.choice = choice
    }

    public var body: some View {
        Canvas { context, size in
            let scale = min(size.width, size.height) / AppIconPainter.canvas
            context.scaleBy(x: scale, y: scale)
            AppIconPainter(choice: choice).draw(in: &context)
        }
        .aspectRatio(1, contentMode: .fit)
        .accessibilityHidden(true)
    }
}

/// Draws an icon on a 1024 x 1024 canvas, like Apple's macOS icon template: an 824-point
/// rounded square with a 100-point margin for its shadow, and a key rotated 45 degrees.
struct AppIconPainter {
    static let canvas: CGFloat = 1024
    static let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
    static let tileRadius: CGFloat = 185

    let choice: AppIconChoice

    func draw(in context: inout GraphicsContext) {
        let tilePath = Path(roundedRect: Self.tile, cornerRadius: Self.tileRadius, style: .continuous)
        context.drawLayer { layer in
            layer.addFilter(.shadow(color: .black.opacity(0.3), radius: 12, x: 0, y: 10))
            layer.drawLayer { tile in
                tile.clip(to: tilePath)
                drawBackground(in: &tile)
                tile.fill(Path(Self.tile), with: .linearGradient(
                    Gradient(stops: [
                        .init(color: .white.opacity(0.2), location: 0),
                        .init(color: .white.opacity(0), location: 0.5),
                    ]),
                    startPoint: CGPoint(x: 512, y: Self.tile.minY),
                    endPoint: CGPoint(x: 512, y: Self.tile.maxY)
                ))
            }
            let rim = Path(
                roundedRect: Self.tile.insetBy(dx: 1, dy: 1),
                cornerRadius: Self.tileRadius - 1,
                style: .continuous
            )
            layer.stroke(rim, with: .color(.white.opacity(0.16)), lineWidth: 2)
        }
        drawKey(in: &context)
    }

    private func drawBackground(in context: inout GraphicsContext) {
        if let colors = AppIconPalette.gradient(choice.style) {
            context.fill(Path(Self.tile), with: .linearGradient(
                Gradient(colors: colors),
                startPoint: CGPoint(x: 512, y: Self.tile.minY),
                endPoint: CGPoint(x: 512, y: Self.tile.maxY)
            ))
            return
        }
        let stripes = AppIconPalette.stripes(choice.style)
        let total = stripes.reduce(0) { $0 + $1.weight }
        var top = Self.tile.minY
        for stripe in stripes {
            let height = Self.tile.height * stripe.weight / total
            // Half a point of overlap, so no background shows between stripes.
            let rect = CGRect(x: Self.tile.minX, y: top, width: Self.tile.width, height: height + 0.5)
            context.fill(Path(rect), with: .color(stripe.color))
            top += height
        }
        if choice.style == .progress {
            drawProgressChevron(in: &context)
        }
    }

    /// The Progress Pride flag's chevron: nested triangles from the left edge, outermost first.
    private func drawProgressChevron(in context: inout GraphicsContext) {
        let tile = Self.tile
        for (index, color) in AppIconPalette.progressChevron.enumerated() {
            let step = CGFloat(index) * 0.075
            let tip = tile.minX + tile.width * (0.46 - step)
            let left = tile.minX - tile.width * step - 1
            var triangle = Path()
            triangle.move(to: CGPoint(x: left, y: tile.minY))
            triangle.addLine(to: CGPoint(x: tip, y: tile.midY))
            triangle.addLine(to: CGPoint(x: left, y: tile.maxY))
            triangle.closeSubpath()
            context.fill(triangle, with: .color(color))
        }
    }

    private func drawKey(in context: inout GraphicsContext) {
        let geometry = AppIconKeyGeometry(shape: choice.shape)
        let key = geometry.keyPath
        let onFlag = AppIconPalette.gradient(choice.style) == nil
        let colors = (choice.style == .blue || onFlag) ? AppIconPalette.whiteKey : AppIconPalette.goldKey
        context.drawLayer { layer in
            layer.addFilter(.shadow(color: .black.opacity(onFlag ? 0.55 : 0.4), radius: 16, x: 0, y: 16))
            if onFlag {
                // A dark rim keeps the white key visible on light stripes.
                layer.stroke(key, with: .color(.black.opacity(0.35)), lineWidth: 20)
            }
            layer.fill(key, with: .linearGradient(
                Gradient(stops: [
                    .init(color: colors[0], location: 0),
                    .init(color: colors[1], location: 0.5),
                    .init(color: colors[2], location: 1),
                ]),
                startPoint: CGPoint(x: 230, y: 230),
                endPoint: CGPoint(x: 800, y: 800)
            ))
            layer.fill(geometry.marksPath, with: .color(.black.opacity(0.22)))
        }
    }
}

/// The keys, built from simple shapes in a horizontal layout (bow on the left), then moved,
/// scaled and rotated 45 degrees about the center of the canvas.
struct AppIconKeyGeometry {
    private enum Part {
        case roundedRect(CGRect, radius: CGFloat)
        case circle(center: CGPoint, radius: CGFloat)
        case polygon([CGPoint])

        var path: Path {
            switch self {
            case .roundedRect(let rect, let radius):
                Path(roundedRect: rect, cornerRadius: radius, style: .circular)
            case .circle(let center, let radius):
                Path(ellipseIn: CGRect(x: center.x, y: center.y, width: 0, height: 0).insetBy(dx: -radius, dy: -radius))
            case .polygon(let points):
                Path { path in
                    path.addLines(points)
                    path.closeSubpath()
                }
            }
        }
    }

    private let solid: [Part]
    private let holes: [Part]
    private let marks: [Part]
    private let transform: CGAffineTransform

    init(shape: AppIconShape) {
        var offset = CGSize.zero
        var scale: CGFloat = 1
        switch shape {
        case .modern:
            offset = CGSize(width: -5, height: 0)
            scale = 0.9
            let blade: [(CGFloat, CGFloat)] = [
                (460, 452), (790, 452), (834, 512), (790, 572), (760, 572), (734, 542), (708, 572),
                (682, 542), (656, 572), (630, 542), (604, 572), (460, 572),
            ]
            solid = [
                .roundedRect(CGRect(x: 200, y: 322, width: 270, height: 380), radius: 70),
                .polygon(blade.map { CGPoint(x: $0.0, y: $0.1) }),
            ]
            holes = [.circle(center: CGPoint(x: 300, y: 512), radius: 38)]
            marks = []
        case .classic:
            offset = CGSize(width: 14, height: -10)
            solid = [
                .circle(center: CGPoint(x: 300, y: 512), radius: 140),
                .roundedRect(CGRect(x: 420, y: 470, width: 402, height: 84), radius: 22),
                .roundedRect(CGRect(x: 734, y: 520, width: 56, height: 134), radius: 14),
                .roundedRect(CGRect(x: 660, y: 520, width: 56, height: 116), radius: 14),
                .roundedRect(CGRect(x: 700, y: 520, width: 50, height: 80), radius: 0),
            ]
            holes = [.circle(center: CGPoint(x: 300, y: 512), radius: 50)]
            marks = []
        case .symbol:
            offset = CGSize(width: 19, height: -14)
            solid = [
                .circle(center: CGPoint(x: 330, y: 512), radius: 160),
                .roundedRect(CGRect(x: 450, y: 466, width: 366, height: 92), radius: 46),
                .roundedRect(CGRect(x: 714, y: 520, width: 46, height: 152), radius: 22),
                .roundedRect(CGRect(x: 596, y: 520, width: 46, height: 120), radius: 22),
            ]
            holes = [.circle(center: CGPoint(x: 330, y: 512), radius: 56)]
            marks = []
        case .securityKey:
            // A generic USB security key: body with a key-ring hole and a touch button, and a plug.
            offset = CGSize(width: -18, height: 0)
            solid = [
                .roundedRect(CGRect(x: 230, y: 420, width: 470, height: 184), radius: 64),
                .roundedRect(CGRect(x: 680, y: 452, width: 150, height: 120), radius: 12),
            ]
            holes = [
                .circle(center: CGPoint(x: 292, y: 512), radius: 30),
                .roundedRect(CGRect(x: 744, y: 478, width: 34, height: 24), radius: 4),
                .roundedRect(CGRect(x: 744, y: 522, width: 34, height: 24), radius: 4),
            ]
            marks = [.circle(center: CGPoint(x: 530, y: 512), radius: 58)]
        }
        let center = AppIconPainter.canvas / 2
        transform = CGAffineTransform(translationX: -center, y: -center)
            .concatenating(CGAffineTransform(scaleX: scale, y: scale))
            .concatenating(CGAffineTransform(translationX: offset.width, y: offset.height))
            .concatenating(CGAffineTransform(rotationAngle: .pi / 4))
            .concatenating(CGAffineTransform(translationX: center, y: center))
    }

    /// The key's outline with its holes cut out.
    var keyPath: Path {
        let body = solid.dropFirst().reduce(solid[0].path) { $0.union($1.path) }
        let cutouts = holes.reduce(Path()) { $0.union($1.path) }
        return body.subtracting(cutouts).applying(transform)
    }

    /// Details drawn darker on top of the key, like a security key's touch button.
    var marksPath: Path {
        marks.reduce(Path()) { $0.union($1.path) }.applying(transform)
    }
}

/// The colors of each style. Flags follow their commonly used versions.
enum AppIconPalette {
    struct Stripe {
        let color: Color
        let weight: CGFloat
    }

    static let goldKey: [Color] = [Color(hex: 0xFFE9A8), Color(hex: 0xE6B43A), Color(hex: 0xB8840F)]
    static let whiteKey: [Color] = [Color(hex: 0xFFFFFF), Color(hex: 0xEEF2F8), Color(hex: 0xC8D1DE)]
    /// Black, brown, light blue, pink and white.
    static let progressChevron: [Color] = ([0x000000, 0x784F17, 0x5BCEFA, 0xF5A9B8, 0xFFFFFF] as [UInt32])
        .map { Color(hex: $0) }

    /// The top-to-bottom gradient of a plain style, or `nil` for a flag.
    static func gradient(_ style: AppIconStyle) -> [Color]? {
        switch style {
        case .graphite: [Color(hex: 0x5B616B), Color(hex: 0x24282E)]
        case .blue: [Color(hex: 0x4F9BFF), Color(hex: 0x0B4FD0)]
        case .silver: [Color(hex: 0xFBFBFD), Color(hex: 0xC7CCD4)]
        default: nil
        }
    }

    /// A flag's stripes from top to bottom.
    static func stripes(_ style: AppIconStyle) -> [Stripe] {
        let colors: [UInt32]
        switch style {
        case .rainbow, .progress: colors = [0xE40303, 0xFF8C00, 0xFFED00, 0x008026, 0x004DFF, 0x750787]
        case .transgender: colors = [0x5BCEFA, 0xF5A9B8, 0xFFFFFF, 0xF5A9B8, 0x5BCEFA]
        case .nonbinary: colors = [0xFCF434, 0xFFFFFF, 0x9C59D1, 0x2C2C2C]
        case .bisexual:
            return [
                Stripe(color: Color(hex: 0xD60270), weight: 2),
                Stripe(color: Color(hex: 0x9B4F96), weight: 1),
                Stripe(color: Color(hex: 0x0038A8), weight: 2),
            ]
        case .pansexual: colors = [0xFF218C, 0xFFD800, 0x21B1FF]
        case .lesbian: colors = [0xD52D00, 0xEF7627, 0xFF9A56, 0xFFFFFF, 0xD162A4, 0xB55690, 0xA30262]
        case .asexual: colors = [0x000000, 0xA3A3A3, 0xFFFFFF, 0x800080]
        case .aromantic: colors = [0x3DA542, 0xA7D379, 0xFFFFFF, 0xA9A9A9, 0x000000]
        case .graphite, .blue, .silver: colors = []
        }
        return colors.map { Stripe(color: Color(hex: $0), weight: 1) }
    }
}

private extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }
}

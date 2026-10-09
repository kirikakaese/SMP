import AppKit
import Observation
import SwiftUI

/// The key drawn on SMP's app icon.
public enum AppIconShape: String, CaseIterable, Identifiable, Sendable {
    case modern
    case classic
    case symbol
    case securityKey

    public var id: String { rawValue }

    public var title: LocalizedStringKey {
        switch self {
        case .modern: "Modern"
        case .classic: "Classic"
        case .symbol: "Symbol"
        case .securityKey: "Security Key"
        }
    }
}

/// The tile behind the key: a color, or a pride flag.
public enum AppIconStyle: String, CaseIterable, Identifiable, Sendable {
    case graphite
    case blue
    case silver
    case rainbow
    case progress
    case transgender
    case nonbinary
    case bisexual
    case pansexual
    case lesbian
    case asexual
    case aromantic

    public var id: String { rawValue }

    public static let colors: [AppIconStyle] = [.graphite, .blue, .silver]
    public static let pride: [AppIconStyle] = allCases.filter { !colors.contains($0) }

    public var title: LocalizedStringKey {
        switch self {
        case .graphite: "Graphite"
        case .blue: "Blue"
        case .silver: "Silver"
        case .rainbow: "Rainbow"
        case .progress: "Progress Pride"
        case .transgender: "Transgender"
        case .nonbinary: "Nonbinary"
        case .bisexual: "Bisexual"
        case .pansexual: "Pansexual"
        case .lesbian: "Lesbian"
        case .asexual: "Asexual"
        case .aromantic: "Aromantic"
        }
    }
}

/// One app icon: a key shape on a style.
public struct AppIconChoice: Equatable, Sendable {
    public var shape: AppIconShape
    public var style: AppIconStyle

    public init(shape: AppIconShape, style: AppIconStyle) {
        self.shape = shape
        self.style = style
    }

    /// The icon in the app bundle, which Finder, Launchpad and the Dock show while SMP isn't running.
    public static let standard = AppIconChoice(shape: .modern, style: .graphite)

    public var isStandard: Bool { self == .standard }
}

/// The app icon the user picked in Settings. macOS has no alternate app icons, so SMP shows the
/// choice in the Dock while it runs; the bundle (and its signature) stays untouched.
@MainActor
@Observable
public final class AppIconModel {
    private static let shapeKey = "appIcon.shape"
    private static let styleKey = "appIcon.style"

    public var choice: AppIconChoice {
        didSet {
            guard choice != oldValue else { return }
            defaults.set(choice.shape.rawValue, forKey: Self.shapeKey)
            defaults.set(choice.style.rawValue, forKey: Self.styleKey)
            apply()
        }
    }

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let setDockIcon: @MainActor (NSImage?) -> Void

    /// - Parameter setDockIcon: Shows an icon in the Dock; `nil` restores the bundle's icon.
    public init(
        defaults: UserDefaults = .standard,
        setDockIcon: @escaping @MainActor (NSImage?) -> Void = { NSApplication.shared.applicationIconImage = $0 }
    ) {
        self.defaults = defaults
        self.setDockIcon = setDockIcon
        let shape = defaults.string(forKey: Self.shapeKey).flatMap(AppIconShape.init(rawValue:))
        let style = defaults.string(forKey: Self.styleKey).flatMap(AppIconStyle.init(rawValue:))
        choice = AppIconChoice(
            shape: shape ?? AppIconChoice.standard.shape,
            style: style ?? AppIconChoice.standard.style
        )
    }

    /// Shows the chosen icon in the Dock. Called once SMP has finished launching and on every change.
    public func apply() {
        setDockIcon(choice.isStandard ? nil : Self.image(for: choice))
    }

    public func restoreDefault() {
        choice = .standard
    }

    /// Renders an icon. `size` is in points; the image has twice as many pixels.
    public static func image(for choice: AppIconChoice, size: CGFloat = 512) -> NSImage? {
        let renderer = ImageRenderer(content: AppIconArtwork(choice: choice).frame(width: size, height: size))
        renderer.scale = 2
        return renderer.nsImage
    }
}

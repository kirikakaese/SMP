import AppKit
import Testing

@testable import SMPUI

@MainActor
@Suite("App icon")
struct AppIconModelTests {
    /// Records what the model would show in the Dock.
    private final class Dock {
        var icons: [NSImage?] = []
    }

    private func defaults() -> UserDefaults {
        UserDefaults(suiteName: "smp-icon-\(UUID().uuidString)") ?? .standard
    }

    @Test func startsWithTheStandardIconAndKeepsTheBundleIconInTheDock() {
        let dock = Dock()
        let model = AppIconModel(defaults: defaults()) { dock.icons.append($0) }
        #expect(model.choice == .standard)
        #expect(model.choice == AppIconChoice(shape: .modern, style: .graphite))
        model.apply()
        #expect(dock.icons.count == 1)
        #expect(dock.icons.first == .some(nil))
    }

    @Test func showsAndRemembersAnotherIcon() throws {
        let store = defaults()
        let dock = Dock()
        let model = AppIconModel(defaults: store) { dock.icons.append($0) }
        model.choice = AppIconChoice(shape: .securityKey, style: .transgender)

        let shown = try #require(dock.icons.last.flatMap { $0 })
        let pixels = try #require(shown.cgImage(forProposedRect: nil, context: nil, hints: nil))
        #expect(pixels.width == 1024)
        #expect(pixels.height == 1024)

        let reopened = AppIconModel(defaults: store) { _ in }
        #expect(reopened.choice == AppIconChoice(shape: .securityKey, style: .transgender))
    }

    @Test func restoringTheDefaultHandsTheDockBackToTheBundleIcon() {
        let dock = Dock()
        let model = AppIconModel(defaults: defaults()) { dock.icons.append($0) }
        model.choice.style = .rainbow
        model.restoreDefault()
        #expect(model.choice.isStandard)
        #expect(dock.icons.last == .some(nil))
    }

    @Test func settingTheSameIconAgainChangesNothing() {
        let dock = Dock()
        let model = AppIconModel(defaults: defaults()) { dock.icons.append($0) }
        model.choice = .standard
        #expect(dock.icons.isEmpty)
    }

    @Test func ignoresUnknownStoredValues() {
        let store = defaults()
        store.set("hexagon", forKey: "appIcon.shape")
        store.set("plaid", forKey: "appIcon.style")
        let model = AppIconModel(defaults: store) { _ in }
        #expect(model.choice == .standard)
    }

    @Test func drawsEveryKeyOnEveryStyle() throws {
        #expect(AppIconStyle.colors.count + AppIconStyle.pride.count == AppIconStyle.allCases.count)
        for shape in AppIconShape.allCases {
            for style in AppIconStyle.allCases {
                let image = try #require(AppIconModel.image(for: AppIconChoice(shape: shape, style: style), size: 32))
                let pixels = try #require(image.cgImage(forProposedRect: nil, context: nil, hints: nil))
                #expect(pixels.width == 64, "\(shape) on \(style)")
            }
        }
    }

    @Test func everyFlagHasStripes() {
        for style in AppIconStyle.pride {
            #expect(AppIconPalette.gradient(style) == nil, "\(style)")
            #expect(!AppIconPalette.stripes(style).isEmpty, "\(style)")
        }
        for style in AppIconStyle.colors {
            #expect(AppIconPalette.gradient(style) != nil, "\(style)")
        }
    }
}

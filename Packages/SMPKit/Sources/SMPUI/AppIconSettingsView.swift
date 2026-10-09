import SwiftUI

/// Settings → App Icon: pick a key and a color or pride flag for SMP's Dock icon.
struct AppIconSettingsView: View {
    @Bindable var model: AppIconModel

    var body: some View {
        Form {
            Section {
                HStack(spacing: 16) {
                    AppIconArtwork(choice: model.choice)
                        .frame(width: 88, height: 88)
                    VStack(alignment: .leading, spacing: 8) {
                        Text("""
                            SMP shows this icon in the Dock while it's running. Finder and Launchpad keep the \
                            standard icon.
                            """)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Restore Default") { model.restoreDefault() }
                            .disabled(model.choice.isStandard)
                    }
                }
            }
            Section("Key") {
                optionGrid(columns: 4) {
                    ForEach(AppIconShape.allCases) { shape in
                        AppIconOption(
                            choice: AppIconChoice(shape: shape, style: model.choice.style),
                            title: shape.title,
                            isSelected: model.choice.shape == shape
                        ) { model.choice.shape = shape }
                    }
                }
            }
            Section("Colors") {
                optionGrid(columns: 5) { styleOptions(AppIconStyle.colors) }
            }
            Section("Pride") {
                optionGrid(columns: 5) { styleOptions(AppIconStyle.pride) }
            }
        }
        .formStyle(.grouped)
    }

    private func optionGrid(columns: Int, @ViewBuilder content: () -> some View) -> some View {
        let options = content()
        return LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 8), count: columns), spacing: 12) {
            options
        }
        .padding(.vertical, 4)
    }

    private func styleOptions(_ styles: [AppIconStyle]) -> some View {
        ForEach(styles) { style in
            AppIconOption(
                choice: AppIconChoice(shape: model.choice.shape, style: style),
                title: style.title,
                isSelected: model.choice.style == style
            ) { model.choice.style = style }
        }
    }
}

/// One selectable icon with its name below.
private struct AppIconOption: View {
    let choice: AppIconChoice
    let title: LocalizedStringKey
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 4) {
                AppIconArtwork(choice: choice)
                    .frame(width: 48, height: 48)
                    .padding(3)
                    .background {
                        RoundedRectangle(cornerRadius: 13, style: .continuous)
                            .strokeBorder(isSelected ? Color.accentColor : .clear, lineWidth: 2.5)
                    }
                Text(title)
                    .font(.caption)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            .frame(maxWidth: .infinity)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}

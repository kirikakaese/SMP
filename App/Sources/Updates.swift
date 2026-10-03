import Foundation
import Observation
import Sparkle
import SwiftUI

/// Lets Sparkle offer beta versions when the user opted in.
final class UpdaterDelegate: NSObject, SPUUpdaterDelegate {
    static let includeBetaKey = "updates.includeBeta"

    func allowedChannels(for updater: SPUUpdater) -> Set<String> {
        UserDefaults.standard.bool(forKey: Self.includeBetaKey) ? ["beta"] : []
    }
}

/// SMP's update manager. Sparkle downloads updates from the GitHub release feed and installs
/// them only if they carry a valid EdDSA signature from SMP's release key. Builds without that
/// key (local builds) never check for updates.
@MainActor
@Observable
final class UpdateModel {
    enum Interval: Double, CaseIterable, Identifiable {
        case daily = 86_400
        case weekly = 604_800
        case monthly = 2_592_000

        var id: Double { rawValue }

        var title: LocalizedStringKey {
            switch self {
            case .daily: "Daily"
            case .weekly: "Weekly"
            case .monthly: "Monthly"
            }
        }
    }

    /// `false` in builds without SMP's update key.
    let isAvailable: Bool
    var automaticallyChecks: Bool {
        didSet { updater?.automaticallyChecksForUpdates = automaticallyChecks }
    }
    var interval: Interval {
        didSet { updater?.updateCheckInterval = interval.rawValue }
    }
    var automaticallyInstalls: Bool {
        didSet { updater?.automaticallyDownloadsUpdates = automaticallyInstalls }
    }
    var includeBeta: Bool {
        didSet { UserDefaults.standard.set(includeBeta, forKey: UpdaterDelegate.includeBetaKey) }
    }
    private(set) var lastCheck: Date?

    @ObservationIgnored private let controller: SPUStandardUpdaterController?
    @ObservationIgnored private let delegate: UpdaterDelegate

    private var updater: SPUUpdater? { controller?.updater }

    init(bundle: Bundle = .main) {
        let key = bundle.object(forInfoDictionaryKey: "SUPublicEDKey") as? String ?? ""
        let delegate = UpdaterDelegate()
        self.delegate = delegate
        isAvailable = !key.trimmingCharacters(in: .whitespaces).isEmpty
        controller = isAvailable
            ? SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: delegate, userDriverDelegate: nil)
            : nil
        let updater = controller?.updater
        automaticallyChecks = updater?.automaticallyChecksForUpdates ?? false
        interval = Interval.allCases.min {
            abs($0.rawValue - (updater?.updateCheckInterval ?? 86_400))
                < abs($1.rawValue - (updater?.updateCheckInterval ?? 86_400))
        } ?? .daily
        automaticallyInstalls = updater?.automaticallyDownloadsUpdates ?? false
        includeBeta = UserDefaults.standard.bool(forKey: UpdaterDelegate.includeBetaKey)
        lastCheck = updater?.lastUpdateCheckDate
    }

    var canCheck: Bool { updater?.canCheckForUpdates ?? false }

    func checkNow() {
        controller?.checkForUpdates(nil)
        lastCheck = updater?.lastUpdateCheckDate
    }

    func refresh() {
        lastCheck = updater?.lastUpdateCheckDate
    }
}

/// Settings → Updates.
struct UpdateSettingsView: View {
    @Bindable var model: UpdateModel

    var body: some View {
        Form {
            if model.isAvailable {
                Toggle("Check for updates automatically", isOn: $model.automaticallyChecks)
                Picker("Check", selection: $model.interval) {
                    ForEach(UpdateModel.Interval.allCases) { Text($0.title).tag($0) }
                }
                .disabled(!model.automaticallyChecks)
                Toggle("Download and install updates automatically", isOn: $model.automaticallyInstalls)
                    .disabled(!model.automaticallyChecks)
                Toggle("Include beta versions", isOn: $model.includeBeta)
                LabeledContent("Last checked") {
                    if let lastCheck = model.lastCheck {
                        Text(lastCheck, format: .relative(presentation: .named))
                    } else {
                        Text("Never")
                    }
                }
                Button("Check Now") { model.checkNow() }
                    .disabled(!model.canCheck)
                Text("""
                    Updates come from SMP's GitHub releases and are installed only if they are signed \
                    with SMP's release key. When an update is installed automatically, it takes effect \
                    the next time SMP quits.
                    """)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("This build of SMP was not made by the release workflow, so it does not update itself.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .onAppear { model.refresh() }
    }
}

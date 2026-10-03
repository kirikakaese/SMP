import SMPCore
import SwiftUI
import UniformTypeIdentifiers

/// The Settings window.
public struct SettingsView: View {
    private let library: LibraryModel
    private let appLock: AppLockModel

    public init(library: LibraryModel, appLock: AppLockModel) {
        self.library = library
        self.appLock = appLock
    }

    public var body: some View {
        TabView {
            GeneralSettingsView(library: library)
                .tabItem { Label("General", systemImage: "gearshape") }
            AppLockSettingsView(appLock: appLock)
                .tabItem { Label("App Lock", systemImage: "lock") }
            KeyFoldersSettingsView(library: library)
                .tabItem { Label("Key Folders", systemImage: "folder") }
        }
        .frame(width: 520, height: 340)
    }
}

struct GeneralSettingsView: View {
    let library: LibraryModel
    @AppStorage("terminalApp") private var terminalApp: TerminalApp = .terminal

    var body: some View {
        Form {
            Picker("Open connections in", selection: $terminalApp) {
                ForEach(TerminalApp.allCases) { app in
                    let installed = library.services.terminal.installedApps().contains(app)
                    Text(installed ? app.displayName : "\(app.displayName) (not installed)").tag(app)
                }
            }
            LabeledContent("Privacy") {
                Text("SMP collects no telemetry.")
                    .foregroundStyle(.secondary)
            }
            LabeledContent("Introduction") {
                Button("Show at Next Launch") { OnboardingState.setCompleted(false) }
            }
        }
        .formStyle(.grouped)
    }
}

struct AppLockSettingsView: View {
    @Bindable var appLock: AppLockModel

    var body: some View {
        Form {
            if appLock.isAvailable {
                Toggle("Lock SMP with Touch ID or password", isOn: $appLock.settings.isEnabled)
                IdleLockPicker(settings: $appLock.settings)
                    .disabled(!appLock.settings.isEnabled)
                Button("Lock Now") { appLock.lock() }
                    .disabled(!appLock.settings.isEnabled)
            } else {
                Text("The app lock needs a login password on this Mac.")
                    .foregroundStyle(.secondary)
            }
            Text("SMP also locks when your screen locks or the Mac goes to sleep. Deleting or exporting keys "
                + "always asks again, whether the lock is on or not.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
    }
}

/// Lets the user add folders that SMP scans for keys, in addition to ~/.ssh.
struct KeyFoldersSettingsView: View {
    let library: LibraryModel

    @State private var selection: URL?
    @State private var isImporting = false

    var body: some View {
        Form {
            Section {
                LabeledContent("Always scanned") {
                    Text("~/.ssh").foregroundStyle(.secondary)
                }
                List(library.additionalFolders, id: \.self, selection: $selection) { folder in
                    Label(folder.path(percentEncoded: false), systemImage: "folder")
                }
                .frame(minHeight: 120)
                HStack {
                    Button("Add Folder…") { isImporting = true }
                    Button("Remove", role: .destructive) {
                        guard let selection else { return }
                        let remaining = library.additionalFolders.filter { $0 != selection }
                        self.selection = nil
                        Task { await library.setAdditionalFolders(remaining) }
                    }
                    .disabled(selection == nil)
                }
            } footer: {
                Text(
                    "Folders are scanned without subfolders and watched for changes. "
                        + "Removing a folder never deletes keys."
                )
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .fileImporter(
            isPresented: $isImporting,
            allowedContentTypes: [.folder],
            allowsMultipleSelection: true
        ) { result in
            guard case .success(let urls) = result else { return }
            Task { await library.setAdditionalFolders(library.additionalFolders + urls) }
        }
    }
}

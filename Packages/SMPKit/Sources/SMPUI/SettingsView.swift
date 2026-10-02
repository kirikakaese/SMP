import SwiftUI
import UniformTypeIdentifiers

/// The Settings window.
public struct SettingsView: View {
    private let library: LibraryModel

    public init(library: LibraryModel) {
        self.library = library
    }

    public var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem { Label("General", systemImage: "gearshape") }
            KeyFoldersSettingsView(library: library)
                .tabItem { Label("Key Folders", systemImage: "folder") }
        }
        .frame(width: 520, height: 340)
    }
}

struct GeneralSettingsView: View {
    var body: some View {
        Form {
            LabeledContent("Privacy") {
                Text("SMP collects no telemetry.")
                    .foregroundStyle(.secondary)
            }
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

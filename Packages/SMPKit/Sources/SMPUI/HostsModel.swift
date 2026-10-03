import AppKit
import Foundation
import Observation
import SMPCore
import SMPServices
import SMPSSH

/// A proposed change to a config file, shown as a diff before it is written.
public struct ConfigChange: Identifiable, Sendable {
    public let id = UUID()
    public let file: LoadedConfigFile
    public let newText: String
    public let summary: String
    /// Validation problems reported by `ssh -G` for the new text.
    public var problems: [String] = []
    /// For renames: the old and new alias, so host metadata can follow the rename.
    var renamedAlias: (old: String, new: String)?
    /// For deletions: the alias whose metadata is removed with the host.
    var deletedAlias: String?

    public var diff: [TextDiff.Line] { TextDiff.lines(from: file.document.render(), to: newText) }
}

/// State behind the Hosts section: hosts from ~/.ssh/config, edits with diff preview, connection tests.
@MainActor
@Observable
public final class HostsModel {
    public private(set) var files: [LoadedConfigFile] = []
    public private(set) var hosts: [HostEntry] = []
    public private(set) var metadata: [String: HostMetadata] = [:]
    public private(set) var hostTags: [String: Set<Int64>] = [:]
    public private(set) var testResults: [String: ConnectionTestResult] = [:]
    public private(set) var testsRunning: Set<String> = []
    public var selectedHostID: String?
    public var searchText = ""
    public var pendingChange: ConfigChange?
    public var lastError: SMPError?
    public var notice: String?

    @ObservationIgnored let services: ServiceContainer

    public init(services: ServiceContainer) {
        self.services = services
    }

    // MARK: Derived

    public var visibleHosts: [HostEntry] {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        let filtered = query.isEmpty ? hosts : hosts.filter { host in
            ([host.alias, host.block.value(of: "HostName") ?? "", host.block.value(of: "User") ?? ""]
                + host.block.patterns)
                .contains { $0.localizedCaseInsensitiveContains(query) }
        }
        return filtered.sorted { lhs, rhs in
            let lhsFavorite = metadata[lhs.alias]?.isFavorite ?? false
            let rhsFavorite = metadata[rhs.alias]?.isFavorite ?? false
            if lhsFavorite != rhsFavorite { return lhsFavorite }
            if lhs.block.isWildcard != rhs.block.isWildcard { return !lhs.block.isWildcard }
            return lhs.alias.localizedStandardCompare(rhs.alias) == .orderedAscending
        }
    }

    public var selectedHost: HostEntry? { hosts.first { $0.id == selectedHostID } }

    /// Aliases that can be connected to directly (no wildcards).
    public var connectableAliases: [String] {
        hosts.filter { !$0.block.isWildcard }.map(\.alias).sorted()
    }

    public var mainConfigFile: LoadedConfigFile? { files.first }

    // MARK: Loading

    public func reload() {
        do {
            files = try services.hosts.loadFiles()
            hosts = try services.hosts.hosts()
            metadata = try services.metadata.allHostMetadata()
            hostTags = try services.metadata.hostTagAssignments()
            if let selectedHostID, !hosts.contains(where: { $0.id == selectedHostID }) {
                self.selectedHostID = nil
            }
        } catch {
            lastError = error.asSMPError
        }
    }

    // MARK: Editing (always via a reviewed diff)

    /// Proposes setting `keyword` on a host; shows the diff for confirmation.
    public func proposeSet(_ keyword: String, to values: [String], on host: HostEntry) {
        propose(on: host, summary: "Change \(keyword) of \(host.alias)") { document in
            document.setValues(values, for: keyword, inBlockAt: host.block.headerLine)
        }
    }

    /// Proposes several field changes at once (from the host card's Save button).
    public func proposeEdits(_ edits: [(keyword: String, values: [String])], on host: HostEntry) {
        propose(on: host, summary: "Update \(host.alias)") { document in
            for edit in edits {
                // Headers move when lines are inserted above; look the block up by its header each time.
                document.setValues(edit.values, for: edit.keyword, inBlockAt: host.block.headerLine)
            }
        }
    }

    public func proposeNewHost(alias: String, options: [(keyword: String, value: String)]) {
        guard let file = mainConfigFile ?? emptyMainFile() else { return }
        if let problem = HostAlias.problem(with: alias) {
            lastError = SMPError.invalidArgument(problem)
            return
        }
        var document = file.document
        document.appendHostBlock(patterns: [alias], options: options.filter { !$0.value.isEmpty })
        stage(ConfigChange(file: file, newText: document.render(), summary: "Add host \(alias)"))
    }

    public func proposeDuplicate(_ host: HostEntry, as alias: String) {
        if let problem = HostAlias.problem(with: alias) {
            lastError = SMPError.invalidArgument(problem)
            return
        }
        propose(on: host, summary: "Duplicate \(host.alias) as \(alias)") { document in
            document.duplicateBlock(at: host.block.headerLine, as: [alias])
        }
    }

    public func proposeRename(_ host: HostEntry, to alias: String) {
        if let problem = HostAlias.problem(with: alias) {
            lastError = SMPError.invalidArgument(problem)
            return
        }
        let otherPatterns = Array(host.block.patterns.dropFirst())
        propose(on: host, summary: "Rename \(host.alias) to \(alias)", renaming: (host.alias, alias)) { document in
            document.setPatterns([alias] + otherPatterns, forBlockAt: host.block.headerLine)
        }
    }

    public func proposeDelete(_ host: HostEntry) {
        // Other blocks may share the alias (e.g. in an included file); keep their metadata then.
        let isLastBlock = hosts.filter { $0.alias == host.alias }.count == 1
        propose(on: host, summary: "Delete host \(host.alias)", deleting: isLastBlock ? host.alias : nil) { document in
            document.removeBlock(at: host.block.headerLine)
        }
    }

    /// Proposes replacing a whole file with text edited in the raw editor.
    public func proposeRawText(_ text: String, for file: LoadedConfigFile) {
        stage(ConfigChange(file: file, newText: text, summary: "Edit \(file.url.lastPathComponent)"))
    }

    /// Writes the reviewed change (with backup), then reloads.
    public func applyPendingChange() async -> Bool {
        guard let change = pendingChange else { return false }
        do {
            try services.hosts.save(change.newText, to: change.file)
            if let renamed = change.renamedAlias {
                try? services.metadata.renameHost(from: renamed.old, to: renamed.new)
            }
            if let deleted = change.deletedAlias {
                try? services.metadata.deleteHostMetadata(alias: deleted)
            }
            pendingChange = nil
            notice = "Saved \(change.file.url.lastPathComponent). A backup of the previous version was kept."
            reload()
            return true
        } catch {
            lastError = error.asSMPError
            return false
        }
    }

    private func propose(
        on host: HostEntry,
        summary: String,
        renaming: (old: String, new: String)? = nil,
        deleting: String? = nil,
        edit: (inout SSHConfigDocument) -> Void
    ) {
        guard let file = files.first(where: { $0.url == host.file }) else { return }
        var document = file.document
        edit(&document)
        var change = ConfigChange(file: file, newText: document.render(), summary: summary)
        change.renamedAlias = renaming
        change.deletedAlias = deleting
        stage(change)
    }

    private func stage(_ change: ConfigChange) {
        pendingChange = change
        let hosts = services.hosts
        Task {
            var validated = change
            validated.problems = (try? await hosts.validate(change.newText)) ?? []
            if pendingChange?.id == validated.id {
                pendingChange = validated
            }
        }
    }

    private func emptyMainFile() -> LoadedConfigFile? {
        LoadedConfigFile(url: services.environment.configFile, document: SSHConfigDocument(text: ""), snapshot: nil)
    }

    // MARK: Actions

    public func testConnection(_ host: HostEntry) async {
        testsRunning.insert(host.alias)
        defer { testsRunning.remove(host.alias) }
        testResults[host.alias] = await services.hosts.testConnection(alias: host.alias)
    }

    public func connect(_ host: HostEntry, in app: TerminalApp) {
        do {
            try services.terminal.connect(to: host.alias, in: app)
            var entry = metadata[host.alias] ?? HostMetadata(alias: host.alias)
            entry.lastConnectedAt = Date()
            try? services.metadata.saveHostMetadata(entry)
            metadata[host.alias] = entry
        } catch {
            lastError = error.asSMPError
        }
    }

    public func copyCommand(_ host: HostEntry) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(HostService.sshCommand(for: host.alias), forType: .string)
        notice = "Copied “\(HostService.sshCommand(for: host.alias))”."
    }

    public func effectiveConfig(_ host: HostEntry) async -> [(key: String, value: String)] {
        do {
            return try await services.hosts.effectiveConfig(for: host.alias)
        } catch {
            lastError = error.asSMPError
            return []
        }
    }

    public func installedTerminals() -> [TerminalApp] {
        services.terminal.installedApps()
    }

    // MARK: Metadata

    public func setFavorite(_ isFavorite: Bool, for host: HostEntry) {
        var entry = metadata[host.alias] ?? HostMetadata(alias: host.alias)
        entry.isFavorite = isFavorite
        save(entry)
    }

    public func setNotes(_ notes: String, for host: HostEntry) {
        var entry = metadata[host.alias] ?? HostMetadata(alias: host.alias)
        entry.notes = notes
        save(entry)
    }

    public func toggleTag(_ tagID: Int64, for host: HostEntry) {
        var ids = hostTags[host.alias] ?? []
        if !ids.insert(tagID).inserted {
            ids.remove(tagID)
        }
        do {
            try services.metadata.setHostTags(ids, forHost: host.alias)
            hostTags[host.alias] = ids
        } catch {
            lastError = error.asSMPError
        }
    }

    private func save(_ entry: HostMetadata) {
        do {
            try services.metadata.saveHostMetadata(entry)
            metadata[entry.alias] = entry
        } catch {
            lastError = error.asSMPError
        }
    }
}

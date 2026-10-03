import Foundation
import Observation
import SMPCore
import SMPServices

/// What the sidebar has selected.
public enum SidebarSelection: Hashable, Sendable {
    case library(SidebarItem)
    case tag(Int64)
    case group(Int64)
}

public enum KeySortOrder: String, CaseIterable, Identifiable, Sendable {
    case name, type, created, modified

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .name: "Name"
        case .type: "Type"
        case .created: "Date Created"
        case .modified: "Date Modified"
        }
    }
}

/// A discovered key combined with its metadata, tags, groups and agent state.
public struct LibraryItem: Identifiable, Hashable, Sendable {
    public let key: DiscoveredKey
    public var metadata: KeyMetadata?
    public var tagIDs: Set<Int64>
    public var groupIDs: Set<Int64>
    public var isLoadedInAgent: Bool
    /// Set for keys that live in SMP's encrypted archive instead of on disk.
    public let archive: ArchivedKey?

    public init(
        key: DiscoveredKey,
        metadata: KeyMetadata? = nil,
        tagIDs: Set<Int64> = [],
        groupIDs: Set<Int64> = [],
        isLoadedInAgent: Bool = false,
        archive: ArchivedKey? = nil
    ) {
        self.key = key
        self.metadata = metadata
        self.tagIDs = tagIDs
        self.groupIDs = groupIDs
        self.isLoadedInAgent = isLoadedInAgent
        self.archive = archive
    }

    public var id: String { archive.map { "archive:\($0.id.uuidString)" } ?? key.id }
    public var displayName: String { metadata?.displayName ?? key.name }
    public var isFavorite: Bool { metadata?.isFavorite ?? false }
    public var isArchived: Bool { archive != nil }
    /// Metadata can only be stored for keys whose fingerprint is known.
    public var canStoreMetadata: Bool { key.fingerprint != nil }

    public func isExpired(at date: Date = Date()) -> Bool {
        guard let expiresAt = metadata?.expiresAt else { return false }
        return expiresAt <= date
    }

    public var needsAttention: Bool { !key.issues.isEmpty || isExpired() }
}

/// The state behind the main window: discovered keys, metadata, filtering and selection.
@MainActor
@Observable
public final class LibraryModel {
    public private(set) var items: [LibraryItem] = []
    public private(set) var tags: [KeyTag] = []
    public private(set) var groups: [KeyGroup] = []
    public private(set) var agentStatus: AgentStatus = .unavailable
    public private(set) var isLoading = false
    public private(set) var additionalFolders: [URL]
    public var lastError: SMPError?

    public var sidebarSelection: SidebarSelection? = .library(.allKeys)
    public var selectedKeyIDs: Set<String> = []
    public var searchText = ""
    public var sortOrder: KeySortOrder = .name

    @ObservationIgnored let services: ServiceContainer
    /// The main window's undo manager; sheets use it so undo survives the sheet closing.
    @ObservationIgnored public weak var windowUndoManager: UndoManager?
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private var watchTask: Task<Void, Never>?

    public init(services: ServiceContainer, defaults: UserDefaults = .standard) {
        self.services = services
        self.defaults = defaults
        self.additionalFolders = KeyFolderSettings.additionalFolders(in: defaults)
        self.lastError = services.startupIssue
    }

    // MARK: Derived state

    public var visibleItems: [LibraryItem] {
        Self.sorted(Self.filter(items, selection: sidebarSelection, searchText: searchText, tags: tags), by: sortOrder)
    }

    /// Sheet or dialog currently shown for the library.
    public var activeSheet: LibrarySheet?
    /// A short confirmation shown after an operation (for example "Key archived").
    public var notice: String?

    /// The selected keys, in list order.
    public var selectedItems: [LibraryItem] {
        items.filter { selectedKeyIDs.contains($0.id) }
    }

    /// The single selected key, if exactly one is selected.
    public var selectedItem: LibraryItem? {
        guard selectedKeyIDs.count == 1, let id = selectedKeyIDs.first else { return nil }
        return items.first { $0.id == id }
    }

    public var watchedFolders: [URL] {
        [services.environment.sshDirectory] + additionalFolders
    }

    public func count(for item: SidebarItem) -> Int {
        Self.filter(items, selection: .library(item), searchText: "", tags: tags).count
    }

    public func tags(for item: LibraryItem) -> [KeyTag] {
        tags.filter { item.tagIDs.contains($0.id) }
    }

    public func groups(for item: LibraryItem) -> [KeyGroup] {
        groups.filter { item.groupIDs.contains($0.id) }
    }

    // MARK: Loading

    /// Rescans all folders and reloads metadata and agent state.
    public func reload() async {
        isLoading = true
        defer { isLoading = false }
        do {
            let discovered = try await services.keyDiscovery.discoverKeys(in: watchedFolders)
            let status = await services.agent.status()
            let metadata = try services.metadata.allMetadata()
            let tagMap = try services.metadata.tagAssignments()
            let groupMap = try services.metadata.groupAssignments()
            let archived = try services.archive.list()
            tags = try services.metadata.allTags()
            groups = try services.metadata.allGroups()
            agentStatus = status
            let onDisk: [LibraryItem] = discovered.map { key in
                let fingerprint = key.fingerprint ?? ""
                return LibraryItem(
                    key: key,
                    metadata: metadata[fingerprint],
                    tagIDs: tagMap[fingerprint] ?? [],
                    groupIDs: groupMap[fingerprint] ?? [],
                    isLoadedInAgent: status.loadedFingerprints.contains(fingerprint)
                )
            }
            let inArchive: [LibraryItem] = archived.map { entry in
                let fingerprint = entry.fingerprint ?? ""
                return LibraryItem(
                    key: Self.discoveredKey(fromArchived: entry),
                    metadata: metadata[fingerprint],
                    tagIDs: tagMap[fingerprint] ?? [],
                    groupIDs: groupMap[fingerprint] ?? [],
                    archive: entry
                )
            }
            items = onDisk + inArchive
            selectedKeyIDs.formIntersection(items.map(\.id))
        } catch {
            report(error, whatHappened: "SMP could not scan your key folders.")
        }
    }

    /// Reloads whenever something changes in the watched folders, until `stopWatching()`.
    public func startWatching() {
        watchTask?.cancel()
        let stream = services.fileWatcher.changes(in: watchedFolders)
        watchTask = Task { [weak self] in
            for await _ in stream {
                guard let self else { return }
                await self.reload()
            }
        }
    }

    public func stopWatching() {
        watchTask?.cancel()
        watchTask = nil
    }

    public func setAdditionalFolders(_ folders: [URL]) async {
        KeyFolderSettings.setAdditionalFolders(folders, in: defaults)
        additionalFolders = KeyFolderSettings.additionalFolders(in: defaults)
        startWatching()
        await reload()
    }

    // MARK: Metadata editing

    public func setFavorite(_ isFavorite: Bool, for item: LibraryItem) {
        updateMetadata(for: item) { $0.isFavorite = isFavorite }
    }

    public func setDisplayName(_ name: String, for item: LibraryItem) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        updateMetadata(for: item) { $0.displayName = trimmed.isEmpty || trimmed == item.key.name ? nil : trimmed }
    }

    public func setNotes(_ notes: String, for item: LibraryItem) {
        updateMetadata(for: item) { $0.notes = notes }
    }

    public func setExpiry(_ date: Date?, for item: LibraryItem) {
        updateMetadata(for: item) { $0.expiresAt = date }
    }

    public func toggleTag(_ tagID: Int64, for item: LibraryItem) {
        guard let fingerprint = item.key.fingerprint else { return }
        var ids = item.tagIDs
        if !ids.insert(tagID).inserted {
            ids.remove(tagID)
        }
        perform("SMP could not update the key's tags.") {
            try services.metadata.setTags(ids, for: fingerprint)
            updateItems(withFingerprint: fingerprint) { $0.tagIDs = ids }
        }
    }

    public func toggleGroup(_ groupID: Int64, for item: LibraryItem) {
        guard let fingerprint = item.key.fingerprint else { return }
        var ids = item.groupIDs
        if !ids.insert(groupID).inserted {
            ids.remove(groupID)
        }
        perform("SMP could not update the key's groups.") {
            try services.metadata.setGroups(ids, for: fingerprint)
            updateItems(withFingerprint: fingerprint) { $0.groupIDs = ids }
        }
    }

    @discardableResult
    public func createTag(named name: String, color: TagColor) -> KeyTag? {
        var created: KeyTag?
        perform("SMP could not create the tag. Tag names must be unique.") {
            created = try services.metadata.createTag(named: name, color: color)
            tags = try services.metadata.allTags()
        }
        return created
    }

    public func deleteTag(id: Int64) {
        perform("SMP could not delete the tag.") {
            try services.metadata.deleteTag(id: id)
            tags.removeAll { $0.id == id }
            items = items.map { item in
                var copy = item
                copy.tagIDs.remove(id)
                return copy
            }
            if sidebarSelection == .tag(id) {
                sidebarSelection = .library(.allKeys)
            }
        }
    }

    @discardableResult
    public func createGroup(named name: String) -> KeyGroup? {
        var created: KeyGroup?
        perform("SMP could not create the group.") {
            created = try services.metadata.createGroup(named: name)
            groups = try services.metadata.allGroups()
        }
        return created
    }

    public func deleteGroup(id: Int64) {
        perform("SMP could not delete the group.") {
            try services.metadata.deleteGroup(id: id)
            groups.removeAll { $0.id == id }
            items = items.map { item in
                var copy = item
                copy.groupIDs.remove(id)
                return copy
            }
            if sidebarSelection == .group(id) {
                sidebarSelection = .library(.allKeys)
            }
        }
    }

    private func updateMetadata(for item: LibraryItem, _ change: (inout KeyMetadata) -> Void) {
        guard let fingerprint = item.key.fingerprint else { return }
        let stored = try? services.metadata.metadata(for: fingerprint)
        var metadata = stored ?? item.metadata ?? KeyMetadata(fingerprint: fingerprint, lastSeenPath: item.key.id)
        change(&metadata)
        perform("SMP could not save your changes to this key.") {
            try services.metadata.save(metadata)
            updateItems(withFingerprint: fingerprint) { $0.metadata = metadata }
        }
    }

    /// Metadata is per fingerprint, so copies of the same key in several folders change together.
    private func updateItems(withFingerprint fingerprint: String, _ change: (inout LibraryItem) -> Void) {
        for index in items.indices where items[index].key.fingerprint == fingerprint {
            change(&items[index])
        }
    }

    private func perform(_ whatHappened: String, _ body: () throws -> Void) {
        do {
            try body()
        } catch {
            report(error, whatHappened: whatHappened)
        }
    }

    func report(_ error: Error, whatHappened: String) {
        if let error = error as? SMPError {
            lastError = error
        } else {
            lastError = SMPError(.fileSystem, whatHappened: whatHappened, details: error.localizedDescription)
        }
    }

    // MARK: Filtering (pure, for tests)

    nonisolated static func filter(
        _ items: [LibraryItem],
        selection: SidebarSelection?,
        searchText: String,
        tags: [KeyTag]
    ) -> [LibraryItem] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return items.filter { item in
            matches(item, selection: selection) && (query.isEmpty || matches(item, query: query, tags: tags))
        }
    }

    nonisolated static func matches(_ item: LibraryItem, selection: SidebarSelection?) -> Bool {
        switch selection {
        case .library(.archived):
            return item.isArchived
        case .library(let section):
            guard !item.isArchived else { return false }
            switch section {
            case .allKeys, .archived: return true
            case .favorites: return item.isFavorite
            case .secureEnclave: return false  // Secure Enclave keys arrive in milestone 5.
            case .hardware: return item.key.algorithm.isSecurityKey
            case .loadedInAgent: return item.isLoadedInAgent
            case .needsAttention: return item.needsAttention
            }
        case .tag(let id):
            return item.tagIDs.contains(id)
        case .group(let id):
            return item.groupIDs.contains(id)
        case nil:
            return !item.isArchived
        }
    }

    nonisolated static func matches(_ item: LibraryItem, query: String, tags: [KeyTag]) -> Bool {
        let tagNames = tags.filter { item.tagIDs.contains($0.id) }.map(\.name)
        let fields = [
            item.displayName,
            item.key.name,
            item.key.comment,
            item.key.algorithm.displayName,
            item.key.fingerprint ?? "",
            item.key.publicKey?.fingerprintMD5 ?? "",
        ] + tagNames
        return fields.contains { $0.localizedCaseInsensitiveContains(query) }
    }

    nonisolated static func sorted(_ items: [LibraryItem], by order: KeySortOrder) -> [LibraryItem] {
        items.sorted { lhs, rhs in
            switch order {
            case .name:
                return lhs.displayName.localizedStandardCompare(rhs.displayName) == .orderedAscending
            case .type:
                if lhs.key.algorithm != rhs.key.algorithm {
                    return lhs.key.algorithm.displayName < rhs.key.algorithm.displayName
                }
                return lhs.displayName.localizedStandardCompare(rhs.displayName) == .orderedAscending
            case .created:
                let lhsDate = lhs.key.primaryFile.createdAt ?? .distantPast
                return lhsDate > (rhs.key.primaryFile.createdAt ?? .distantPast)
            case .modified:
                let lhsDate = lhs.key.primaryFile.modifiedAt ?? .distantPast
                return lhsDate > (rhs.key.primaryFile.modifiedAt ?? .distantPast)
            }
        }
    }
}

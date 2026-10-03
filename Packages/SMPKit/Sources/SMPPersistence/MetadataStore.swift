import Foundation
import GRDB
import SMPCore

/// Persists user-managed key metadata, tags and groups. Contains no secrets.
public protocol MetadataStoring: Sendable {
    func allMetadata() throws -> [String: KeyMetadata]
    func metadata(for fingerprint: String) throws -> KeyMetadata?
    func save(_ metadata: KeyMetadata) throws
    /// Removes the key's metadata and its tag and group assignments.
    func deleteMetadata(for fingerprint: String) throws

    func allTags() throws -> [KeyTag]
    func createTag(named name: String, color: TagColor) throws -> KeyTag
    func updateTag(_ tag: KeyTag) throws
    func deleteTag(id: Int64) throws
    /// Tag IDs per key fingerprint.
    func tagAssignments() throws -> [String: Set<Int64>]
    func setTags(_ tagIDs: Set<Int64>, for fingerprint: String) throws

    func allGroups() throws -> [KeyGroup]
    func createGroup(named name: String) throws -> KeyGroup
    func renameGroup(id: Int64, to name: String) throws
    func deleteGroup(id: Int64) throws
    /// Group IDs per key fingerprint.
    func groupAssignments() throws -> [String: Set<Int64>]
    func setGroups(_ groupIDs: Set<Int64>, for fingerprint: String) throws
}

/// `MetadataStoring` backed by SQLite through GRDB.
public final class GRDBMetadataStore: MetadataStoring, Sendable {
    private let database: DatabaseQueue

    /// Opens (and migrates) the store at `url`. The file is created with mode 0600.
    public convenience init(url: URL) throws {
        let queue = try DatabaseQueue(path: url.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        try self.init(database: queue)
    }

    /// The default store in Application Support.
    public static func live() throws -> GRDBMetadataStore {
        try GRDBMetadataStore(url: AppPaths.applicationSupportDirectory().appending(path: "metadata.sqlite"))
    }

    /// An in-memory store for tests and previews.
    public static func inMemory() throws -> GRDBMetadataStore {
        try GRDBMetadataStore(database: DatabaseQueue())
    }

    private init(database: DatabaseQueue) throws {
        self.database = database
        try Self.migrator.migrate(database)
    }

    static var migrator: DatabaseMigrator {
        var migrator = DatabaseMigrator()
        migrator.registerMigration("v1-metadata-tags-groups") { db in
            try db.create(table: KeyMetadataRecord.databaseTableName) { table in
                table.primaryKey("fingerprint", .text)
                table.column("displayName", .text)
                table.column("notes", .text).notNull().defaults(to: "")
                table.column("isFavorite", .boolean).notNull().defaults(to: false)
                table.column("expiresAt", .datetime)
                table.column("archivedAt", .datetime)
                table.column("firstSeenAt", .datetime).notNull()
                table.column("lastSeenPath", .text)
            }
            try db.create(table: TagRecord.databaseTableName) { table in
                table.autoIncrementedPrimaryKey("id")
                table.column("name", .text).notNull().unique().collate(.nocase)
                table.column("color", .text).notNull()
            }
            try db.create(table: KeyTagRecord.databaseTableName) { table in
                table.column("fingerprint", .text).notNull()
                table.column("tagID", .integer).notNull().references(TagRecord.databaseTableName, onDelete: .cascade)
                table.primaryKey(["fingerprint", "tagID"])
            }
            try db.create(table: GroupRecord.databaseTableName) { table in
                table.autoIncrementedPrimaryKey("id")
                table.column("name", .text).notNull()
                table.column("sortIndex", .integer).notNull().defaults(to: 0)
            }
            try db.create(table: GroupMemberRecord.databaseTableName) { table in
                table.column("fingerprint", .text).notNull()
                table.column("groupID", .integer).notNull()
                    .references(GroupRecord.databaseTableName, onDelete: .cascade)
                table.primaryKey(["fingerprint", "groupID"])
            }
        }
        return migrator
    }

    // MARK: Key metadata

    public func allMetadata() throws -> [String: KeyMetadata] {
        try database.read { db in
            let records = try KeyMetadataRecord.fetchAll(db)
            return Dictionary(uniqueKeysWithValues: records.map { ($0.fingerprint, $0.model) })
        }
    }

    public func metadata(for fingerprint: String) throws -> KeyMetadata? {
        try database.read { db in
            try KeyMetadataRecord.fetchOne(db, key: fingerprint)?.model
        }
    }

    public func save(_ metadata: KeyMetadata) throws {
        try database.write { db in
            try KeyMetadataRecord(metadata).save(db)
        }
    }

    public func deleteMetadata(for fingerprint: String) throws {
        try database.write { db in
            _ = try KeyMetadataRecord.deleteOne(db, key: fingerprint)
            try KeyTagRecord.filter(Column("fingerprint") == fingerprint).deleteAll(db)
            try GroupMemberRecord.filter(Column("fingerprint") == fingerprint).deleteAll(db)
        }
    }

    // MARK: Tags

    public func allTags() throws -> [KeyTag] {
        try database.read { db in
            try TagRecord.fetchAll(db)
                .compactMap(\.model)
                .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        }
    }

    public func createTag(named name: String, color: TagColor) throws -> KeyTag {
        let trimmed = try Self.validatedName(name)
        return try database.write { db in
            var record = TagRecord(id: nil, name: trimmed, color: color.rawValue)
            try record.insert(db)
            guard let tag = record.model else { throw DatabaseError(message: "Tag was not inserted") }
            return tag
        }
    }

    public func updateTag(_ tag: KeyTag) throws {
        let trimmed = try Self.validatedName(tag.name)
        try database.write { db in
            try TagRecord(id: tag.id, name: trimmed, color: tag.color.rawValue).update(db)
        }
    }

    public func deleteTag(id: Int64) throws {
        _ = try database.write { db in
            try TagRecord.deleteOne(db, key: id)
        }
    }

    public func tagAssignments() throws -> [String: Set<Int64>] {
        try database.read { db in
            try KeyTagRecord.fetchAll(db).reduce(into: [:]) { result, row in
                result[row.fingerprint, default: []].insert(row.tagID)
            }
        }
    }

    public func setTags(_ tagIDs: Set<Int64>, for fingerprint: String) throws {
        try database.write { db in
            try KeyTagRecord.filter(Column("fingerprint") == fingerprint).deleteAll(db)
            for tagID in tagIDs {
                try KeyTagRecord(fingerprint: fingerprint, tagID: tagID).insert(db)
            }
        }
    }

    // MARK: Groups

    public func allGroups() throws -> [KeyGroup] {
        try database.read { db in
            try GroupRecord.order(Column("sortIndex"), Column("name")).fetchAll(db).compactMap(\.model)
        }
    }

    public func createGroup(named name: String) throws -> KeyGroup {
        let trimmed = try Self.validatedName(name)
        return try database.write { db in
            let nextIndex = try Int.fetchOne(db, sql: "SELECT COALESCE(MAX(sortIndex), -1) + 1 FROM keyGroup") ?? 0
            var record = GroupRecord(id: nil, name: trimmed, sortIndex: nextIndex)
            try record.insert(db)
            guard let group = record.model else { throw DatabaseError(message: "Group was not inserted") }
            return group
        }
    }

    public func renameGroup(id: Int64, to name: String) throws {
        let trimmed = try Self.validatedName(name)
        try database.write { db in
            try db.execute(sql: "UPDATE keyGroup SET name = ? WHERE id = ?", arguments: [trimmed, id])
        }
    }

    public func deleteGroup(id: Int64) throws {
        _ = try database.write { db in
            try GroupRecord.deleteOne(db, key: id)
        }
    }

    public func groupAssignments() throws -> [String: Set<Int64>] {
        try database.read { db in
            try GroupMemberRecord.fetchAll(db).reduce(into: [:]) { result, row in
                result[row.fingerprint, default: []].insert(row.groupID)
            }
        }
    }

    public func setGroups(_ groupIDs: Set<Int64>, for fingerprint: String) throws {
        try database.write { db in
            try GroupMemberRecord.filter(Column("fingerprint") == fingerprint).deleteAll(db)
            for groupID in groupIDs {
                try GroupMemberRecord(fingerprint: fingerprint, groupID: groupID).insert(db)
            }
        }
    }

    private static func validatedName(_ name: String) throws -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 64 else {
            throw SMPError.invalidArgument("Names must be between 1 and 64 characters long.")
        }
        return trimmed
    }
}

// MARK: - Records (internal)

struct KeyMetadataRecord: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "keyMetadata"

    var fingerprint: String
    var displayName: String?
    var notes: String
    var isFavorite: Bool
    var expiresAt: Date?
    var archivedAt: Date?
    var firstSeenAt: Date
    var lastSeenPath: String?

    init(_ model: KeyMetadata) {
        fingerprint = model.fingerprint
        displayName = model.displayName
        notes = model.notes
        isFavorite = model.isFavorite
        expiresAt = model.expiresAt
        archivedAt = model.archivedAt
        firstSeenAt = model.firstSeenAt
        lastSeenPath = model.lastSeenPath
    }

    var model: KeyMetadata {
        KeyMetadata(
            fingerprint: fingerprint,
            displayName: displayName,
            notes: notes,
            isFavorite: isFavorite,
            expiresAt: expiresAt,
            archivedAt: archivedAt,
            firstSeenAt: firstSeenAt,
            lastSeenPath: lastSeenPath
        )
    }
}

struct TagRecord: Codable, FetchableRecord, MutablePersistableRecord {
    static let databaseTableName = "tag"

    var id: Int64?
    var name: String
    var color: String

    mutating func didInsert(_ inserted: InsertionSuccess) {
        id = inserted.rowID
    }

    var model: KeyTag? {
        guard let id else { return nil }
        return KeyTag(id: id, name: name, color: TagColor(rawValue: color) ?? .gray)
    }
}

struct KeyTagRecord: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "keyTag"

    var fingerprint: String
    var tagID: Int64
}

struct GroupRecord: Codable, FetchableRecord, MutablePersistableRecord {
    static let databaseTableName = "keyGroup"

    var id: Int64?
    var name: String
    var sortIndex: Int

    mutating func didInsert(_ inserted: InsertionSuccess) {
        id = inserted.rowID
    }

    var model: KeyGroup? {
        guard let id else { return nil }
        return KeyGroup(id: id, name: name, sortIndex: sortIndex)
    }
}

struct GroupMemberRecord: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "keyGroupMember"

    var fingerprint: String
    var groupID: Int64
}

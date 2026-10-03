import Foundation
import GRDB
import SMPCore

extension GRDBMetadataStore {
    public func allProviderAccounts() throws -> [ProviderAccount] {
        try database.read { db in
            try ProviderAccountRecord.order(Column("kind"), Column("username")).fetchAll(db).compactMap(\.model)
        }
    }

    public func saveProviderAccount(_ account: ProviderAccount) throws {
        try database.write { db in
            try ProviderAccountRecord(account).save(db)
        }
    }

    public func deleteProviderAccount(id: UUID) throws {
        _ = try database.write { db in
            try ProviderAccountRecord.deleteOne(db, key: id.uuidString)
        }
    }

    public func providerKeys() throws -> [RemoteKey] {
        try database.read { db in
            try ProviderKeyRecord.fetchAll(db).compactMap(\.model)
        }
    }

    public func replaceProviderKeys(_ keys: [RemoteKey], for accountID: UUID) throws {
        let records = try keys.filter { $0.accountID == accountID }.map(ProviderKeyRecord.init)
        try database.write { db in
            try ProviderKeyRecord.filter(Column("accountID") == accountID.uuidString).deleteAll(db)
            for record in records {
                try record.insert(db)
            }
        }
    }
}

struct ProviderAccountRecord: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "providerAccount"

    var id: String
    var kind: String
    var serverURL: String
    var username: String
    var loginEmail: String?
    var lastSyncedAt: Date?

    init(_ model: ProviderAccount) {
        id = model.id.uuidString
        kind = model.kind.rawValue
        serverURL = model.serverURL.absoluteString
        username = model.username
        loginEmail = model.loginEmail
        lastSyncedAt = model.lastSyncedAt
    }

    var model: ProviderAccount? {
        guard let uuid = UUID(uuidString: id), let kind = ProviderKind(rawValue: kind),
              let url = URL(string: serverURL)
        else { return nil }
        return ProviderAccount(
            id: uuid, kind: kind, serverURL: url, username: username,
            loginEmail: loginEmail, lastSyncedAt: lastSyncedAt
        )
    }
}

/// A cached remote key: public data only, stored as JSON so new fields need no migration.
struct ProviderKeyRecord: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "providerKey"

    var id: String
    var accountID: String
    var fingerprint: String?
    var data: Data

    init(_ model: RemoteKey) throws {
        id = model.id
        accountID = model.accountID.uuidString
        fingerprint = model.fingerprint
        data = try JSONEncoder().encode(model)
    }

    var model: RemoteKey? {
        try? JSONDecoder().decode(RemoteKey.self, from: data)
    }
}

// MARK: - Rotation jobs

extension GRDBMetadataStore {
    public func rotationJobs() throws -> [RotationJob] {
        try database.read { db in
            try RotationJobRecord.order(Column("updatedAt").desc).fetchAll(db).compactMap(\.model)
        }
    }

    public func saveRotationJob(_ job: RotationJob) throws {
        let record = try RotationJobRecord(job)
        try database.write { db in
            try record.save(db)
        }
    }

    public func deleteRotationJob(id: UUID) throws {
        _ = try database.write { db in
            try RotationJobRecord.deleteOne(db, key: id.uuidString)
        }
    }
}

/// A rotation job as JSON: paths, fingerprints and step state only, never key material.
struct RotationJobRecord: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "rotationJob"

    var id: String
    var updatedAt: Date
    var data: Data

    init(_ model: RotationJob) throws {
        id = model.id.uuidString
        updatedAt = model.updatedAt
        data = try JSONEncoder().encode(model)
    }

    var model: RotationJob? {
        try? JSONDecoder().decode(RotationJob.self, from: data)
    }
}

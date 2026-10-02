import Foundation
import SMPCore
import SMPPersistence
import Testing

@Suite("GRDBMetadataStore")
struct MetadataStoreTests {
    let store: GRDBMetadataStore

    init() throws {
        store = try GRDBMetadataStore.inMemory()
    }

    @Test func savesAndReloadsMetadata() throws {
        let expiry = Date(timeIntervalSince1970: 1_900_000_000)
        var metadata = KeyMetadata(fingerprint: "SHA256:abc", notes: "deploy key", isFavorite: true, expiresAt: expiry)
        try store.save(metadata)
        #expect(try store.metadata(for: "SHA256:abc")?.notes == "deploy key")
        #expect(try store.metadata(for: "SHA256:abc")?.expiresAt == expiry)

        metadata.isFavorite = false
        metadata.displayName = "Work laptop"
        try store.save(metadata)
        let all = try store.allMetadata()
        #expect(all.count == 1)
        #expect(all["SHA256:abc"]?.isFavorite == false)
        #expect(all["SHA256:abc"]?.displayName == "Work laptop")
        #expect(try store.metadata(for: "SHA256:missing") == nil)
    }

    @Test func tagsAreUniqueCaseInsensitivelyAndSorted() throws {
        _ = try store.createTag(named: "work", color: .blue)
        _ = try store.createTag(named: "  Personal ", color: .green)
        #expect(throws: (any Error).self) { try store.createTag(named: "WORK", color: .red) }
        #expect(throws: SMPError.self) { try store.createTag(named: "   ", color: .red) }
        #expect(try store.allTags().map(\.name) == ["Personal", "work"])
    }

    @Test func assignsAndUnassignsTags() throws {
        let work = try store.createTag(named: "work", color: .blue)
        let prod = try store.createTag(named: "prod", color: .red)
        try store.setTags([work.id, prod.id], for: "SHA256:k1")
        try store.setTags([work.id], for: "SHA256:k2")
        #expect(try store.tagAssignments() == ["SHA256:k1": [work.id, prod.id], "SHA256:k2": [work.id]])

        try store.setTags([], for: "SHA256:k1")
        #expect(try store.tagAssignments() == ["SHA256:k2": [work.id]])
    }

    @Test func deletingATagRemovesItsAssignments() throws {
        let tag = try store.createTag(named: "temp", color: .gray)
        try store.setTags([tag.id], for: "SHA256:k1")
        try store.deleteTag(id: tag.id)
        #expect(try store.allTags().isEmpty)
        #expect(try store.tagAssignments().isEmpty)
    }

    @Test func updatesTags() throws {
        var tag = try store.createTag(named: "old", color: .gray)
        tag.name = "new"
        tag.color = .purple
        try store.updateTag(tag)
        #expect(try store.allTags() == [tag])
    }

    @Test func groupsKeepCreationOrderAndCascade() throws {
        let first = try store.createGroup(named: "Servers")
        let second = try store.createGroup(named: "Clients")
        #expect(try store.allGroups().map(\.name) == ["Servers", "Clients"])
        #expect(second.sortIndex == first.sortIndex + 1)

        try store.setGroups([first.id, second.id], for: "SHA256:k1")
        try store.renameGroup(id: first.id, to: "Production servers")
        try store.deleteGroup(id: second.id)
        #expect(try store.allGroups().map(\.name) == ["Production servers"])
        #expect(try store.groupAssignments() == ["SHA256:k1": [first.id]])
    }

    @Test func persistsToDiskWithPrivatePermissions() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "smp-store-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appending(path: "metadata.sqlite")

        do {
            let store = try GRDBMetadataStore(url: url)
            try store.save(KeyMetadata(fingerprint: "SHA256:disk", notes: "kept"))
        }
        let reopened = try GRDBMetadataStore(url: url)
        #expect(try reopened.metadata(for: "SHA256:disk")?.notes == "kept")
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    }
}

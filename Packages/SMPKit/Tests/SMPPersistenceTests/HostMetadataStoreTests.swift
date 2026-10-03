import Foundation
import SMPCore
import SMPPersistence
import Testing

@Suite("GRDBMetadataStore hosts and tunnels")
struct HostMetadataStoreTests {
    let store: GRDBMetadataStore

    init() throws {
        store = try GRDBMetadataStore.inMemory()
    }

    @Test func savesHostMetadataAndTags() throws {
        let work = try store.createTag(named: "work", color: .blue)
        let prod = try store.createTag(named: "prod", color: .red)
        try store.saveHostMetadata(HostMetadata(alias: "web", isFavorite: true, notes: "frontend"))
        try store.setHostTags([work.id, prod.id], forHost: "web")
        try store.setHostTags([work.id], forHost: "db")

        #expect(try store.allHostMetadata()["web"]?.notes == "frontend")
        #expect(try store.hostTagAssignments() == ["web": [work.id, prod.id], "db": [work.id]])

        try store.deleteTag(id: prod.id)
        #expect(try store.hostTagAssignments()["web"] == [work.id])

        try store.deleteHostMetadata(alias: "web")
        #expect(try store.allHostMetadata()["web"] == nil)
        #expect(try store.hostTagAssignments()["web"] == nil)
    }

    @Test func renamingMovesMetadataTagsAndTunnels() throws {
        let work = try store.createTag(named: "work", color: .blue)
        try store.saveHostMetadata(HostMetadata(alias: "old", notes: "keep me"))
        try store.setHostTags([work.id], forHost: "old")
        // Stale metadata under the new name must not block the rename.
        try store.saveHostMetadata(HostMetadata(alias: "new", notes: "stale"))
        let forward = TunnelForward(bindPort: 8080, targetPort: 80)
        let tunnel = TunnelProfile(name: "T", hostAlias: "old", forwards: [forward])
        try store.saveTunnel(tunnel)

        try store.renameHost(from: "old", to: "new")
        let metadata = try store.allHostMetadata()
        #expect(metadata["old"] == nil)
        #expect(metadata["new"]?.notes == "keep me")
        #expect(try store.hostTagAssignments() == ["new": [work.id]])
        #expect(try store.allTunnels().first?.hostAlias == "new")
    }

    @Test func savesUpdatesAndDeletesTunnels() throws {
        var tunnel = TunnelProfile(
            name: "Postgres",
            hostAlias: "bastion",
            forwards: [TunnelForward(bindPort: 15432, targetHost: "db.internal", targetPort: 5432)]
        )
        try store.saveTunnel(tunnel)
        try store.saveTunnel(TunnelProfile(name: "Admin", hostAlias: "bastion", forwards: []))
        #expect(try store.allTunnels().map(\.name) == ["Admin", "Postgres"])

        tunnel.forwards.append(TunnelForward(kind: .dynamic, bindPort: 1080))
        try store.saveTunnel(tunnel)
        #expect(try store.allTunnels().first { $0.id == tunnel.id } == tunnel)

        try store.deleteTunnel(id: tunnel.id)
        #expect(try store.allTunnels().map(\.name) == ["Admin"])
    }
}

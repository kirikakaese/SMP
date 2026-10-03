import Foundation
import SMPCore
import SMPPersistence
import Testing

@Suite("GRDBMetadataStore rotation jobs")
struct RotationStoreTests {
    @Test func savesUpdatesAndDeletesJobsAndRotationDates() throws {
        let store = try GRDBMetadataStore.inMemory()
        var job = RotationJob(
            oldKeyName: "id_ed25519", oldFingerprint: "SHA256:old", oldPrivateKeyPath: "/k/id_ed25519",
            oldPublicKeyPath: "/k/id_ed25519.pub", oldComment: "me", directoryPath: "/k",
            newKeyName: "id_ed25519_2027",
            targets: [RotationJob.Target(kind: .host(alias: "web"), label: "web")]
        )
        try store.saveRotationJob(job)
        job.complete(.generate, "Created.")
        job.targets[0].deployed = true
        try store.saveRotationJob(job)
        #expect(try store.rotationJobs() == [job])
        #expect(try store.rotationJobs().first?.nextStep == .deploy)

        try store.deleteRotationJob(id: job.id)
        #expect(try store.rotationJobs().isEmpty)

        let rotateAt = Date(timeIntervalSince1970: 1_900_000_000)
        try store.save(KeyMetadata(fingerprint: "SHA256:k", rotateAt: rotateAt))
        #expect(try store.metadata(for: "SHA256:k")?.rotateAt == rotateAt)
    }
}

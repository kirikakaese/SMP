// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SMPKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SMPCore", targets: ["SMPCore"]),
        .library(name: "SMPSSH", targets: ["SMPSSH"]),
        .library(name: "SMPPersistence", targets: ["SMPPersistence"]),
        .library(name: "SMPServices", targets: ["SMPServices"]),
        .library(name: "SMPUI", targets: ["SMPUI"]),
        .library(name: "SMPAgent", targets: ["SMPAgent"]),
    ],
    dependencies: [
        // SQLite toolkit for the metadata store (tags, groups, notes). Chosen over SwiftData for
        // explicit migrations and Swift 6 concurrency support. Never stores secrets.
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0"),
    ],
    targets: [
        // Models, errors, secret-handling primitives. No UI, no process spawning.
        .target(name: "SMPCore"),
        // Everything that talks to OpenSSH: the tool runner and (later) parsers and the agent codec.
        .target(name: "SMPSSH", dependencies: ["SMPCore"]),
        // Metadata store (GRDB/SQLite). Metadata only: no secrets.
        .target(name: "SMPPersistence", dependencies: ["SMPCore", .product(name: "GRDB", package: "GRDB.swift")]),
        // Protocol-based services with live and in-memory implementations.
        .target(name: "SMPServices", dependencies: ["SMPCore", "SMPSSH", "SMPPersistence"]),
        // SwiftUI feature views. Depends on service protocols only.
        .target(name: "SMPUI", dependencies: ["SMPCore", "SMPServices"]),
        // The built-in SSH agent (Secure Enclave keys + proxy to the system agent). Runs in the
        // login-item helper; no UI.
        .target(name: "SMPAgent", dependencies: ["SMPCore", "SMPSSH", "SMPServices"]),
        // Test-only key fixtures. Not part of any product, so it never ships in the app.
        .target(name: "SMPTestFixtures"),

        .testTarget(name: "SMPCoreTests", dependencies: ["SMPCore"]),
        .testTarget(name: "SMPSSHTests", dependencies: ["SMPSSH", "SMPTestFixtures"]),
        .testTarget(name: "SMPPersistenceTests", dependencies: ["SMPPersistence"]),
        .testTarget(name: "SMPServicesTests", dependencies: ["SMPServices", "SMPTestFixtures"]),
        .testTarget(name: "SMPUITests", dependencies: ["SMPUI", "SMPTestFixtures"]),
        .testTarget(name: "SMPAgentTests", dependencies: ["SMPAgent", "SMPServices", "SMPTestFixtures"]),
    ]
)

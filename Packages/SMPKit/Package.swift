// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SMPKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SMPCore", targets: ["SMPCore"]),
        .library(name: "SMPSSH", targets: ["SMPSSH"]),
        .library(name: "SMPServices", targets: ["SMPServices"]),
        .library(name: "SMPUI", targets: ["SMPUI"]),
    ],
    targets: [
        // Models, errors, secret-handling primitives. No UI, no process spawning.
        .target(name: "SMPCore"),
        // Everything that talks to OpenSSH: the tool runner and (later) parsers and the agent codec.
        .target(name: "SMPSSH", dependencies: ["SMPCore"]),
        // Protocol-based services with live and in-memory implementations.
        .target(name: "SMPServices", dependencies: ["SMPCore", "SMPSSH"]),
        // SwiftUI feature views. Depends on service protocols only.
        .target(name: "SMPUI", dependencies: ["SMPCore", "SMPServices"]),

        .testTarget(name: "SMPCoreTests", dependencies: ["SMPCore"]),
        .testTarget(name: "SMPSSHTests", dependencies: ["SMPSSH"]),
        .testTarget(name: "SMPServicesTests", dependencies: ["SMPServices"]),
    ]
)

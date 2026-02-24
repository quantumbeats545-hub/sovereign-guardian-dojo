// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SovereignGuardianDojo",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "guardian-dojo", targets: ["GuardianCLI"]),
        .library(name: "GuardianCore", targets: ["GuardianCore"]),
        .library(name: "GuardianDojo", targets: ["GuardianDojo"]),
    ],
    dependencies: [
        .package(url: "https://github.com/quantumbeats545-hub/sovereign-dojo-core.git", branch: "master"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "6.24.0"),
    ],
    targets: [
        // System library: liboqs via Homebrew
        .systemLibrary(
            name: "CLibOQS",
            path: "Sources/CLibOQS"
        ),
        // Core infrastructure (uses shared DojoCore)
        .target(
            name: "GuardianCore",
            dependencies: [
                .product(name: "DojoCore", package: "sovereign-dojo-core"),
            ]
        ),
        // Guardian Dojo engine
        .target(
            name: "GuardianDojo",
            dependencies: [
                "GuardianCore",
                .product(name: "GRDB", package: "GRDB.swift"),
            ],
            resources: [.copy("Resources")]
        ),
        // CLI
        .executableTarget(
            name: "GuardianCLI",
            dependencies: [
                "GuardianCore",
                "GuardianDojo",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        // Tests
        .testTarget(name: "GuardianCoreTests", dependencies: ["GuardianCore"]),
        .testTarget(name: "GuardianDojoTests", dependencies: ["GuardianDojo", "GuardianCore"]),
    ]
)

// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "VaultageCommunityNative",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "VaultageCommunity", targets: ["VaultageCommunity"]), .library(name: "CommunityKit", targets: ["CommunityKit"])],
    dependencies: [.package(path: "Packages/VaultageOpenCore")],
    targets: [
        .target(name: "CommunityKit", dependencies: [.product(name: "VaultageCore", package: "VaultageOpenCore")]),
        .executableTarget(name: "VaultageCommunity", dependencies: ["CommunityKit", .product(name: "VaultageCore", package: "VaultageOpenCore")]),
        .executableTarget(name: "CommunityKitTests", dependencies: ["CommunityKit", .product(name: "VaultageCore", package: "VaultageOpenCore")], path: "Tests/CommunityKitTests")
    ]
)

// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VaultageOpenCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "VaultageCore", targets: ["VaultageCore"]),
        .library(name: "VaultageMCP", targets: ["VaultageMCP"]),
        .library(name: "VaultageBrokerContract", targets: ["VaultageBrokerContract"])
    ],
    dependencies: [
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", exact: "0.12.1")
    ],
    targets: [
        .target(name: "VaultageCore"),
        .target(name: "VaultageMCP", dependencies: [
            "VaultageCore",
            .product(name: "MCP", package: "swift-sdk")
        ]),
        // The value-free wire shapes that may cross a custody boundary. The
        // peer-identity constants, the XPC client and the XPC service are not
        // part of this package.
        .target(name: "VaultageBrokerContract", dependencies: ["VaultageCore"])
    ]
)

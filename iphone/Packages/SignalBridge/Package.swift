// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SignalBridge",
    platforms: [.iOS(.v17), .macOS(.v13)],
    products: [.library(name: "SignalBridge", targets: ["SignalBridge"])],
    dependencies: [.package(url: "https://github.com/signalapp/libsignal", exact: "0.107.0")],
    targets: [
        .binaryTarget(
            name: "LibSignalFfi",
            url: "https://build-artifacts.signal.org/libraries/libsignal-client-ios-build-v0.107.0.xcframework.zip",
            checksum: "c21686be0c5444a3e297ca8d1338428b951060319ab0b5adb647681650785712"
        ),
        .target(name: "SignalBridge", dependencies: [
            .product(name: "LibSignalClient", package: "libsignal"), "LibSignalFfi"
        ])
    ]
)

// swift-tools-version:6.0
import PackageDescription

let lib: [String] = ["RampartShared"]
let package = Package(
    name: "Rampart",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "rampartd", targets: ["rampartd"]),
        .executable(name: "rampart", targets: ["rampart"]),
        .executable(name: "RampartApp", targets: ["RampartApp"]),
    ],
    targets: [
        .target(name: "RampartShared"),
        .target(name: "CYara", path: "Sources/CYara"),
        .target(name: "RampartEngine", dependencies: ["RampartShared"]),
        .target(name: "RampartYara", dependencies: ["RampartShared", "CYara"]),
        .target(name: "RampartSigning", dependencies: ["RampartShared"]),
        .target(name: "RampartTelemetry", dependencies: ["RampartShared"]),
        .target(name: "RampartBehaviour", dependencies: ["RampartShared"]),
        .target(name: "RampartRemediation", dependencies: ["RampartShared"]),
        .target(name: "RampartNetwork", dependencies: ["RampartShared"]),
        .target(name: "RampartPosture", dependencies: ["RampartShared"]),
        .executableTarget(name: "rampartd", dependencies: [
            "RampartShared", "RampartEngine", "RampartYara", "RampartSigning", "RampartTelemetry",
            "RampartBehaviour", "RampartRemediation", "RampartNetwork", "RampartPosture"]),
        .executableTarget(name: "rampart", dependencies: [
            "RampartShared", "RampartEngine", "RampartYara", "RampartSigning", "RampartRemediation",
            "RampartPosture", "RampartNetwork", "RampartBehaviour"]),
        .executableTarget(name: "RampartApp", dependencies: ["RampartShared"]),
        .executableTarget(name: "rampart-selftest", dependencies: [
            "RampartShared", "RampartEngine", "RampartYara", "RampartSigning", "RampartTelemetry",
            "RampartBehaviour", "RampartRemediation", "RampartNetwork", "RampartPosture"]),
    ],
    swiftLanguageModes: [.v5]
)

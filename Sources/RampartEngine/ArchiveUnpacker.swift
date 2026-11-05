import Foundation
import RampartShared

/// Resource limits for archive/disk-image/package expansion.
public struct ArchiveLimits: Sendable {
    /// Maximum nesting depth (archive inside archive ...). 0 disables unpacking.
    public var maxDepth: Int = 3
    /// Skip containers larger than this on disk.
    public var maxContainerSize: UInt64 = 2 << 30
    /// Maximum declared/observed expanded size per container.
    public var maxExpandedBytes: UInt64 = 4 << 30
    /// Maximum number of member files per container.
    public var maxFiles: Int = 50_000
    /// Maximum expansion ratio (expanded / compressed) for zips, to stop zip bombs before extraction.
    public var maxRatio: Double = 250
    /// Wall-clock limit for each helper tool invocation.
    public var timeout: TimeInterval = 120
    public init() {}
}

/// An expanded container. Call `cleanup()` (idempotent) to delete temp files / detach images.
public final class UnpackedContainer: @unchecked Sendable {
    /// Directory to walk.
    public let root: String
    private let tempDir: String?
    private let mountPoint: String?
    private var done = false
    private let lock = NSLock()

    init(root: String, tempDir: String?, mountPoint: String?) {
        self.root = root; self.tempDir = tempDir; self.mountPoint = mountPoint
    }

    public func cleanup() {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        if let mountPoint {
            if (try? Subprocess.run("/usr/bin/hdiutil", ["detach", mountPoint, "-quiet"], timeout: 30))?.status != 0 {
                _ = try? Subprocess.run("/usr/bin/hdiutil", ["detach", mountPoint, "-force", "-quiet"], timeout: 30)
            }
        }
        if let tempDir { try? FileManager.default.removeItem(atPath: tempDir) }
    }

    deinit { cleanup() }
}

/// Expands zip/tar-family archives, DMGs and flat PKGs into a private temp directory using Apple's own tools:
/// `/usr/bin/ditto -x -k`, `/usr/bin/tar -x`, `hdiutil attach -nobrowse -readonly`, `pkgutil --expand-full`.
public struct ArchiveUnpacker: Sendable {
    public var limits: ArchiveLimits
    /// Parent for temp extraction directories.
    public var tempRoot: String

    public init(limits: ArchiveLimits = ArchiveLimits(),
                tempRoot: String = NSTemporaryDirectory() + "rampart-unpack") {
        self.limits = limits; self.tempRoot = tempRoot
    }

    /// File kinds this unpacker can expand.
    public static func canUnpack(_ kind: FileKind) -> Bool {
        [.zip, .archive, .dmg, .pkg].contains(kind)
    }

    /// Expands `path`. Throws `EngineError.limitExceeded` for oversize/bomb-like input.
    public func unpack(path: String, kind: FileKind, size: UInt64) throws -> UnpackedContainer {
        guard Self.canUnpack(kind) else { throw EngineError.unpackFailed("unsupported kind \(kind.rawValue)") }
        guard size <= limits.maxContainerSize else { throw EngineError.limitExceeded("container \(size) bytes") }
        try FileManager.default.createDirectory(atPath: tempRoot, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let dir = (tempRoot as NSString).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        do {
            switch kind {
            case .zip:
                if let (files, bytes) = zipDeclaredSize(path) {
                    if files > limits.maxFiles { throw EngineError.limitExceeded("\(files) members") }
                    if bytes > limits.maxExpandedBytes { throw EngineError.limitExceeded("\(bytes) bytes expanded") }
                    if size > 0 && Double(bytes) / Double(size) > limits.maxRatio && bytes > 64 << 20 {
                        throw EngineError.limitExceeded("compression ratio")
                    }
                }
                let out = (dir as NSString).appendingPathComponent("x")
                try runChecked("/usr/bin/ditto", ["-x", "-k", "--noqtn", path, out])
                return UnpackedContainer(root: out, tempDir: dir, mountPoint: nil)
            case .archive:
                let out = (dir as NSString).appendingPathComponent("x")
                try FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: false)
                // bsdtar refuses absolute paths and ".." by default; -o / --no-same-permissions keep it unprivileged.
                try runChecked("/usr/bin/tar", ["-x", "-o", "--no-same-permissions", "-f", path, "-C", out])
                return UnpackedContainer(root: out, tempDir: dir, mountPoint: nil)
            case .pkg:
                let out = (dir as NSString).appendingPathComponent("x")
                try runChecked("/usr/sbin/pkgutil", ["--expand-full", path, out])
                return UnpackedContainer(root: out, tempDir: dir, mountPoint: nil)
            case .dmg:
                let mnt = (dir as NSString).appendingPathComponent("mnt")
                try FileManager.default.createDirectory(atPath: mnt, withIntermediateDirectories: false)
                let r = try Subprocess.run("/usr/bin/hdiutil",
                    ["attach", "-nobrowse", "-readonly", "-noautoopen", "-noverify", "-noautofsck",
                     "-mountpoint", mnt, "-plist", path], timeout: limits.timeout)
                guard r.status == 0 else {
                    throw EngineError.unpackFailed("hdiutil: \(String(decoding: r.stderr, as: UTF8.self).prefix(200))")
                }
                return UnpackedContainer(root: mnt, tempDir: dir, mountPoint: mnt)
            default:
                throw EngineError.unpackFailed("unsupported")
            }
        } catch {
            try? FileManager.default.removeItem(atPath: dir)
            throw error
        }
    }

    private func runChecked(_ tool: String, _ args: [String]) throws {
        let r = try Subprocess.run(tool, args, timeout: limits.timeout)
        guard r.status == 0 else {
            throw EngineError.unpackFailed("\((tool as NSString).lastPathComponent) exit \(r.status): \(String(decoding: r.stderr, as: UTF8.self).prefix(200))")
        }
    }

    /// Reads the zip central directory totals via `unzip -Zt` ("N files, B bytes uncompressed, ...").
    func zipDeclaredSize(_ path: String) -> (files: Int, bytes: UInt64)? {
        guard let r = try? Subprocess.run("/usr/bin/unzip", ["-Zt", path], timeout: 30), r.status == 0 else { return nil }
        return Self.parseZipTotals(String(decoding: r.stdout, as: UTF8.self))
    }

    static func parseZipTotals(_ s: String) -> (files: Int, bytes: UInt64)? {
        let parts = s.split(whereSeparator: { $0 == " " || $0 == "," || $0 == "\n" })
        guard parts.count >= 4, let files = Int(parts[0]), parts[1].hasPrefix("file"),
              let bytes = UInt64(parts[2]), parts[3] == "bytes" else { return nil }
        return (files, bytes)
    }
}

import Foundation

/// Allocated-size measurement: counts blocks actually on disk (sparse files count what they use),
/// counts hard links once, and reports bytes that may be shared with APFS clones separately
/// (removing a clone does not free the blocks the other copy still uses).
public enum DiskSizer {
    public struct Measure: Sendable, Equatable {
        public var bytes: UInt64 = 0          // allocated, not shared
        public var sharedBytes: UInt64 = 0    // allocated, may be shared with a clone
        public var logicalBytes: UInt64 = 0
        public var files: Int = 0
        public var newest: Date?
        public var total: UInt64 { bytes + sharedBytes }
    }

    static let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey, .totalFileAllocatedSizeKey, .fileAllocatedSizeKey,
                                         .fileSizeKey, .linkCountKey, .fileResourceIdentifierKey, .contentModificationDateKey,
                                         .mayShareFileContentKey]

    /// Measures a file or folder. `limit` bounds the number of entries visited (nil = unbounded); `cancelled` is polled.
    public static func measure(_ path: String, limit: Int? = nil, cancelled: (() -> Bool)? = nil) -> Measure {
        var m = Measure()
        let url = URL(fileURLWithPath: path)
        var seen = Set<AnyHashable>()
        func add(_ u: URL) {
            guard let v = try? u.resourceValues(forKeys: Set(keys)) else { return }
            if v.isSymbolicLink == true { return }
            guard v.isRegularFile == true else { return }
            // Newest *file* change: folder dates move whenever anything is added, so they say little about use.
            if let d = v.contentModificationDate, d > (m.newest ?? .distantPast) { m.newest = d }
            if (v.linkCount ?? 1) > 1, let id = v.fileResourceIdentifier as? AnyHashable {
                if seen.contains(id) { return }
                seen.insert(id)
            }
            let alloc = UInt64(v.totalFileAllocatedSize ?? v.fileAllocatedSize ?? 0)
            m.logicalBytes += UInt64(v.fileSize ?? 0)
            m.files += 1
            if v.mayShareFileContent == true { m.sharedBytes += alloc } else { m.bytes += alloc }
        }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { return m }
        add(url)
        guard isDir.boolValue else { return m }
        guard let e = FileManager.default.enumerator(at: url, includingPropertiesForKeys: keys, options: [], errorHandler: { _, _ in true }) else { return m }
        var n = 0
        for case let u as URL in e {
            n += 1
            if let limit, n > limit { break }
            if n % 2048 == 0, cancelled?() == true { break }
            add(u)
        }
        return m
    }

    /// Volume-level figures for the disk containing `path`.
    public struct VolumeInfo: Sendable {
        public var total: UInt64, available: UInt64, availableImportant: UInt64
        /// Space macOS can free on its own (iCloud-evictable files, local snapshots, caches it manages).
        public var purgeable: UInt64 { availableImportant > available ? availableImportant - available : 0 }
        public var used: UInt64 { total > availableImportant ? total - availableImportant : 0 }
    }

    public static func volume(for path: String = NSHomeDirectory()) -> VolumeInfo? {
        let u = URL(fileURLWithPath: path)
        guard let v = try? u.resourceValues(forKeys: [.volumeTotalCapacityKey, .volumeAvailableCapacityKey, .volumeAvailableCapacityForImportantUsageKey]),
              let t = v.volumeTotalCapacity else { return nil }
        let a = UInt64(v.volumeAvailableCapacity ?? 0)
        return VolumeInfo(total: UInt64(t), available: a, availableImportant: UInt64(v.volumeAvailableCapacityForImportantUsage ?? Int64(a)))
    }
}

/// Folder-size tree for the disk map (treemap / sunburst). Protected personal folders are skipped unless allowed,
/// because reading them makes macOS ask for permission.
public final class DiskMapper: @unchecked Sendable {
    public final class Node: Identifiable, @unchecked Sendable {
        public let id = UUID()
        public let path: String
        public var name: String { (path as NSString).lastPathComponent }
        public var bytes: UInt64 = 0
        public var sharedBytes: UInt64 = 0
        public var children: [Node] = []
        public var skippedReason: String?
        init(path: String) { self.path = path }
    }

    public static let protectedNames: Set<String> = ["Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music",
                                                     "Mail", "Messages", "Containers", "Group Containers", "Mobile Documents",
                                                     "Safari", "CloudStorage", "Calendars", "Reminders", "HomeKit", "Photos Library.photoslibrary"]
    public var includeProtected: Bool
    public var maxDepth: Int
    private let lock = NSLock()
    private var _cancelled = false
    public var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return _cancelled }
    public func cancel() { lock.lock(); _cancelled = true; lock.unlock() }

    public init(includeProtected: Bool = false, maxDepth: Int = 3) {
        self.includeProtected = includeProtected; self.maxDepth = maxDepth
    }

    /// Builds the tree. Folders below `maxDepth` are measured as a whole. Children are sorted largest first.
    public func map(_ root: String, progress: ((String) -> Void)? = nil) -> Node {
        build(root, depth: 0, progress: progress)
    }

    private func build(_ path: String, depth: Int, progress: ((String) -> Void)?) -> Node {
        let node = Node(path: path)
        if cancelled { return node }
        if !includeProtected, depth > 0, Self.protectedNames.contains(node.name) {
            node.skippedReason = "Not measured: macOS protects this folder. Turn on “Include personal folders” to measure it."
            return node
        }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { return node }
        let isPackage = path.hasSuffix(".app") || path.hasSuffix(".photoslibrary") || path.hasSuffix(".bundle")
        if !isDir.boolValue || depth >= maxDepth || isPackage {
            let m = DiskSizer.measure(path, cancelled: { [weak self] in self?.cancelled ?? true })
            node.bytes = m.bytes; node.sharedBytes = m.sharedBytes
            return node
        }
        progress?(path)
        let kids = (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []
        for k in kids {
            if cancelled { break }
            let child = build(path + "/" + k, depth: depth + 1, progress: progress)
            node.bytes += child.bytes; node.sharedBytes += child.sharedBytes
            if child.bytes + child.sharedBytes > 0 || child.skippedReason != nil { node.children.append(child) }
        }
        node.children.sort { $0.bytes + $0.sharedBytes > $1.bytes + $1.sharedBytes }
        return node
    }
}

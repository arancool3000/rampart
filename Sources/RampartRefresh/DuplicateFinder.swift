import Foundation
import CryptoKit

/// Finds files with identical contents: group by size, then by a partial hash (first + last 64 KiB),
/// then confirm with a full streamed SHA-256. Hard links and clones of the same inode are not duplicates.
public struct DuplicateFinder: Sendable {
    public var minSize: UInt64
    public var maxFiles: Int
    public init(minSize: UInt64 = 1 << 20, maxFiles: Int = 200_000) { self.minSize = minSize; self.maxFiles = maxFiles }

    public struct Group: Sendable, Hashable {
        public var sha256: String
        public var size: UInt64
        /// Oldest first: the first path is the one RamPart suggests keeping.
        public var paths: [String]
        public var wasted: UInt64 { size * UInt64(max(0, paths.count - 1)) }
    }

    static let skipDirs: Set<String> = [".git", "node_modules", ".build", "Library", ".Trash", "DerivedData"]
    static let skipPackages = [".app", ".photoslibrary", ".musiclibrary", ".tvlibrary", ".bundle", ".framework", ".xcarchive"]

    public func find(in roots: [String], cancelled: (() -> Bool)? = nil) -> [Group] {
        var bySize: [UInt64: [(String, Date, UInt64)]] = [:]   // size → (path, created, inode)
        var count = 0
        let keys: [URLResourceKey] = [.isRegularFileKey, .fileSizeKey, .creationDateKey, .isPackageKey, .isDirectoryKey, .isSymbolicLinkKey]
        for root in roots {
            guard let e = FileManager.default.enumerator(at: URL(fileURLWithPath: root), includingPropertiesForKeys: keys,
                                                         options: [.skipsHiddenFiles], errorHandler: { _, _ in true }) else { continue }
            for case let u as URL in e {
                if cancelled?() == true { return [] }
                guard let v = try? u.resourceValues(forKeys: Set(keys)) else { continue }
                if v.isDirectory == true {
                    let n = u.lastPathComponent
                    if Self.skipDirs.contains(n) || v.isPackage == true || Self.skipPackages.contains(where: { n.hasSuffix($0) }) { e.skipDescendants() }
                    continue
                }
                guard v.isRegularFile == true, v.isSymbolicLink != true, let sz = v.fileSize, UInt64(sz) >= minSize else { continue }
                var st = stat()
                guard lstat(u.path, &st) == 0 else { continue }
                bySize[UInt64(sz), default: []].append((u.path, v.creationDate ?? .distantPast, UInt64(st.st_ino) ^ (UInt64(UInt32(bitPattern: st.st_dev)) << 40)))
                count += 1
                if count >= maxFiles { break }
            }
        }
        var groups: [Group] = []
        for (size, entries) in bySize where entries.count > 1 {
            // Same inode twice (hard links) counts once.
            var uniq: [(String, Date, UInt64)] = []
            var inodes = Set<UInt64>()
            for x in entries where inodes.insert(x.2).inserted { uniq.append(x) }
            guard uniq.count > 1 else { continue }
            let byPartial = Dictionary(grouping: uniq) { Self.partialHash($0.0, size: size) ?? UUID().uuidString }
            for (_, cands) in byPartial where cands.count > 1 {
                if cancelled?() == true { return [] }
                let byFull = Dictionary(grouping: cands) { Self.sha256($0.0) ?? UUID().uuidString }
                for (h, same) in byFull where same.count > 1 && h.count == 64 {
                    let sorted = same.sorted { $0.1 == $1.1 ? $0.0 < $1.0 : $0.1 < $1.1 }
                    groups.append(Group(sha256: h, size: size, paths: sorted.map(\.0)))
                }
            }
        }
        return groups.sorted { $0.wasted > $1.wasted }
    }

    static let chunk = 64 * 1024

    static func partialHash(_ path: String, size: UInt64) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        guard let head = try? h.read(upToCount: chunk) else { return size == 0 ? "empty" : nil }
        hasher.update(data: head)
        if size > UInt64(chunk * 2) {
            try? h.seek(toOffset: size - UInt64(chunk))
            if let tail = try? h.read(upToCount: chunk) { hasher.update(data: tail) }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    public static func sha256(_ path: String) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        while true {
            let d: Data?
            do { d = try h.read(upToCount: 1 << 20) } catch { return nil }   // nil or empty = end of file
            guard let d, !d.isEmpty else { break }
            hasher.update(data: d)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

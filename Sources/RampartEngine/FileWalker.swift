import Foundation
import RampartShared

/// A regular file found by `FileWalker`, with the stat fields the scan pipeline needs.
public struct WalkedFile: Sendable {
    public var path: String
    public var device: Int64
    public var inode: UInt64
    public var size: UInt64
    public var mtimeNanos: Int64
    public var ctimeNanos: Int64
    public var mode: UInt16
    public var flags: UInt32
    public var linkCount: UInt16

    public var isExecutable: Bool { mode & 0o111 != 0 }
    /// iCloud / File Provider placeholder whose content is not on disk.
    public var isDataless: Bool { flags & kSFDataless != 0 }

    init(path: String, st: stat) {
        self.path = path
        device = Int64(st.st_dev); inode = UInt64(st.st_ino); size = UInt64(max(0, st.st_size))
        mtimeNanos = st.mtimeNanos; ctimeNanos = st.ctimeNanos
        mode = UInt16(st.st_mode); flags = st.st_flags; linkCount = UInt16(st.st_nlink)
    }

    /// Stats a single path (no symlink following). Returns nil for non-regular files.
    public static func stat(path: String) -> WalkedFile? {
        var st = Darwin.stat()
        guard lstat(path, &st) == 0, st.isRegular else { return nil }
        return WalkedFile(path: path, st: st)
    }
}

/// Rules for which paths a walk skips.
public struct WalkOptions: Sendable {
    /// Absolute path prefixes that are never entered (matched on path-component boundaries).
    public var excludedPrefixes: [String]
    /// Directory or file names skipped anywhere (e.g. ".Trashes").
    public var excludedNames: Set<String>
    /// Skip dataless (iCloud "optimised storage") files and directories so scans never trigger downloads.
    public var skipDataless: Bool
    /// Stay on each root's volume.
    public var stayOnDevice: Bool
    /// Skip regular files larger than this.
    public var maxFileSize: UInt64

    public init(excludedPrefixes: [String] = WalkOptions.defaultExcludedPrefixes,
                excludedNames: Set<String> = WalkOptions.defaultExcludedNames,
                skipDataless: Bool = true, stayOnDevice: Bool = true, maxFileSize: UInt64 = 2 << 30) {
        self.excludedPrefixes = excludedPrefixes; self.excludedNames = excludedNames
        self.skipDataless = skipDataless; self.stayOnDevice = stayOnDevice; self.maxFileSize = maxFileSize
    }

    /// Sealed system volume, virtual filesystems, VM swap, Spotlight/FSEvents stores and Rampart's own quarantine.
    public static let defaultExcludedPrefixes: [String] = [
        "/System", "/dev", "/private/var/vm", "/private/var/db/uuidtext", "/private/var/db/diagnostics",
        "/.Spotlight-V100", "/.fseventsd", "/.DocumentRevisions-V100", "/.MobileBackups", "/Volumes/com.apple.TimeMachine.localsnapshots",
        Paths.quarantineDir.path, Paths.userRoot.appendingPathComponent("Quarantine").path,
    ]
    public static let defaultExcludedNames: Set<String> = [".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100", ".TemporaryItems", ".Trashes"]

    /// True if `path` is equal to or below one of `excludedPrefixes`.
    public func isExcluded(_ path: String) -> Bool {
        for p in excludedPrefixes where path.hasPrefix(p) {
            let pu = p.utf8.count
            if p.hasSuffix("/") || path.utf8.count == pu || path.utf8[path.utf8.index(path.utf8.startIndex, offsetBy: pu)] == UInt8(ascii: "/") {
                return true
            }
        }
        return false
    }
}

/// Counters from one walk.
public struct WalkStats: Sendable {
    public var files = 0
    public var directories = 0
    public var skipped = 0
    public var errors = 0
}

/// Fast physical filesystem walker built on fts(3): never follows symlinks, stays on-device,
/// honours exclusions, and skips dataless iCloud placeholders without materialising them.
public enum FileWalker {
    /// Walks `roots` depth-first and calls `visit` for every regular file. Return false from `visit` to stop.
    /// Roots that are themselves regular files are visited directly (the exclusion list is not applied to them).
    @discardableResult
    public static func walk(roots: [String], options: WalkOptions = WalkOptions(),
                            cancel: ScanCancellation? = nil, visit: (WalkedFile) -> Bool) -> WalkStats {
        var stats = WalkStats()
        var dirRoots: [String] = []
        for r in roots {
            let root = r.count > 1 && r.hasSuffix("/") ? String(r.dropLast()) : r
            var st = stat()
            guard lstat(root, &st) == 0 else { stats.errors += 1; continue }
            if st.isRegular {
                stats.files += 1
                if !visit(WalkedFile(path: root, st: st)) { return stats }
            } else if st.isDirectory {
                dirRoots.append(root)
            } else if (st.st_mode & S_IFMT) == S_IFLNK {
                // Resolve a symlinked root once (e.g. /tmp -> /private/tmp), then walk physically.
                if let real = realpath(root, nil) {
                    let rp = String(cString: real); free(real)
                    var rst = stat()
                    if lstat(rp, &rst) == 0 {
                        if rst.isDirectory { dirRoots.append(rp) }
                        else if rst.isRegular { stats.files += 1; if !visit(WalkedFile(path: rp, st: rst)) { return stats } }
                    }
                }
            } else { stats.skipped += 1 }
        }
        guard !dirRoots.isEmpty else { return stats }

        var cpaths: [UnsafeMutablePointer<CChar>?] = dirRoots.map { strdup($0) } + [nil]
        defer { cpaths.forEach { free($0) } }
        var ftsFlags = FTS_PHYSICAL | FTS_NOCHDIR
        if options.stayOnDevice { ftsFlags |= FTS_XDEV }
        guard let fts = fts_open(&cpaths, ftsFlags, nil) else { stats.errors += 1; return stats }
        defer { fts_close(fts) }

        var counter = 0
        while let ent = fts_read(fts) {
            counter += 1
            if counter & 0xFF == 0, cancel?.isCancelled == true { break }
            let info = Int32(ent.pointee.fts_info)
            let path = String(cString: ent.pointee.fts_path)
            switch info {
            case FTS_D:
                let level = ent.pointee.fts_level
                let name = String(cString: ent.pointee.fts_name_ptr(ent))
                let st = ent.pointee.fts_statp.pointee
                if level > 0 && (options.excludedNames.contains(name) || options.isExcluded(path)) {
                    fts_set(fts, ent, FTS_SKIP); stats.skipped += 1; continue
                }
                if options.skipDataless && st.st_flags & kSFDataless != 0 {
                    fts_set(fts, ent, FTS_SKIP); stats.skipped += 1; continue
                }
                stats.directories += 1
            case FTS_F:
                let st = ent.pointee.fts_statp.pointee
                let name = String(cString: ent.pointee.fts_name_ptr(ent))
                if options.excludedNames.contains(name) { stats.skipped += 1; continue }
                if options.skipDataless && st.st_flags & kSFDataless != 0 { stats.skipped += 1; continue }
                if UInt64(max(0, st.st_size)) > options.maxFileSize { stats.skipped += 1; continue }
                stats.files += 1
                if !visit(WalkedFile(path: path, st: st)) { return stats }
            case FTS_DNR, FTS_ERR, FTS_NS:
                stats.errors += 1
            default:
                break // symlinks, specials, post-order dirs
            }
        }
        return stats
    }
}

private extension FTSENT {
    /// `fts_name` is a flexible array member; Swift imports it as a 1-tuple, so read it via pointer.
    func fts_name_ptr(_ ent: UnsafeMutablePointer<FTSENT>) -> UnsafePointer<CChar> {
        UnsafeRawPointer(ent).advanced(by: MemoryLayout<FTSENT>.offset(of: \FTSENT.fts_name)!)
            .assumingMemoryBound(to: CChar.self)
    }
}

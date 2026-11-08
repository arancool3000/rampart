import Foundation
import Darwin

/// Plants and removes decoys. Safety rules:
/// - never overwrites: files are created with O_EXCL | O_NOFOLLOW, an existing path is skipped;
/// - never follows a symlinked parent folder (an attacker could redirect a plant into a system path);
/// - removal deletes only paths whose registry tag verifies AND whose on-disk content hash still matches;
/// - every decoy gets `com.apple.fileprovider.ignore#P` (iCloud Drive won't sync it), the Finder-hidden flag,
///   and the Time Machine sticky exclusion. Maze roots also get `.metadata_never_index` (Spotlight).
public struct DecoyPlanter: Sendable {
    public let registry: DecoyRegistry
    public let tagger: DecoyTagger
    /// When false, the Finder-hidden flag is not set (tests use this to inspect fixtures easily).
    public var hideFromFinder = true

    public init(registry: DecoyRegistry, tagger: DecoyTagger) { self.registry = registry; self.tagger = tagger }

    public struct Outcome: Sendable, Equatable {
        public var planted: [String] = []
        public var skipped: [String: String] = [:]   // path -> reason
    }

    // MARK: Files

    @discardableResult
    public func plantDefaults(home: String, now: Date = Date()) -> Outcome {
        var out = Outcome()
        for (path, kind) in DecoyContent.defaultPlan(home: home, seed: tagger.installSeed()) {
            if kind == .browserLoginData {
                // Only inside a browser folder that already exists; never invent a browser install.
                let chrome = home + "/Library/Application Support/Google/Chrome"
                guard Self.isRealDirectory(chrome) else { out.skipped[path] = "browser not installed"; continue }
            }
            do { try plantFile(at: path, kind: kind, now: now); out.planted.append(path) }
            catch { out.skipped[path] = "\(error)" }
        }
        try? registry.save()
        return out
    }

    public func plantFile(at path: String, kind: DecoyKind, hint: String? = nil, now: Date = Date()) throws {
        let dir = (path as NSString).deletingLastPathComponent
        try Self.ensureDirectory(dir, mode: (dir.hasSuffix("/.ssh") || dir.hasSuffix("/.aws")) ? 0o700 : 0o755)
        let canary = DecoyContent.newCanaryID()
        let data = Data(DecoyContent.text(for: kind, canary: canary, hint: hint).utf8)
        // Write into a `.nosync` temp name first (never synced), mark it, then rename into place without replacing.
        let tmp = dir + "/.rampart-decoy-\(canary).nosync"
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw DeceptionError.io("create \(tmp)") }
        let ok = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) } == data.count
        close(fd)
        guard ok else { unlink(tmp); throw DeceptionError.io("write") }
        Self.markNoSyncNoBackup(tmp)
        guard renamex_np(tmp, path, UInt32(RENAME_EXCL)) == 0 else {
            unlink(tmp)
            throw errno == EEXIST ? DeceptionError.exists(path) : DeceptionError.io("rename \(errno)")
        }
        if hideFromFinder { _ = lchflags(path, UInt32(UF_HIDDEN)) }
        DecoyIO.arm(path)   // atime a day before mtime: the next read moves it forward (see DecoyWatcher)
        let hash = deceptionSHA256(data)
        let created = Date(timeIntervalSince1970: floor(now.timeIntervalSince1970))
        registry.add(DecoyRecord(path: path, kind: kind, contentSHA256: hash, created: created,
                                 tag: tagger.tag(path: path, kind: kind, contentSHA256: hash, created: created), canaryID: canary))
    }

    func registerDir(_ path: String, root: Bool, now: Date) {
        let created = Date(timeIntervalSince1970: floor(now.timeIntervalSince1970))
        let marker = root ? "maze-root" : ""
        registry.add(DecoyRecord(path: path, kind: .mazeDir, contentSHA256: marker, created: created,
                                 tag: tagger.tag(path: path, kind: .mazeDir, contentSHA256: marker, created: created), canaryID: ""))
    }

    func registerLink(_ path: String, target: String, now: Date) {
        let created = Date(timeIntervalSince1970: floor(now.timeIntervalSince1970))
        registry.add(DecoyRecord(path: path, kind: .mazeLink, contentSHA256: target, created: created,
                                 tag: tagger.tag(path: path, kind: .mazeLink, contentSHA256: target, created: created), canaryID: ""))
    }

    // MARK: Removal

    public struct RemovalOutcome: Sendable, Equatable {
        public var removed = 0
        public var keptBecauseChanged: [String] = []   // tag or content mismatch: not ours any more, leave it
    }

    /// "Remove all decoys": files and links first, then directories deepest-first (only if empty).
    @discardableResult
    public func removeAll() -> RemovalOutcome {
        var out = RemovalOutcome()
        let records = registry.all
        for r in records where r.kind != .mazeDir {
            guard tagger.verify(r) else { out.keptBecauseChanged.append(r.path); registry.remove(r.path); continue }
            var st = stat()
            guard lstat(r.path, &st) == 0 else { registry.remove(r.path); continue }   // already gone
            if r.kind == .mazeLink {
                guard (st.st_mode & S_IFMT) == S_IFLNK, Self.readLink(r.path) == r.contentSHA256 else { out.keptBecauseChanged.append(r.path); registry.remove(r.path); continue }
            } else {
                guard (st.st_mode & S_IFMT) == S_IFREG, st.st_size < 1 << 20,
                      let d = Self.readNoFollow(r.path), deceptionSHA256(d) == r.contentSHA256 else {
                    out.keptBecauseChanged.append(r.path); registry.remove(r.path); continue
                }
                _ = lchflags(r.path, 0)
            }
            if unlink(r.path) == 0 { out.removed += 1 }
            registry.remove(r.path)
        }
        for r in records.filter({ $0.kind == .mazeDir }).sorted(by: { $0.path.count > $1.path.count }) {
            guard tagger.verify(r) else { registry.remove(r.path); continue }
            if r.contentSHA256 == "maze-root" { unlink(r.path + "/.metadata_never_index") }
            if rmdir(r.path) == 0 { out.removed += 1 } else if Self.isRealDirectory(r.path) { out.keptBecauseChanged.append(r.path) }
            registry.remove(r.path)
        }
        try? registry.save()
        return out
    }

    // MARK: Helpers

    static func isRealDirectory(_ p: String) -> Bool {
        var st = stat(); return lstat(p, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR
    }

    /// Creates missing directories one level at a time and refuses any symlinked component we would pass through
    /// below the home folder level (components that already exist must be real directories).
    static func ensureDirectory(_ dir: String, mode: mode_t) throws {
        var st = stat()
        if lstat(dir, &st) == 0 {
            guard (st.st_mode & S_IFMT) == S_IFDIR else { throw DeceptionError.unsafePath(dir) }
            return
        }
        try ensureDirectory((dir as NSString).deletingLastPathComponent, mode: 0o755)
        guard mkdir(dir, mode) == 0 || errno == EEXIST else { throw DeceptionError.io("mkdir \(dir)") }
        guard lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { throw DeceptionError.unsafePath(dir) }
    }

    /// RamPart's own read of a decoy: never follows a link and never updates atime (so it can't look like a thief).
    static func readNoFollow(_ p: String) -> Data? {
        DecoyIO.withoutAtimeUpdates {
            let fd = open(p, O_RDONLY | O_NOFOLLOW)
            guard fd >= 0 else { return nil }
            defer { close(fd) }
            return FileHandle(fileDescriptor: fd, closeOnDealloc: false).readDataToEndOfFile()
        }
    }

    static func readLink(_ p: String) -> String? {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let n = readlink(p, &buf, Int(PATH_MAX))
        guard n >= 0 else { return nil }
        return String(decoding: buf[0..<n].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /// iCloud: `com.apple.fileprovider.ignore#P` (the #P keeps it across copies). Time Machine: the sticky
    /// exclusion xattr `tmutil addexclusion` writes, without spawning tmutil.
    public static let iCloudIgnoreXattr = "com.apple.fileprovider.ignore#P"
    public static let backupExcludeXattr = "com.apple.metadata:com_apple_backup_excludeItem"

    static func markNoSyncNoBackup(_ path: String) {
        var one: UInt8 = 0x31
        _ = setxattr(path, iCloudIgnoreXattr, &one, 1, 0, XATTR_NOFOLLOW)
        if let plist = try? PropertyListSerialization.data(fromPropertyList: "com.apple.backupd", format: .binary, options: 0) {
            _ = plist.withUnsafeBytes { setxattr(path, backupExcludeXattr, $0.baseAddress, plist.count, 0, XATTR_NOFOLLOW) }
        }
    }

    public static func hasXattr(_ path: String, _ name: String) -> Bool {
        getxattr(path, name, nil, 0, 0, XATTR_NOFOLLOW) >= 0
    }
}

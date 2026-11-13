import Foundation
import Darwin

/// Moves items to the Trash (never deletes), re-checking the safety policy for every path at the moment of cleaning,
/// and journals each move so it can be undone. `dryRun` reports what would happen without touching anything.
public final class RefreshCleaner: @unchecked Sendable {
    public typealias Trasher = (URL) throws -> URL?
    public let policy: RefreshSafetyPolicy
    public let journalURL: URL
    let trasher: Trasher?
    /// o8: where the secure mover puts items (default ~/.Trash). Tests pass a scratch folder.
    public let trashDirectory: String
    /// Test hook: runs after the safety check and before the move (simulates a mid-clean swap).
    public var beforeMove: ((String) -> Void)?
    let fm = FileManager.default

    public static var defaultJournal: URL {
        URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support/Rampart/Refresh/undo.json")
    }

    /// `trasher` defaults to FileManager.trashItem; tests pass one that moves into a scratch folder.
    /// o8: with no `trasher`, items are moved by `SecureTrash` (folder chain opened without following links, item
    /// identity re-checked, then renamed relative to the verified folder), so a path swapped mid-clean can't redirect it.
    public init(policy: RefreshSafetyPolicy = RefreshSafetyPolicy(), journalURL: URL = RefreshCleaner.defaultJournal, trasher: Trasher? = nil,
                trashDirectory: String? = nil) {
        self.policy = policy
        self.journalURL = journalURL
        self.trasher = trasher
        self.trashDirectory = RefreshSafetyPolicy.normalize(trashDirectory ?? policy.home + "/.Trash")
    }

    /// Preview: which items would be refused and why (same checks the real run makes).
    public func preview(_ items: [RefreshItem]) -> (ok: [RefreshItem], refused: [(RefreshItem, RefreshRefusal)]) {
        let openNow = policy.openFilesOverride ?? OpenFiles.snapshot()
        var p = policy; p.openFilesOverride = openNow
        var ok: [RefreshItem] = [], refused: [(RefreshItem, RefreshRefusal)] = []
        for it in items {
            if !it.category.actionable { refused.append((it, .systemPath)); continue }
            if let r = p.categoryRefusal(it.path, it.category) ?? p.refusal(it.path) { refused.append((it, r)) } else { ok.append(it) }
        }
        return (ok, refused)
    }

    public func clean(_ items: [RefreshItem], dryRun: Bool) -> RefreshOutcome {
        var outcome = RefreshOutcome(dryRun: dryRun)
        var p = policy
        p.openFilesOverride = policy.openFilesOverride ?? OpenFiles.snapshot()   // one snapshot per run
        // Never trash a parent and its child in the same run (the child would already be gone).
        let norm = items.map { i -> RefreshItem in var c = i; c.path = RefreshSafetyPolicy.normalize(i.path); return c }
        let paths = Set(norm.map { $0.path.lowercased() })
        for it in norm.sorted(by: { $0.path < $1.path }) {
            if paths.contains(where: { it.path.lowercased().hasPrefix($0 + "/") }) { continue }
            guard it.category.actionable else { outcome.refused.append((it.path, .systemPath)); continue }
            if let r = p.categoryRefusal(it.path, it.category) ?? p.refusal(it.path) { outcome.refused.append((it.path, r)); continue }
            if dryRun {
                outcome.trashed.append(RefreshUndoEntry(original: it.path, trashed: "", bytes: it.bytes, date: Date()))
                continue
            }
            do {
                let dest: String
                if let trasher {
                    beforeMove?(it.path)
                    dest = try trasher(URL(fileURLWithPath: it.path))?.path ?? ""
                } else {
                    dest = try SecureTrash.move(it.path, into: trashDirectory, policy: p, category: it.category, beforeMove: beforeMove)
                }
                outcome.trashed.append(RefreshUndoEntry(original: it.path, trashed: dest, bytes: it.bytes, date: Date()))
            } catch let e as SecureTrash.Refused {
                outcome.refused.append((it.path, e.reason))
            } catch {
                outcome.failed.append((it.path, error.localizedDescription))
            }
        }
        if !dryRun, !outcome.trashed.isEmpty { appendJournal(outcome.trashed) }
        return outcome
    }

    // MARK: Undo

    public func journal() -> [RefreshUndoEntry] {
        guard let d = try? Data(contentsOf: journalURL) else { return [] }
        return (try? JSONDecoder().decode([RefreshUndoEntry].self, from: d)) ?? []
    }

    func appendJournal(_ e: [RefreshUndoEntry]) {
        var all = journal() + e
        let cutoff = Date().addingTimeInterval(-30 * 86400)
        all.removeAll { $0.date < cutoff }
        try? fm.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(all) { try? d.write(to: journalURL, options: .atomic) }
    }

    /// o8: an undo entry is honoured only if it moves something OUT of a Trash folder back INTO a place Refresh could
    /// have cleaned. A tampered undo.json can't be used to move documents around ("restore" ~/Documents to /tmp).
    public func undoAllowed(_ e: RefreshUndoEntry) -> Bool {
        guard !e.trashed.isEmpty, !e.original.isEmpty else { return false }
        let t = RefreshSafetyPolicy.normalize(e.trashed), lt = t.lowercased()
        let trashRoots = [trashDirectory, policy.home + "/.Trash"].map { $0.lowercased() }
        // An injected trasher (tests) defines its own Trash; production entries must come out of a real Trash folder.
        let inTrash = trasher != nil || trashRoots.contains { lt.hasPrefix($0 + "/") } || lt.split(separator: "/").contains(".trashes")
        guard inTrash, !lt.dropFirst(1).contains("/../") else { return false }
        // The original must be a path the policy allows (lexically); "missing" is expected, so only path rules apply.
        return policy.pathRefusal(e.original) == nil
    }

    /// Puts trashed items back where they were. Never overwrites: if something now exists at the original path, it's skipped.
    @discardableResult
    public func undo(_ entries: [RefreshUndoEntry]) -> (restored: [String], skipped: [String]) {
        var restored: [String] = [], skipped: [String] = []
        for e in entries {
            var st = stat()
            guard undoAllowed(e), lstat(e.trashed, &st) == 0, lstat(e.original, &st) != 0 else { skipped.append(e.original); continue }
            do {
                let parent = (e.original as NSString).deletingLastPathComponent
                try fm.createDirectory(atPath: parent, withIntermediateDirectories: true)
                // The folder we restore into must still resolve to an allowed place (no symlinked parent).
                if let rp = RefreshSafetyPolicy.realPath(parent), policy.pathRefusal(rp + "/" + (e.original as NSString).lastPathComponent) != nil {
                    skipped.append(e.original); continue
                }
                guard rename(e.trashed, e.original) == 0 || ((try? fm.moveItem(atPath: e.trashed, toPath: e.original)) != nil) else {
                    skipped.append(e.original); continue
                }
                restored.append(e.original)
            } catch { skipped.append(e.original) }
        }
        let done = Set(restored)
        let remaining = journal().filter { !done.contains($0.original) }
        if let d = try? JSONEncoder().encode(remaining) { try? d.write(to: journalURL, options: .atomic) }
        return (restored, skipped)
    }

    // MARK: Emptying the Trash (the only permanent action; requires explicit confirmation)

    public enum EmptyTrashError: Error { case notConfirmed, notATrashFolder }

    /// Permanently removes everything in `trashDir` (default ~/.Trash). `confirmed` must come from an explicit user confirmation.
    /// o8: refuses when the Trash folder is a symlink (or not a real folder), so a planted `~/.Trash -> ~/Documents`
    /// can't turn "Empty Trash" into "erase Documents".
    public func emptyTrash(confirmed: Bool, trashDir: String = NSHomeDirectory() + "/.Trash", dryRun: Bool) throws -> UInt64 {
        guard confirmed else { throw EmptyTrashError.notConfirmed }
        guard Self.isRealTrashFolder(trashDir) else { throw EmptyTrashError.notATrashFolder }
        var freed: UInt64 = 0
        for n in (try? fm.contentsOfDirectory(atPath: trashDir)) ?? [] {
            let p = trashDir + "/" + n
            freed += DiskSizer.measure(p).total
            if !dryRun { try? fm.removeItem(atPath: p) }
        }
        return freed
    }

    static func isRealTrashFolder(_ dir: String) -> Bool {
        var st = stat()
        guard lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { return false }
        let n = RefreshSafetyPolicy.normalize(dir)
        let parent = (n as NSString).deletingLastPathComponent
        guard let rp = RefreshSafetyPolicy.realPath(parent), let rd = RefreshSafetyPolicy.realPath(n) else { return false }
        return rd == rp + "/" + (n as NSString).lastPathComponent
    }
}

/// o8: TOCTOU-safe move into a Trash folder. The item's folder chain is opened from "/" one component at a time with
/// O_NOFOLLOW, the item is identified by device + inode, the policy is re-run on the resolved path, the identity is
/// re-checked, and the rename is done relative to the verified folder descriptor. Swapping a folder for a symlink
/// after the check moves nothing outside the checked folder.
public enum SecureTrash {
    public struct Refused: Error { public let reason: RefreshRefusal }

    /// Opens `path` (an absolute, already resolved directory) without following any symlink in it.
    static func openDirNoFollow(_ path: String) -> Int32? {
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        for c in path.split(separator: "/") {
            let next = openat(fd, String(c), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            close(fd)
            guard next >= 0 else { return nil }
            fd = next
        }
        return fd
    }

    static func identity(_ dirfd: Int32, _ name: String) -> (dev: Int32, ino: UInt64)? {
        var st = stat()
        guard fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 else { return nil }
        return (st.st_dev, st.st_ino)
    }

    /// Moves `path` into `trashDir`; returns the destination path. Throws `Refused` when the policy refuses
    /// the verified location or the item changed between check and move.
    public static func move(_ path: String, into trashDir: String, policy: RefreshSafetyPolicy, category: RefreshCategory? = nil,
                            beforeMove: ((String) -> Void)? = nil) throws -> String {
        let p = RefreshSafetyPolicy.normalize(path)
        let name = (p as NSString).lastPathComponent
        guard !name.isEmpty, name != ".", name != ".." else { throw Refused(reason: .missing) }
        guard let parent = RefreshSafetyPolicy.realPath((p as NSString).deletingLastPathComponent) else { throw Refused(reason: .missing) }
        guard let dfd = openDirNoFollow(parent) else { throw Refused(reason: .changedDuringClean) }
        defer { close(dfd) }
        guard let id0 = identity(dfd, name) else { throw Refused(reason: .missing) }
        // Re-check the policy on the verified location (the lexical path may have pointed through a link).
        let verified = parent + "/" + name
        if let c = category, let r = policy.categoryRefusal(verified, c) { throw Refused(reason: r) }
        if let r = policy.refusal(verified) { throw Refused(reason: r) }
        beforeMove?(p)
        // The folder we hold must still be where we checked it, and the item in it must be the same object.
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(dfd, F_GETPATH, &buf) == 0, String(cString: buf) == parent,
              let id1 = identity(dfd, name), id1 == id0 else { throw Refused(reason: .changedDuringClean) }

        guard let trashReal = RefreshSafetyPolicy.realPath(trashDir) ?? { () -> String? in
            try? FileManager.default.createDirectory(atPath: trashDir, withIntermediateDirectories: true)
            return RefreshSafetyPolicy.realPath(trashDir)
        }(), let tfd = openDirNoFollow(trashReal) else {
            return try fallback(verified, dfd: dfd, name: name, id: id0)
        }
        defer { close(tfd) }
        let base = (name as NSString).deletingPathExtension, ext = (name as NSString).pathExtension
        for i in 0..<100 {
            let dest = i == 0 ? name : base + " \(i)" + (ext.isEmpty ? "" : "." + ext)
            if renameatx_np(dfd, name, tfd, dest, UInt32(RENAME_EXCL)) == 0 { return trashReal + "/" + dest }
            let e = errno
            if e == EEXIST { continue }
            if e == EXDEV || e == EPERM || e == EACCES { return try fallback(verified, dfd: dfd, name: name, id: id0) }
            throw POSIXError(POSIXErrorCode(rawValue: e) ?? .EIO)
        }
        throw POSIXError(.EEXIST)
    }

    /// The Trash can't be written directly (other volume, or macOS privacy rules): use Finder's trash API, but only
    /// after confirming the path still names the verified object.
    static func fallback(_ verified: String, dfd: Int32, name: String, id: (dev: Int32, ino: UInt64)) throws -> String {
        var st = stat()
        guard lstat(verified, &st) == 0, st.st_dev == id.dev, st.st_ino == id.ino,
              RefreshSafetyPolicy.realPath((verified as NSString).deletingLastPathComponent) == (verified as NSString).deletingLastPathComponent
        else { throw Refused(reason: .changedDuringClean) }
        var out: NSURL?
        try FileManager.default.trashItem(at: URL(fileURLWithPath: verified), resultingItemURL: &out)
        return (out as URL?)?.path ?? ""
    }
}

import Foundation
import Darwin
import Security
import RampartShared

// Cat & Mouse without eslogger (user mode). Two signals, both honest about what they can't see:
//
// 1. Access time. APFS updates a file's (or folder's) atime on the next read only while atime is older than its
//    mtime. RamPart "arms" every decoy by setting atime a day before mtime, then lstat()s them every ~2 s (about
//    100 files: cheap). A newer atime means something read it (cat, cp, an editor, a stealer); a read never fires
//    a kqueue event, so polling is the only way. After a read the decoy is re-armed. Verified on APFS
//    (macOS 27): `cat` and `cp` both update an armed file's atime; `ls`/`find` update an armed folder's atime.
// 2. kqueue (EVFILT_VNODE) on every decoy file and maze folder: writes, renames (with the new location),
//    deletes and attribute changes arrive at once. A vnode event only triggers a re-check; the change itself is
//    classified from the lstat() difference, so RamPart's own re-arming (which also fires NOTE_ATTRIB) is
//    never reported.
//
// RamPart only lstat()s decoys. Where it must read one (verifying content before removal, comparing a copy),
// it does so with atime updates turned off for that thread, so its own reads never look like an attacker.

/// Reads that never update atime (IOPOL_TYPE_VFS_ATIME_UPDATES, thread scope: children are not affected).
public enum DecoyIO {
    public static func withoutAtimeUpdates<T>(_ body: () throws -> T) rethrows -> T {
        let prev = getiopolicy_np(IOPOL_TYPE_VFS_ATIME_UPDATES, IOPOL_SCOPE_THREAD)
        _ = setiopolicy_np(IOPOL_TYPE_VFS_ATIME_UPDATES, IOPOL_SCOPE_THREAD, IOPOL_ATIME_UPDATES_OFF)
        defer { _ = setiopolicy_np(IOPOL_TYPE_VFS_ATIME_UPDATES, IOPOL_SCOPE_THREAD, prev >= 0 ? prev : IOPOL_ATIME_UPDATES_DEFAULT) }
        return try body()
    }

    /// Seconds before mtime an armed decoy's atime is set to.
    public static let armOffset: Int = 86_400

    /// Sets atime to mtime - 1 day (mtime untouched, symlinks not followed). The next read moves atime forward.
    @discardableResult
    public static func arm(_ path: String) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0 else { return false }
        let kind = st.st_mode & S_IFMT
        guard kind == S_IFREG || kind == S_IFDIR else { return false }
        var times = [timespec(tv_sec: st.st_mtimespec.tv_sec - armOffset, tv_nsec: 0), timespec(tv_sec: 0, tv_nsec: Int(UTIME_OMIT))]
        return utimensat(AT_FDCWD, path, &times, AT_SYMLINK_NOFOLLOW) == 0
    }

    public static func isArmed(_ st: stat) -> Bool {
        st.st_atimespec.tv_sec == st.st_mtimespec.tv_sec - armOffset && st.st_atimespec.tv_nsec == 0
    }
}

/// One change seen on a decoy by the watcher (no actor: plain file-system facts).
public struct DecoyTouch: Sendable, Equatable {
    public var date: Date
    public var path: String
    public var kind: DecoyKind
    public var access: DeceptionAccess
    public var destPath: String?
    /// Set when the change happened while RamPart wasn't watching (found at start-up).
    public var whileOffline = false
}

/// Watches the registry's decoys. All state lives on `queue`; `onTouch` is called on it.
public final class DecoyWatcher: @unchecked Sendable {
    struct Snapshot: Equatable {
        var ino: UInt64, size: Int64, mode: UInt16, flags: UInt32
        var mtime: Int, mtimeN: Int, atime: Int, atimeN: Int, ctime: Int, ctimeN: Int
        init(_ st: stat) {
            ino = st.st_ino; size = st.st_size; mode = st.st_mode; flags = st.st_flags
            mtime = st.st_mtimespec.tv_sec; mtimeN = st.st_mtimespec.tv_nsec
            atime = st.st_atimespec.tv_sec; atimeN = st.st_atimespec.tv_nsec
            ctime = st.st_ctimespec.tv_sec; ctimeN = st.st_ctimespec.tv_nsec
        }
        var atimeKey: (Int, Int) { (atime, atimeN) }
    }
    struct Watched {
        var record: DecoyRecord
        var snap: Snapshot?          // nil = gone (already reported)
        var source: DispatchSourceFileSystemObject?
        var renamedTo: String?
    }

    public let registry: DecoyRegistry
    public let interval: TimeInterval
    /// Reads within this many seconds of planting are indexers / RamPart's own on-write scan settling: re-armed silently.
    public var settleSeconds: TimeInterval = 30
    public var onTouch: (@Sendable (DecoyTouch) -> Void)?
    let armedURL: URL?
    let queue = DispatchQueue(label: "app.rampart.deception.watcher", qos: .utility)
    private var watched: [String: Watched] = [:]
    private var timer: DispatchSourceTimer?
    private var armed: Set<String> = []
    public private(set) var polls = 0

    /// `armedURL`: where the set of armed paths is kept, so a read that happened while RamPart wasn't running is
    /// still reported at the next start.
    public init(registry: DecoyRegistry, interval: TimeInterval = 2, armedURL: URL? = nil) {
        self.registry = registry; self.interval = max(0.2, interval); self.armedURL = armedURL
        if let u = armedURL, let d = try? Data(contentsOf: u), let list = try? JSONDecoder().decode([String].self, from: d) { armed = Set(list) }
    }

    public var isRunning: Bool { queue.sync { timer != nil } }
    public var watchedCount: Int { queue.sync { watched.count } }

    public func start() {
        queue.sync {
            guard timer == nil else { return }
            syncLocked(initial: true)
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now() + interval, repeating: interval, leeway: .milliseconds(250))
            t.setEventHandler { [weak self] in self?.pollLocked() }
            t.resume(); timer = t
        }
    }

    public func stop() {
        queue.sync {
            timer?.cancel(); timer = nil
            for w in watched.values { w.source?.cancel() }
            watched.removeAll()
        }
    }

    /// Re-reads the registry (after planting or removing decoys): new decoys are armed and watched silently.
    public func reload() { queue.sync { if timer != nil { syncLocked(initial: false) } } }

    /// Runs `body` (RamPart's own change to decoys, e.g. the Finder-hidden flag) and re-baselines afterwards, so
    /// the change is never reported.
    public func selfChange<T>(_ body: () throws -> T) rethrows -> T {
        try queue.sync {
            let r = try DecoyIO.withoutAtimeUpdates(body)
            for (p, var w) in watched { var st = stat(); if lstat(p, &st) == 0 { w.snap = Snapshot(st) }; watched[p] = w }
            return r
        }
    }

    /// One synchronous poll (tests; the timer does this every `interval`).
    public func pollNow() { queue.sync { pollLocked() } }

    // MARK: Internals (queue only)

    private func watchable(_ r: DecoyRecord) -> Bool { r.kind != .mazeLink }

    private func syncLocked(initial: Bool) {
        let records = registry.all.filter(watchable)
        let keep = Set(records.map(\.path))
        for (p, w) in watched where !keep.contains(p) { w.source?.cancel(); watched[p] = nil }
        var touches: [DecoyTouch] = []
        for r in records where watched[r.path] == nil {
            var st = stat()
            guard lstat(r.path, &st) == 0, (st.st_mode & S_IFMT) == (r.kind == .mazeDir ? S_IFDIR : S_IFREG) else {
                watched[r.path] = Watched(record: r, snap: nil, source: nil); continue
            }
            if !DecoyIO.isArmed(st) {
                // Armed before, atime moved while we weren't watching: something read it (unless still settling).
                if initial, armed.contains(r.path), st.st_atimespec.tv_sec > st.st_mtimespec.tv_sec - DecoyIO.armOffset,
                   Date().timeIntervalSince(r.created) > settleSeconds {
                    touches.append(DecoyTouch(date: Date(timeIntervalSince1970: Double(st.st_atimespec.tv_sec)), path: r.path, kind: r.kind,
                                              access: r.kind == .mazeDir ? .mazeWalk : .read, whileOffline: true))
                }
                DecoyIO.arm(r.path); _ = lstat(r.path, &st)
            }
            armed.insert(r.path)
            watched[r.path] = Watched(record: r, snap: Snapshot(st), source: openSource(r.path))
        }
        armed = armed.intersection(keep)
        saveArmed()
        for t in touches { onTouch?(t) }
    }

    private func saveArmed() {
        guard let u = armedURL, let d = try? JSONEncoder().encode(armed.sorted()) else { return }
        try? d.write(to: u, options: .atomic); _ = chmod(u.path, 0o600)
    }

    private func openSource(_ path: String) -> DispatchSourceFileSystemObject? {
        let fd = open(path, O_EVTONLY | O_NOFOLLOW)
        guard fd >= 0 else { return nil }
        let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .extend, .delete, .rename, .attrib, .link, .revoke], queue: queue)
        src.setEventHandler { [weak self, weak src] in
            guard let self, let src else { return }
            let ev = src.data
            if ev.contains(.rename) {
                var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
                if fcntl(fd, F_GETPATH, &buf) == 0 { self.watched[path]?.renamedTo = String(cString: buf) }
            }
            self.check(path)
        }
        src.setCancelHandler { close(fd) }
        src.resume()
        return src
    }

    private func pollLocked() {
        polls += 1
        for p in watched.keys { check(p) }
    }

    /// Compares the current lstat() with the baseline and reports at most one access per change.
    private func check(_ path: String) {
        guard var w = watched[path], let old = w.snap else { return }
        var st = stat()
        let exists = lstat(path, &st) == 0
        let r = w.record
        var access: DeceptionAccess?
        var dest: String?
        if !exists || Snapshot(st).ino != old.ino && w.renamedTo != nil {
            if let to = w.renamedTo, to != path { access = .rename; dest = to } else if !exists { access = .delete } else { access = .write }
        } else {
            let now = Snapshot(st)
            if now == old { return }
            if now.ino != old.ino || now.size != old.size || (now.mtime, now.mtimeN) != (old.mtime, old.mtimeN) {
                access = .write
            } else if now.atimeKey != old.atimeKey {
                access = r.kind == .mazeDir ? .mazeWalk : .read
            } else if now.mode != old.mode || now.flags != old.flags || (now.ctime, now.ctimeN) != (old.ctime, old.ctimeN) {
                access = .xattr
            }
        }
        if exists {
            // Re-arm (reads and writes leave atime ≥ mtime) and re-open the vnode if the file was replaced.
            if !DecoyIO.isArmed(st) { DecoyIO.arm(path); _ = lstat(path, &st) }
            if Snapshot(st).ino != old.ino { w.source?.cancel(); w.source = openSource(path) }
            w.snap = Snapshot(st)
        } else {
            w.source?.cancel(); w.source = nil; w.snap = nil
        }
        w.renamedTo = nil
        watched[path] = w
        guard let a = access else { return }
        if a == .read || a == .mazeWalk, Date().timeIntervalSince(r.created) < settleSeconds { return }   // indexers settling
        onTouch?(DecoyTouch(date: Date(), path: path, kind: r.kind, access: a, destPath: dest.map { SafeText.path($0) }))
    }
}

/// "Which program was it?" without eslogger: processes holding the decoy open right now (libproc, our own
/// user's processes only in user mode), else a recent exec whose command line named the decoy.
public enum DecoyAttribution {
    public struct Holder: Sendable, Equatable { public var process: ProcessInfoLite; public var path: String }

    /// Open-file sweep. `targets` are decoy paths; matching is on resolved paths. Our own pid is skipped.
    public static func holders(of targets: [String]) -> [Holder] {
        var want: [String: String] = [:]
        for t in targets { want[resolved(t)] = t; want[t] = t }
        guard !want.isEmpty else { return [] }
        let n = proc_listallpids(nil, 0)
        guard n > 0 else { return [] }
        var pids = [Int32](repeating: 0, count: Int(n) + 128)
        let got = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        let me = getpid()
        var out: [Holder] = []
        let fdSize = MemoryLayout<proc_fdinfo>.stride
        for pid in pids.prefix(Int(max(0, got))) where pid > 0 && pid != me {
            let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard bytes > 0 else { continue }
            var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(bytes) / fdSize + 16)
            let used = fds.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
            guard used > 0 else { continue }
            for f in fds.prefix(Int(used) / fdSize) where f.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
                var vi = vnode_fdinfowithpath()
                let sz = proc_pidfdinfo(pid, f.proc_fd, PROC_PIDFDVNODEPATHINFO, &vi, Int32(MemoryLayout<vnode_fdinfowithpath>.size))
                guard sz > 0 else { continue }
                let p = withUnsafeBytes(of: vi.pvip.vip_path) { raw in String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self) }
                if let decoy = want[p], let proc = processInfo(pid) { out.append(Holder(process: proc, path: decoy)); break }
            }
        }
        return out
    }

    static func resolved(_ p: String) -> String {
        guard let r = realpath(p, nil) else { return p }
        defer { free(r) }
        return String(cString: r)
    }

    /// pid -> path, parent, uid, and the code signature (identifier, team, Apple platform binary).
    public static func processInfo(_ pid: Int32) -> ProcessInfoLite? {
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return nil }
        let path = String(cString: buf)
        var bi = proc_bsdinfo()
        let ok = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0
        var p = ProcessInfoLite(pid: pid, ppid: ok ? Int32(bi.pbi_ppid) : 0, path: path, uid: ok ? bi.pbi_uid : 0)
        let sig = signing(path)
        p.signingID = sig.id; p.teamID = sig.team; p.isPlatformBinary = sig.platform
        return p
    }

    static func signing(_ path: String) -> (id: String?, team: String?, platform: Bool) {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else { return (nil, nil, false) }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let d = info as? [String: Any] else { return (nil, nil, false) }
        let platform = (d[kSecCodeInfoPlatformIdentifier as String] as? NSNumber).map { $0.intValue != 0 } ?? false
        return (d[kSecCodeInfoIdentifier as String] as? String, d[kSecCodeInfoTeamIdentifier as String] as? String, platform)
    }

    /// The most recent exec (within `window` before `date`) whose command line names the decoy: its full path,
    /// a path ending in its file name, or the bare file name (only when that name is distinctive, ≥ 8 chars).
    public static func commandLine(naming decoy: String, before date: Date, window: TimeInterval = 20, log: DeceptionEventLog) -> ProcessInfoLite? {
        let name = (decoy as NSString).lastPathComponent
        let resolvedDecoy = resolved(decoy)
        func names(_ a: String) -> Bool {
            a == decoy || a == resolvedDecoy || a.hasSuffix("/" + name) || (name.count >= 8 && a == name)
                || (a.contains(decoy) && a.count < 4096)
        }
        return log.recent(since: date.addingTimeInterval(-window), until: date.addingTimeInterval(1))
            .filter { $0.kind == .exec }
            .compactMap(\.process)
            .last { $0.pid != getpid() && $0.args.dropFirst().contains(where: names) }
    }
}

import Foundation
import Darwin
import RampartShared

/// Thread-safe signing-identity cache keyed by (path, inode, mtime).
public final class CodeIdentityCache: @unchecked Sendable {
    private struct Key: Hashable { var path: String; var ino: UInt64; var mtime: Int }
    private let lock = NSLock()
    private var cache: [Key: ProcInspector.CodeIdentity] = [:]
    public static let shared = CodeIdentityCache()
    public init() {}
    public func identity(for path: String) -> ProcInspector.CodeIdentity? {
        guard !path.isEmpty else { return nil }
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        let k = Key(path: path, ino: st.st_ino, mtime: st.st_mtimespec.tv_sec)
        lock.lock(); if let c = cache[k] { lock.unlock(); return c }; lock.unlock()
        let id = ProcInspector.codeIdentity(path: path)
        lock.lock(); if cache.count > 4096 { cache.removeAll(keepingCapacity: true) }; cache[k] = id; lock.unlock()
        return id
    }
}

/// Catches short-lived processes the periodic sweep misses: kqueue `EVFILT_PROC` with
/// `NOTE_FORK | NOTE_EXEC | NOTE_EXIT` on "interesting" parents (shells, terminals, script interpreters,
/// browsers). macOS has no `NOTE_TRACK`, so on every fork the watcher lists the parent's children and arms
/// each one too (descendants up to `maxDepth`). A child that already exec'd before it was armed is
/// reported immediately from its current image (`detail["late"]="1"`); otherwise its `NOTE_EXEC` reports it.
/// Children inside a browser's own .app bundle (renderer/GPU helpers) are neither reported nor armed.
/// Unprivileged it sees only the caller's processes; as root, everyone's.
public final class ExecWatchSource: EventSource, CPUReporting {
    public let name = "execwatch"
    public let cpu = CPUMeter()
    public let discoveryInterval: TimeInterval
    public var maxWatched = 4096
    public var maxDepth = 8
    /// Process names (`p_comm`, ≤ 16 chars) that become watch roots. Matched exactly, or by prefix for
    /// entries ending in "*".
    public var rootNames: Set<String>
    public let identities: CodeIdentityCache

    public static let defaultRootNames: Set<String> = [
        // shells
        "zsh", "bash", "sh", "dash", "fish", "tcsh", "csh", "ksh",
        // terminals
        "Terminal", "iTerm2", "Warp", "stable", "Hyper", "kitty", "alacritty", "WezTerm", "wezterm-gui", "Ghostty", "ghostty",
        // interpreters / script hosts
        "python*", "Python", "perl*", "ruby", "node", "osascript", "Script Editor", "tclsh*", "php", "deno", "bun",
        // browsers (main processes)
        "Safari", "Google Chrome", "firefox", "Brave Browser", "Microsoft Edge", "Arc", "Opera", "Vivaldi", "Chromium", "Orion",
    ]

    private struct Watched { var startSec: UInt64; var startUsec: UInt64; var path: String; var depth: Int; var root: String; var bundle: String? }

    private let queue = DispatchQueue(label: "app.rampart.telemetry.execwatch", qos: .userInitiated)
    private var kq: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var discovery: DispatchSourceTimer?
    private var handler: (@Sendable (SecurityEvent) -> Void)?
    private var watched: [Int32: Watched] = [:]
    private var explicitRoots: Set<Int32> = []
    private let selfPid = getpid()

    public private(set) var forks = 0
    public private(set) var execsReported = 0
    public private(set) var lateReports = 0
    public private(set) var missedChildren = 0

    public init(discoveryInterval: TimeInterval = 2, rootNames: Set<String> = ExecWatchSource.defaultRootNames,
                identities: CodeIdentityCache = .shared) {
        self.discoveryInterval = discoveryInterval
        self.rootNames = rootNames
        self.identities = identities
    }

    public var isAvailable: Bool { true }
    public var watchedCount: Int { queue.sync { watched.count } }
    public var isRunning: Bool { queue.sync { readSource != nil } }

    /// Adds an explicit root (e.g. the self-test process, or a pid the behaviour engine wants followed).
    public func watch(pid: Int32) {
        queue.async { [self] in
            explicitRoots.insert(pid)
            if kq >= 0 { _ = armRoot(pid, name: "explicit") }
        }
    }

    public func start(handler: @escaping @Sendable (SecurityEvent) -> Void) throws {
        stop()
        let fd = kqueue()
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        queue.sync {
            self.handler = handler
            kq = fd
            let rs = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
            rs.setEventHandler { [weak self] in self?.drain() }
            readSource = rs
            rs.resume()
            for pid in explicitRoots { _ = armRoot(pid, name: "explicit") }
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now(), repeating: discoveryInterval, leeway: .milliseconds(Int(discoveryInterval * 200)))
            t.setEventHandler { [weak self] in self?.discover() }
            discovery = t
            t.resume()
        }
    }

    public func stop() {
        queue.sync {
            discovery?.cancel(); discovery = nil
            readSource?.cancel(); readSource = nil
            if kq >= 0 { close(kq); kq = -1 }
            watched.removeAll()
            handler = nil
        }
    }

    deinit { if kq >= 0 { close(kq) } }

    private func matchesRoot(_ comm: String) -> Bool {
        if rootNames.contains(comm) { return true }
        for n in rootNames where n.hasSuffix("*") && comm.hasPrefix(String(n.dropLast())) { return true }
        return false
    }

    /// Runs on `queue`.
    private func discover() {
        cpu.measure {
            for pid in ProcInspector.allPids() where pid != selfPid && watched[pid] == nil {
                guard watched.count < maxWatched, let info = ProcInspector.bsdInfo(pid), matchesRoot(info.comm) else { continue }
                _ = armRoot(pid, name: info.comm)
            }
        }
    }

    private func arm(_ pid: Int32) -> Bool {
        var ev = kevent(ident: UInt(pid), filter: Int16(EVFILT_PROC), flags: UInt16(EV_ADD | EV_ENABLE),
                        fflags: UInt32(truncatingIfNeeded: NOTE_FORK) | UInt32(truncatingIfNeeded: NOTE_EXEC) | UInt32(truncatingIfNeeded: NOTE_EXIT), data: 0, udata: nil)
        var ts = timespec(tv_sec: 0, tv_nsec: 0)
        return kevent(kq, &ev, 1, nil, 0, &ts) == 0
    }

    private static func bundlePath(_ path: String) -> String? {
        guard let r = path.range(of: ".app/") else { return nil }
        return String(path[..<r.upperBound])
    }

    private func armRoot(_ pid: Int32, name: String) -> Bool {
        guard watched[pid] == nil, let info = ProcInspector.bsdInfo(pid), arm(pid) else { return false }
        let path = ProcInspector.path(pid) ?? ""
        watched[pid] = Watched(startSec: info.startSec, startUsec: info.startUsec, path: path, depth: 0, root: name,
                               bundle: Self.bundlePath(path))
        return true
    }

    private func drain() {
        cpu.measure {
            let cap = 64
            let events = UnsafeMutablePointer<kevent>.allocate(capacity: cap)
            defer { events.deallocate() }
            var ts = timespec(tv_sec: 0, tv_nsec: 0)
            while true {
                let n = kevent(kq, nil, 0, events, Int32(cap), &ts)
                guard n > 0 else { break }
                for i in 0..<Int(n) {
                    let e = events[i]
                    let pid = Int32(e.ident)
                    if e.flags & UInt16(EV_ERROR) != 0 { watched[pid] = nil; continue }
                    if e.fflags & UInt32(truncatingIfNeeded: NOTE_EXEC) != 0 { onExec(pid) }
                    if e.fflags & UInt32(truncatingIfNeeded: NOTE_FORK) != 0 { onFork(pid) }
                    if e.fflags & UInt32(truncatingIfNeeded: NOTE_EXIT) != 0 { watched[pid] = nil }
                }
                if n < Int32(cap) { break }
            }
        }
    }

    private func onFork(_ parent: Int32) {
        forks += 1
        guard let p = watched[parent] else { return }
        for child in ProcInspector.childPids(parent) where watched[child] == nil {
            guard watched.count < maxWatched, p.depth < maxDepth else { missedChildren += 1; continue }
            // Arm first, then look: an exec after arming produces NOTE_EXEC, one before it is visible now.
            guard arm(child), let info = ProcInspector.bsdInfo(child) else { missedChildren += 1; continue }
            let path = ProcInspector.path(child) ?? ""
            if let bundle = p.bundle, path.hasPrefix(bundle) {
                // Browser's own helper: stop following it.
                var ev = kevent(ident: UInt(child), filter: Int16(EVFILT_PROC), flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
                var ts = timespec(tv_sec: 0, tv_nsec: 0)
                _ = kevent(kq, &ev, 1, nil, 0, &ts)
                continue
            }
            watched[child] = Watched(startSec: info.startSec, startUsec: info.startUsec, path: path, depth: p.depth + 1, root: p.root, bundle: nil)
            if !path.isEmpty && path != p.path {
                lateReports += 1
                report(child, info: info, path: path, late: true, root: p.root)
            }
        }
    }

    private func onExec(_ pid: Int32) {
        guard var w = watched[pid], let info = ProcInspector.bsdInfo(pid) else { return }
        let path = ProcInspector.path(pid) ?? ""
        w.path = path
        watched[pid] = w
        report(pid, info: info, path: path, late: false, root: w.root)
    }

    private var argBuffer: [UInt8] = []

    private func report(_ pid: Int32, info: ProcInspector.BSDInfo, path: String, late: Bool, root: String) {
        let argv = ProcInspector.arguments(pid, buffer: &argBuffer)
        let exe = path.isEmpty ? (argv?.execPath ?? info.comm) : path
        let id = identities.identity(for: exe)
        let proc = ProcessInfoLite(pid: pid, ppid: info.ppid, path: exe, args: argv?.args ?? [], uid: info.uid,
                                   signingID: id?.signingID, teamID: id?.teamID, isPlatformBinary: id?.isPlatformBinary ?? false)
        var detail: [String: String] = ["start": "\(info.startSec).\(String(format: "%06llu", info.startUsec))", "watch_root": root]
        if let id { detail["signing"] = id.tier }
        if late { detail["late"] = "1" }
        if argv == nil { detail["argv"] = "unavailable" }
        if let pp = watched[info.ppid]?.path, !pp.isEmpty { detail["parent_path"] = pp }
        if let rp = ProcInspector.responsiblePid(pid) {
            detail["responsible_pid"] = String(rp)
            if let rpath = ProcInspector.path(rp) { detail["responsible_path"] = rpath }
        }
        execsReported += 1
        handler?(SecurityEvent(date: Date(timeIntervalSince1970: Double(info.startSec) + Double(info.startUsec) / 1e6),
                               kind: .exec, process: proc, path: exe, detail: detail, source: name))
    }
}

import Foundation
import Darwin
import RampartShared

@_silgen_name("csops")
private func _csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

/// A process identity that survives pid reuse: (pid, start time in microseconds since epoch).
public struct ProcessIdentity: Codable, Hashable, Sendable {
    public var pid: Int32
    public var startTime: UInt64
    public init(pid: Int32, startTime: UInt64) { self.pid = pid; self.startTime = startTime }
}

public struct ProcessNode: Codable, Hashable, Sendable {
    public var identity: ProcessIdentity
    public var ppid: Int32
    public var uid: UInt32
    public var path: String
    public var depth: Int
    public var isZombie: Bool
}

public struct KillReport: Codable, Sendable {
    public var dryRun: Bool
    /// Processes in kill order (leaves first).
    public var plan: [ProcessNode]
    public var stopped: [Int32]
    public var killed: [Int32]
    public var skipped: [String]     // reasons (protected, pid reused, gone)
    public var survivors: [Int32]
}

/// Libproc-backed process enumeration and tree termination.
public final class ProcessKiller: @unchecked Sendable {
    /// Never signal Apple platform binaries (CS_PLATFORM_BINARY). Tests that spawn /bin/sleep turn this off.
    public var protectPlatformBinaries: Bool
    public var extraProtectedPIDs: Set<Int32>
    private let log = RLog.logger("killer")

    public init(protectPlatformBinaries: Bool = true, extraProtectedPIDs: Set<Int32> = []) {
        self.protectPlatformBinaries = protectPlatformBinaries
        self.extraProtectedPIDs = extraProtectedPIDs
    }

    // MARK: Enumeration

    public struct BSDInfo { public var pid: Int32; public var ppid: Int32; public var uid: UInt32; public var start: UInt64; public var zombie: Bool }

    public static func info(_ pid: Int32) -> BSDInfo? {
        var bi = proc_bsdinfo()
        let sz = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sz) == sz else { return nil }
        let start = UInt64(bi.pbi_start_tvsec) * 1_000_000 + UInt64(bi.pbi_start_tvusec)
        return BSDInfo(pid: Int32(bi.pbi_pid), ppid: Int32(bi.pbi_ppid), uid: bi.pbi_uid, start: start, zombie: bi.pbi_status == 5 /* SZOMB */)
    }

    public static func identity(of pid: Int32) -> ProcessIdentity? {
        info(pid).map { ProcessIdentity(pid: pid, startTime: $0.start) }
    }

    public static func path(of pid: Int32) -> String {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : ""
    }

    public static func allPIDs() -> [Int32] {
        var cap = Int(proc_listallpids(nil, 0)) + 64
        while true {
            var pids = [Int32](repeating: 0, count: cap)
            let n = pids.withUnsafeMutableBytes { Int(proc_listallpids($0.baseAddress, Int32($0.count))) }
            if n < 0 { return [] }
            if n < cap { return Array(pids.prefix(n)).filter { $0 > 0 } }
            cap *= 2
        }
    }

    public static func isPlatformBinary(_ pid: Int32) -> Bool {
        var flags: UInt32 = 0
        guard _csops(pid, 0 /* CS_OPS_STATUS */, &flags, MemoryLayout<UInt32>.size) == 0 else { return false }
        return flags & 0x4000000 /* CS_PLATFORM_BINARY */ != 0
    }

    /// Returns the tree rooted at `root` (root first, breadth-first), or empty if the identity no longer matches.
    public func tree(of root: ProcessIdentity) -> [ProcessNode] {
        guard let ri = Self.info(root.pid), ri.start == root.startTime else { return [] }
        var children: [Int32: [BSDInfo]] = [:]
        for pid in Self.allPIDs() {
            if let i = Self.info(pid) { children[i.ppid, default: []].append(i) }
        }
        var out: [ProcessNode] = []
        var queue: [(BSDInfo, Int)] = [(ri, 0)]
        var seen: Set<Int32> = []
        while !queue.isEmpty {
            let (i, d) = queue.removeFirst()
            guard seen.insert(i.pid).inserted else { continue }
            out.append(ProcessNode(identity: ProcessIdentity(pid: i.pid, startTime: i.start), ppid: i.ppid, uid: i.uid,
                                   path: Self.path(of: i.pid), depth: d, isZombie: i.zombie))
            // A child must have started after its parent; filters reused parent pids.
            for c in children[i.pid] ?? [] where c.start >= i.start && c.pid != i.pid { queue.append((c, d + 1)) }
        }
        return out
    }

    func protectionReason(_ pid: Int32) -> String? {
        if pid <= 1 { return "pid \(pid) is kernel/launchd" }
        if pid == getpid() { return "pid \(pid) is Rampart itself" }
        if extraProtectedPIDs.contains(pid) { return "pid \(pid) is protected" }
        if protectPlatformBinaries && Self.isPlatformBinary(pid) { return "pid \(pid) is an Apple platform binary" }
        return nil
    }

    private func stillSame(_ id: ProcessIdentity) -> Bool {
        guard let i = Self.info(id.pid) else { return false }
        return i.start == id.startTime
    }

    // MARK: Kill

    /// SIGSTOPs the whole tree, then SIGKILLs leaves-up, re-checking each pid's start time before signalling.
    /// Re-scans up to `rounds` times for late children. With `dryRun` only the plan is returned.
    public func killTree(_ root: ProcessIdentity, dryRun: Bool = true, rounds: Int = 3) -> KillReport {
        var initial = tree(of: root)
        var report = KillReport(dryRun: dryRun, plan: [], stopped: [], killed: [], skipped: [], survivors: [])
        if initial.isEmpty { report.skipped.append("pid \(root.pid) gone or reused"); return report }
        // If the root is protected, refuse the whole operation.
        if let why = protectionReason(root.pid) { report.skipped.append(why); return report }
        initial = initial.filter { n in
            if let why = protectionReason(n.identity.pid) { report.skipped.append(why); return false }
            return true
        }
        report.plan = initial.sorted { $0.depth > $1.depth }
        if dryRun { return report }

        var targets: [ProcessIdentity: ProcessNode] = [:]
        for round in 0..<max(1, rounds) {
            let nodes = round == 0 ? initial : tree(of: root).filter { protectionReason($0.identity.pid) == nil }
            var fresh = nodes.filter { targets[$0.identity] == nil && !$0.isZombie }
            if round > 0 {
                // Late children of already-killed parents get reparented; also sweep processes whose
                // parent was one of our targets.
                let ours = Set(targets.keys.map(\.pid))
                for pid in Self.allPIDs() {
                    if let i = Self.info(pid), ours.contains(i.ppid), !i.zombie,
                       targets[ProcessIdentity(pid: pid, startTime: i.start)] == nil, protectionReason(pid) == nil {
                        fresh.append(ProcessNode(identity: ProcessIdentity(pid: pid, startTime: i.start), ppid: i.ppid, uid: i.uid,
                                                 path: Self.path(of: pid), depth: 99, isZombie: false))
                    }
                }
            }
            if fresh.isEmpty && round > 0 { break }
            for n in fresh where stillSame(n.identity) {
                if kill(n.identity.pid, SIGSTOP) == 0 { report.stopped.append(n.identity.pid) }
                targets[n.identity] = n
            }
            for n in fresh.sorted(by: { $0.depth > $1.depth }) {
                guard stillSame(n.identity) else { report.skipped.append("pid \(n.identity.pid) exited or reused"); continue }
                if kill(n.identity.pid, SIGKILL) == 0 { report.killed.append(n.identity.pid) }
                else { report.skipped.append("pid \(n.identity.pid): \(String(cString: strerror(errno)))") }
            }
            usleep(round == 0 ? 200_000 : 500_000)
        }
        // Survivors: still alive with the same identity and not a zombie.
        for id in targets.keys {
            if let i = Self.info(id.pid), i.start == id.startTime, !i.zombie { report.survivors.append(id.pid) }
        }
        log.info("killTree root=\(root.pid) killed=\(report.killed.count) survivors=\(report.survivors.count)")
        return report
    }

    /// PIDs whose executable path equals `path` (for killing everything running a quarantined file).
    public func processes(runningExecutable path: String) -> [ProcessIdentity] {
        let target = (path as NSString).resolvingSymlinksInPath
        return Self.allPIDs().compactMap { pid in
            let p = Self.path(of: pid)
            guard !p.isEmpty, (p as NSString).resolvingSymlinksInPath == target else { return nil }
            return Self.identity(of: pid)
        }
    }
}

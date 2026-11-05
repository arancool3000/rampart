import Foundation
import RampartShared

/// Identity of one process lifetime. `gen` increments every time a pid is reused.
public struct ProcessKey: Hashable, Codable, Sendable, CustomStringConvertible {
    public var pid: Int32
    public var gen: UInt32
    public var description: String { "\(pid)#\(gen)" }
}

/// One process lifetime in the lineage tree. Kept after exit for `retention` seconds.
public final class ProcessNode: @unchecked Sendable {
    public let key: ProcessKey
    public var pid: Int32 { key.pid }
    public internal(set) var ppid: Int32
    public internal(set) var parent: ProcessKey?
    public internal(set) var path: String
    public internal(set) var args: [String]
    public internal(set) var uid: UInt32
    public internal(set) var signingID: String?
    public internal(set) var teamID: String?
    public internal(set) var isPlatformBinary: Bool
    public internal(set) var tierHint: String?
    public internal(set) var cwd: String?
    public internal(set) var responsiblePid: Int32?
    public let start: Date
    public internal(set) var lastSeen: Date
    public internal(set) var exitDate: Date?
    /// Every image this pid has executed (exec replaces the image but keeps the pid).
    public internal(set) var images: [String]
    let startToken: String?
    var trust: TrustClass?

    public var name: String { PathUtil.basename(path) }
    public var argvText: String { ArgvText.normalise(args.isEmpty ? [path] : args) }
    public var isLive: Bool { exitDate == nil }

    init(key: ProcessKey, info: ProcessInfoLite, start: Date, startToken: String?, parent: ProcessKey?) {
        self.key = key; self.ppid = info.ppid; self.parent = parent; self.path = info.path; self.args = info.args
        self.uid = info.uid; self.signingID = info.signingID; self.teamID = info.teamID
        self.isPlatformBinary = info.isPlatformBinary; self.start = start; self.lastSeen = start
        self.images = [info.path]; self.startToken = startToken
    }
}

/// Process lineage tracker with pid-reuse handling.
///
/// A pid gets a new generation when: a fork event names it as the child; an exec arrives whose
/// kernel start time (`detail["start"]`, from the process sweep) differs from the recorded one;
/// an exec arrives for a pid we saw exit; or an exec arrives with a different ppid and no hint that
/// it is an in-place image replacement (`exec_replace`/`prev_path`). Exited nodes stay queryable for
/// `retention` seconds so chains survive short-lived parents.
public final class ProcessTracker: @unchecked Sendable {
    public var retention: TimeInterval = 600
    public var maxNodes = 50_000
    private var live: [Int32: ProcessKey] = [:]
    private var nodes: [ProcessKey: ProcessNode] = [:]
    private var gens: [Int32: UInt32] = [:]
    private var lastPrune = Date.distantPast
    private let lock = NSRecursiveLock()

    public init() {}

    public var count: Int { lock.lock(); defer { lock.unlock() }; return nodes.count }

    public func node(_ key: ProcessKey) -> ProcessNode? { lock.lock(); defer { lock.unlock() }; return nodes[key] }
    public func liveNode(pid: Int32) -> ProcessNode? {
        lock.lock(); defer { lock.unlock() }
        return live[pid].flatMap { nodes[$0] }
    }

    static func isExit(_ e: SecurityEvent) -> Bool {
        e.detail["es_event"] == "exit" || e.detail["exit"] == "1" || e.detail["type"] == "exit"
    }

    /// Updates the tree from one event and returns the node of the acting process (if any).
    @discardableResult
    public func observe(_ e: SecurityEvent) -> ProcessNode? {
        lock.lock(); defer { lock.unlock() }
        let now = e.date
        if now.timeIntervalSince(lastPrune) > 30 || nodes.count > maxNodes { prune(now: now) }
        guard let p = e.process, p.pid > 0 else { return nil }

        if Self.isExit(e) {
            guard let k = live[p.pid], let n = nodes[k] else { return nil }
            n.exitDate = now; n.lastSeen = now
            live[p.pid] = nil
            return n
        }

        if e.detail["es_event"] == "fork", let cs = e.detail["child_pid"], let cpid = Int32(cs) {
            let parentNode = ensure(p, date: now, startToken: nil)
            if let old = live[cpid].flatMap({ nodes[$0] }) { old.exitDate = old.exitDate ?? now }
            var ci = p; ci.pid = cpid; ci.ppid = p.pid
            let child = makeNode(ci, date: now, startToken: nil, parent: parentNode.key)
            child.cwd = parentNode.cwd
            return parentNode
        }

        if e.kind == .exec {
            let token = e.detail["start"]
            if let k = live[p.pid], let existing = nodes[k] {
                let replaceHint = e.detail["exec_replace"] == "1" || e.detail["prev_path"] != nil
                var reused = false
                if let token, let old = existing.startToken, token != old { reused = true }
                else if !replaceHint && existing.ppid != p.ppid && p.ppid > 1 && existing.ppid > 0 { reused = true }
                if !reused {
                    // In-place image replacement (or the exec that follows a fork).
                    existing.path = p.path; existing.args = p.args
                    existing.signingID = p.signingID; existing.teamID = p.teamID
                    existing.isPlatformBinary = p.isPlatformBinary; existing.tierHint = e.detail["signing"]
                    existing.uid = p.uid; existing.trust = nil; existing.lastSeen = now
                    if p.ppid > 0 && existing.ppid != p.ppid { existing.ppid = p.ppid }
                    if existing.images.last != p.path { existing.images.append(p.path) }
                    if let cwd = e.detail["cwd"] { existing.cwd = cwd }
                    if let r = e.detail["responsible_pid"].flatMap(Int32.init) { existing.responsiblePid = r }
                    return existing
                }
                existing.exitDate = existing.exitDate ?? now
                live[p.pid] = nil
            }
            let parentKey = resolveParent(ppid: p.ppid, childStart: now)
            let n = makeNode(p, date: now, startToken: token, parent: parentKey)
            n.tierHint = e.detail["signing"]; n.cwd = e.detail["cwd"]
            n.responsiblePid = e.detail["responsible_pid"].flatMap(Int32.init)
            return n
        }

        return ensure(p, date: now, startToken: e.detail["start"])
    }

    private func ensure(_ p: ProcessInfoLite, date: Date, startToken: String?) -> ProcessNode {
        if let k = live[p.pid], let n = nodes[k] {
            if !p.path.isEmpty && n.path != p.path && !n.images.contains(p.path) && date.timeIntervalSince(n.lastSeen) > 1 {
                // Different image under the same pid with no exec seen: the pid was reused.
                n.exitDate = n.exitDate ?? date
                live[p.pid] = nil
            } else {
                n.lastSeen = max(n.lastSeen, date)
                return n
            }
        }
        return makeNode(p, date: date, startToken: startToken, parent: resolveParent(ppid: p.ppid, childStart: date))
    }

    private func makeNode(_ p: ProcessInfoLite, date: Date, startToken: String?, parent: ProcessKey?) -> ProcessNode {
        let g = (gens[p.pid] ?? 0) &+ 1
        gens[p.pid] = g
        let key = ProcessKey(pid: p.pid, gen: g)
        let n = ProcessNode(key: key, info: p, start: date, startToken: startToken, parent: parent)
        nodes[key] = n
        live[p.pid] = key
        return n
    }

    private func resolveParent(ppid: Int32, childStart: Date) -> ProcessKey? {
        guard ppid > 0, let k = live[ppid], let n = nodes[k] else { return nil }
        return n.start <= childStart.addingTimeInterval(1) ? k : nil
    }

    /// Parent chain, nearest first. Falls back to the live pid table when the parent was unknown at exec time.
    public func ancestors(of n: ProcessNode, maxDepth: Int = 32) -> [ProcessNode] {
        lock.lock(); defer { lock.unlock() }
        var out: [ProcessNode] = []
        var seen: Set<ProcessKey> = [n.key]
        var cur = n
        while out.count < maxDepth {
            var next: ProcessNode?
            if let pk = cur.parent { next = nodes[pk] }
            if next == nil, cur.ppid > 1, let lk = live[cur.ppid], let cand = nodes[lk], cand.start <= cur.start.addingTimeInterval(1) {
                next = cand
            }
            guard let nx = next, !seen.contains(nx.key) else { break }
            seen.insert(nx.key); out.append(nx); cur = nx
        }
        return out
    }

    /// Other children of the same parent started within `window` seconds of `n`.
    public func siblings(of n: ProcessNode, within window: TimeInterval) -> [ProcessNode] {
        lock.lock(); defer { lock.unlock() }
        guard let pk = n.parent ?? live[n.ppid] else { return [] }
        return nodes.values.filter {
            $0.key != n.key && ($0.parent == pk || ($0.parent == nil && $0.ppid == n.ppid))
                && abs($0.start.timeIntervalSince(n.start)) <= window
        }
    }

    /// Live processes whose current image is `path`.
    public func liveNodes(image path: String) -> [ProcessNode] {
        lock.lock(); defer { lock.unlock() }
        return live.values.compactMap { nodes[$0] }.filter { $0.path == path }
    }

    private func prune(now: Date) {
        lastPrune = now
        nodes = nodes.filter { _, n in
            if let x = n.exitDate { return now.timeIntervalSince(x) < retention }
            return true
        }
        if nodes.count > maxNodes {
            let drop = nodes.values.sorted { $0.lastSeen < $1.lastSeen }.prefix(nodes.count - maxNodes * 9 / 10)
            for n in drop { nodes[n.key] = nil; if live[n.pid] == n.key { live[n.pid] = nil } }
        }
    }
}

import Foundation
import Darwin
import RampartShared

/// One TCP/UDP socket of a process, from libproc.
public struct SocketTuple: Hashable, Sendable {
    public var proto: String          // "tcp" | "udp"
    public var family: Int32          // AF_INET | AF_INET6
    public var localIP: String
    public var localPort: UInt16
    public var remoteIP: String
    public var remotePort: UInt16
    public var state: String          // tcp: listen/syn_sent/established/...; udp: "" 
    public var isListen: Bool { state == "listen" }
}

extension ProcInspector {
    static let tcpStates = ["closed", "listen", "syn_sent", "syn_received", "established", "close_wait",
                            "fin_wait_1", "closing", "last_ack", "fin_wait_2", "time_wait"]

    /// Internet sockets of `pid` via PROC_PIDLISTFDS + PROC_PIDFDSOCKETINFO. Returns nil when the
    /// pid is not inspectable (another user's process without root, or gone).
    public static func sockets(_ pid: Int32, fdBuffer: inout [proc_fdinfo]) -> [SocketTuple]? {
        let stride = MemoryLayout<proc_fdinfo>.stride
        if fdBuffer.isEmpty { fdBuffer = [proc_fdinfo](repeating: proc_fdinfo(), count: 256) }
        var bytes = fdBuffer.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
        guard bytes > 0 else { return nil }
        if Int(bytes) >= fdBuffer.count * stride {
            // Grow and retry once for fd-heavy processes.
            let needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            fdBuffer = [proc_fdinfo](repeating: proc_fdinfo(), count: max(Int(needed) / stride + 64, fdBuffer.count * 2))
            bytes = fdBuffer.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
            guard bytes > 0 else { return nil }
        }
        let count = Int(bytes) / stride
        var out: [SocketTuple] = []
        for i in 0..<count where fdBuffer[i].proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            var si = socket_fdinfo()
            let sz = Int32(MemoryLayout<socket_fdinfo>.stride)
            guard proc_pidfdinfo(pid, fdBuffer[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, sz) == sz else { continue }
            let fam = si.psi.soi_family
            guard fam == AF_INET || fam == AF_INET6 else { continue }
            let ini: in_sockinfo
            var proto: String, state = ""
            switch si.psi.soi_kind {
            case Int32(SOCKINFO_TCP):
                ini = si.psi.soi_proto.pri_tcp.tcpsi_ini
                proto = "tcp"
                let st = Int(si.psi.soi_proto.pri_tcp.tcpsi_state)
                state = st < tcpStates.count ? tcpStates[st] : "state_\(st)"
            case Int32(SOCKINFO_IN):
                ini = si.psi.soi_proto.pri_in
                proto = si.psi.soi_protocol == IPPROTO_UDP ? "udp" : "ip\(si.psi.soi_protocol)"
            default: continue
            }
            let v4 = ini.insi_vflag & UInt8(INI_IPV4) != 0
            out.append(SocketTuple(proto: proto, family: fam,
                                   localIP: addr(v4: v4, ini.insi_laddr.ina_46.i46a_addr4, ini.insi_laddr.ina_6), localPort: port(ini.insi_lport),
                                   remoteIP: addr(v4: v4, ini.insi_faddr.ina_46.i46a_addr4, ini.insi_faddr.ina_6), remotePort: port(ini.insi_fport), state: state))
        }
        return out
    }

    static func port(_ p: Int32) -> UInt16 { UInt16(bigEndian: UInt16(truncatingIfNeeded: p)) }

    static func addr(v4: Bool, _ a4: in_addr, _ a6: in6_addr) -> String {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var ok: Bool
        if v4 { var v = a4; ok = inet_ntop(AF_INET, &v, &buf, socklen_t(buf.count)) != nil }
        else { var v = a6; ok = inet_ntop(AF_INET6, &v, &buf, socklen_t(buf.count)) != nil }
        return ok ? String(cString: buf) : ""
    }
}

/// Samples every inspectable process's Internet sockets every `interval` and emits a `.networkConnect`
/// event for each new connection (`remote_ip`, `remote_port`, `local_ip`, `local_port`, `proto`, `state`,
/// `listen=0`) and for each new listening socket (`listen=1`, `local_ip` `0.0.0.0`/`::` when bound to all
/// interfaces). Attributed to the pid. Apple platform binaries are skipped entirely (except the
/// `EventHub.neverMute` LOLBins); signing is resolved only for processes with a new socket; DNS names come separately from the DNS filter.
/// Short connections that open and close between sweeps are missed. Unprivileged: own processes only.
public final class SocketSource: EventSource, CPUReporting {
    public let name = "sockets"
    public let cpu = CPUMeter()
    public let interval: TimeInterval
    public var skipPlatformBinaries = true
    public var excludeSelf = true
    /// Emit listeners that already exist at start (a backdoor may have bound before we started).
    public var reportExistingListeners = true
    /// Report connected UDP sockets (remote set) as well as TCP.
    public var includeUDP = true

    private struct ProcKey: Hashable { var pid: Int32; var sec: UInt64; var usec: UInt64 }
    private struct ProcEntry { var path: String; var identity: ProcInspector.CodeIdentity?; var skip: Bool; var ppid: Int32; var uid: UInt32; var lastSeenSweep: Int }
    private struct ConnKey: Hashable { var proc: ProcKey; var tuple: SocketTuple }

    private let identities: CodeIdentityCache
    private let queue = DispatchQueue(label: "app.rampart.telemetry.sockets", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var handler: (@Sendable (SecurityEvent) -> Void)?
    private var procs: [ProcKey: ProcEntry] = [:]
    private var known: [ConnKey: Int] = [:]   // -> last sweep seen
    private var sweepNo = 0
    private var fdBuffer: [proc_fdinfo] = []
    public private(set) var emitted = 0
    public var sweeps: Int { queue.sync { sweepNo } }
    public private(set) var processesInspected = 0

    public init(interval: TimeInterval = 2, identities: CodeIdentityCache = .shared) {
        self.interval = max(0.1, interval)
        self.identities = identities
    }

    public var isAvailable: Bool { true }
    public var isRunning: Bool { queue.sync { timer != nil } }

    public func start(handler: @escaping @Sendable (SecurityEvent) -> Void) throws {
        stop()
        queue.sync {
            self.handler = handler
            sweepNo = 0; known.removeAll(); procs.removeAll()
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now(), repeating: interval, leeway: .milliseconds(Int(interval * 100)))
            t.setEventHandler { [weak self] in self?.sweep() }
            timer = t
            t.resume()
        }
    }

    public func stop() { queue.sync { timer?.cancel(); timer = nil; handler = nil } }
    deinit { timer?.cancel() }

    @discardableResult
    public func sweepNow() -> [SecurityEvent] {
        queue.sync {
            final class Box: @unchecked Sendable { var events: [SecurityEvent] = [] }
            let box = Box(); let saved = handler
            handler = { box.events.append($0) }
            sweep(); handler = saved
            return box.events
        }
    }

    private func sweep() {
        cpu.measure {
            sweepNo += 1
            let baseline = sweepNo == 1
            let me = getpid()
            var inspected = 0
            for pid in ProcInspector.allPids() where !(excludeSelf && pid == me) && pid > 0 {
                guard let info = ProcInspector.bsdInfo(pid) else { continue }
                let pk = ProcKey(pid: pid, sec: info.startSec, usec: info.startUsec)
                if var e = procs[pk], e.skip { e.lastSeenSweep = sweepNo; procs[pk] = e; continue }
                // Sockets first (cheap syscalls); signing identity only for processes that have a new
                // interesting socket, so the baseline doesn't code-check every process on the machine.
                guard let socks = ProcInspector.sockets(pid, fdBuffer: &fdBuffer) else { continue }
                inspected += 1
                var fresh: [SocketTuple] = []
                for t in socks {
                    let interesting: Bool
                    if t.isListen { interesting = true }
                    else if t.proto == "tcp" { interesting = !t.remoteIP.isEmpty && t.remotePort != 0 && (t.state == "established" || t.state == "syn_sent") }
                    else { interesting = includeUDP && t.remotePort != 0 }
                    guard interesting else { continue }
                    let ck = ConnKey(proc: pk, tuple: t)
                    let isNew = known[ck] == nil
                    known[ck] = sweepNo
                    if isNew && (!baseline || (t.isListen && reportExistingListeners)) { fresh.append(t) }
                }
                if var e = procs[pk] { e.lastSeenSweep = sweepNo; procs[pk] = e }
                guard !fresh.isEmpty else { continue }
                var entry: ProcEntry
                if let e = procs[pk] { entry = e } else {
                    let path = ProcInspector.path(pid) ?? ""
                    let id = identities.identity(for: path)
                    let skip = skipPlatformBinaries && (id?.isPlatformBinary ?? false) && !EventHub.neverMute.contains(path)
                    entry = ProcEntry(path: path, identity: id, skip: skip, ppid: info.ppid, uid: info.uid, lastSeenSweep: sweepNo)
                    procs[pk] = entry
                }
                if entry.skip { continue }
                for t in fresh { emit(pid: pid, entry: entry, t: t, existing: baseline) }
            }
            processesInspected = inspected
            // Forget closed sockets and exited processes.
            if known.count > 0 { known = known.filter { $0.value == sweepNo } }
            if sweepNo % 10 == 0 { procs = procs.filter { $0.value.lastSeenSweep >= sweepNo - 1 } }
        }
    }

    private func emit(pid: Int32, entry: ProcEntry, t: SocketTuple, existing: Bool) {
        let proc = ProcessInfoLite(pid: pid, ppid: entry.ppid, path: entry.path, uid: entry.uid, signingID: entry.identity?.signingID,
                                   teamID: entry.identity?.teamID, isPlatformBinary: entry.identity?.isPlatformBinary ?? false)
        var detail: [String: String] = [
            "proto": t.proto, "local_ip": t.localIP, "local_port": String(t.localPort),
            "listen": t.isListen ? "1" : "0", "family": t.family == AF_INET6 ? "ipv6" : "ipv4",
        ]
        if t.isListen {
            if t.localIP == "0.0.0.0" || t.localIP == "::" || t.localIP.isEmpty { detail["local_ip"] = t.localIP.isEmpty ? "*" : t.localIP }
        } else {
            detail["remote_ip"] = t.remoteIP; detail["remote_port"] = String(t.remotePort)
            if let host = DNSAnswerCache.shared.host(for: t.remoteIP) { detail["remote_host"] = host }
        }
        if !t.state.isEmpty { detail["state"] = t.state }
        if let id = entry.identity { detail["signing"] = id.tier }
        if existing { detail["existing"] = "1" }
        emitted += 1
        handler?(SecurityEvent(kind: .networkConnect, process: proc, path: entry.path, detail: detail, source: name))
    }
}

/// IP → hostname map fed from DNS answers (EventHub records `dnsQuery` events that carry `answers`; the DNS
/// filter can call `record` directly), so `SocketSource` can label a connection with `remote_host`.
/// Bounded (LRU-ish, 4096 entries, 1 h TTL). Honest limit: a host resolved through DoH or a hard-coded IP never
/// appears here.
public final class DNSAnswerCache: @unchecked Sendable {
    public static let shared = DNSAnswerCache()
    public var capacity = 4096
    public var ttl: TimeInterval = 3600
    private var map: [String: (host: String, at: Date)] = [:]
    private let lock = NSLock()
    public init() {}

    public func record(ip: String, host: String, at: Date = Date()) {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !ip.isEmpty, !h.isEmpty, h.count <= 253, ip.count <= 45 else { return }
        lock.lock(); defer { lock.unlock() }
        map[ip] = (h, at)
        if map.count > capacity {
            let cutoff = map.values.map(\.at).sorted()[map.count / 4]
            map = map.filter { $0.value.at > cutoff }
        }
    }
    public func host(for ip: String, now: Date = Date()) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard let e = map[ip], now.timeIntervalSince(e.at) <= ttl else { return nil }
        return e.host
    }
}

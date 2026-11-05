import Foundation
import Darwin
import Security
import RampartShared

/// libproc helpers. Everything works unprivileged for the caller's own processes; root sees all argv.
public enum ProcInspector {
    public struct BSDInfo: Equatable, Sendable {
        public var pid: Int32, ppid: Int32, uid: UInt32
        public var startSec: UInt64, startUsec: UInt64
        public var comm: String
    }

    public static func allPids() -> [Int32] {
        let n = proc_listallpids(nil, 0)
        guard n > 0 else { return [] }
        var buf = [Int32](repeating: 0, count: Int(n) + 64)
        let got = buf.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard got > 0 else { return [] }
        return Array(buf.prefix(Int(got))).filter { $0 > 0 }
    }

    public static func bsdInfo(_ pid: Int32) -> BSDInfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.stride)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        let comm = withUnsafeBytes(of: info.pbi_comm) { raw -> String in
            let bytes = raw.prefix { $0 != 0 }
            return String(decoding: bytes, as: UTF8.self)
        }
        return BSDInfo(pid: pid, ppid: Int32(info.pbi_ppid), uid: info.pbi_uid,
                       startSec: info.pbi_start_tvsec, startUsec: info.pbi_start_tvusec, comm: comm)
    }

    public static func path(_ pid: Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        guard n > 0 else { return nil }
        return String(cString: buf)
    }

    private static let argMax: Int = {
        var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]; var v: Int32 = 0; var sz = MemoryLayout<Int32>.size
        return sysctl(&mib, 2, &v, &sz, nil, 0) == 0 && v > 0 ? Int(v) : 1024 * 1024
    }()

    /// argv via sysctl KERN_PROCARGS2: [argc:int32][exec_path\0][\0 padding][argv0\0]...[envp...]
    public static func arguments(_ pid: Int32, maxArgs: Int = 256) -> (execPath: String?, args: [String])? {
        var buf = [UInt8](repeating: 0, count: argMax)
        return arguments(pid, buffer: &buf, maxArgs: maxArgs)
    }

    /// Same, reusing a caller-owned buffer (avoids a 1 MB allocation per call in the sweep loop).
    public static func arguments(_ pid: Int32, buffer buf: inout [UInt8], maxArgs: Int = 256) -> (execPath: String?, args: [String])? {
        if buf.count < argMax { buf = [UInt8](repeating: 0, count: argMax) }
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = buf.count
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        let argc = buf.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        var i = MemoryLayout<Int32>.size
        func cstring() -> String? {
            let start = i
            while i < size && buf[i] != 0 { i += 1 }
            guard i <= size else { return nil }
            let s = String(decoding: buf[start..<i], as: UTF8.self)
            return s
        }
        let execPath = cstring()
        while i < size && buf[i] == 0 { i += 1 }
        var args: [String] = []
        while args.count < min(Int(argc), maxArgs) && i < size {
            guard let s = cstring() else { break }
            args.append(s)
            i += 1
        }
        return (execPath, args)
    }

    public struct CodeIdentity: Sendable, Equatable {
        public var signingID: String?
        public var teamID: String?
        public var isPlatformBinary: Bool
        /// "apple", "team", "adHoc", "unsigned", "unknown"
        public var tier: String
    }

    private static let appleReq: SecRequirement? = {
        var r: SecRequirement?
        return SecRequirementCreateWithString("anchor apple" as CFString, [], &r) == errSecSuccess ? r : nil
    }()

    /// Static signing identity of an executable. Platform = Apple platform identifier present and the
    /// code directory validates against `anchor apple` (resources not validated, to stay cheap).
    public static func codeIdentity(path: String) -> CodeIdentity {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else {
            return CodeIdentity(signingID: nil, teamID: nil, isPlatformBinary: false, tier: "unknown")
        }
        var infoCF: CFDictionary?
        let st = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &infoCF)
        guard st == errSecSuccess, let info = infoCF as? [String: Any] else {
            return CodeIdentity(signingID: nil, teamID: nil, isPlatformBinary: false, tier: "unknown")
        }
        let ident = info[kSecCodeInfoIdentifier as String] as? String
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String
        guard ident != nil || info[kSecCodeInfoUnique as String] != nil else {
            return CodeIdentity(signingID: nil, teamID: nil, isPlatformBinary: false, tier: "unsigned")
        }
        let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let platformID = info[kSecCodeInfoPlatformIdentifier as String] as? NSNumber
        var platform = false
        if platformID != nil, let req = appleReq {
            platform = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), req) == errSecSuccess
        }
        let tier: String
        if platform { tier = "apple" }
        else if flags & 0x2 != 0 { tier = "adHoc" }      // kSecCodeSignatureAdhoc
        else if team != nil { tier = "team" }
        else { tier = "unknown" }
        return CodeIdentity(signingID: ident, teamID: team, isPlatformBinary: platform, tier: tier)
    }
}

/// Polls libproc and emits `.exec` events for processes that appeared (new pid, pid reuse, or exec-replace)
/// since the previous sweep. Catches what eslogger misses and is the only exec source when not root.
/// Per sweep: one `proc_listallpids` + one `PROC_PIDTBSDINFO` per pid. Only new pids are enriched
/// (path, argv, signing); signing is cached by (path, inode, mtime).
public final class ProcessSweepSource: EventSource {
    public let name = "procsweep"
    public let interval: TimeInterval
    /// Emit events for processes already running at start.
    public var emitExisting: Bool
    /// Emit `.other` events with detail exit=1 when a tracked pid disappears.
    public var emitExits: Bool
    /// Resolve code-signing identity for new processes (cached).
    public var resolveSigning: Bool

    private struct Key: Hashable { var pid: Int32; var sec: UInt64; var usec: UInt64 }
    private struct Tracked { var key: Key; var comm: String; var path: String }
    private struct CacheKey: Hashable { var path: String; var ino: UInt64; var mtime: Int }

    private let queue = DispatchQueue(label: "app.rampart.telemetry.procsweep", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var handler: (@Sendable (SecurityEvent) -> Void)?
    private var tracked: [Int32: Tracked] = [:]
    private var signingCache: [CacheKey: ProcInspector.CodeIdentity] = [:]
    private var baselined = false
    private var argBuffer: [UInt8] = []
    private let selfPid = getpid()

    public private(set) var sweeps = 0
    public private(set) var totalSweepNanos: UInt64 = 0
    public private(set) var lastSweepNanos: UInt64 = 0
    public private(set) var emitted = 0

    public init(interval: TimeInterval = 0.5, emitExisting: Bool = false, emitExits: Bool = false, resolveSigning: Bool = true) {
        self.interval = max(0.05, interval)
        self.emitExisting = emitExisting
        self.emitExits = emitExits
        self.resolveSigning = resolveSigning
    }

    public var isAvailable: Bool { true }
    public var isRunning: Bool { queue.sync { timer != nil } }
    /// Average wall-clock cost of a sweep in milliseconds.
    public var averageSweepMillis: Double { queue.sync { sweeps == 0 ? 0 : Double(totalSweepNanos) / Double(sweeps) / 1e6 } }

    public func start(handler: @escaping @Sendable (SecurityEvent) -> Void) throws {
        stop()
        queue.sync {
            self.handler = handler
            self.baselined = false
            self.tracked.removeAll()
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now(), repeating: interval, leeway: .milliseconds(Int(interval * 100)))
            t.setEventHandler { [weak self] in self?.sweep() }
            timer = t
            t.resume()
        }
    }

    public func stop() {
        queue.sync {
            timer?.cancel(); timer = nil; handler = nil
        }
    }

    deinit { timer?.cancel() }

    /// Runs one sweep synchronously (for tests/benchmarks) and returns the events it produced.
    @discardableResult
    public func sweepNow() -> [SecurityEvent] {
        queue.sync {
            final class Box: @unchecked Sendable { var events: [SecurityEvent] = [] }
            let box = Box()
            let saved = handler
            handler = { box.events.append($0) }
            sweep()
            handler = saved
            return box.events
        }
    }

    private func identity(for path: String) -> ProcInspector.CodeIdentity? {
        guard resolveSigning, !path.isEmpty else { return nil }
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        let key = CacheKey(path: path, ino: st.st_ino, mtime: st.st_mtimespec.tv_sec)
        if let c = signingCache[key] { return c }
        let id = ProcInspector.codeIdentity(path: path)
        if signingCache.count > 4096 { signingCache.removeAll(keepingCapacity: true) }
        signingCache[key] = id
        return id
    }

    /// Runs on `queue`.
    private func sweep() {
        let t0 = DispatchTime.now().uptimeNanoseconds
        defer {
            let dt = DispatchTime.now().uptimeNanoseconds - t0
            sweeps += 1; totalSweepNanos += dt; lastSweepNanos = dt
        }
        let pids = ProcInspector.allPids()
        var seen = Set<Int32>(minimumCapacity: pids.count)
        let emit = baselined || emitExisting
        for pid in pids where pid != selfPid {
            seen.insert(pid)
            guard let info = ProcInspector.bsdInfo(pid) else { continue }
            let key = Key(pid: pid, sec: info.startSec, usec: info.startUsec)
            if let t = tracked[pid], t.key == key, t.comm == info.comm { continue }
            let replaced = tracked[pid]?.key == key   // same process, new image (exec without fork)
            let path = ProcInspector.path(pid) ?? ""
            if replaced, tracked[pid]?.path == path { tracked[pid]?.comm = info.comm; continue }
            tracked[pid] = Tracked(key: key, comm: info.comm, path: path)
            guard emit else { continue }
            emitExec(info: info, path: path, replaced: replaced)
        }
        if tracked.count != seen.count {
            for pid in tracked.keys where !seen.contains(pid) {
                let gone = tracked.removeValue(forKey: pid)
                if emitExits, baselined, let gone {
                    handler?(SecurityEvent(kind: .other, process: ProcessInfoLite(pid: pid, ppid: 0, path: gone.path),
                                           path: gone.path, detail: ["exit": "1"], source: name))
                }
            }
        }
        baselined = true
    }

    private func emitExec(info: ProcInspector.BSDInfo, path: String, replaced: Bool) {
        let argv = ProcInspector.arguments(info.pid, buffer: &argBuffer)
        let exe = path.isEmpty ? (argv?.execPath ?? info.comm) : path
        let id = identity(for: exe)
        let proc = ProcessInfoLite(pid: info.pid, ppid: info.ppid, path: exe, args: argv?.args ?? [], uid: info.uid,
                                   signingID: id?.signingID, teamID: id?.teamID, isPlatformBinary: id?.isPlatformBinary ?? false)
        var detail: [String: String] = ["start": "\(info.startSec).\(String(format: "%06llu", info.startUsec))"]
        if let id { detail["signing"] = id.tier }
        if replaced { detail["exec_replace"] = "1" }
        if argv == nil { detail["argv"] = "unavailable" }
        let date = Date(timeIntervalSince1970: Double(info.startSec) + Double(info.startUsec) / 1e6)
        emitted += 1
        handler?(SecurityEvent(date: date, kind: .exec, process: proc, path: exe, detail: detail, source: name))
    }
}

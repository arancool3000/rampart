import Foundation
import Darwin

/// Honest memory and CPU figures. RamPart does not "clean RAM": macOS uses free memory as cache on purpose
/// and reclaims it instantly. The only real actions are quitting apps you don't need and trimming startup items.
public enum SpeedMonitor {
    public enum Pressure: Int, Sendable { case normal = 1, warning = 2, critical = 4, unknown = 0
        public var label: String { [1: "Normal", 2: "Elevated", 4: "High", 0: "Unknown"][rawValue]! }
    }

    public struct Memory: Sendable, Equatable {
        public var total: UInt64
        public var wired: UInt64, active: UInt64, inactive: UInt64, free: UInt64, compressed: UInt64, purgeable: UInt64, speculative: UInt64
        public var swapUsed: UInt64
        public var pressure: Pressure
        /// What Activity Monitor calls "Memory Used": app memory + wired + compressed.
        public var used: UInt64 { min(total, active + wired + compressed) }
        /// File cache macOS can drop instantly when an app needs memory.
        public var cached: UInt64 { inactive + purgeable + speculative }
    }

    public static func memory() -> Memory? {
        var stats = vm_statistics64()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.stride / MemoryLayout<integer_t>.stride)
        let kr = withUnsafeMutablePointer(to: &stats) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count) }
        }
        guard kr == KERN_SUCCESS else { return nil }
        var pageSize: vm_size_t = 0
        host_page_size(mach_host_self(), &pageSize)
        let pg = UInt64(pageSize)
        var total: UInt64 = 0
        var size = MemoryLayout<UInt64>.size
        sysctlbyname("hw.memsize", &total, &size, nil, 0)
        var level: Int32 = 0
        size = MemoryLayout<Int32>.size
        let p: Pressure = sysctlbyname("kern.memorystatus_vm_pressure_level", &level, &size, nil, 0) == 0 ? (Pressure(rawValue: Int(level)) ?? .unknown) : .unknown
        var swap = xsw_usage()
        size = MemoryLayout<xsw_usage>.size
        sysctlbyname("vm.swapusage", &swap, &size, nil, 0)
        return Memory(total: total, wired: UInt64(stats.wire_count) * pg, active: UInt64(stats.active_count) * pg,
                      inactive: UInt64(stats.inactive_count) * pg, free: UInt64(stats.free_count) * pg,
                      compressed: UInt64(stats.compressor_page_count) * pg, purgeable: UInt64(stats.purgeable_count) * pg,
                      speculative: UInt64(stats.speculative_count) * pg, swapUsed: UInt64(swap.xsu_used), pressure: p)
    }

    public struct ProcessSample: Sendable, Hashable, Identifiable {
        public var id: Int32 { pid }
        public var pid: Int32
        public var name: String
        public var path: String
        /// The .app this process belongs to (helpers are grouped into their app), if any.
        public var appPath: String?
        public var footprint: UInt64
        public var cpuNanos: UInt64
    }

    public struct AppUsage: Sendable, Hashable, Identifiable {
        public var id: String { key }
        public var key: String          // app path, or process path
        public var name: String
        public var appPath: String?
        public var pids: [Int32]
        public var memory: UInt64
        public var cpuPercent: Double
    }

    static let timebase: (numer: UInt64, denom: UInt64) = {
        var tb = mach_timebase_info_data_t()
        mach_timebase_info(&tb)
        return (UInt64(tb.numer), UInt64(max(1, tb.denom)))
    }()

    /// Outermost .app in a path (so "Foo.app/Contents/Frameworks/Helper.app/…" → Foo.app).
    public static func outermostApp(_ path: String) -> String? {
        guard let r = path.range(of: ".app/") ?? (path.hasSuffix(".app") ? path.range(of: ".app", options: .backwards) : nil) else { return nil }
        return String(path[..<r.upperBound]).replacingOccurrences(of: ".app/", with: ".app")
    }

    public static func sampleProcesses() -> [ProcessSample] {
        let n = proc_listallpids(nil, 0)
        guard n > 0 else { return [] }
        var pids = [Int32](repeating: 0, count: Int(n) + 64)
        let got = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard got > 0 else { return [] }
        var out: [ProcessSample] = []
        let uid = getuid()
        for pid in pids.prefix(Int(got)) where pid > 0 {
            var info = proc_bsdinfo()
            let sz = Int32(MemoryLayout<proc_bsdinfo>.stride)
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sz) == sz, info.pbi_uid == uid else { continue }
            var ru = rusage_info_v4()
            let ok = withUnsafeMutablePointer(to: &ru) { ptr in
                ptr.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V4, $0) }
            }
            guard ok == 0 else { continue }
            var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            let path = proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : ""
            let comm = withUnsafeBytes(of: info.pbi_comm) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
            let cpu = (ru.ri_user_time + ru.ri_system_time) * timebase.numer / timebase.denom
            out.append(ProcessSample(pid: pid, name: comm, path: path, appPath: outermostApp(path), footprint: ru.ri_phys_footprint, cpuNanos: cpu))
        }
        return out
    }

    /// Groups two samples taken `interval` seconds apart into per-app usage, largest memory first.
    public static func usage(before: [ProcessSample], after: [ProcessSample], interval: TimeInterval) -> [AppUsage] {
        let prev = Dictionary(before.map { ($0.pid, $0.cpuNanos) }, uniquingKeysWith: { a, _ in a })
        var byKey: [String: AppUsage] = [:]
        for s in after {
            let key = s.appPath ?? (s.path.isEmpty ? "pid:\(s.pid)" : s.path)
            let name = s.appPath.map { (($0 as NSString).lastPathComponent as NSString).deletingPathExtension } ?? s.name
            let dCPU = s.cpuNanos >= (prev[s.pid] ?? s.cpuNanos) ? s.cpuNanos - (prev[s.pid] ?? s.cpuNanos) : 0
            let pct = interval > 0 ? Double(dCPU) / (interval * 1e9) * 100 : 0
            var u = byKey[key] ?? AppUsage(key: key, name: name, appPath: s.appPath, pids: [], memory: 0, cpuPercent: 0)
            u.pids.append(s.pid); u.memory += s.footprint; u.cpuPercent += pct
            byKey[key] = u
        }
        return byKey.values.sorted { $0.memory > $1.memory }
    }

    // MARK: Launch agents (fallback when the daemon's PersistenceScanner data isn't available)

    public struct LaunchAgentInfo: Sendable, Hashable, Identifiable {
        public var id: String { path }
        public var path: String
        public var label: String
        public var program: String?
        public var runAtLoad: Bool
        public var keepAlive: Bool
        public var targetMissing: Bool
        /// Rough impact: starts at login and stays running costs the most.
        public var impact: String { keepAlive ? "High" : (runAtLoad ? "Medium" : "Low") }
    }

    public static func userLaunchAgents(home: String = NSHomeDirectory()) -> [LaunchAgentInfo] {
        let dir = home + "/Library/LaunchAgents"
        return ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).filter { $0.hasSuffix(".plist") }.sorted().compactMap { n in
            let p = dir + "/" + n
            guard let d = NSDictionary(contentsOfFile: p) as? [String: Any] else { return nil }
            let prog = (d["Program"] as? String) ?? (d["ProgramArguments"] as? [String])?.first
            let keep = (d["KeepAlive"] as? Bool) ?? (d["KeepAlive"] is [String: Any])
            return LaunchAgentInfo(path: p, label: (d["Label"] as? String) ?? n, program: prog, runAtLoad: (d["RunAtLoad"] as? Bool) ?? false,
                                   keepAlive: keep, targetMissing: prog.map { !FileManager.default.fileExists(atPath: $0) } ?? false)
        }
    }
}

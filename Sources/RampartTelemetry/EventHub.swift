import Foundation
import RampartShared

/// Fans in every `EventSource`, then filters (platform-binary muting), dedupes across sources,
/// rate-limits per source, and buffers with priority-aware backpressure before delivering to one
/// consumer on a dedicated serial queue. `ingest` is safe to call from any thread and never blocks
/// on the consumer.
public final class EventHub {
    public struct Config {
        /// Window in which identical events (same kind/pid/path/dest, any source) are collapsed.
        public var dedupeWindow: TimeInterval = 2
        /// Token-bucket refill per source, events/second, and burst size.
        public var perSourceRate: Double = 2000
        public var perSourceBurst: Double = 5000
        /// Max undelivered events. When full, low-priority (file) events are dropped first.
        public var bufferCapacity: Int = 20_000
        public var mute: MutePolicy = .standard
        /// Feed clipboard events received from another process (session agent) into `clipboardMemory`.
        /// Leave false when the ClipboardSource runs in this process with the same memory.
        public var ingestRemoteClipboard = false
        public init() {}
    }

    public enum MutePolicy {
        /// Deliver everything.
        case none
        /// Drop file and network events from Apple platform binaries (except `neverMute` tools) and execs of Apple
        /// system daemons (platform binary, launched by launchd, under /System, /usr/libexec, /usr/sbin).
        /// Platform shells/interpreters still produce exec events so lineage rules work.
        case standard
        /// Drop every event whose process is an Apple platform binary (except `neverMute`).
        case allPlatform
    }

    /// Platform binaries that are frequently abused and must never be muted (LOLBins).
    public static let neverMute: Set<String> = [
        "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/csh", "/bin/tcsh", "/bin/ksh",
        "/usr/bin/osascript", "/usr/bin/curl", "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/ruby",
        "/usr/bin/ditto", "/usr/bin/xattr", "/usr/bin/security", "/usr/bin/sqlite3", "/usr/bin/base64",
        "/usr/bin/openssl", "/usr/bin/nscurl", "/usr/bin/hdiutil", "/usr/sbin/installer", "/usr/bin/launchctl",
        "/bin/launchctl", "/usr/bin/crontab", "/usr/bin/tclsh", "/usr/bin/swift", "/usr/bin/screencapture",
        "/usr/sbin/screencapture", "/usr/bin/dscl", "/usr/bin/tccutil", "/usr/bin/spctl", "/usr/sbin/spctl",
        "/usr/bin/codesign", "/usr/bin/nc", "/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/zip", "/usr/bin/unzip",
        "/usr/bin/tar", "/usr/bin/funzip", "/usr/bin/pbpaste", "/usr/bin/pbcopy", "/usr/bin/sudo",
        "/usr/bin/env", "/usr/bin/open", "/usr/bin/chflags", "/bin/chmod", "/usr/sbin/chown", "/bin/cp", "/bin/mv",
    ]

    public struct Stats: Codable, Sendable, Equatable {
        public var received = 0
        public var delivered = 0
        public var muted = 0
        public var deduped = 0
        public var rateLimited = 0
        public var overflowDropped = 0
        public var perSource: [String: Int] = [:]
        public var buffered = 0
    }

    public private(set) var config: Config
    /// When set, exec events whose argv matches a recent risky/command clipboard copy are annotated with
    /// `clipboard_match=1`, `clipboard_exact`, `clipboard_overlap`, `clipboard_class`, `clipboard_reasons`,
    /// `clipboard_source_app`, `clipboard_age` (seconds).
    public var clipboardMemory: ClipboardMemory?
    private let lock = NSLock()
    private var sources: [EventSource] = []
    private var running: [String: Bool] = [:]
    private var errors: [String: String] = [:]
    private var handler: ((SecurityEvent) -> Void)?
    private var high: [SecurityEvent] = []   // FIFO via head index
    private var low: [SecurityEvent] = []
    private var highHead = 0, lowHead = 0
    private var draining = false
    private var recent: [DedupeKey: TimeInterval] = [:]
    private var lastPrune: TimeInterval = 0
    private var buckets: [String: (tokens: Double, at: TimeInterval)] = [:]
    private var stats = Stats()
    private let deliverQueue = DispatchQueue(label: "app.rampart.telemetry.hub", qos: .userInitiated)
    private let log = RLog.logger("telemetry.hub")

    private struct DedupeKey: Hashable { var kind: SecurityEventKind; var pid: Int32; var path: String; var dest: String; var extra: String }

    public init(config: Config = Config()) { self.config = config }

    public func add(_ source: EventSource) { lock.withLock { sources.append(source) } }

    /// Starts every available source and delivers filtered events to `handler` (serially, off-thread).
    /// Sources that fail to start are recorded in `sourceErrors` and skipped.
    public func start(handler: @escaping (SecurityEvent) -> Void) {
        let list = lock.withLock { () -> [EventSource] in self.handler = handler; return sources }
        for s in list {
            guard s.isAvailable else {
                lock.withLock { running[s.name] = false; errors[s.name] = "unavailable" }
                continue
            }
            do {
                try s.start { [weak self] ev in self?.ingest(ev) }
                lock.withLock { running[s.name] = true; errors[s.name] = nil }
            } catch {
                lock.withLock { running[s.name] = false; errors[s.name] = String(describing: error) }
                log.error("source \(s.name, privacy: .public) failed: \(String(describing: error), privacy: .public)")
            }
        }
    }

    public func stop() {
        let list = lock.withLock { () -> [EventSource] in sources }
        for s in list { s.stop() }
        lock.withLock { for k in running.keys { running[k] = false }; handler = nil }
    }

    /// Source name → running, for `ProtectionStatus.sources`.
    public var sourceStatus: [String: Bool] { lock.withLock { running } }
    public var sourceErrors: [String: String] { lock.withLock { errors } }
    /// CPU seconds each source has spent in its own work (sources that implement `CPUReporting`).
    public var cpuBySource: [String: Double] {
        let list = lock.withLock { sources }
        var out: [String: Double] = [:]
        for s in list { if let r = s as? CPUReporting { out[s.name] = r.cpu.cpuSeconds } }
        return out
    }
    public var currentStats: Stats { lock.withLock { var s = stats; s.buffered = (high.count - highHead) + (low.count - lowHead); return s } }

    static func isHighPriority(_ k: SecurityEventKind) -> Bool {
        switch k {
        case .fileCreate, .fileWrite, .fileClose, .fileRename, .fileDelete, .other: return false
        default: return true
        }
    }

    static func isFileEvent(_ k: SecurityEventKind) -> Bool {
        switch k { case .fileCreate, .fileWrite, .fileClose, .fileRename, .fileDelete: return true; default: return false }
    }

    /// Mute decision, exposed for tests.
    public static func shouldMute(_ ev: SecurityEvent, policy: MutePolicy) -> Bool {
        guard let p = ev.process, p.isPlatformBinary, !neverMute.contains(p.path) else { return false }
        switch policy {
        case .none: return false
        case .allPlatform: return true
        case .standard:
            if isFileEvent(ev.kind) || ev.kind == .networkConnect { return true }
            if ev.kind == .exec {
                let daemonDir = p.path.hasPrefix("/System/") || p.path.hasPrefix("/usr/libexec/") || p.path.hasPrefix("/usr/sbin/")
                return daemonDir && p.ppid == 1
            }
            return false
        }
    }

    static func dedupeExtra(_ ev: SecurityEvent) -> String {
        let d = ev.detail
        switch ev.kind {
        case .networkConnect, .dnsQuery:
            return [d["proto"], d["local_ip"], d["local_port"], d["remote_ip"], d["remote_port"], d["listen"], d["name"]]
                .map { $0 ?? "" }.joined(separator: "|")
        case .other:
            if d["type"] == "clipboard" { return "clipboard|" + (d["text_fp"] ?? d["change_count"] ?? "") }
            return d["es_event"] ?? d["fsevent"] ?? d["type"] ?? d["message"].map { String($0.prefix(120)) } ?? ""
        default:
            return ""
        }
    }

    /// Entry point for every source. Cheap; never calls the consumer synchronously.
    public func ingest(_ incoming: SecurityEvent) {
        var ev = incoming
        if let mem = clipboardMemory {
            if ev.kind == .exec, let args = ev.process?.args, args.count > 0, let m = mem.match(args: args) {
                ev.detail["clipboard_match"] = "1"
                ev.detail["clipboard_exact"] = m.exact ? "1" : "0"
                ev.detail["clipboard_overlap"] = String(format: "%.2f", m.overlap)
                ev.detail["clipboard_class"] = m.entry.cls.rawValue
                if !m.entry.reasons.isEmpty { ev.detail["clipboard_reasons"] = m.entry.reasons.joined(separator: ",") }
                if let app = m.entry.sourceApp { ev.detail["clipboard_source_app"] = app }
                ev.detail["clipboard_age"] = String(Int(Date().timeIntervalSince(m.entry.date)))
            } else if config.ingestRemoteClipboard, ev.kind == .other, ev.detail["type"] == "clipboard" {
                mem.ingest(ev)
            }
        }
        let now = ProcessInfo.processInfo.systemUptime
        lock.lock()
        stats.received += 1
        if Self.shouldMute(ev, policy: config.mute) { stats.muted += 1; lock.unlock(); return }
        // Dedupe (cross-source: eslogger exec + procsweep exec of the same pid collapse).
        let extra = Self.dedupeExtra(ev)
        let key = DedupeKey(kind: ev.kind, pid: ev.process?.pid ?? 0, path: ev.path ?? "", dest: ev.destPath ?? "", extra: extra)
        if let t = recent[key], now - t < config.dedupeWindow { stats.deduped += 1; lock.unlock(); return }
        recent[key] = now
        if now - lastPrune > config.dedupeWindow * 2 || recent.count > 50_000 {
            recent = recent.filter { now - $0.value < config.dedupeWindow }
            lastPrune = now
        }
        // Per-source token bucket.
        var b = buckets[ev.source] ?? (config.perSourceBurst, now)
        b.tokens = min(config.perSourceBurst, b.tokens + (now - b.at) * config.perSourceRate); b.at = now
        if b.tokens < 1 { buckets[ev.source] = b; stats.rateLimited += 1; lock.unlock(); return }
        b.tokens -= 1; buckets[ev.source] = b
        stats.perSource[ev.source, default: 0] += 1
        // Backpressure: bounded buffer, shed low priority first, then oldest high.
        if Self.isHighPriority(ev.kind) { high.append(ev) } else { low.append(ev) }
        while (high.count - highHead) + (low.count - lowHead) > config.bufferCapacity {
            if low.count > lowHead { lowHead += 1 } else { highHead += 1 }
            stats.overflowDropped += 1
        }
        let kick = !draining
        draining = true
        lock.unlock()
        if kick { deliverQueue.async { [weak self] in self?.drain() } }
    }

    private func drain() {
        while true {
            lock.lock()
            let ev: SecurityEvent
            if highHead < high.count { ev = high[highHead]; highHead += 1 }
            else if lowHead < low.count { ev = low[lowHead]; lowHead += 1 }
            else {
                high.removeAll(keepingCapacity: true); low.removeAll(keepingCapacity: true)
                highHead = 0; lowHead = 0; draining = false
                lock.unlock(); return
            }
            if highHead > 4096 && highHead * 2 > high.count { high.removeFirst(highHead); highHead = 0 }
            if lowHead > 4096 && lowHead * 2 > low.count { low.removeFirst(lowHead); lowHead = 0 }
            let h = handler
            stats.delivered += 1
            lock.unlock()
            h?(ev)
        }
    }
}

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
        /// Hard safety cap for the critical-event queue (xprotect/persistence/tcc/xattr-delete). These are
        /// never shed by normal backpressure; only a pathological flood past this much larger cap sheds them.
        public var critBufferCapacity: Int = 200_000
        public var mute: MutePolicy = .standard
        /// Feed clipboard events received from another process (session agent) into `clipboardMemory`.
        /// Leave false when the ClipboardSource runs in this process with the same memory.
        public var ingestRemoteClipboard = false
        /// How often the health monitor checks that every started source is still alive.
        public var healthCheckInterval: TimeInterval = 15
        /// If > 0, a started source that has delivered events but then goes silent for this long is treated
        /// as blinded (off by default: many sources are legitimately quiet).
        public var sourceSilence: TimeInterval = 0
        /// Paths where RamPart's own helpers legitimately live (for impostor detection). The daemon adds its
        /// real/development binary path so it never flags itself.
        public var rampartInstallPaths: [String] = RampartService.installPrefixes
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
        // Writers seen in persistence / trust tampering (X6 T-X6-2); low exec volume.
        "/usr/bin/tee", "/usr/libexec/PlistBuddy", "/usr/bin/plutil", "/usr/bin/defaults", "/usr/bin/at", "/usr/bin/sed",
        "/usr/sbin/sysadminctl", "/usr/sbin/dseditgroup", "/usr/libexec/ApplicationFirewall/socketfilterfw", "/sbin/pfctl",
        "/usr/bin/log", "/usr/sbin/scutil", "/usr/sbin/networksetup", "/usr/bin/profiles", "/usr/bin/lldb", "/usr/bin/vmmap",
        "/usr/bin/leaks", "/usr/bin/sample", "/usr/bin/rsync", "/usr/bin/sftp", "/bin/rm", "/bin/dd",
        "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
    ]

    /// File events on these persistence- or trust-critical paths are never muted, whoever writes them (T-X6-2).
    public static let criticalPathPrefixes = ["/private/etc/", "/etc/", "/Library/LaunchAgents/", "/Library/LaunchDaemons/",
        "/usr/lib/cron/", "/private/var/at/", "/Library/Security/SecurityAgentPlugins/", "/usr/local/lib/pam/",
        "/Library/Preferences/SystemConfiguration/", "/Library/Managed Preferences/", "/Library/DirectoryServices/PlugIns/"]
    public static let criticalPathInfixes = ["/Library/LaunchAgents/", "/.ssh/", "/External Extensions/", "/NativeMessagingHosts/"]

    static func isCriticalPath(_ path: String) -> Bool {
        criticalPathPrefixes.contains(where: path.hasPrefix) || criticalPathInfixes.contains(where: path.contains)
    }

    public struct Stats: Codable, Sendable, Equatable {
        public var received = 0
        public var delivered = 0
        public var muted = 0
        public var deduped = 0
        public var rateLimited = 0
        /// High-priority security events admitted past an exhausted token bucket (never dropped).
        public var rateLimitExempt = 0
        public var overflowDropped = 0
        /// Critical security events shed — only ever non-zero under extreme, pathological memory pressure.
        public var criticalDropped = 0
        public var perSource: [String: Int] = [:]
        public var buffered = 0
        /// Identical execs (same parent, image and argv) beyond the storm limit, collapsed (wms-o6).
        public var floodCollapsed = 0
        /// `telemetry_gap` events the hub itself raised because it had to shed events.
        public var gapEvents = 0
    }

    /// Identical execs from one parent allowed per `stormWindow` before the rest are collapsed. A `while true; do
    /// /usr/bin/true; done` storm can't then evict a real exec from the bounded buffer.
    public static let stormLimit = 32
    public static let stormWindow: TimeInterval = 2

    public private(set) var config: Config
    /// When set, exec events whose argv matches a recent risky/command clipboard copy are annotated with
    /// `clipboard_match=1`, `clipboard_exact`, `clipboard_overlap`, `clipboard_class`, `clipboard_reasons`,
    /// `clipboard_source_app`, `clipboard_age` (seconds).
    public var clipboardMemory: ClipboardMemory?
    /// Called when the hub synthesises a Detection of its own: a telemetry source went blind
    /// ("lost its event feed") or a process is impersonating a RamPart helper. The daemon routes these to
    /// the detection store / UI so protection state can flip to "not protected".
    public var onDetection: ((Detection) -> Void)?
    /// A telemetry source is down (not permitted / missing Full Disk Access / stopped / crashed). Called with the
    /// deduplicated note (count 1 the first time, then the running count). Never a Detection, never tampering.
    public var onHealthNote: ((HealthNote) -> Void)?
    private var notes: [String: HealthNote] = [:]
    /// One entry per problem with a repeat count (user incident 2026-11-07: dozens of identical "feed lost" detections).
    public var healthNotes: [HealthNote] { lock.withLock { Array(notes.values) }.sorted { $0.id < $1.id } }
    private let lock = NSLock()
    private let selfPid = getpid()
    private var healthTimer: DispatchSourceTimer?
    private var startedSources: Set<String> = []
    private var downSources: Set<String> = []
    private var lastEventAt: [String: TimeInterval] = [:]
    private let healthQueue = DispatchQueue(label: "app.rampart.telemetry.hub.health", qos: .utility)
    private var sources: [EventSource] = []
    private var running: [String: Bool] = [:]
    private var errors: [String: String] = [:]
    private var handler: ((SecurityEvent) -> Void)?
    private var crit: [SecurityEvent] = []   // critical security events: never rate-limited, never shed
    private var high: [SecurityEvent] = []   // FIFO via head index
    private var low: [SecurityEvent] = []
    private var critHead = 0, highHead = 0, lowHead = 0
    private var draining = false
    private var recent: [DedupeKey: TimeInterval] = [:]
    private var lastPrune: TimeInterval = 0
    private var buckets: [String: (tokens: Double, at: TimeInterval)] = [:]
    private var storms: [Int: (start: TimeInterval, count: Int)] = [:]
    private var lastGapAt: TimeInterval = -1_000
    private var droppedSinceGap = 0
    private var pendingGap: SecurityEvent?
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
                lock.withLock { running[s.name] = true; errors[s.name] = nil; startedSources.insert(s.name); downSources.remove(s.name) }
            } catch {
                lock.withLock { running[s.name] = false; errors[s.name] = String(describing: error) }
                log.error("source \(s.name, privacy: .public) failed: \(String(describing: error), privacy: .public)")
                // Never started (e.g. eslogger not permitted without Full Disk Access): a status note, not a detection.
                let hr = s as? SourceHealthReporting
                let n = noteDown(s.name, lastError: hr?.lastError ?? String(describing: error))
                onHealthNote?(n)
            }
        }
        startHealthMonitor()
    }

    public func stop() {
        let list = lock.withLock { () -> [EventSource] in sources }
        for s in list { s.stop() }
        healthTimer?.cancel(); healthTimer = nil
        lock.withLock { for k in running.keys { running[k] = false }; startedSources.removeAll(); downSources.removeAll(); handler = nil }
    }

    // MARK: - Source health (never go blind silently)

    private func startHealthMonitor() {
        healthTimer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: healthQueue)
        let interval = max(1, config.healthCheckInterval)
        t.schedule(deadline: .now() + interval, repeating: interval, leeway: .seconds(2))
        t.setEventHandler { [weak self] in self?.healthTick() }
        healthTimer = t
        t.resume()
    }

    /// Public hook so the daemon (or a test) can force an immediate health evaluation.
    public func checkHealthNow() { healthTick() }

    private func healthTick() {
        let list = lock.withLock { sources }
        let handlerSnapshot = lock.withLock { handler }
        for s in list {
            let wasStarted = lock.withLock { startedSources.contains(s.name) }
            guard wasStarted else { continue }          // never started ⇒ nothing to lose
            let hr = s as? SourceHealthReporting
            let avail = s.isAvailable
            let running = hr?.isRunning ?? lock.withLock { self.running[s.name] ?? false }
            var healthy = avail && running
            if healthy, config.sourceSilence > 0, let last = lock.withLock({ lastEventAt[s.name] }),
               ProcessInfo.processInfo.systemUptime - last > config.sourceSilence {
                healthy = false
            }
            let wasDown = lock.withLock { downSources.contains(s.name) }
            if !healthy && !wasDown {
                lock.withLock { _ = downSources.insert(s.name); self.running[s.name] = false; errors[s.name] = hr?.lastError ?? "stopped" }
                log.error("telemetry source \(s.name, privacy: .public) is down — real-time protection is blind")
                let n = noteDown(s.name, lastError: hr?.lastError)
                onHealthNote?(n)
            } else if healthy && wasDown {
                lock.withLock { downSources.remove(s.name); self.running[s.name] = true; errors[s.name] = nil; notes[s.name] = nil }
                log.notice("telemetry source \(s.name, privacy: .public) recovered")
            }
            // Keep retrying a down-but-available source instead of staying blind forever.
            if !healthy, avail, let h = handlerSnapshot {
                try? s.start { [weak self] ev in self?.ingest(ev) }
                let backUp = (s as? SourceHealthReporting)?.isRunning ?? true
                if backUp { lock.withLock { self.running[s.name] = true; downSources.remove(s.name) } }
                _ = h
            }
        }
    }

    /// Records (or counts) the health note for a down source. Flapping (restart, down again) increments the count.
    private func noteDown(_ name: String, lastError: String?) -> HealthNote {
        lock.withLock {
            let now = Date()
            if var n = notes[name] {
                n.count += 1; n.lastSeen = now
                if HealthNote.isPermissionError(lastError) && n.fix != .fullDiskAccess { let f = HealthNote.sourceDown(name, lastError: lastError, at: n.firstSeen); n.message = f.message; n.detail = f.detail; n.fix = f.fix }
                notes[name] = n; return n
            }
            let n = HealthNote.sourceDown(name, lastError: lastError, at: now)
            notes[name] = n; return n
        }
    }

    /// Legacy shape of the feed-lost signal, kept for callers that still build it. It is a health issue
    /// (EmergencyTriggerPolicy.isHealthIssue) and is never raised by the hub any more.
    public static func feedLostDetectionForTest(name: String, lastError: String?) -> Detection { feedLostDetection(name: name, lastError: lastError) }
    static func feedLostDetection(name: String, lastError: String?) -> Detection {
        Detection(name: "\(Product.name) lost its real-time event feed",
                  category: .suspicious, severity: .high, confidence: 85,
                  evidence: [Evidence(source: .behaviour,
                                      title: "Telemetry source '\(name)' is down",
                                      detail: lastError ?? "source stopped; real-time protection is blind until it restarts",
                                      score: 85)])
    }

    /// A RamPart developer build: inside a RamPart source checkout (Package.swift + Sources/rampartd beside it),
    /// under its .build*/ or dist/ output. Those are unsigned-by-design copies, not impostors.
    static func isRampartDevBuild(_ path: String) -> Bool {
        var dir = (path as NSString).deletingLastPathComponent
        let fm = FileManager.default
        while dir.count > 1 {
            let name = (dir as NSString).lastPathComponent
            if name == "dist" || name.hasPrefix(".build") {
                let repo = (dir as NSString).deletingLastPathComponent
                return fm.fileExists(atPath: repo + "/Package.swift") && fm.fileExists(atPath: repo + "/Sources/rampartd")
            }
            dir = (dir as NSString).deletingLastPathComponent
        }
        return false
    }

    static func impostorDetection(path: String?, pid: Int32?, reason: String) -> Detection {
        Detection(path: path, pid: pid, name: "Process impersonating \(Product.name)",
                  category: .suspicious, severity: .medium, confidence: 45,
                  evidence: [Evidence(source: .behaviour,
                                      title: "A process is pretending to be \(Product.name)",
                                      detail: reason, score: 45)])
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
    public var currentStats: Stats { lock.withLock { var s = stats; s.buffered = (crit.count - critHead) + (high.count - highHead) + (low.count - lowHead); return s } }

    static func isHighPriority(_ k: SecurityEventKind) -> Bool {
        switch k {
        case .fileCreate, .fileWrite, .fileClose, .fileRename, .fileDelete, .other: return false
        default: return true
        }
    }

    /// Security-defining events that must never be dropped by rate limiting or buffer backpressure.
    /// An attacker floods cheaper events (short-lived execs, file churn) to exhaust limits and hide one
    /// of these; they get their own reserved, delivery-first queue.
    static func isCritical(_ k: SecurityEventKind) -> Bool {
        switch k {
        case .xprotectDetection, .persistenceAdded, .persistenceRemoved, .tccRequest, .xattrDelete: return true
        default: return false
        }
    }

    /// Critical by kind, or a report that telemetry was lost (that report must survive the very flood it describes).
    static func isCriticalEvent(_ ev: SecurityEvent) -> Bool {
        isCritical(ev.kind) || (ev.kind == .other && ev.detail["type"] == "telemetry_gap")
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
            if isFileEvent(ev.kind), let path = ev.destPath ?? ev.path, isCriticalPath(path) || (ev.path.map(isCriticalPath) ?? false) {
                return false
            }
            if isFileEvent(ev.kind) || ev.kind == .networkConnect { return true }
            if ev.kind == .exec {
                // GUI app bundles (Terminal, Script Editor, Finder…) anchor lineage for ClickFix rules (T-X6-1).
                if p.path.contains(".app/Contents/MacOS/") { return false }
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
        if ev.kind == .dnsQuery, let name = ev.detail["name"] ?? ev.detail["query"], let answers = ev.detail["answers"] {
            for ip in answers.split(separator: ",").prefix(16) { DNSAnswerCache.shared.record(ip: String(ip).trimmingCharacters(in: .whitespaces), host: name, at: ev.date) }
        }
        if ev.kind == .networkConnect, ev.detail["remote_host"] == nil, let ip = ev.detail["remote_ip"], let h = DNSAnswerCache.shared.host(for: ip, now: ev.date) {
            ev.detail["remote_host"] = h
        }
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
        // Impostor check: a process named like a RamPart helper that isn't an installed, RamPart-signed binary.
        if ev.kind == .exec, let p = ev.process, p.pid != selfPid,
           RampartService.names.contains((p.path as NSString).lastPathComponent),
           !Self.isRampartDevBuild(p.path),
           let reason = RampartService.impostorReason(name: (p.path as NSString).lastPathComponent, path: p.path,
                                                       signingID: p.signingID, installPaths: config.rampartInstallPaths) {
            ev.detail["impostor_rampart"] = "1"
            ev.detail["impostor_reason"] = reason
            onDetection?(Self.impostorDetection(path: ev.path, pid: p.pid, reason: reason))
        }
        let now = ProcessInfo.processInfo.systemUptime
        lock.lock()
        stats.received += 1
        lastEventAt[ev.source] = now
        if Self.shouldMute(ev, policy: config.mute) { stats.muted += 1; lock.unlock(); return }
        // Dedupe (cross-source: eslogger exec + procsweep exec of the same pid collapse).
        let extra = Self.dedupeExtra(ev)
        let key = DedupeKey(kind: ev.kind, pid: ev.process?.pid ?? 0, path: ev.path ?? "", dest: ev.destPath ?? "", extra: extra)
        if let t = recent[key], now - t < config.dedupeWindow { stats.deduped += 1; lock.unlock(); return }
        recent[key] = now
        if now - lastPrune > config.dedupeWindow * 2 || recent.count > 50_000 {
            recent = recent.filter { now - $0.value < config.dedupeWindow }
            storms = storms.filter { now - $0.value.start < Self.stormWindow }
            lastPrune = now
        }
        // Exec storm collapse (wms-o6): identical execs from one parent beyond the limit carry no new information.
        if ev.kind == .exec, let p = ev.process {
            var h = Hasher(); h.combine(p.ppid); h.combine(p.path); h.combine(p.args)
            let sk = h.finalize()
            var st = storms[sk] ?? (now, 0)
            if now - st.start > Self.stormWindow { st = (now, 0) }
            st.count += 1; storms[sk] = st
            if storms.count > 50_000 { storms.removeAll(keepingCapacity: true) }
            if st.count > Self.stormLimit { stats.floodCollapsed += 1; lock.unlock(); return }
        }
        // Per-source token bucket. High-priority security events are NEVER dropped by rate limiting: a
        // flood of cheap events (short-lived execs, file churn) must not drain the bucket and silently
        // hide a real detection. Low-priority events still shed when the bucket is empty.
        var b = buckets[ev.source] ?? (config.perSourceBurst, now)
        b.tokens = min(config.perSourceBurst, b.tokens + (now - b.at) * config.perSourceRate); b.at = now
        let highPri = Self.isHighPriority(ev.kind) || Self.isCriticalEvent(ev)
        if b.tokens < 1 {
            if highPri {
                buckets[ev.source] = b            // bucket stays empty; admit the event anyway
                stats.rateLimitExempt += 1
            } else {
                buckets[ev.source] = b; stats.rateLimited += 1; lock.unlock(); return
            }
        } else {
            b.tokens -= 1; buckets[ev.source] = b
        }
        stats.perSource[ev.source, default: 0] += 1
        // Backpressure: bounded buffer. Critical events get a reserved queue that normal overflow never
        // sheds; otherwise shed low priority first, then oldest non-critical high.
        func buffered() -> Int { (crit.count - critHead) + (high.count - highHead) + (low.count - lowHead) }
        if Self.isCriticalEvent(ev) { crit.append(ev) }
        else if highPri { high.append(ev) } else { low.append(ev) }
        while buffered() > config.bufferCapacity {
            if low.count > lowHead { lowHead += 1; stats.overflowDropped += 1; droppedSinceGap += 1 }
            else if high.count > highHead { highHead += 1; stats.overflowDropped += 1; droppedSinceGap += 1 }
            else { break }   // only critical events remain: keep them unless the hard cap below trips
        }
        // Shedding is itself a signal: at most one telemetry_gap every 10 s, on the never-shed critical queue.
        // It lives in its own single slot (never shed, merged while pending) and is delivered after critical and
        // high-priority events, before file events: it is context, not something to outrank a real exec.
        if droppedSinceGap > 0 && (pendingGap != nil || now - lastGapAt >= 10) {
            let lost = droppedSinceGap + (pendingGap?.detail["lost"].flatMap(Int.init) ?? 0)
            if pendingGap == nil { stats.gapEvents += 1 }
            pendingGap = SecurityEvent(date: ev.date, kind: .other,
                                       detail: ["type": "telemetry_gap", "reason": "hub_overflow", "lost": String(lost),
                                                "gap_source": "hub"], source: "hub")
            droppedSinceGap = 0; lastGapAt = now
        }
        // Absolute safety valve: critical events alone must blow past a much larger hard cap before any
        // are shed (keeps a flood of real detections from unbounded memory growth).
        while (crit.count - critHead) > config.critBufferCapacity { critHead += 1; stats.criticalDropped += 1 }
        let kick = !draining
        draining = true
        lock.unlock()
        if kick { deliverQueue.async { [weak self] in self?.drain() } }
    }

    private func drain() {
        while true {
            lock.lock()
            let ev: SecurityEvent
            if critHead < crit.count { ev = crit[critHead]; critHead += 1 }   // critical first
            else if highHead < high.count { ev = high[highHead]; highHead += 1 }
            else if let g = pendingGap { ev = g; pendingGap = nil }
            else if lowHead < low.count { ev = low[lowHead]; lowHead += 1 }
            else {
                crit.removeAll(keepingCapacity: true); high.removeAll(keepingCapacity: true); low.removeAll(keepingCapacity: true)
                critHead = 0; highHead = 0; lowHead = 0; draining = false
                lock.unlock(); return
            }
            if critHead > 4096 && critHead * 2 > crit.count { crit.removeFirst(critHead); critHead = 0 }
            if highHead > 4096 && highHead * 2 > high.count { high.removeFirst(highHead); highHead = 0 }
            if lowHead > 4096 && lowHead * 2 > low.count { low.removeFirst(lowHead); lowHead = 0 }
            let h = handler
            stats.delivered += 1
            lock.unlock()
            h?(ev)
        }
    }
}

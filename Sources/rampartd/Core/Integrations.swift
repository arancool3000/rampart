import Foundation
import RampartShared
import RampartEngine
import RampartSigning
import RampartRemediation
import RampartNetwork
import RampartPosture

// Wires the library modules into Services. Daemon-only modules (RampartTelemetry: event sources)
// are wired from Sources/rampartd/DaemonWiring.swift through `daemonHook`, because the CLI target
// doesn't link them.

/// Runs an async function to completion from synchronous code (daemon worker threads only).
func runBlocking<T>(_ f: @escaping () async -> T) -> T {
    let sem = DispatchSemaphore(value: 0)
    var out: T?
    Task.detached { out = await f(); sem.signal() }
    sem.wait()
    return out!
}

enum Integrations {
    /// Set by rampartd before `Services.make` to add daemon-only wiring (event sources, behaviour engine).
    static var daemonHook: ((Services, Runtime) -> Void)?
    /// The YARA engine, if wired (for warm-up and status).
    static var lastYara: AnyObject?
    /// (ip, host) for every DNS filter answer; the daemon points this at RampartTelemetry.DNSAnswerCache.
    static var onDNSAnswer: ((String, String) -> Void)?

    static func wire(_ s: Services, runtime: Runtime, daemon: Bool) {
        var updaters: [(String, () -> String)] = []

        // Engine: hash DB + scan coordinator (+ signing heuristics, YARA).
        var db: HashDatabase?
        do { db = try HashDatabase(url: runtime.databaseDir.appendingPathComponent("rampart.sqlite")) }
        catch { logWarn("hash database unavailable: \(error)") }
        let coord = ScanCoordinator(database: db)
        coord.register(ScanGate())          // pause support; must run first
        coord.register(SigningEnricher())
        coord.register(SigningHeuristicDetector())
        var engineNotes = ["eicar", db != nil ? "hash-db" : "no-hash-db", "signing-heuristics"]
        engineNotes += wireYara(coord, runtime: runtime, updaters: &updaters)
        s.warmups += YaraWiring.warmups()
        let engine = EngineScanService(coord: coord, db: db, runtime: runtime)
        s.scanner = engine
        s.wiring = ["scanner: RampartEngine.ScanCoordinator [\(coord.detectorNames.joined(separator: ", "))]"]
        if let db {
            s.allowHooks.append { h in try? db.allow(sha256: h, note: "user allowed") }
            let updater = HashFeedUpdater(database: db)
            updaters.append(("hashes", {
                let r = runBlocking { () -> String in
                    do { let r = try await updater.update(); return "\(r.feed): \(r.stored) stored, \(r.pruned) pruned (sig \(r.signatureVersion))" }
                    catch {
                        // abuse.ch closed the free export (HTTP 307/410 without an Auth-Key). That isn't a network
                        // failure: report it as skipped so the scheduler doesn't retry (and rebuild everything) hourly.
                        let msg = "\(error)"
                        if msg.contains("HTTP 307") || msg.contains("HTTP 410") || msg.contains("HTTP 401") || msg.contains("HTTP 403") {
                            return "hash feed skipped (MalwareBazaar now needs an abuse.ch Auth-Key)"
                        }
                        return "hash feed failed: \(error)"
                    }
                }
                return r
            }))
        }
        _ = engineNotes

        // Remediation: encrypted vault + process killer.
        do {
            let vault = try QuarantineVault(root: runtime.quarantineDir)
            s.quarantine = VaultQuarantine(vault: vault)
            s.wiring.append("quarantine: RampartRemediation.QuarantineVault (AES-GCM)")
            let journal = try ActionJournal(directory: runtime.journalDir)
            s.persistenceRemediation = PersistenceRemediator(runtime: runtime, executor: RemediationExecutor(vault: vault, journal: journal, runner: GuardedRemediationRunner()))
            s.wiring.append("persistence cleanup: RampartRemediation.RemediationExecutor + ActionJournal\(runtime.userMode ? " (user-domain items only)" : "")")
        } catch {
            s.wiring.append("quarantine: builtin vault (QuarantineVault failed: \(error))")
        }
        s.processes = KillerResponder()
        s.wiring.append("process response: RampartRemediation.ProcessKiller")

        // Posture.
        s.posture = PostureAdapter(runtime: runtime)
        s.wiring.append("posture: RampartPosture.PostureScanner + PostureFixer")

        // Persistence (RampartBehaviour.PersistenceScanner when available).
        wireBehaviourPersistence(s, runtime: runtime)

        // Network: DNS filter (off by default) + blocklist updates.
        let lists = BlocklistUpdater(directory: runtime.blocklistDir)
        let web = WebProtection(runtime: runtime, lists: lists)
        s.web = web
        s.network = web
        s.webCheck = WebCheckService(runtime: runtime, web: web)
        web.onBlock = { [weak s] d, l in s?.onWebBlock?(d, l) }
        web.onQuery = { [weak s] e in s?.onDNSEvent?(e) }
        s.signingLookup = { path in SigningInspector.inspectCached(path: path).info }
        s.wiring.append("web protection: RampartNetwork.DNSFilterServer on 127.0.0.1:\(runtime.dnsPort) (\(runtime.config.webProtection ? "on" : "off"))")
        if let ng = NetGuardWiring.wire(s, runtime: runtime, web: web, daemon: daemon) {
            updaters.append(("content filter", { ng.updateLists() }))
        }
        updaters.append(("blocklists", {
            let r = runBlocking { await lists.updateAll() }
            // Rebuilding the blocklist parses hundreds of thousands of domains (CPU + memory churn). Only do it when
            // a list actually changed, not when every source said "not modified", was rejected or was unreachable.
            let changed = r.values.contains { if case .updated = $0 { return true }; return false }
            if changed { web.reloadBlocklist() }
            return r.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: ", ")
        }))

        s.updater = CompositeUpdater(updaters)
        if daemon {
            s.guardian = GuardService(runtime: runtime)
            s.wiring.append("guard: RampartGuard tamper detection + remote-access monitor (\(s.guardian!.enforce ? "enforcing" : "monitor only"))")
            daemonHook?(s, runtime)
        }
    }

    // MARK: modules that may still be placeholders

    static func wireYara(_ coord: ScanCoordinator, runtime: Runtime, updaters: inout [(String, () -> String)]) -> [String] {
        YaraWiring.wire(coord, runtime: runtime, updaters: &updaters)
    }

    static func wireBehaviourPersistence(_ s: Services, runtime: Runtime) {
        if let p = BehaviourWiring.persistence(runtime: runtime) {
            s.persistence = p
            s.wiring.append("persistence: RampartBehaviour.PersistenceScanner")
            if let e = BehaviourWiring.engine { s.behaviour = BehaviourControlAdapter(engine: e) }
        } else {
            s.wiring.append("persistence: builtin launchd enumeration")
        }
    }
}

// MARK: - Adapters

/// Blocks scan workers while the user has paused the scan (on-write scans are exempt).
struct ScanGate: FileFactsEnricher {
    func enrich(_ facts: inout FileFacts) { ScanControl.shared.waitIfPaused() }
}

/// Adds signing + provenance facts for executables so the engine's trust prior and detectors can use them.
struct SigningEnricher: FileFactsEnricher {
    func enrich(_ facts: inout FileFacts) {
        guard facts.signing == nil else { return }
        switch facts.kind {
        case .machO, .fatMachO, .appBundle:
            facts.signing = SigningInspector.inspectCached(path: facts.path).info
        default:
            guard facts.isExecutable, facts.kind == .script else { return }
        }
        if facts.quarantineOrigin == nil {
            let prov = Provenance.read(path: facts.path)
            facts.quarantineOrigin = prov.whereFroms.first ?? prov.quarantine?.agentName
        }
    }
}

final class EngineScanService: ScanService {
    let coord: ScanCoordinator
    /// More folders to skip (Cat & Mouse decoys and maze), set by the daemon wiring.
    var extraExclusions: (() -> [String])?
    let db: HashDatabase?
    let runtime: Runtime
    init(coord: ScanCoordinator, db: HashDatabase?, runtime: Runtime) { self.coord = coord; self.db = db; self.runtime = runtime }

    var engineNames: [String] { coord.detectorNames }
    var signatureVersion: String { "\(EngineInfo.version)/\(db?.signatureVersion ?? "nodb")" }

    private func options(for roots: [String]) -> ScanOptions {
        var o = coord.options
        func under(_ p: String, _ prefix: String) -> Bool { p == prefix || p.hasPrefix(prefix.hasSuffix("/") ? prefix : prefix + "/") }
        // Our exclusions, minus those that contain an explicitly requested root (the vault is always excluded).
        let ours = runtime.exclusions.filter { ex in !roots.contains { under($0, ex) } }
        // Our own data folders are excluded even when a request names them (or a parent) explicitly.
        o.walk.excludedPrefixes = Array(Set(WalkOptions.defaultExcludedPrefixes + ours + runtime.ownDataRoots + (extraExclusions?() ?? [])))
        o.walk.maxFileSize = UInt64(runtime.config.maxFileSizeMB) << 20
        o.unpackArchives = runtime.config.scanArchives
        // Keep the Mac responsive: half the cores on power (min 2), one on battery or in Low Power Mode.
        o.concurrency = PowerThrottle.shared.factor > 1 ? 1 : max(2, ProcessInfo.processInfo.activeProcessorCount / 2)
        return o
    }

    func scan(paths: [String], progress: @escaping ScanProgress, cancelled: @escaping () -> Bool) -> ScanOutcome {
        let cancel = ScanCancellation()
        let report = coord.scan(paths: paths, options: options(for: paths), cancel: cancel) { p in
            if cancelled() { cancel.cancel() }
            progress(p.scanned, max(p.discovered, p.scanned), p.current,
                     ScanTick(walkFinished: p.walkFinished, timedOut: p.timedOut, secondsSinceLastCompletion: p.secondsSinceLastCompletion))
        }
        // Files abandoned at the per-file deadline count as "couldn't be scanned".
        return ScanOutcome(scanned: report.scanned, detections: report.detections, seconds: report.seconds, errors: report.errors + report.timedOut)
    }

    func scanFile(_ path: String) -> Detection? {
        if runtime.isOwnData(path) { return nil }
        var o = options(for: [path]); o.unpackDiskImages = false
        guard let d = coord.scanFile(at: path, options: o).detection, d.confidence >= 30 else { return nil }
        return d
    }
}

final class VaultQuarantine: QuarantineService {
    let vault: QuarantineVault
    init(vault: QuarantineVault) { self.vault = vault }
    func list() -> [QuarantineRecord] { vault.list() }
    func quarantine(path: String, detection: Detection) throws -> QuarantineRecord {
        // wms-o2: pin the scanned content (only when the detection is about this exact file).
        let pin = detection.path.map { normalizePath($0) == normalizePath(path) } == true ? detection.sha256 : nil
        return try vault.quarantine(path: path, detectionName: detection.name, expectedSHA256: pin)
    }
    func restore(id: UUID) throws -> String {
        // wms-o2: restore the macOS quarantine flag with the item so Gatekeeper still checks it on first open.
        try vault.restore(id: id, options: QuarantineVault.RestoreOptions(reapplyQuarantineXattr: true, allowlist: false))
    }
    func delete(id: UUID) throws { try vault.delete(id: id) }
    func purgeExpired() { _ = vault.purge(olderThanDays: 30) }
}

final class KillerResponder: ProcessResponder {
    let killer = ProcessKiller()
    func terminate(pid: Int32, expectedPath: String?) -> String {
        guard let ident = ProcessKiller.identity(of: pid) else { return "pid \(pid) already gone" }
        if let exp = expectedPath {
            let actual = ProcessKiller.path(of: pid)
            if !actual.isEmpty && actual != exp && !exp.hasPrefix(actual) && !actual.hasPrefix(exp) {
                return "pid \(pid) now runs \(actual), not \(exp); not killed (pid reuse)"
            }
        }
        let r = killer.killTree(ident, dryRun: false)
        return "killed \(r.killed.count) process(es)\(r.skipped.isEmpty ? "" : "; skipped: \(r.skipped.joined(separator: ", "))")"
    }
}

final class PostureAdapter: PostureService {
    let runtime: Runtime
    init(runtime: Runtime) { self.runtime = runtime }
    func checks() -> [PostureCheck] { PostureScanner(runner: GuardedPostureRunner()).checks() }
    func score(_ checks: [PostureCheck]) -> Int? { SecurityScore.compute(checks).value }
    func fix(checkID: String, dryRun: Bool) throws -> String {
        guard let fix = PostureFixer.fix(for: checkID, dryRun: dryRun) else {
            throw ServiceError.failed("'\(checkID)' has no one-click fix\(PostureFixer.settingsLink(for: checkID).map { "; open \($0)" } ?? "")")
        }
        if dryRun || (fix.requiresRoot && getuid() != 0) {
            throw ServiceError.failed("not running as root; the fix would run:\n\(fix.preview)")
        }
        // hx10 #12: only allow-listed absolute tools with plain arguments, and never an unbounded wait.
        guard PostureFixer.isSafe(fix) else { throw ServiceError.denied("unsafe fix") }
        var out: [String] = []
        let runner = GuardedPostureRunner()
        for cmd in fix.commands {
            guard let exe = cmd.first else { continue }
            if let why = Privileged.refusal(exe) { throw ServiceError.denied(why) }
            let r = runner.run(exe, Array(cmd.dropFirst()), timeout: 30)
            out.append("\(cmd.joined(separator: " ")) -> \(r.timedOut ? "timed out" : String(r.status))")
            if !r.usable || r.status != 0 { throw ServiceError.failed("fix failed: \(out.joined(separator: "; "))") }
        }
        // Re-scan to verify the fix took effect.
        let after = PostureScanner(runner: GuardedPostureRunner()).checks().first { $0.id == checkID }
        out.append("re-check: \(after?.state.rawValue ?? "unknown")")
        if after?.state == .fail { throw ServiceError.failed("fix ran but the check still fails: \(out.joined(separator: "; "))") }
        return out.joined(separator: "; ")
    }
}

/// DNS web protection + everything the Network screen shows (connections, Wi-Fi, block stats).
final class WebProtection: WebProtectionService, NetworkInfoService {
    let runtime: Runtime
    let lists: BlocklistUpdater
    var onBlock: ((String, String?) -> Void)?
    var onQuery: ((SecurityEvent) -> Void)?
    /// Content filter / SafeSearch / app-firewall DNS policy (NetGuardWiring.swift) and a raw query-log observer.
    var dnsPolicy: DNSPolicy?
    var onLog: ((DNSQueryLogEntry) -> Void)?
    private var server: DNSFilterServer?
    private var switcher: DNSSwitcher?
    private let lock = NSLock()
    private let monitor = ConnectionMonitor()
    private lazy var wifiGuard = WiFiGuard(stateURL: runtime.root.appendingPathComponent("wifiguard.json"))

    // Block statistics (persisted) and IP -> host map from the DNS query log.
    private struct Stats: Codable { var byDay: [String: Int] = [:]; var recent: [String] = [] }
    private var stats = Stats()
    private var statsDirty = false
    private var ipToHost: [String: String] = [:]
    private var lastActivity: [String: Date] = [:]
    private var cachedList: DomainBlocklist?
    private var statsURL: URL { runtime.root.appendingPathComponent("dns-stats.json") }
    private static let dayFmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"; f.locale = Locale(identifier: "en_US_POSIX"); return f
    }()

    init(runtime: Runtime, lists: BlocklistUpdater) {
        self.runtime = runtime; self.lists = lists
        stats = (try? Data(contentsOf: runtime.root.appendingPathComponent("dns-stats.json")))
            .flatMap { try? JSONDecoder.rampart.decode(Stats.self, from: $0) } ?? Stats()
    }

    var isOn: Bool { lock.lock(); defer { lock.unlock() }; return server?.isRunning ?? false }

    func setOn(_ on: Bool) throws {
        lock.lock(); defer { lock.unlock() }
        if on {
            if server?.isRunning == true { return }
            let list = lists.buildBlocklist()
            cachedList = list
            var cfg = DNSFilterConfig(port: UInt16(runtime.dnsPort))   // listenAddress stays 127.0.0.1 (hx4 N2)
            cfg.pinStateURL = runtime.root.appendingPathComponent("doh-pins.json")   // hx4 N5: learned DoH key pins
            let srv = DNSFilterServer(config: cfg, blocklist: list)
            srv.queryLog = { [weak self] e in self?.record(e) }
            srv.policy = dnsPolicy
            srv.doh.onPinFailure = { [weak self] host, detail in self?.pinFailed(host: host, detail: detail) }
            try srv.start()
            server = srv
            // Point the system resolver at us only as the real root daemon (never in --user/dev runs).
            if getuid() == 0 && !runtime.userMode {
                let sw = DNSSwitcher(snapshotURL: runtime.root.appendingPathComponent("dns-original.json"), dryRun: false)
                do { _ = try sw.apply(); switcher = sw; suspendedForHealth = false } catch { logWarn("DNS switch failed: \(error)") }
            }
            startWatchdogLocked()
            logInfo("web protection on (DNS filter 127.0.0.1:\(runtime.dnsPort))")
        } else {
            if let sw = switcher { _ = sw.restore(); switcher = nil }
            suspendedForHealth = false
            watchdog?.cancel(); watchdog = nil
            server?.stop(); server = nil
            saveStatsLocked()
            logInfo("web protection off")
        }
    }

    // MARK: DNS restore guarantee (hx4 N1)

    /// Detections from the network layer (DoH pin failures); set by the daemon.
    var onDetection: ((Detection) -> Void)?
    private var watchdog: DispatchSourceTimer?
    private var suspendedForHealth = false
    private var lastPinAlert: [String: Date] = [:]
    private var mayTouchSystemDNS: Bool { getuid() == 0 && !runtime.userMode && !Privileged.noPrivilegedTools }
    private var snapshotURL: URL { runtime.root.appendingPathComponent("dns-original.json") }

    /// At launch, before anything else: a DNS snapshot left by a run that died while DNS pointed at us is restored.
    func recoverAtLaunch() {
        guard mayTouchSystemDNS else { return }
        let sw = DNSSwitcher(snapshotURL: snapshotURL, dryRun: false)
        if sw.needsRecovery(filterRunning: false) { _ = sw.restore(); logWarn("DNS restored at launch: a previous run had left DNS switched") }
    }

    /// SIGTERM/SIGINT: put DNS back even if the filter already died.
    func restoreOnExit() {
        lock.lock(); defer { lock.unlock() }
        if let sw = switcher { _ = sw.restore(); switcher = nil; logInfo("DNS restored on exit") }
        else if mayTouchSystemDNS {
            let sw = DNSSwitcher(snapshotURL: snapshotURL, dryRun: false)
            if sw.needsRecovery(filterRunning: false) { _ = sw.restore() }
        }
    }

    /// Every 10 s while on: a dead filter or an unreachable upstream gives DNS back to the system (visibly), and it is
    /// switched to RamPart again once the upstream is healthy.
    private func startWatchdogLocked() {
        guard watchdog == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "app.rampart.dns.watchdog", qos: .utility))
        t.schedule(deadline: .now() + 10, repeating: 10, leeway: .seconds(1))
        t.setEventHandler { [weak self] in self?.watchdogTick() }
        t.resume(); watchdog = t
    }

    private var failedProbes = 0

    /// Sends one real A query for a well-known name to the local resolver and waits up to `timeout` for any reply
    /// with the same ID (NOERROR or NXDOMAIN both prove the resolver answers). No system DNS settings are touched.
    static func probeResolver(port: UInt16, name: String = "apple.com", timeout: TimeInterval = 2) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - floor(timeout)) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let id = UInt16.random(in: 1...UInt16.max)
        var q: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") { q.append(UInt8(label.utf8.count)); q += Array(label.utf8) }
        q += [0, 0, 1, 0, 1]
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let sent = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            sendto(fd, q, q.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard sent == q.count else { return false }
        var buf = [UInt8](repeating: 0, count: 1500)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let n = recv(fd, &buf, buf.count, 0)
            if n < 0 && errno == EINTR { continue }
            guard n >= 12 else { return false }
            if buf[0] == UInt8(id >> 8) && buf[1] == UInt8(id & 0xff) && buf[2] & 0x80 != 0 {
                let rcode = buf[3] & 0x0f
                return rcode == 0 || rcode == 3
            }
        }
        return false
    }

    func watchdogTick() {
        // Probe outside the lock: a real query to the local resolver (the server object can be "running" and still
        // never answer, which left an installed Mac without DNS and broke iMessage).
        let port: UInt16? = { lock.lock(); defer { lock.unlock() }; return server.map { _ in UInt16(runtime.dnsPort) } }()
        let answers = port.map { Self.probeResolver(port: $0) } ?? true
        lock.lock(); defer { lock.unlock() }
        guard let s = server else { return }
        failedProbes = answers ? 0 : failedProbes + 1
        let healthy = s.isRunning && s.upstreamHealthy && failedProbes < 2
        if !healthy, let sw = switcher {
            _ = sw.restore(); switcher = nil; suspendedForHealth = true
            logWarn("DNS restored: filter unhealthy (\(!s.isRunning ? "filter stopped" : failedProbes >= 2 ? "local resolver not answering test queries" : "encrypted DNS upstream unreachable"))")
        } else if healthy, suspendedForHealth, mayTouchSystemDNS {
            let sw = DNSSwitcher(snapshotURL: snapshotURL, dryRun: false)
            do { _ = try sw.apply(); switcher = sw; suspendedForHealth = false; logInfo("DNS filter healthy again: re-applied") }
            catch { logWarn("DNS re-apply failed: \(error)") }
        }
    }

    private func pinFailed(host: String, detail: String) {
        lock.lock()
        let recent = Date().timeIntervalSince(lastPinAlert[host] ?? .distantPast) < 3600
        if !recent { lastPinAlert[host] = Date() }
        lock.unlock()
        guard !recent else { return }
        let h = LogRedact.clean(host, max: 120)
        logWarn("DoH key pin mismatch for \(h): \(LogRedact.clean(detail, max: 300))")
        let ev = Evidence(source: .network, title: "Encrypted DNS was intercepted",
                          detail: "The encrypted DNS server \(h) presented a key RamPart has not seen before. Something on this network may be intercepting secure connections. RamPart stopped using that server.",
                          score: 75)
        onDetection?(Detection(path: nil, name: "Encrypted DNS was intercepted (\(h))", category: .suspicious,
                               severity: .high, confidence: 75, evidence: [ev]))
    }

    /// The DNS policy's config or lists changed: drop cached answers so the change applies at once.
    func dnsPolicyChanged() {
        lock.lock(); let srv = server; lock.unlock()
        srv?.cache.clear()
    }

    func reloadBlocklist() {
        lock.lock(); defer { lock.unlock() }
        let l = lists.buildBlocklist()
        cachedList = l
        server?.blocklist = l
    }

    private func record(_ e: DNSQueryLogEntry) {
        lock.lock()
        var notify: (String, String?)?
        if e.verdict == .blocked {
            let day = Self.dayFmt.string(from: e.date)
            stats.byDay[day, default: 0] += 1
            stats.recent.removeAll { $0 == e.name }
            stats.recent.insert(e.name, at: 0); if stats.recent.count > 50 { stats.recent.removeLast() }
            statsDirty = true
            // One activity row per domain per 10 minutes.
            if Date().timeIntervalSince(lastActivity[e.name] ?? .distantPast) > 600 {
                lastActivity[e.name] = Date(); notify = (e.name, e.listSource)
                if lastActivity.count > 2000 { lastActivity.removeAll() }
            }
        } else {
            for a in e.answers where a.contains(".") || a.contains(":") {
                if a.first?.isNumber == true || a.contains(":") {
                    ipToHost[a] = e.name
                    Integrations.onDNSAnswer?(a, e.name)   // b5x TC5: DNSAnswerCache for SocketSource remote_host (daemon wiring)
                }
            }
            if ipToHost.count > 20000 { ipToHost.removeAll() }
        }
        let dirty = statsDirty && stats.byDay.values.reduce(0, +) % 20 == 0
        if dirty { saveStatsLocked() }
        lock.unlock()
        if let (d, l) = notify { onBlock?(d, l) }
        if !e.name.isEmpty { onQuery?(e.securityEvent) }
        onLog?(e)
    }

    private func saveStatsLocked() {
        // Keep 62 days.
        let cutoff = Self.dayFmt.string(from: Date().addingTimeInterval(-62 * 86400))
        stats.byDay = stats.byDay.filter { $0.key >= cutoff }
        try? Util.writeJSON(stats, to: statsURL); statsDirty = false
    }

    /// Current blocklist (built lazily, rebuilt on updates).
    func currentBlocklist() -> DomainBlocklist { blocklist() }

    private func blocklist() -> DomainBlocklist {
        lock.lock(); defer { lock.unlock() }
        if let l = cachedList { return l }
        let l = lists.buildBlocklist(); cachedList = l; return l
    }

    func connections() -> [ConnectionInfo] {
        let list = blocklist()
        lock.lock(); let hosts = ipToHost; lock.unlock()
        var seen = Set<String>()
        return monitor.snapshot().filter(\.hasRemote).compactMap { c -> ConnectionInfo? in
            let host = hosts[c.remoteAddress]
            let sig = c.processPath.map { SigningInspector.inspectCached(path: $0).info.status }
            let flagged = host.map { list.isBlocked($0) } ?? false || list.isBlocked(c.remoteAddress)
            let info = ConnectionInfo(pid: c.pid, processName: c.processName, processPath: c.processPath, proto: c.proto.uppercased(),
                                      localPort: Int(c.localPort), remoteAddress: c.remoteAddress, remotePort: Int(c.remotePort),
                                      remoteHost: host, state: c.state, signing: sig, flagged: flagged)
            return seen.insert(info.id).inserted ? info : nil
        }.sorted { ($0.flagged ? 0 : 1, $0.processName, $0.remoteAddress) < ($1.flagged ? 0 : 1, $1.processName, $1.remoteAddress) }
    }

    func wifi() -> WiFiStatus {
        guard let st = wifiGuard.currentStatus() else {
            return WiFiStatus(connected: false, note: "No Wi-Fi interface found.")
        }
        guard st.poweredOn else { return WiFiStatus(connected: false, note: "Wi-Fi is off.") }
        let alerts = wifiGuard.check()
        let gw = wifiGuard.defaultGateway()
        var note: String?
        if st.associated && st.ssid == nil { note = "The network name is hidden by macOS until \(Product.name) has Location access." }
        if let a = alerts.first(where: { $0.kind == .gatewayMACChanged }) { note = a.message }
        return WiFiStatus(connected: st.associated, ssid: st.ssid, security: st.security, weakSecurity: st.isWeak,
                          gatewayIP: gw, gatewayMACChanged: alerts.contains { $0.kind == .gatewayMACChanged }, note: note)
    }

    func stats(available: Bool) -> NetworkStats {
        let list = blocklist()
        lock.lock(); let st = stats; lock.unlock()
        let cal = Calendar.current
        let today = Date()
        let days: [Int] = (0..<14).reversed().map { back in
            let d = cal.date(byAdding: .day, value: -back, to: today)!
            return st.byDay[Self.dayFmt.string(from: d)] ?? 0
        }
        let monthPrefix = String(Self.dayFmt.string(from: today).prefix(7))
        let month = st.byDay.filter { $0.key.hasPrefix(monthPrefix) }.values.reduce(0, +)
        let updated = lists.sources.compactMap { lists.lastFetched($0) }.max()
        return NetworkStats(webProtectionOn: isOn, webProtectionAvailable: available, blockedToday: days.last ?? 0,
                            blockedThisMonth: month, blockedByDay: days, blocklistDomains: list.blockedCount,
                            blocklistsUpdated: updated, recentBlocks: Array(st.recent.prefix(20)))
    }
}

final class CompositeUpdater: UpdateService {
    let parts: [(String, () -> String)]
    init(_ parts: [(String, () -> String)]) { self.parts = parts }
    func update() -> String { parts.map { "\($0.0): \($0.1())" }.joined(separator: "; ") }
}

/// Turns a PersistenceItem into a typed RemediationPlan and runs it through RemediationExecutor (journaled).
/// In --user mode only items in the user's own domain are accepted.
final class PersistenceRemediator: PersistenceRemediationService {
    let runtime: Runtime
    let executor: RemediationExecutor
    init(runtime: Runtime, executor: RemediationExecutor) { self.runtime = runtime; self.executor = executor }

    private var limited: Bool { runtime.userMode || getuid() != 0 }

    func plan(_ r: PersistenceLookup) throws -> RemediationPlan {
        let item = r.item, home = NSHomeDirectory()
        let uid = getuid()
        var actions: [RemediationAction] = []
        switch item.kind {
        case .launchAgent, .launchDaemon:
            let jobs = LaunchdRemediator.job(fromPlist: item.location, consoleUIDs: [uid])
            guard !jobs.isEmpty else { throw ServiceError.failed("couldn't read the launchd plist at \(item.location)") }
            if limited {
                guard item.location.hasPrefix(home + "/Library/LaunchAgents/") else {
                    throw ServiceError.denied("\(item.label) is a system-wide launch item (\(item.location)); removing it needs the Rampart system service. In user mode Rampart only removes LaunchAgents in your own ~/Library/LaunchAgents.")
                }
                guard jobs.allSatisfy({ if case .gui(let u) = $0.domain { return u == uid }; return false }) else {
                    throw ServiceError.denied("\(item.label) belongs to another user")
                }
            }
            actions = jobs.map { .launchdJob($0) }
        case .cron:
            let line = r.attributes["line"] ?? item.label
            if limited && !item.location.hasPrefix("crontab:") {
                throw ServiceError.denied("system cron files (\(item.location)) need the Rampart system service; user mode only edits your own crontab")
            }
            actions = [.removeCronLines(user: nil, containing: [line])]
        case .browserExtension:
            guard let ext = r.attributes["extensionID"] ?? Optional((item.location as NSString).lastPathComponent),
                  let browser = r.attributes["browser"] ?? item.label.components(separatedBy: " ").first else {
                throw ServiceError.failed("couldn't identify the extension")
            }
            let profile: String
            if let range = item.location.range(of: "/Extensions/") { profile = String(item.location[..<range.lowerBound]) }
            else if let range = item.location.range(of: "/extensions/") { profile = String(item.location[..<range.lowerBound]) }
            else { throw ServiceError.failed("couldn't find the browser profile for \(item.location)") }
            if limited && !profile.hasPrefix(home + "/") { throw ServiceError.denied("that browser profile belongs to another user") }
            if let spec = BrowserSpec.named(browser), executor.browsers.isRunning(spec) {
                throw ServiceError.failed("\(spec.name) is open. Quit it, then remove the extension (the browser would restore it otherwise).")
            }
            actions = [.removeBrowserExtension(browser: browser, profilePath: profile, extensionID: ext)]
        case .loginItem, .btm:
            if limited { throw ServiceError.denied("login items are removed in System Settings > General > Login Items (or with the Rampart system service)") }
            actions = [.removeLoginItem(name: item.label, path: item.target)]
        case .profile:
            if limited { throw ServiceError.denied("configuration profiles can only be removed by the Rampart system service or in System Settings > Privacy & Security > Profiles") }
            actions = [.removeProfile(identifier: r.attributes["identifier"] ?? item.label)]
        default:
            throw ServiceError.failed("Rampart can't remove \(item.kind.rawValue) items automatically yet; remove \(item.location) by hand")
        }
        return RemediationPlan(title: "Remove \(item.label)", actions: actions)
    }

    func preview(_ r: PersistenceLookup) throws -> RemediationPreview {
        let p = try plan(r)
        let steps = executor.preview(p)
        let refused = steps.flatMap(\.notes).first { $0.hasPrefix("REFUSED") }
        if let refused { throw ServiceError.denied(refused) }
        return RemediationPreview(persistenceID: r.item.id, title: p.title,
                                  steps: steps.map { s in ([s.action.title] + s.notes.map { "  " + $0 }).joined(separator: "\n") },
                                  commands: steps.flatMap { $0.commands.map(\.description) },
                                  undoable: steps.allSatisfy(\.reversible),
                                  requiresRoot: steps.contains { $0.commands.contains(where: \.requiresRoot) })
    }

    func remediate(_ r: PersistenceLookup) throws -> String {
        let p = try plan(r)
        if limited, executor.preview(p).contains(where: { $0.commands.contains(where: \.requiresRoot) }) {
            throw ServiceError.denied("this cleanup needs root; run it from the Rampart system service")
        }
        let res = executor.run(p, dryRun: false)
        let msg = res.steps.map { "\($0.action.title): \($0.success ? "ok" : "failed") — \($0.message)" }.joined(separator: "; ")
        logInfo("persistence remediation \(r.item.id): \(msg)")
        guard res.allSucceeded else { throw ServiceError.failed(msg) }
        return msg + " (journal \(res.transactionID.uuidString))"
    }
}

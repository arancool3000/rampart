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
                    catch { return "hash feed failed: \(error)" }
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
        web.onBlock = { [weak s] d, l in s?.onWebBlock?(d, l) }
        web.onQuery = { [weak s] e in s?.onDNSEvent?(e) }
        s.signingLookup = { path in SigningInspector.inspectCached(path: path).info }
        s.wiring.append("web protection: RampartNetwork.DNSFilterServer on 127.0.0.1:\(runtime.dnsPort) (\(runtime.config.webProtection ? "on" : "off"))")
        updaters.append(("blocklists", {
            let r = runBlocking { await lists.updateAll() }
            web.reloadBlocklist()
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
        o.walk.excludedPrefixes = Array(Set(WalkOptions.defaultExcludedPrefixes + ours + [runtime.quarantineDir.path]))
        o.walk.maxFileSize = UInt64(runtime.config.maxFileSizeMB) << 20
        o.unpackArchives = runtime.config.scanArchives
        return o
    }

    func scan(paths: [String], progress: @escaping ScanProgress, cancelled: @escaping () -> Bool) -> ScanOutcome {
        let cancel = ScanCancellation()
        let report = coord.scan(paths: paths, options: options(for: paths), cancel: cancel) { p in
            if cancelled() { cancel.cancel() }
            progress(p.scanned, max(p.discovered, p.scanned), p.current)
        }
        return ScanOutcome(scanned: report.scanned, detections: report.detections, seconds: report.seconds, errors: report.errors)
    }

    func scanFile(_ path: String) -> Detection? {
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
        try vault.quarantine(path: path, detectionName: detection.name)
    }
    func restore(id: UUID) throws -> String {
        try vault.restore(id: id, options: QuarantineVault.RestoreOptions(allowlist: false))
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
        var out: [String] = []
        for cmd in fix.commands {
            if let why = Privileged.refusal(cmd[0]) { throw ServiceError.denied(why) }
            let p = Process()
            p.executableURL = URL(fileURLWithPath: cmd[0]); p.arguments = Array(cmd.dropFirst())
            p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
            try p.run(); p.waitUntilExit()
            out.append("\(cmd.joined(separator: " ")) -> \(p.terminationStatus)")
            if p.terminationStatus != 0 { throw ServiceError.failed("fix failed: \(out.joined(separator: "; "))") }
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
            let srv = DNSFilterServer(config: DNSFilterConfig(port: UInt16(runtime.dnsPort)), blocklist: list)
            srv.queryLog = { [weak self] e in self?.record(e) }
            try srv.start()
            server = srv
            // Point the system resolver at us only as the real root daemon (never in --user/dev runs).
            if getuid() == 0 && !runtime.userMode {
                let sw = DNSSwitcher(snapshotURL: runtime.root.appendingPathComponent("dns-original.json"), dryRun: false)
                do { _ = try sw.apply(); switcher = sw } catch { logWarn("DNS switch failed: \(error)") }
            }
            logInfo("web protection on (DNS filter 127.0.0.1:\(runtime.dnsPort))")
        } else {
            if let sw = switcher { _ = sw.restore(); switcher = nil }
            server?.stop(); server = nil
            saveStatsLocked()
            logInfo("web protection off")
        }
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
                if a.first?.isNumber == true || a.contains(":") { ipToHost[a] = e.name }
            }
            if ipToHost.count > 20000 { ipToHost.removeAll() }
        }
        let dirty = statsDirty && stats.byDay.values.reduce(0, +) % 20 == 0
        if dirty { saveStatsLocked() }
        lock.unlock()
        if let (d, l) = notify { onBlock?(d, l) }
        if !e.name.isEmpty { onQuery?(e.securityEvent) }
    }

    private func saveStatsLocked() {
        // Keep 62 days.
        let cutoff = Self.dayFmt.string(from: Date().addingTimeInterval(-62 * 86400))
        stats.byDay = stats.byDay.filter { $0.key >= cutoff }
        try? Util.writeJSON(stats, to: statsURL); statsDirty = false
    }

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

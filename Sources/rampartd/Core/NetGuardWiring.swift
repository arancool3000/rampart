import Foundation
import RampartShared
import RampartNetwork
import RampartSigning

/// App Firewall (per-app connections, block by destination via pf + DNS), content filter / parental schedules /
/// SafeSearch (DNS policy) and the privacy report. Lives next to WebProtection in whichever daemon runs DNS.
final class NetGuardService {
    let runtime: Runtime
    weak var web: WebProtection?
    let firewall: AppFirewall
    let policy: ContentFilterPolicy
    let ledger: PrivacyLedger
    /// New first-time prompts (unknown, untrusted app connecting out).
    var onPrompts: (([FirewallPrompt]) -> Void)?

    private let lock = NSLock()
    private var categoryUpdater: BlocklistUpdater
    private let monitor = ConnectionMonitor()
    private var timer: DispatchSourceTimer?
    private var bytes: [Int32: (UInt64, UInt64)] = [:]
    private var bytesAt = Date.distantPast
    private var trackerApps = Set<String>()
    private var trackerAppsDay = ""
    private let queue = DispatchQueue(label: "app.rampart.netguard", qos: .utility)

    var configURL: URL { runtime.root.appendingPathComponent("content-filter.json") }
    var categoriesDir: URL { runtime.blocklistDir.appendingPathComponent("categories") }

    /// pf commands only really run as the installed root daemon with privileged tools allowed.
    static func dryRun(runtime: Runtime) -> Bool { getuid() != 0 || runtime.userMode || Privileged.noPrivilegedTools }

    init(runtime: Runtime, web: WebProtection?) {
        self.runtime = runtime; self.web = web
        let cfg = (try? Data(contentsOf: runtime.root.appendingPathComponent("content-filter.json")))
            .flatMap { try? JSONDecoder.rampart.decode(ContentFilterConfig.self, from: $0) } ?? .defaults
        policy = ContentFilterPolicy(config: cfg)
        categoryUpdater = .categoryUpdater(for: cfg, directory: runtime.blocklistDir.appendingPathComponent("categories"))
        policy.loadCategoryLists(updater: categoryUpdater)
        firewall = AppFirewall(stateURL: runtime.root.appendingPathComponent("app-firewall.json"),
                               pfDirectory: runtime.root.appendingPathComponent("pf-appfw"),
                               dryRun: Self.dryRun(runtime: runtime),
                               signer: { SigningInspector.inspectCached(path: $0).info })
        ledger = PrivacyLedger(url: runtime.root.appendingPathComponent("privacy-ledger.json"))
        policy.setFirewallDomains(firewall.blockedDomains())
        firewall.onDomains = { [weak self] d in self?.policy.setFirewallDomains(d); self?.web?.dnsPolicyChanged() }
        web?.dnsPolicy = policy
        web?.onLog = { [weak self] e in self?.observe(e) }
    }

    // MARK: DNS log -> answer cache + privacy ledger

    func observe(_ e: DNSQueryLogEntry) {
        guard !e.name.isEmpty else { return }
        if !e.answers.isEmpty { firewall.noteDNS(name: e.name, answers: e.answers) }
        let blocked = e.verdict == .blocked
        let safe = e.listSource == "safesearch" && e.verdict != .servfail
        let tracker = policy.category(of: e.name) == .trackers
        let cat = blocked ? ContentFilterPolicy.category(forListSource: e.listSource) : nil
        guard tracker || cat != nil || safe else { return }
        ledger.record(name: e.name, blocked: blocked, isTracker: tracker, blockedCategory: cat, safeSearch: safe, date: e.date)
    }

    // MARK: Connection monitor

    func start() {
        guard timer == nil else { return }
        if firewall.status().rules.contains(where: { $0.decision == .block }) { queue.async { [weak self] in self?.firewall.reapplyAll() } }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 3, repeating: 15, leeway: .seconds(3))
        var n = 0
        t.setEventHandler { [weak self] in n += 1; if PowerThrottle.shared.shouldRun(tick: n) { self?.tick() } }
        t.resume(); timer = t
    }

    func stop() {
        timer?.cancel(); timer = nil; ledger.save()
        if firewall.status().rules.contains(where: { $0.decision == .block }) { firewall.unloadAll() }
    }

    func tick() {
        // o4: the user's original DNS servers (what the DNS watchdog restores to) never go into the firewall's pf table.
        let orig = DNSSwitcher(snapshotURL: runtime.root.appendingPathComponent("dns-original.json")).loadSnapshot()?
            .services.flatMap(\.servers) ?? []
        if !Set(orig).isSubset(of: Set(firewall.extraProtectedAddresses)) {
            firewall.extraProtectedAddresses = Array(Set(orig + firewall.extraProtectedAddresses)).sorted()
        }
        let conns = monitor.snapshot()
        if Date().timeIntervalSince(bytesAt) > 120 { bytes = AppFirewall.byteCounts(); bytesAt = Date() }
        let prompts = firewall.update(connections: conns, bytes: bytes)
        if !prompts.isEmpty {
            for p in prompts { logInfo("app firewall: first connection by untrusted app \(LogRedact.clean(p.name, max: 80))") }
            onPrompts?(prompts)
        }
        // Apps talking to trackers (once per app+host per day).
        let day = String(ISO8601DateFormatter().string(from: Date()).prefix(10))
        if day != trackerAppsDay { trackerApps.removeAll(); trackerAppsDay = day }
        for app in firewall.status().apps {
            for ep in app.endpoints { if let h = ep.host, policy.category(of: h) == .trackers, trackerApps.insert(app.key + "|" + h).inserted { ledger.recordApp(app.name) } }
        }
    }

    // MARK: Lists

    /// Downloads category lists the config wants (scheduler / `rampart update`), then reloads them.
    func updateLists() -> String {
        lock.lock(); let up = categoryUpdater; lock.unlock()
        guard !up.sources.isEmpty else { return "no category lists switched on" }
        let r = runBlocking { await up.updateAll() }
        policy.loadCategoryLists(updater: up)
        web?.dnsPolicyChanged()
        return r.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: ", ")
    }

    func setConfig(_ c: ContentFilterConfig) throws {
        try Util.writeJSON(c, to: configURL)
        policy.config = c
        let up = BlocklistUpdater.categoryUpdater(for: c, directory: categoriesDir)
        lock.lock(); categoryUpdater = up; lock.unlock()
        policy.loadCategoryLists(updater: up)
        web?.dnsPolicyChanged()
        // Fetch newly wanted lists in the background (the built-in seeds work meanwhile).
        let missing = up.sources.filter { up.lastFetched($0) == nil }
        if !missing.isEmpty, !Privileged.noPrivilegedTools || ProcessInfo.processInfo.environment["RAMPART_ALLOW_LIST_FETCH"] == "1" {
            queue.async { [weak self] in _ = self?.updateLists() }
        }
    }

    // MARK: IPC

    /// Whether this command turns protection down (for the authorization matrix).
    func weakens(_ data: Data) -> Bool {
        guard let cmd = try? JSONDecoder.rampart.decode(NetGuardCommand.self, from: data) else { return true }
        switch cmd.op {
        case .filterSet: return cmd.config.map { ContentFilterConfig.weakens(old: policy.config, new: $0) } ?? true
        case .firewallDecide, .firewallForget:
            guard cmd.decision != .block, let k = cmd.key else { return false }
            return firewall.status().rules.contains { $0.key == k && $0.decision == .block }
        default: return false
        }
    }

    func handle(_ cmd: NetGuardCommand) throws -> NetGuardStatus {
        var plan: AppBlockPlan?, classified: TrackerClassifier.Result?
        switch cmd.op {
        case .status, .report: break
        case .plan:
            guard let k = cmd.key else { throw ServiceError.failed("no app given") }
            plan = firewall.plan(key: k)
        case .classifyHosts:
            classified = TrackerClassifier.classify(hosts: cmd.hosts ?? [], pageHost: cmd.pageHost, policy: policy)
        case .firewallDecide:
            guard let k = cmd.key, let d = cmd.decision else { throw ServiceError.failed("no app or decision given") }
            do { try firewall.decide(key: k, decision: d) } catch { throw ServiceError.denied("\(error)") }
            if d == .block { plan = firewall.plan(key: k) }
        case .firewallForget:
            guard let k = cmd.key else { throw ServiceError.failed("no app given") }
            try firewall.forget(key: k)
        case .filterSet:
            guard let c = cmd.config else { throw ServiceError.failed("no filter settings given") }
            try setConfig(c)
        }
        return status(plan: plan, classified: classified)
    }

    func status(plan: AppBlockPlan? = nil, classified: TrackerClassifier.Result? = nil) -> NetGuardStatus {
        let cfg = policy.config
        lock.lock(); let up = categoryUpdater; lock.unlock()
        var updated: [String: Date] = [:]
        for s in up.sources { if let d = up.lastFetched(s) { updated[s.id] = d } }
        var limits = NetGuardStatus.filterLimitations
        if web?.isOn != true { limits.insert("Web Protection is off, so the content filter and DNS-level app blocks aren't active.", at: 0) }
        return NetGuardStatus(firewall: firewall.status(), filter: cfg,
                              activeNow: ContentCategory.allCases.filter { cfg.isActive($0) }.map(\.rawValue),
                              categoryDomains: policy.categoryDomainCount, listsUpdated: updated, webProtectionOn: web?.isOn ?? false,
                              report: ledger.report(days: 7, trackerBlockingOn: cfg.rule(.trackers).mode != .off),
                              plan: plan, classified: classified, limitations: limits)
    }
}

enum NetGuardWiring {
    /// Builds the service next to WebProtection; the connection monitor runs only in a daemon (not CLI --local).
    @discardableResult
    static func wire(_ s: Services, runtime: Runtime, web: WebProtection, daemon: Bool) -> NetGuardService? {
        let ng = NetGuardService(runtime: runtime, web: web)
        s.netGuard = ng
        if daemon { ng.start() }
        s.wiring.append("app firewall + content filter: RampartNetwork.AppFirewall (\(NetGuardService.dryRun(runtime: runtime) ? "pf preview only" : "pf enforcing")), ContentFilterPolicy")
        return ng
    }
}

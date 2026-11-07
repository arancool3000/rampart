import SwiftUI
import Observation
import RampartShared

// MARK: - App-local types (UI-only; not part of the shared IPC contract)

enum SidebarItem: String, CaseIterable, Identifiable, Hashable {
    case dashboard, scan, threats, activity, network, posture, rules, settings
    // Tools (owned by feature agents; their screens live in Features/<Name>/). One case per feature.
    case scamCheck, passwords, authenticator, passwordChecker, networkScan, aiAssistant, remoteAccess

    static let core: [SidebarItem] = [.dashboard, .scan, .threats, .activity, .network, .posture, .rules, .settings]
    static let tools: [SidebarItem] = [.scamCheck, .passwords, .networkScan, .aiAssistant, .remoteAccess]
    var id: String { rawValue }
    var title: String {
        switch self {
        case .dashboard: return "Overview"
        case .scan: return "Scan"
        case .threats: return "Threats & Quarantine"
        case .activity: return "Protection Activity"
        case .network: return "Network"
        case .posture: return "Privacy & Posture"
        case .rules: return "Rules"
        case .settings: return "Settings"
        case .scamCheck: return "Scam Check"
        case .passwords: return "Passwords"
        case .authenticator: return "Authenticator"
        case .passwordChecker: return "Password Checker"
        case .networkScan: return "Network Scan"
        case .aiAssistant: return "AI Assistant"
        case .remoteAccess: return "Remote Access"
        }
    }
    var symbol: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled"
        case .scan: return "magnifyingglass"
        case .threats: return "ladybug"
        case .activity: return "clock.arrow.circlepath"
        case .network: return "network"
        case .posture: return "hand.raised.square"
        case .rules: return "list.bullet.rectangle"
        case .settings: return "gearshape"
        case .scamCheck: return "exclamationmark.bubble"
        case .passwords: return "key.horizontal"
        case .authenticator: return "clock.badge.checkmark"
        case .passwordChecker: return "checkmark.shield"
        case .networkScan: return "wifi.router"
        case .aiAssistant: return "sparkles"
        case .remoteAccess: return "rectangle.connected.to.line.below"
        }
    }
}

enum ScanKind: String, CaseIterable, Identifiable {
    case quick, full, custom
    var id: String { rawValue }
    var title: String { ["quick": "Quick Scan", "full": "Full Scan", "custom": "Custom Scan"][rawValue]! }
    var symbol: String { ["quick": "bolt", "full": "internaldrive", "custom": "folder.badge.gearshape"][rawValue]! }
    var detail: String {
        switch self {
        case .quick: return "Checks the places malware usually hides. About 1 minute."
        case .full: return "Checks every file on your Mac. Can take 20 minutes or more."
        case .custom: return "Choose files, folders or drives to check."
        }
    }
}

struct ScanProgress: Equatable {
    var kind: ScanKind
    var scanned: Int
    var total: Int
    var current: String
    var started: Date
    var found: Int
    var paused: Bool
    /// True once the file walker has finished discovering files, so `total` is final.
    /// The daemon's IPC `scanProgress` carries no walk flag yet, so this is inferred: the walker
    /// discovers files while scanning, and `total` stops growing once it is done.
    var walkFinished = false
    var lastTotalChange = Date()
    /// Smoothed scan rate in files per second (exponential moving average).
    var rate: Double = 0
    var rateSampleAt: Date? = nil
    var rateSampleCount = 0
    var rateSampleScanned = 0

    /// Seconds `total` must stay unchanged (while files are still being scanned) before it is treated as final.
    static let totalSettleSeconds: Double = 2.5

    /// A real percentage only once the walk has finished; nil means "Finding files…".
    var fraction: Double? {
        guard walkFinished, total > 0 else { return nil }
        return min(1, Double(scanned) / Double(total))
    }
    /// Shown only after walking finishes, at least 5 % is done and the smoothed rate is meaningful.
    var etaSeconds: Double? {
        guard let f = fraction, f >= 0.05, f < 1, rate > 0.5 else { return nil }
        let left = Double(max(0, total - scanned)) / rate
        return left.isFinite ? max(1, left) : nil
    }

    /// Applies a progress update from the scanner.
    mutating func update(scanned newScanned: Int, total newTotal: Int, walkDone: Bool? = nil, now: Date = Date()) {
        if newTotal != total { lastTotalChange = now }
        // Rate: sample at most twice a second so bursty updates don't swing the estimate.
        if let at = rateSampleAt {
            let dt = now.timeIntervalSince(at)
            if dt >= 0.5 {
                let inst = Double(max(0, newScanned - rateSampleScanned)) / dt
                rate = rateSampleCount == 0 ? inst : rate * 0.85 + inst * 0.15
                rateSampleCount += 1
                rateSampleAt = now; rateSampleScanned = newScanned
            }
        } else {
            rateSampleAt = now; rateSampleScanned = newScanned
        }
        scanned = newScanned
        total = newTotal
        if let walkDone, walkDone { walkFinished = true }
        inferWalk(now: now)
    }

    private mutating func inferWalk(now: Date) {
        guard !walkFinished, total > 0 else { return }
        if now.timeIntervalSince(lastTotalChange) >= Self.totalSettleSeconds { walkFinished = true }
    }
}

struct ScanRecord: Identifiable, Equatable {
    let id = UUID()
    var kind: ScanKind
    var date: Date
    var scanned: Int
    var seconds: Double
    var found: Int
    var skipped: Int
}

enum ScanPhase: Equatable {
    case idle
    case running(ScanProgress)
    case finished(ScanRecord, [Detection])
}

struct ActivityItem: Identifiable, Hashable {
    enum Kind: String, CaseIterable, Identifiable {
        case threat, network, scan, update, settings, protection
        var id: String { rawValue }
        var filterTitle: String {
            switch self {
            case .threat: return "Threats"; case .network: return "Network"; case .scan: return "Scans"
            case .update: return "Updates"; case .settings: return "Settings changes"; case .protection: return "Protection"
            }
        }
        var symbol: String {
            switch self {
            case .threat: return "ladybug"; case .network: return "hand.raised"; case .scan: return "magnifyingglass"
            case .update: return "arrow.triangle.2.circlepath"; case .settings: return "gearshape"; case .protection: return "shield.lefthalf.filled"
            }
        }
    }
    let id = UUID()
    var date: Date
    var kind: Kind
    var title: String
    var outcome: String
}

struct AppConnections: Identifiable, Hashable {
    struct Destination: Hashable, Identifiable {
        var id: String { host + ":" + String(port) }
        var host: String; var port: Int; var proto: String; var country: String; var blocked: Bool
        /// Live mode: the daemon flagged this destination (blocklist or behaviour rule) rather than blocking it.
        var flaggedOnly = false
        var state: String? = nil
        var statusLabel: String { blocked ? (flaggedOnly ? "Flagged" : "Blocked") : (state ?? "Allowed") }
    }
    var id: String { app }
    var app: String
    var bundlePath: String?
    var signing: SigningInfo.Status? = nil
    var sentKB: Int
    var receivedKB: Int
    var destinations: [Destination]
    var blockedCount: Int { destinations.filter(\.blocked).count }
}

struct WiFiInfo: Hashable {
    var ssid: String?
    var security: String
    var encrypted: Bool
    var gatewayChanged: Bool
    var note: String? = nil
}

extension AllowRuleSpec.Scope {
    var label: String {
        switch self {
        case .fileHash: return "This file only"
        case .developer: return "This developer"
        case .folder: return "This folder"
        case .signingID: return "This app"
        }
    }
}

extension AllowRuleSpec {
    /// Rule as a readable sentence.
    var sentence: String {
        switch scope {
        case .fileHash: return "\(name) is always allowed (fingerprint \(value.prefix(12))…)."
        case .developer: return "Apps from \(name) are allowed."
        case .folder: return "Everything in \((value as NSString).abbreviatingWithTildeInPath) is allowed."
        case .signingID: return "\(name) is allowed (signing ID \(value))."
        }
    }
}

/// Where the protection comes from.
enum ProtectionSource: Equatable {
    case none
    case systemService          // root LaunchDaemon
    case basic                  // `rampartd --user` (no install)
}

/// `offline`: the protection service couldn't be reached or started. Shown honestly, never with sample numbers.
/// `demo`: developer-only sample data (`--demo`).
enum ConnectionMode: Equatable { case connecting, live, offline, demo }

// MARK: - Store

@MainActor
@Observable
final class AppModel {
    static let shared = AppModel()

    var mode: ConnectionMode = .connecting
    var selection: SidebarItem? = .dashboard
    var status = ProtectionStatus()
    var detections: [Detection] = [] { didSet { syncChrome() } }
    var quarantine: [QuarantineRecord] = []
    var posture: [PostureCheck] = []
    var persistence: [PersistenceItem] = []
    var activity: [ActivityItem] = []
    var scanPhase: ScanPhase = .idle { didSet { syncChrome() } }
    var scanHistory: [ScanRecord] = []
    var connections: [AppConnections] = []
    var wifi: WiFiInfo?
    var blockedThisMonth = 0
    var blockedToday = 0
    var allowRules: [AllowRuleSpec] = []
    var settings = RampartSettings()
    var health: HealthReport?
    var source: ProtectionSource = .none
    var webProtectionAvailable = true
    var recentBlocks: [String] = []
    var blocklistDomains = 0
    var launchState: DaemonLauncher.State = .idle
    var ignoredChecks: Set<String> = []
    var dismissedRecommendations: Set<String> = []
    var pausedUntil: Date?
    var lastError: String?
    var definitionsUpdated: Date?
    var isUpdatingDefinitions = false
    var fixingChecks: Set<String> = []
    var hasFullDiskAccess = Headless.active ? false : FDAProbe.check()
    /// Last 14 days, oldest first (charts).
    var daily: [DayStat] = []
    @ObservationIgnored var liveBlockedByDay: [Int] = []
    /// Most recent scanned paths, newest first (scan animation), updated at most 5×/s.
    var recentScanPaths: [String] = []
    @ObservationIgnored private var lastPathNote = Date.distantPast

    @ObservationIgnored let client = DaemonClient()
    @ObservationIgnored private var scanHandle: DaemonClient.StreamHandle?
    @ObservationIgnored private var eventHandle: DaemonClient.StreamHandle?
    @ObservationIgnored private var demoTimer: Timer?
    @ObservationIgnored private var pollTimer: Timer?
    @ObservationIgnored private var started = false
    @ObservationIgnored private var pauseTimer: Timer?
    @ObservationIgnored private var lastHeavyRefresh = Date.distantPast
    @ObservationIgnored private var lastNetworkStats: NetworkStats?
    @ObservationIgnored private var lastActivity: [ActivityEntry] = []
    @ObservationIgnored private var lastConnections: [ConnectionInfo] = []

    var isDemo: Bool { mode == .demo }
    var isOffline: Bool { mode == .offline }
    /// True when the numbers on screen are real (or explicit developer demo data).
    var hasData: Bool { mode == .live || mode == .demo }
    static let demoRequested = CommandLine.arguments.contains("--demo")
    var openDetections: [Detection] { detections.filter { !$0.resolved } }
    var isScanning: Bool { if case .running = scanPhase { return true }; return false }
    var scanProgress: ScanProgress? { if case .running(let p) = scanPhase { return p }; return nil }
    var fullDiskAccess: Bool { mode == .live ? status.fullDiskAccess : hasFullDiskAccess || isDemo }
    var failingChecks: [PostureCheck] {
        posture.filter { $0.state == .fail && !ignoredChecks.contains($0.id) }.sorted { $0.weight > $1.weight }
    }
    var recommendations: [PostureCheck] { failingChecks.filter { !dismissedRecommendations.contains($0.id) } }

    func noteScanPath(_ p: String) {
        let now = Date()
        guard now.timeIntervalSince(lastPathNote) >= 0.2, recentScanPaths.first != p else { return }
        lastPathNote = now
        recentScanPaths.insert(p, at: 0)
        if recentScanPaths.count > 7 { recentScanPaths.removeLast(recentScanPaths.count - 7) }
    }

    /// Derives per-day stats from the activity log (live mode).
    func rebuildDaily() {
        let cal = Calendar.current
        let today = cal.startOfDay(for: Date())
        daily = (0..<14).reversed().map { back in
            let day = cal.date(byAdding: .day, value: -back, to: today)!
            let items = activity.filter { cal.isDate($0.date, inSameDayAs: day) }
            let files = scanHistory.filter { cal.isDate($0.date, inSameDayAs: day) }.reduce(0) { $0 + $1.scanned }
            let idx = 13 - back
            let blocked = liveBlockedByDay.count == 14 ? liveBlockedByDay[idx] : items.filter { $0.kind == .network }.count
            let scanFiles = files > 0 ? files : 0
            return DayStat(day: day, filesChecked: scanFiles, sitesBlocked: blocked,
                           threats: items.filter { $0.kind == .threat && ($0.outcome.contains("uarantin") || $0.title.lowercased().contains("detect")) }.count)
        }
    }

    var blockedLast7: [Double] { daily.suffix(7).map { Double($0.sitesBlocked) } }
    var filesLast14: [Double] { daily.map { Double($0.filesChecked) } }

    private func syncChrome() {
        ChromeState.shared.update(hasThreat: detections.contains { !$0.resolved }, isScanning: isScanning)
    }

    // MARK: Lifecycle

    func start() {
        guard !started else { return }
        started = true
        if ProcessInfo.processInfo.arguments.contains("--demo") { enterDemo(); return }
        Task { await connect(autoLaunch: true) }
        pollTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { _ in
            Task { @MainActor in await AppModel.shared.periodic() }
        }
    }

    private func periodic() async {
        if !Headless.active { hasFullDiskAccess = FDAProbe.check() }
        if Self.demoRequested { return }
        if await client.isReachable() {
            if mode != .live { await connect(autoLaunch: false) }
            else {
                let heavy = Date().timeIntervalSince(lastHeavyRefresh) > 600
                let c0 = ProcStats.cpuSeconds(), t0 = Date()
                await refresh(heavy: heavy)
                if Headless.active {
                    HeadlessRunner.log(String(format: "headless-check: periodic refresh%@ took %.2f s wall, %.3f s CPU; activity=%d",
                                              heavy ? " (heavy)" : "", Date().timeIntervalSince(t0), ProcStats.cpuSeconds() - c0, activity.count))
                }
            }
        } else if mode == .live || mode == .offline {
            // The service went away (or never came up): try to bring basic protection back.
            await connect(autoLaunch: true)
        }
    }

    /// User-initiated retry from the offline state.
    func retry() async {
        mode = .connecting
        lastError = nil
        await connect(autoLaunch: true)
    }

    func connect(autoLaunch: Bool = true) async {
        if !(await client.isReachable()), autoLaunch, DaemonLauncher.shared.helperURL != nil {
            launchState = .starting
            launchState = await DaemonLauncher.shared.launchAndWait(client: client)
        }
        if await client.isReachable() {
            if mode == .demo { clearDemo() }
            mode = .live
            demoTimer?.invalidate()
            await refresh()
            subscribe()
        } else {
            // No sample data: show the honest "service isn't running" state with a Retry button.
            if mode == .live || mode == .demo { clearDemo() }
            mode = .offline
            if DaemonLauncher.shared.helperMissing { lastError = DaemonLauncher.shared.missingHelperMessage }
            else if case .failed(let why) = launchState { lastError = why }
            else if DaemonLauncher.shared.helperURL == nil { lastError = DaemonLauncher.shared.missingHelperMessage }
        }
    }

    private func clearDemo() {
        detections = []; quarantine = []; posture = []; persistence = []; activity = []; scanHistory = []
        connections = []; wifi = nil; allowRules = []; daily = []; blockedToday = 0; blockedThisMonth = 0
        recentBlocks = []; definitionsUpdated = nil
    }

    /// Light refresh (every 15 s): status, detections, quarantine, activity, network stats, settings.
    /// Heavy refresh adds posture and startup items (on connect, on demand, every 10 minutes).
    func refresh(heavy: Bool = true) async {
        guard mode == .live else { return }
        do {
            if case .status(let s) = try await client.request(.status) { status = s }
            lastError = nil
        } catch {
            lastError = error.localizedDescription
            return
        }
        // Each v2 request is optional: an older daemon answers .error and that screen keeps its empty state.
        if heavy || health == nil {
            if case .health(let h)? = try? await client.request(.health) {
                if h != health { health = h }
                let src: ProtectionSource = h.mode == "user" ? .basic : .systemService
                if src != source { source = src }
            } else if source != .systemService {
                source = .systemService
            }
        }
        if case .detections(let d)? = try? await client.request(.listDetections) { set(\.detections, d.sorted { $0.date > $1.date }) }
        if case .quarantine(let q)? = try? await client.request(.listQuarantine) { set(\.quarantine, q.sorted { $0.date > $1.date }) }
        if case .settings(let st)? = try? await client.request(.getSettings) { set(\.settings, st) }
        if case .allowRules(let r)? = try? await client.request(.listAllowRules) { set(\.allowRules, r.sorted { $0.created > $1.created }) }
        if case .networkStats(let n)? = try? await client.request(.networkStats), n != lastNetworkStats { lastNetworkStats = n; apply(n) }
        if case .wifi(let w)? = try? await client.request(.wifi) {
            set(\.wifi, w.connected ? WiFiInfo(ssid: w.ssid, security: w.security ?? "Unknown security", encrypted: !w.weakSecurity,
                                               gatewayChanged: w.gatewayMACChanged, note: w.note) : nil)
        }
        if case .activity(let a)? = try? await client.request(.activity(limit: 300)) {
            if a != lastActivity { lastActivity = a; apply(a) }
        } else { rebuildLiveActivity() }
        if heavy {
            lastHeavyRefresh = Date()
            if case .connections(let c)? = try? await client.request(.connections) { apply(c) }
            await refreshPosture()
        }
        let defs = status.definitionsUpdated ?? definitionsUpdated
        if defs != definitionsUpdated { definitionsUpdated = defs }
    }

    func refreshPosture() async {
        guard mode == .live else { return }
        if case .posture(let p)? = try? await client.request(.posture, timeout: 30) { set(\.posture, p) }
        if case .persistence(let p)? = try? await client.request(.persistence, timeout: 30) { set(\.persistence, p) }
    }

    /// Assigns only when the value changed, so unchanged data doesn't re-render views.
    private func set<T: Equatable>(_ kp: ReferenceWritableKeyPath<AppModel, T>, _ v: T) {
        if self[keyPath: kp] != v { self[keyPath: kp] = v }
    }

    private func apply(_ n: NetworkStats) {
        status.webProtectionOn = n.webProtectionOn
        webProtectionAvailable = n.webProtectionAvailable
        blockedToday = n.blockedToday
        blockedThisMonth = n.blockedThisMonth
        recentBlocks = n.recentBlocks
        blocklistDomains = n.blocklistDomains
        liveBlockedByDay = n.blockedByDay
    }

    private func apply(_ c: [ConnectionInfo]) {
        guard c != lastConnections else { return }
        lastConnections = c
        let groups = Dictionary(grouping: c) { $0.processName }
        connections = groups.map { name, rows in
            AppConnections(app: name, bundlePath: rows.first?.processPath.flatMap(Self.bundlePath(forExecutable:)), signing: rows.first?.signing, sentKB: 0, receivedKB: 0,
                           destinations: rows.map {
                               .init(host: $0.remoteHost ?? $0.remoteAddress, port: $0.remotePort, proto: $0.proto, country: "", blocked: $0.flagged,
                                     flaggedOnly: true, state: $0.state.map { $0.capitalized })
                           }.uniqued())
        }
        .sorted { ($0.blockedCount, $0.destinations.count) > ($1.blockedCount, $1.destinations.count) }
    }

    static func bundlePath(forExecutable p: String) -> String? {
        if let r = p.range(of: ".app/") { return String(p[..<r.lowerBound]) + ".app" }
        return p
    }

    private func apply(_ entries: [ActivityEntry]) {
        activity = entries.map { e in
            let kind: ActivityItem.Kind
            switch e.kind {
            case .scan: kind = .scan
            case .detection, .quarantine, .restore: kind = .threat
            case .webBlock: kind = .network
            case .update: kind = .update
            case .posture, .settings: kind = .settings
            case .persistence, .system: kind = .protection
            }
            return ActivityItem(date: e.date, kind: kind, title: e.title, outcome: e.outcome.isEmpty ? e.detail : e.outcome)
        }
        .sorted { $0.date > $1.date }
        rebuildDaily()
    }

    private func subscribe() {
        eventHandle?.cancel()
        eventHandle = client.stream(.subscribeEvents, onMessage: { resp in
            if case .event(let d) = resp { AppModel.shared.receive(detection: d) }
            return true
        }, onEnd: { _ in
            AppModel.shared.eventHandle = nil
        })
    }

    func receive(detection d: Detection) {
        if let i = detections.firstIndex(where: { $0.id == d.id }) { detections[i] = d } else { detections.insert(d, at: 0) }
        activity.insert(ActivityItem(date: d.date, kind: .threat, title: "\(d.name) detected\(d.path.map { " in \(($0 as NSString).lastPathComponent)" } ?? "")",
                                     outcome: d.resolved ? "Quarantined" : "Needs decision"), at: 0)
        if d.confidence >= 60 { Notifier.shared.threat(d) }
    }

    private func rebuildLiveActivity() {
        var items: [ActivityItem] = detections.map {
            ActivityItem(date: $0.date, kind: .threat, title: "\($0.name) detected", outcome: $0.resolved ? "Resolved" : "Needs decision")
        }
        items += quarantine.map { ActivityItem(date: $0.date, kind: .threat, title: "Moved \(($0.originalPath as NSString).lastPathComponent) to quarantine", outcome: "Contained") }
        items += scanHistory.map { ActivityItem(date: $0.date, kind: .scan, title: "\($0.kind.title) checked \(Fmt.count($0.scanned)) files", outcome: $0.found == 0 ? "No threats" : "\($0.found) found") }
        if let ls = status.lastScan, scanHistory.isEmpty {
            items.append(ActivityItem(date: ls, kind: .scan, title: "Scheduled scan finished", outcome: "Completed"))
        }
        activity = items.sorted { $0.date > $1.date }
        rebuildDaily()
    }

    func enterDemo() {
        mode = .demo
        DemoData.populate(self)
    }

    // MARK: Security score (honest: only things fixable on this Mac, for free)

    struct ScoreItem: Identifiable { let id: String; let title: String; let weight: Int; let earned: Bool; let target: SidebarItem }

    var scoreBreakdown: [ScoreItem] {
        func check(_ keys: [String]) -> Bool {
            let matches = posture.filter { c in keys.contains { c.id.lowercased().contains($0) || c.title.lowercased().contains($0) } }
            if matches.isEmpty { return true }   // unknown never counts as a failure
            return !matches.contains { $0.state == .fail && !ignoredChecks.contains($0.id) }
        }
        let defsFresh: Bool = {
            guard let d = definitionsUpdated else { return mode != .live }
            return Date().timeIntervalSince(d) < 86_400
        }()
        let unknownPersistence = persistence.contains { $0.signing?.status == .unsigned || $0.signing?.status == .adHoc }
        return [
            ScoreItem(id: "rt", title: "Real-time protection on", weight: 25, earned: status.realtimeOn && pausedUntil == nil, target: .settings),
            ScoreItem(id: "defs", title: "Definitions updated in the last 24 hours", weight: 10, earned: defsFresh, target: .settings),
            ScoreItem(id: "fda", title: "Full Disk Access granted", weight: 10, earned: fullDiskAccess, target: .dashboard),
            ScoreItem(id: "threats", title: "No unresolved detections", weight: 20, earned: openDetections.isEmpty, target: .threats),
            ScoreItem(id: "filevault", title: "FileVault on", weight: 10, earned: check(["filevault"]), target: .posture),
            ScoreItem(id: "firewall", title: "macOS firewall on", weight: 5, earned: check(["firewall"]), target: .posture),
            ScoreItem(id: "updates", title: "Automatic macOS updates on", weight: 5, earned: check(["autoupdate", "auto-update", "automatic update", "softwareupdate"]), target: .posture),
            ScoreItem(id: "gk", title: "Gatekeeper and System Integrity Protection on", weight: 10, earned: check(["gatekeeper", "sip", "integrity"]), target: .posture),
            ScoreItem(id: "persist", title: "No unknown login items or launch agents", weight: 5, earned: !unknownPersistence, target: .posture),
        ]
    }
    var securityScore: Int { scoreBreakdown.filter(\.earned).reduce(0) { $0 + $1.weight } }

    static func scoreLabel(_ s: Int) -> String {
        switch s { case 90...: return "Excellent"; case 75..<90: return "Good"; case 50..<75: return "Fair"; default: return "Needs attention" }
    }
    static func scoreColor(_ s: Int) -> Color {
        switch s { case 75...: return .statusProtected; case 50..<75: return .statusAttention; default: return .statusAction }
    }

    // MARK: Overall state for hero / menu bar

    enum Overall { case protected, recommendations(Int), threat(Int), off, limited, paused(Date), starting, serviceDown }
    var overall: Overall {
        if mode == .connecting { return .starting }
        if mode == .offline { return .serviceDown }
        if !openDetections.isEmpty { return .threat(openDetections.count) }
        if let p = pausedUntil, p > Date() { return .paused(p) }
        if !status.realtimeOn { return .off }
        if !fullDiskAccess { return .limited }
        if !recommendations.isEmpty { return .recommendations(recommendations.count) }
        return .protected
    }

    // MARK: Actions

    func startScan(_ kind: ScanKind, paths: [String] = []) {
        guard !isScanning else { return }
        let home = NSHomeDirectory()
        let targets: [String]
        switch kind {
        case .quick: targets = [home + "/Downloads", home + "/Desktop", home + "/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Applications", "/tmp"]
        case .full: targets = ["/"]
        case .custom: targets = paths
        }
        recentScanPaths = []
        let progress = ScanProgress(kind: kind, scanned: 0, total: 0, current: "Preparing…", started: Date(), found: 0, paused: false)
        scanPhase = .running(progress)
        if mode == .live {
            var lastUI = Date.distantPast
            scanHandle = client.stream(.scan(paths: targets, quick: kind == .quick), onMessage: { resp in
                let m = AppModel.shared
                switch resp {
                case .scanProgress(let scanned, let total, let current):
                    if Headless.active && scanned <= 1 { HeadlessRunner.log("headless-check: scan progress \(scanned)/\(total) \(current)") }
                    guard case .running(var p) = m.scanPhase else { return true }
                    let now = Date()
                    if now.timeIntervalSince(lastUI) < 0.1 { return true }   // throttle to 10 Hz
                    lastUI = now
                    p.update(scanned: scanned, total: total, now: now); p.current = current
                    m.scanPhase = .running(p)
                    m.noteScanPath(current)
                    return true
                case .scanFinished(let scanned, let found, let seconds):
                    if Headless.active { HeadlessRunner.log("headless-check: scan finished: \(scanned) files, \(found.count) found (\(found.map(\.name).joined(separator: ", "))) in \(String(format: "%.2f", seconds)) s") }
                    m.finishScan(kind: kind, scanned: scanned, found: found, seconds: seconds, skipped: 0)
                    return false
                case .event(let d):
                    m.receive(detection: d)
                    if case .running(var p) = m.scanPhase { p.found += 1; m.scanPhase = .running(p) }
                    return true
                default: return true
                }
            }, onEnd: { err in
                let m = AppModel.shared
                if Headless.active { HeadlessRunner.log("headless-check: scan stream ended \(err.map { "with error: \($0.localizedDescription)" } ?? "cleanly")") }
                if let err, m.isScanning { m.lastError = err.localizedDescription; m.scanPhase = .idle }
            })
        } else {
            DemoData.runScan(self, kind: kind, paths: paths)
        }
    }

    func finishScan(kind: ScanKind, scanned: Int, found: [Detection], seconds: Double, skipped: Int) {
        let rec = ScanRecord(kind: kind, date: Date(), scanned: scanned, seconds: seconds, found: found.count, skipped: skipped)
        scanHistory.insert(rec, at: 0)
        if scanHistory.count > 10 { scanHistory.removeLast() }
        for d in found where !detections.contains(where: { $0.id == d.id }) { detections.insert(d, at: 0) }
        scanPhase = .finished(rec, found)
        status.lastScan = Date()
        activity.insert(ActivityItem(date: Date(), kind: .scan, title: "\(kind.title) checked \(Fmt.count(scanned)) files",
                                     outcome: found.isEmpty ? "No threats" : "\(found.count) found"), at: 0)
        Notifier.shared.scanFinished(rec)
        if mode == .live { Task { await refresh() } }
    }

    func togglePause() {
        guard case .running(var p) = scanPhase else { return }
        p.paused.toggle()
        scanPhase = .running(p)
        if mode == .live {
            let paused = p.paused
            Task { do { _ = try await client.request(.pauseScan(paused: paused)) } catch { lastError = error.localizedDescription } }
        }
    }

    func stopScan() {
        if mode == .live, isScanning { Task { _ = try? await client.request(.cancelScan) } }
        scanHandle?.cancel(); scanHandle = nil
        demoTimer?.invalidate()
        if case .running(let p) = scanPhase {
            activity.insert(ActivityItem(date: Date(), kind: .scan, title: "\(p.kind.title) stopped after \(Fmt.count(p.scanned)) files", outcome: "Stopped"), at: 0)
        }
        scanPhase = .idle
    }

    func setDemoTimer(_ t: Timer?) { demoTimer?.invalidate(); demoTimer = t }

    func quarantine(_ d: Detection) async {
        if mode == .live {
            do { _ = try await client.request(.quarantine(detectionID: d.id)); await refresh() } catch { lastError = error.localizedDescription }
        } else {
            mark(d.id, resolved: true)
            if let p = d.path {
                quarantine.insert(QuarantineRecord(originalPath: p, sha256: d.sha256 ?? "", size: 184_320, detectionName: d.name, ownerUID: 501, mode: 0o755), at: 0)
            }
        }
        activity.insert(ActivityItem(date: Date(), kind: .threat, title: "Moved \(d.name) to quarantine", outcome: "Contained"), at: 0)
    }

    func restore(_ r: QuarantineRecord, allow: Bool) async {
        if mode == .live {
            do { _ = try await client.request(.restore(id: r.id, allow: allow)); await refresh() } catch { lastError = error.localizedDescription; return }
        } else {
            quarantine.removeAll { $0.id == r.id }
        }
        if allow && mode != .live {
            allowRules.insert(AllowRuleSpec(scope: .fileHash, value: r.sha256, name: (r.originalPath as NSString).lastPathComponent), at: 0)
        }
        activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Restored \((r.originalPath as NSString).lastPathComponent)\(allow ? " and allowed it" : " once")", outcome: "Restored"), at: 0)
    }

    func delete(_ r: QuarantineRecord) async {
        if mode == .live {
            do { _ = try await client.request(.deleteQuarantined(id: r.id)); await refresh() } catch { lastError = error.localizedDescription; return }
        } else {
            quarantine.removeAll { $0.id == r.id }
        }
        activity.insert(ActivityItem(date: Date(), kind: .threat, title: "Deleted \((r.originalPath as NSString).lastPathComponent) permanently", outcome: "Deleted"), at: 0)
    }

    func allow(_ d: Detection, scope: AllowRuleSpec.Scope) async {
        let name = (d.path.map { ($0 as NSString).lastPathComponent }) ?? d.name
        let value: String
        switch scope {
        case .fileHash: value = d.sha256 ?? d.path ?? d.name
        case .developer, .signingID: value = d.evidence.first { $0.source == .signing }?.detail ?? "Unknown developer"
        case .folder: value = ((d.path ?? "/") as NSString).deletingLastPathComponent
        }
        let ok = await addAllowRule(AllowRuleSpec(scope: scope, value: value, name: scope == .folder ? (value as NSString).lastPathComponent : name))
        guard ok else { return }
        mark(d.id, resolved: true)
        if mode == .live { await refresh() }
    }

    @discardableResult
    func addAllowRule(_ rule: AllowRuleSpec) async -> Bool {
        if mode == .live {
            do { _ = try await client.request(.addAllowRule(rule)) } catch { lastError = error.localizedDescription; return false }
            if case .allowRules(let r)? = try? await client.request(.listAllowRules) { allowRules = r.sorted { $0.created > $1.created } }
        } else {
            allowRules.insert(rule, at: 0)
        }
        activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Allowed \(rule.name) (\(rule.scope.label.lowercased()))", outcome: "Rule added"), at: 0)
        return true
    }

    func removeAllowRule(_ rule: AllowRuleSpec) async {
        if mode == .live {
            do { _ = try await client.request(.removeAllowRule(id: rule.id)) } catch { lastError = error.localizedDescription; return }
            if case .allowRules(let r)? = try? await client.request(.listAllowRules) { allowRules = r.sorted { $0.created > $1.created } }
        } else {
            allowRules.removeAll { $0.id == rule.id }
        }
        activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Removed rule for \(rule.name)", outcome: "Rule removed"), at: 0)
    }

    // MARK: Settings (owned by the daemon in live mode)

    func updateSettings(_ change: (inout RampartSettings) -> Void) {
        var next = settings
        change(&next)
        guard next != settings else { return }
        let previous = settings
        settings = next
        if next.realtimeOn != previous.realtimeOn { status.realtimeOn = next.realtimeOn }
        guard mode == .live else { return }
        Task {
            do {
                let resp = try await client.request(.setSettings(next))
                if case .settings(let confirmed) = resp { self.settings = confirmed }
            } catch {
                self.settings = previous
                self.lastError = error.localizedDescription
            }
        }
    }

    // MARK: Startup item cleanup

    func previewRemediation(_ item: PersistenceItem) async -> Result<RemediationPreview, Error> {
        if mode != .live {
            return .success(RemediationPreview(persistenceID: item.id, title: "Turn off \(item.label)",
                steps: ["Stop \(item.label) if it is running", "Turn it off so it doesn't start at login", "Move \((item.location as NSString).lastPathComponent) to \(Product.name)'s quarantine so you can undo this"],
                commands: ["launchctl bootout gui/501 \(item.location)", "launchctl disable gui/501/\(item.label)", "mv \(item.location) ~/Library/Application Support/Rampart/Quarantine/"],
                undoable: true, requiresRoot: item.kind == .launchDaemon))
        }
        do {
            let resp = try await client.request(.previewRemediation(persistenceID: item.id), timeout: 20)
            if case .remediationPreview(let p) = resp { return .success(p) }
            return .failure(DaemonClient.ClientError.unexpected)
        } catch { return .failure(error) }
    }

    func remediate(_ item: PersistenceItem) async -> String? {
        if mode == .live {
            do { _ = try await client.request(.remediate(persistenceID: item.id), timeout: 60) } catch { return error.localizedDescription }
            await refresh()
        } else {
            persistence.removeAll { $0.id == item.id }
        }
        activity.insert(ActivityItem(date: Date(), kind: .protection, title: "Turned off startup item \(item.label)", outcome: "Removed"), at: 0)
        return nil
    }

    func refreshConnections() async {
        guard mode == .live else { return }
        if case .connections(let c)? = try? await client.request(.connections) { apply(c) }
    }

    func refreshHealth() async {
        guard mode == .live else { return }
        if case .health(let h)? = try? await client.request(.health) { health = h }
    }

    private func mark(_ id: UUID, resolved: Bool) {
        if let i = detections.firstIndex(where: { $0.id == id }) { detections[i].resolved = resolved }
    }

    func fix(_ c: PostureCheck) async {
        fixingChecks.insert(c.id)
        defer { fixingChecks.remove(c.id) }
        if mode == .live {
            do { _ = try await client.request(.fixPosture(checkID: c.id), timeout: 60); await refresh() } catch { lastError = error.localizedDescription; return }
        } else {
            try? await Task.sleep(nanoseconds: 700_000_000)
            if let i = posture.firstIndex(where: { $0.id == c.id }) { posture[i].state = .pass; posture[i].detail = "Turned on by \(Product.name) just now." }
        }
        activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Fixed: \(c.title)", outcome: "Done"), at: 0)
    }

    func setWebProtection(_ on: Bool) async {
        if mode == .live {
            guard webProtectionAvailable else { lastError = "Web protection needs the full system service."; return }
            do { _ = try await client.request(.setWebProtection(on: on)); await refresh() } catch { lastError = error.localizedDescription; return }
        } else { status.webProtectionOn = on }
        activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Web protection turned \(on ? "on" : "off")", outcome: "Changed"), at: 0)
    }

    func setRealtime(_ on: Bool, pauseFor minutes: Int? = nil) {
        if let minutes { pausedUntil = Date().addingTimeInterval(Double(minutes) * 60) } else { pausedUntil = nil }
        let effectiveOn = on && minutes == nil
        status.realtimeOn = effectiveOn || minutes != nil
        settings.realtimeOn = effectiveOn
        if mode == .live {
            Task {
                do { _ = try await client.request(.setRealtime(on: effectiveOn)); await self.refresh() } catch { self.lastError = error.localizedDescription }
            }
            if let minutes {
                pauseTimer?.invalidate()
                pauseTimer = Timer.scheduledTimer(withTimeInterval: Double(minutes) * 60, repeats: false) { _ in
                    Task { @MainActor in AppModel.shared.setRealtime(true) }
                }
            }
        } else {
            status.realtimeOn = on || minutes != nil
        }
        activity.insert(ActivityItem(date: Date(), kind: .protection,
                                     title: minutes.map { "Real-time protection paused for \($0 >= 60 ? "\($0 / 60) hour" : "\($0) minutes")" } ?? "Real-time protection turned \(on ? "on" : "off")",
                                     outcome: "Changed"), at: 0)
    }

    func updateDefinitions() async {
        isUpdatingDefinitions = true
        defer { isUpdatingDefinitions = false }
        if mode == .live {
            do { _ = try await client.request(.updateSignatures, timeout: 120); await refresh() } catch { lastError = error.localizedDescription; return }
        } else {
            try? await Task.sleep(nanoseconds: 1_200_000_000)
        }
        definitionsUpdated = Date()
        activity.insert(ActivityItem(date: Date(), kind: .update, title: "Definitions updated", outcome: "Up to date"), at: 0)
    }
}

/// Full Disk Access probe: try to read a TCC-protected file.
enum FDAProbe {
    static func check() -> Bool {
        let home = NSHomeDirectory()
        let probes = [home + "/Library/Safari/Bookmarks.plist", home + "/Library/Application Support/com.apple.TCC/TCC.db",
                      "/Library/Application Support/com.apple.TCC/TCC.db"]
        for p in probes where FileManager.default.fileExists(atPath: p) {
            if let h = FileHandle(forReadingAtPath: p) { try? h.close(); return true }
        }
        return false
    }
    static let settingsURL = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!
}

extension Array where Element: Hashable {
    func uniqued() -> [Element] { var seen = Set<Element>(); return filter { seen.insert($0).inserted } }
}

import SwiftUI
import Observation
import RampartShared

// MARK: - App-local types (UI-only; not part of the shared IPC contract)

enum SidebarItem: String, CaseIterable, Identifiable, Hashable {
    case dashboard, scan, threats, activity, network, posture, rules, settings
    // Tools (owned by feature agents; their screens live in Features/<Name>/). One case per feature.
    case scamCheck, passwords, authenticator, passwordChecker, networkScan, aiAssistant, remoteAccess, refresh, emergency, catAndMouse
    case downloadGate, mediaGuard
    case appFirewall, privacyFilters
    case vpn
    // Refresh mode (its own sidebar): one destination per former RefreshView tab / category.
    case refreshSmart, refreshStorage, refreshMap, refreshSpeed, refreshStartup, refreshLargeOld, refreshDuplicates, refreshLeftovers, refreshSettings

    static let core: [SidebarItem] = [.dashboard, .scan, .threats, .activity, .network, .posture, .rules, .settings]
    static let tools: [SidebarItem] = [.emergency, .catAndMouse, .downloadGate, .mediaGuard, .appFirewall, .privacyFilters, .vpn, .scamCheck, .passwords, .authenticator, .passwordChecker, .networkScan, .aiAssistant, .remoteAccess]
    static let refreshItems: [SidebarItem] = [.refreshSmart, .refreshStorage, .refreshMap, .refreshSpeed, .refreshStartup, .refreshLargeOld, .refreshDuplicates, .refreshLeftovers, .refreshSettings]
    var isRefresh: Bool { self == .refresh || Self.refreshItems.contains(self) }
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
        case .refresh: return "Refresh"
        case .emergency: return "Emergency"
        case .catAndMouse: return "Cat & Mouse"
        case .vpn: return "VPN"
        case .downloadGate: return "Download Gate"
        case .mediaGuard: return "Camera & Mic"
        case .appFirewall: return "App Firewall"
        case .privacyFilters: return "Filters & Privacy"
        case .refreshSmart: return "Smart Refresh"
        case .refreshStorage: return "Storage Cleanup"
        case .refreshMap: return "Disk Map"
        case .refreshSpeed: return "Speed & Memory"
        case .refreshStartup: return "Startup Items"
        case .refreshLargeOld: return "Large & Old Files"
        case .refreshDuplicates: return "Duplicates"
        case .refreshLeftovers: return "App Leftovers"
        case .refreshSettings: return "Refresh Settings"
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
        case .refresh: return "sparkles.rectangle.stack"
        case .emergency: return "exclamationmark.octagon"
        case .catAndMouse: return "cat"
        case .vpn: return "network.badge.shield.half.filled"
        case .downloadGate: return "arrow.down.to.line.circle"
        case .mediaGuard: return "video.badge.checkmark"
        case .appFirewall: return "flame"
        case .privacyFilters: return "line.3.horizontal.decrease.circle"
        case .refreshSmart: return "sparkles"
        case .refreshStorage: return "internaldrive"
        case .refreshMap: return "square.grid.3x3.square"
        case .refreshSpeed: return "gauge.with.dots.needle.67percent"
        case .refreshStartup: return "power"
        case .refreshLargeOld: return "doc.badge.clock"
        case .refreshDuplicates: return "doc.on.doc"
        case .refreshLeftovers: return "shippingbox"
        case .refreshSettings: return "slider.horizontal.3"
        }
    }
}

/// The two sidebar modes (segmented control at the top of the sidebar). Remembered across launches.
enum SidebarMode: String, CaseIterable, Identifiable {
    case protection, refresh
    var id: String { rawValue }
    var title: String { self == .protection ? "Protection" : "Refresh" }
    /// Destinations ⌘1–⌘9 select in this mode.
    var shortcutItems: [SidebarItem] { self == .protection ? SidebarItem.core : SidebarItem.refreshItems }
    var home: SidebarItem { self == .protection ? .dashboard : .refreshSmart }
    static let storageKey = "sidebar.mode"
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
    /// Reported by the daemon (`scanProgress.walkFinished`); older daemons are covered by inference
    /// (`total` stops growing once the walk is done).
    var walkFinished = false
    /// Files abandoned at the per-file time limit so far.
    var timedOut = 0
    /// Seconds since the scanner last finished any file; large means one big file is being checked.
    var secondsSinceLastCompletion: Double = 0
    /// True when no file has finished for a while (a large file is being checked): the ETA is hidden.
    var stalled: Bool { secondsSinceLastCompletion >= 3 }
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
        guard !stalled, let f = fraction, f >= 0.05, f < 1, rate > 0.5 else { return nil }
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

/// One Protection Activity row: the stored entry plus its plain-English presentation (computed once).
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
        var entryKind: ActivityEntry.Kind {
            switch self {
            case .threat: return .detection; case .network: return .webBlock; case .scan: return .scan
            case .update: return .update; case .settings: return .settings; case .protection: return .system
            }
        }
    }
    let entry: ActivityEntry
    let presentation: ActivityPresentation
    /// Lowercased title, subtitle, explanation and facts (search).
    let searchText: String
    var id: UUID { entry.id }
    var date: Date { entry.date }
    var kind: Kind {
        switch presentation.category {
        case .threats: return .threat; case .web, .network: return .network; case .scans: return .scan
        case .updates: return .update; case .settings: return .settings; case .protection, .privacy, .maintenance: return .protection
        }
    }
    /// hx8: titles and outcomes carry file names, process names and daemon text. Shown as one plain line.
    let title: String
    let outcome: String

    init(entry: ActivityEntry) {
        self.entry = entry
        let p = ActivityPresenter.present(entry)
        presentation = p
        self.title = SafeText.line(p.title, max: 160)
        self.outcome = SafeText.line(p.status, max: 80)
        searchText = ActivityPresenter.searchText(p, entry).lowercased()
    }

    /// Free-text item (demo data and older call sites).
    init(date: Date, kind: Kind, title: String, outcome: String) {
        self.init(entry: ActivityEntry(date: date, kind: kind.entryKind, title: title, outcome: outcome))
    }

    static func == (a: ActivityItem, b: ActivityItem) -> Bool { a.entry == b.entry }
    func hash(into h: inout Hasher) { h.combine(entry.id) }
}

// SafeText lives in RampartShared/SafeText.swift (hx8: shared with the CLI, the browser and rampart-selftest).

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
    /// The connected background service speaks an older IPC version (shown as a calm update banner).
    var daemonOutdated = false
    /// Sidebar mode; switching shows that mode's own sidebar and remembers the last destination per mode.
    var sidebarMode: SidebarMode = SidebarMode(rawValue: UserDefaults.standard.string(forKey: SidebarMode.storageKey) ?? "") ?? .protection {
        didSet { UserDefaults.standard.set(sidebarMode.rawValue, forKey: SidebarMode.storageKey) }
    }
    @ObservationIgnored private var lastSelection: [SidebarMode: SidebarItem] = [:]
    func switchMode(_ m: SidebarMode) {
        guard m != sidebarMode else { return }
        if let s = selection { lastSelection[sidebarMode] = s }
        sidebarMode = m
        selection = lastSelection[m] ?? m.home
    }
    /// ⌘1–⌘9 within the current mode.
    func selectShortcut(_ i: Int) {
        let items = sidebarMode.shortcutItems
        guard items.indices.contains(i) else { return }
        selection = items[i]
    }
    var status = ProtectionStatus()
    var detections: [Detection] = [] { didSet { recountNeedsYou(); syncChrome() } }
    var quarantine: [QuarantineRecord] = [] { didSet { recountNeedsYou() } }
    /// Cached: views read it many times per frame and the full policy pass over every detection is not cheap.
    private(set) var needsYouCount = 0
    private func recountNeedsYou() {
        let hashes = Set(quarantine.compactMap(\.sha256)), paths = Set(quarantine.map(\.originalPath))
        let n = DetectionPolicy.needsYouCount(detections) { d in (d.sha256.map(hashes.contains) ?? false) || (d.path.map(paths.contains) ?? false) }
        if n != needsYouCount { needsYouCount = n }
    }
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
    @ObservationIgnored private var lastActivitySignature = ""
    /// Daemon entries by id (merged across light and full fetches), newest kept for 90 days.
    @ObservationIgnored private var daemonActivity: [UUID: ActivityEntry] = [:]
    @ObservationIgnored private var lastFullActivityFetch = Date.distantPast
    @ObservationIgnored private var activityFetchScheduled = false
    @ObservationIgnored private var activityItemCache: [UUID: ActivityItem] = [:]
    /// App-process events (PasteGuard, Wi-Fi, vault, Refresh, network scan...) and who-did-it notes.
    @ObservationIgnored let localActivity = AppActivityLog()
    /// Set while an approved AI action runs, so its changes are attributed to the AI assistant.
    @ObservationIgnored var activityActorOverride: ActivityActor?
    @ObservationIgnored private var lastConnections: [ConnectionInfo] = []

    var isDemo: Bool { mode == .demo }
    var isOffline: Bool { mode == .offline }
    /// True when the numbers on screen are real (or explicit developer demo data).
    var hasData: Bool { mode == .live || mode == .demo }
    static let demoRequested = CommandLine.arguments.contains("--demo")
    /// "Needs you" only: open, likely or confirmed threats (see `DetectionPolicy`). Possible findings, notes, test files
    /// and quarantined items are not counted anywhere (badge, "Needs attention" footer, menu bar).
    var openDetections: [Detection] { detections.filter { DetectionPolicy.tier($0, quarantined: isQuarantined($0)) == .needsYou } }
    /// Rows in "Needs you" (one per file, process or login item): the sidebar badge number.
    func isQuarantined(_ d: Detection) -> Bool {
        quarantine.contains { ($0.sha256 == d.sha256 && d.sha256 != nil) || $0.originalPath == d.path }   // one-off checks; counts use the cache
    }
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
        let tallies = ActivityStats.daily(activity.map(\.entry), days: 14)
        daily = tallies.enumerated().map { idx, t in
            // DNS blocks: the DNS filter's own per-day counter also sees blocks it doesn't log (one entry per domain
            // per few minutes), so the larger of the two is used. Scam-link and page blocks come from the log.
            let dns = liveBlockedByDay.count == 14 ? max(liveBlockedByDay[idx], t.dnsBlocks) : t.dnsBlocks
            return DayStat(day: t.day, filesChecked: t.filesChecked, sitesBlocked: dns + t.webBlocks, threats: t.threatsStopped)
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
                await CatAndMouseModel.shared.backgroundPoll()   // Cat & Mouse catches notify without the screen open
                await DownloadGateModel.shared.backgroundPoll(); await MediaGuardModel.shared.backgroundPoll()
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
            EmergencyModel.shared.startAlways()
        } else {
            // No sample data: show the honest "service isn't running" state with a Retry button.
            if mode == .live || mode == .demo { clearDemo() }
            mode = .offline
            if client.lastRejection != nil { lastError = DaemonClient.ClientError.untrusted.errorDescription }
            else if DaemonLauncher.shared.helperMissing { lastError = DaemonLauncher.shared.missingHelperMessage }
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
    /// Error text for the UI: decoding failures become the "older background service" notice, never raw text.
    nonisolated static func userFacing(_ error: Error) -> String {
        if error is DecodingError { DaemonClient.daemonOutdated = true; return DaemonClient.outdatedMessage }
        let m = error.localizedDescription
        if DaemonClient.isDecodeFailureText(m) { DaemonClient.daemonOutdated = true; return DaemonClient.outdatedMessage }
        return m
    }

    private var refreshOwnsError = false

    func refresh(heavy: Bool = true) async {
        guard mode == .live else { return }
        do {
            if case .status(let s) = try await client.request(.status) { status = s; daemonOutdated = (s.ipcVersion ?? 0) < IPC.version }
            // Only clear an error the refresh itself raised: errors from user actions stay until dismissed.
            if refreshOwnsError { lastError = nil; refreshOwnsError = false }
        } catch {
            lastError = AppModel.userFacing(error); refreshOwnsError = true
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
        await fetchActivity(full: heavy || Date().timeIntervalSince(lastFullActivityFetch) > 600)
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

    /// Fetches the daemon's activity: everything kept (full) or the newest 300 (light), merged by id.
    func fetchActivity(full: Bool) async {
        guard mode == .live else { return }
        let limit = full ? 0 : 300
        if case .activity(let a)? = try? await client.request(.activity(limit: limit), timeout: full ? 30 : 10) {
            if full { lastFullActivityFetch = Date() }
            let sig = "\(a.count)|\(a.first?.id.uuidString ?? "")|\(full)"
            if sig == lastActivitySignature && !full { return }
            lastActivitySignature = sig
            if full {
                // A full list is authoritative (the daemon prunes after 90 days).
                daemonActivity = Dictionary(a.map { ($0.id, $0) }, uniquingKeysWith: { x, _ in x })
            } else {
                for e in a { daemonActivity[e.id] = e }
            }
            rebuildActivity()
        } else if daemonActivity.isEmpty {
            rebuildLiveActivity()
        }
    }

    /// Debounced light fetch so a new detection or block shows up within a second or two.
    func scheduleActivityFetch() {
        guard mode == .live, !activityFetchScheduled else { return }
        activityFetchScheduled = true
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            self.activityFetchScheduled = false
            await self.fetchActivity(full: false)
        }
    }

    /// Daemon entries (annotated with who did it) + the app's own entries, newest first.
    func rebuildActivity() {
        let cutoff = Date().addingTimeInterval(-AppActivityLog.retention)
        var all: [ActivityEntry] = []
        all.reserveCapacity(daemonActivity.count + localActivity.entries.count)
        for e in daemonActivity.values where e.date >= cutoff { all.append(localActivity.annotate(e)) }
        let ids = Set(all.map(\.id))
        all += localActivity.entries.filter { $0.date >= cutoff && !ids.contains($0.id) }
        all.sort { $0.date > $1.date }
        // Presentation is computed once per entry and reused while the entry is unchanged.
        var cache: [UUID: ActivityItem] = [:]
        cache.reserveCapacity(all.count)
        activity = all.map { e in
            let item = activityItemCache[e.id].flatMap { $0.entry == e ? $0 : nil } ?? ActivityItem(entry: e)
            cache[e.id] = item
            return item
        }
        activityItemCache = cache
        rebuildDaily()
    }

    /// Records an app-side event. `daemonRecordsWhenLive`: the service logs this itself when connected, so the
    /// app only records it in offline/demo mode (no duplicates).
    func recordActivity(_ e: ActivityEntry, daemonRecordsWhenLive: Bool = false) {
        if daemonRecordsWhenLive && mode == .live { scheduleActivityFetch(); return }
        var e = e
        if e.actor == nil { e.actor = activityActorOverride }
        else if e.actor == .user, let o = activityActorOverride { e.actor = o }
        if mode == .demo { activity.insert(ActivityItem(entry: e), at: 0); rebuildDaily(); return }
        localActivity.add(e)
        rebuildActivity()
    }

    /// The app is about to ask the service for a change: attribute the resulting daemon entries.
    func noteActivityActor(place: String? = nil, events: Set<ActivityEvent> = ActivityEvent.attributable) {
        localActivity.note(activityActorOverride ?? .user, place: activityActorOverride == .ai ? "AI assistant" : place, events: events)
    }

    private func subscribe() {
        eventHandle?.cancel()
        eventHandle = client.stream(.subscribeEvents, onMessage: { resp in
            if case .event(let d) = resp { AppModel.shared.receive(detection: d) }
            if case .emergency(let d) = resp { EmergencyModel.shared.receivePush(d) }
            if case .deception(let d) = resp { CatAndMouseModel.shared.receiveAlert(d) }   // Cat & Mouse catch / lure knock
            if case .downloadGate(let d) = resp { DownloadGateModel.shared.receive(d) }
            if case .mediaGuard(let d) = resp { MediaGuardModel.shared.receiveStatus(d) }
            if case .mediaGuardAlert(let d) = resp { MediaGuardModel.shared.receiveAlert(d) }
            if case .netGuard(let d) = resp { NetGuardModel.shared.receivePush(d) }   // App Firewall first-connection prompt
            return true
        }, onEnd: { _ in
            AppModel.shared.eventHandle = nil
        })
    }

    func receive(detection d: Detection) {
        if let i = detections.firstIndex(where: { $0.id == d.id }) { detections[i] = d } else { detections.insert(d, at: 0) }
        if mode == .live { scheduleActivityFetch() }   // the service logged it; show it within a second or two
        else { recordActivity(Self.activityEntry(for: d)) }
        // Notify only for "Needs you" (likely or confirmed); possible findings and notes stay quiet in FYI.
        // Decoy and lure detections get their own Cat & Mouse notification (one per story): don't post a second one.
        let catMouse = d.name == "Decoy accessed: credential theft behaviour" || d.name == "Network lure contacted"
        if DetectionPolicy.tier(d) == .needsYou && !catMouse { Notifier.shared.threat(d) }
    }

    /// PasteGuard runs in the app: its decisions are recorded here (reasons only, never the command text).
    func receivePasteGuard(_ d: Detection) {
        if let i = detections.firstIndex(where: { $0.id == d.id }) { detections[i] = d } else { detections.insert(d, at: 0) }
        let blocked = d.name.lowercased().contains("blocked")
        let reasons = d.evidence.first?.detail ?? ""
        let decision = d.evidence.first { $0.title.hasPrefix("Decision ") }
        var source: String?
        if let det = decision?.detail, det.hasPrefix("Copied from "), let dot = det.range(of: ". ") {
            source = String(det[det.index(det.startIndex, offsetBy: "Copied from ".count)..<dot.lowerBound])
            if source == "an unknown app" { source = nil }
        }
        let ai = d.evidence.first { $0.title.hasPrefix("AI check:") }?.title
        recordActivity(ActivityEntry(date: d.date, kind: .pasteGuard, title: d.name, outcome: blocked ? "blocked" : "warned",
                                     severity: d.severity, detectionID: d.id, event: blocked ? .pasteGuardBlocked : .pasteGuardWarned,
                                     actor: .system, rule: decision.map { String($0.title.dropFirst("Decision ".count)) },
                                     reason: reasons.isEmpty ? nil : reasons, score: d.confidence,
                                     action: blocked ? "Replaced the command on the clipboard with a harmless note, so pasting it does nothing." : "Warned you before it could be pasted.",
                                     facts: ["sourceApp": source ?? "", "AI opinion": ai.map { String($0.dropFirst("AI check: ".count)) } ?? ""]))
        if d.confidence >= 60 { Notifier.shared.threat(d) }
    }

    /// Entry for a detection seen while the service isn't connected (offline/demo).
    static func activityEntry(for d: Detection) -> ActivityEntry {
        let top = d.evidence.filter { $0.score > 0 }.max { $0.score < $1.score }
        return ActivityEntry(date: d.date, kind: .detection, title: d.name, detail: d.path ?? "", outcome: d.resolved ? "contained" : (DetectionPolicy.tier(d) == .needsYou ? "needs review" : "logged"),
                             severity: d.severity, detectionID: d.id, event: d.name.hasPrefix("Tampering with ") ? .tamper : .detection,
                             process: d.pid.map { ActivityProcess(pid: $0) }, target: d.path, rule: top?.title,
                             reason: top.map { $0.detail.isEmpty ? $0.title : $0.detail }, score: d.confidence, sha256: d.sha256,
                             facts: ["threat": d.name])
    }

    private func rebuildLiveActivity() {
        var entries: [ActivityEntry] = detections.map {
            ActivityEntry(id: $0.id, date: $0.date, kind: .detection, title: $0.name, detail: $0.path ?? "", outcome: $0.resolved ? "contained" : "needs review",
                          severity: $0.severity, detectionID: $0.id, event: .detection, target: $0.path, score: $0.confidence, sha256: $0.sha256)
        }
        entries += quarantine.map {
            ActivityEntry(id: $0.id, date: $0.date, kind: .quarantine, title: "Quarantined \($0.detectionName)", detail: $0.originalPath, outcome: "quarantined",
                          event: .quarantined, target: $0.originalPath, sha256: $0.sha256, refID: $0.id.uuidString, facts: ["threat": $0.detectionName])
        }
        entries += scanHistory.map {
            ActivityEntry(date: $0.date, kind: .scan, title: "\($0.kind.title) finished", outcome: $0.found == 0 ? "no threats" : "\($0.found) found",
                          event: .scanFinished, count: $0.scanned, found: $0.found, facts: ["scanType": $0.kind.title, "seconds": String(format: "%.1f", $0.seconds)])
        }
        if let ls = status.lastScan, scanHistory.isEmpty {
            entries.append(ActivityEntry(date: ls, kind: .scan, title: "Scheduled scan finished", outcome: "completed", event: .scanFinished, actor: .schedule))
        }
        let ids = Set(entries.map(\.id))
        entries += localActivity.entries.filter { !ids.contains($0.id) }
        activity = entries.sorted { $0.date > $1.date }.map(ActivityItem.init(entry:))
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
        if needsYouCount > 0 { return .threat(needsYouCount) }
        if let p = pausedUntil, p > Date() { return .paused(p) }
        if !status.realtimeOn { return .off }
        if !fullDiskAccess { return .limited }
        if !recommendations.isEmpty { return .recommendations(recommendations.count) }
        return .protected
    }

    // MARK: Actions

    func startScan(_ kind: ScanKind, paths: [String] = []) {
        guard !isScanning else { return }
        noteActivityActor(events: [.scanStarted, .scanFinished, .scanCancelled])
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
                case .scanProgress(let scanned, let total, let current, let walkDone, let timedOut, let sinceLast):
                    if Headless.active && scanned <= 1 { HeadlessRunner.log("headless-check: scan progress \(scanned)/\(total) \(current)") }
                    guard case .running(var p) = m.scanPhase else { return true }
                    let now = Date()
                    if now.timeIntervalSince(lastUI) < 0.1 { return true }   // throttle to 10 Hz
                    lastUI = now
                    p.update(scanned: scanned, total: total, walkDone: walkDone, now: now); p.current = current
                    p.timedOut = timedOut ?? 0; p.secondsSinceLastCompletion = sinceLast ?? 0
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
                if let err, m.isScanning {
                    m.lastError = AppModel.userFacing(err)
                    if case .running(let p) = m.scanPhase {
                        m.recordActivity(ActivityEntry(kind: .scan, title: "\(p.kind.title) couldn't finish", outcome: "failed", severity: .low,
                                                       event: .scanFailed, actor: .user, reason: m.lastError, count: p.scanned, found: p.found,
                                                       facts: ["scanType": p.kind.title]))
                    }
                    m.scanPhase = .idle
                }
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
        recordActivity(ActivityEntry(kind: .scan, title: "\(kind.title) finished", outcome: found.isEmpty ? "no threats" : "\(found.count) found",
                                     severity: found.isEmpty ? .info : .medium, event: .scanFinished, actor: .user, count: scanned, found: found.count,
                                     facts: ["scanType": kind.title, "seconds": String(format: "%.1f", seconds)]), daemonRecordsWhenLive: true)
        Notifier.shared.scanFinished(rec)
        if mode == .live { Task { await refresh() } }
    }

    func togglePause() {
        guard case .running(var p) = scanPhase else { return }
        p.paused.toggle()
        scanPhase = .running(p)
        if mode == .live {
            let paused = p.paused
            Task { do { _ = try await client.request(.pauseScan(paused: paused)) } catch { lastError = AppModel.userFacing(error) } }
        }
    }

    func stopScan() {
        if mode == .live, isScanning { Task { _ = try? await client.request(.cancelScan) } }
        scanHandle?.cancel(); scanHandle = nil
        demoTimer?.invalidate()
        if case .running(let p) = scanPhase {
            noteActivityActor(events: [.scanCancelled])
            recordActivity(ActivityEntry(kind: .scan, title: "\(p.kind.title) cancelled", outcome: "stopped", event: .scanCancelled, actor: .user,
                                         count: p.scanned, found: p.found, facts: ["scanType": p.kind.title]), daemonRecordsWhenLive: true)
        }
        scanPhase = .idle
    }

    func setDemoTimer(_ t: Timer?) { demoTimer?.invalidate(); demoTimer = t }

    func quarantine(_ d: Detection) async {
        noteActivityActor()
        if mode == .live {
            do { _ = try await client.request(.quarantine(detectionID: d.id)); await refresh() } catch { lastError = AppModel.userFacing(error) }
        } else {
            mark(d.id, resolved: true)
            if let p = d.path {
                quarantine.insert(QuarantineRecord(originalPath: p, sha256: d.sha256 ?? "", size: 184_320, detectionName: d.name, ownerUID: 501, mode: 0o755), at: 0)
            }
        }
        recordActivity(ActivityEntry(kind: .quarantine, title: "Quarantined \(d.name)", detail: d.path ?? "", outcome: "quarantined", severity: d.severity,
                                     detectionID: d.id, event: .quarantined, actor: .user, target: d.path, score: d.confidence, sha256: d.sha256,
                                     facts: ["threat": d.name]), daemonRecordsWhenLive: true)
    }

    func restore(_ r: QuarantineRecord, allow: Bool) async {
        noteActivityActor()
        if mode == .live {
            do { _ = try await client.request(.restore(id: r.id, allow: allow)); await refresh() } catch { lastError = AppModel.userFacing(error); return }
        } else {
            quarantine.removeAll { $0.id == r.id }
        }
        if allow && mode != .live {
            allowRules.insert(AllowRuleSpec(scope: .fileHash, value: r.sha256, name: (r.originalPath as NSString).lastPathComponent), at: 0)
        }
        recordActivity(ActivityEntry(kind: .restore, title: "Restored \(r.detectionName)", detail: r.originalPath, outcome: allow ? "restored and trusted" : "restored",
                                     event: .restored, actor: .user, target: r.originalPath, sha256: r.sha256, refID: r.id.uuidString,
                                     facts: ["threat": r.detectionName]), daemonRecordsWhenLive: true)
    }

    func delete(_ r: QuarantineRecord) async {
        noteActivityActor()
        if mode == .live {
            do { _ = try await client.request(.deleteQuarantined(id: r.id)); await refresh() } catch { lastError = AppModel.userFacing(error); return }
        } else {
            quarantine.removeAll { $0.id == r.id }
        }
        recordActivity(ActivityEntry(kind: .quarantine, title: "Deleted \((r.originalPath as NSString).lastPathComponent)", detail: r.originalPath, outcome: "deleted",
                                     event: .deleted, actor: .user, target: r.originalPath, sha256: r.sha256, facts: ["threat": r.detectionName]), daemonRecordsWhenLive: true)
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
        noteActivityActor()
        if mode == .live {
            do { _ = try await client.request(.addAllowRule(rule)) } catch { lastError = AppModel.userFacing(error); return false }
            if case .allowRules(let r)? = try? await client.request(.listAllowRules) { allowRules = r.sorted { $0.created > $1.created } }
        } else {
            allowRules.insert(rule, at: 0)
        }
        recordActivity(ActivityEntry(kind: .settings, title: "Allowed \(rule.name)", outcome: "allow rule added", event: .allowRuleAdded, actor: .user,
                                     refID: rule.id.uuidString, facts: ["name": rule.name, "scope": rule.scope.rawValue]), daemonRecordsWhenLive: true)
        return true
    }

    func removeAllowRule(_ rule: AllowRuleSpec) async {
        noteActivityActor()
        if mode == .live {
            do { _ = try await client.request(.removeAllowRule(id: rule.id)) } catch { lastError = AppModel.userFacing(error); return }
            if case .allowRules(let r)? = try? await client.request(.listAllowRules) { allowRules = r.sorted { $0.created > $1.created } }
        } else {
            allowRules.removeAll { $0.id == rule.id }
        }
        recordActivity(ActivityEntry(kind: .settings, title: "Removed rule for \(rule.name)", outcome: "allow rule removed", event: .allowRuleRemoved, actor: .user,
                                     refID: rule.id.uuidString, facts: ["name": rule.name, "scope": rule.scope.rawValue]), daemonRecordsWhenLive: true)
    }

    // MARK: Settings (owned by the daemon in live mode)

    func updateSettings(_ change: (inout RampartSettings) -> Void) {
        var next = settings
        change(&next)
        guard next != settings else { return }
        noteActivityActor()
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
                self.lastError = AppModel.userFacing(error)
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
        noteActivityActor()
        if mode == .live {
            do { _ = try await client.request(.remediate(persistenceID: item.id), timeout: 60) } catch { return error.localizedDescription }
            await refresh()
        } else {
            persistence.removeAll { $0.id == item.id }
        }
        recordActivity(ActivityEntry(kind: .persistence, title: "Turned off startup item \(item.label)", outcome: "removed", event: .startupItemRemoved, actor: .user,
                                     target: item.location, facts: ["label": item.label]), daemonRecordsWhenLive: true)
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
        noteActivityActor()
        fixingChecks.insert(c.id)
        defer { fixingChecks.remove(c.id) }
        if mode == .live {
            do { _ = try await client.request(.fixPosture(checkID: c.id), timeout: 60); await refresh() } catch { lastError = AppModel.userFacing(error); return }
        } else {
            try? await Task.sleep(nanoseconds: 700_000_000)
            if let i = posture.firstIndex(where: { $0.id == c.id }) { posture[i].state = .pass; posture[i].detail = "Turned on by \(Product.name) just now." }
        }
        recordActivity(ActivityEntry(kind: .posture, title: "Fixed: \(c.title)", outcome: "fixed", event: .postureFixed, actor: .user,
                                     facts: ["check": c.title]), daemonRecordsWhenLive: true)
    }

    func setWebProtection(_ on: Bool) async {
        noteActivityActor()
        if mode == .live {
            guard webProtectionAvailable else { lastError = "Web protection needs the full system service."; return }
            do { _ = try await client.request(.setWebProtection(on: on)); await refresh() } catch { lastError = AppModel.userFacing(error); return }
        } else { status.webProtectionOn = on }
        recordActivity(ActivityEntry(kind: .settings, title: "Web protection \(on ? "on" : "off")", outcome: on ? "on" : "off", event: .protectionToggled, actor: .user,
                                     facts: ["setting": "Web protection", "value": on ? "on" : "off"]), daemonRecordsWhenLive: true)
    }

    func setRealtime(_ on: Bool, pauseFor minutes: Int? = nil) {
        noteActivityActor()
        if let minutes { pausedUntil = Date().addingTimeInterval(Double(minutes) * 60) } else { pausedUntil = nil }
        let effectiveOn = on && minutes == nil
        status.realtimeOn = effectiveOn || minutes != nil
        settings.realtimeOn = effectiveOn
        if mode == .live {
            Task {
                do { _ = try await client.request(.setRealtime(on: effectiveOn)); await self.refresh() } catch { self.lastError = AppModel.userFacing(error) }
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
        if let minutes {
            // The service only sees "off": the pause and its length are known to the app.
            recordActivity(ActivityEntry(kind: .settings, title: "Protection paused for \(minutes) min", outcome: "paused", severity: .medium,
                                         event: .protectionPaused, actor: .user, count: minutes))
        } else {
            recordActivity(ActivityEntry(kind: .settings, title: "Real-time protection \(on ? "on" : "off")", outcome: on ? "on" : "off",
                                         severity: on ? .info : .medium, event: .protectionToggled, actor: .user,
                                         facts: ["setting": "Real-time protection", "value": on ? "on" : "off"]), daemonRecordsWhenLive: true)
        }
    }

    func updateDefinitions() async {
        noteActivityActor()
        isUpdatingDefinitions = true
        defer { isUpdatingDefinitions = false }
        if mode == .live {
            do { _ = try await client.request(.updateSignatures, timeout: 120); await refresh() } catch { lastError = AppModel.userFacing(error); return }
        } else {
            try? await Task.sleep(nanoseconds: 1_200_000_000)
        }
        definitionsUpdated = Date()
        recordActivity(ActivityEntry(kind: .update, title: "Protection updated", outcome: "ok", event: .definitionsUpdated, actor: .user), daemonRecordsWhenLive: true)
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


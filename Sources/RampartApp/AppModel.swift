import SwiftUI
import Observation
import RampartShared

// MARK: - App-local types (UI-only; not part of the shared IPC contract)

enum SidebarItem: String, CaseIterable, Identifiable, Hashable {
    case dashboard, scan, threats, activity, network, posture, settings
    var id: String { rawValue }
    var title: String {
        switch self {
        case .dashboard: return "Overview"
        case .scan: return "Scan"
        case .threats: return "Threats & Quarantine"
        case .activity: return "Protection Activity"
        case .network: return "Network"
        case .posture: return "Privacy & Posture"
        case .settings: return "Settings"
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
        case .settings: return "gearshape"
        }
    }
    var shortcut: KeyEquivalent { KeyEquivalent(Character(String((SidebarItem.allCases.firstIndex(of: self) ?? 0) + 1))) }
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
    var fraction: Double? { total > 0 ? min(1, Double(scanned) / Double(total)) : nil }
    var etaSeconds: Double? {
        guard let f = fraction, f > 0.03 else { return nil }
        let elapsed = Date().timeIntervalSince(started)
        return elapsed / f - elapsed
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
    }
    var id: String { app }
    var app: String
    var bundlePath: String?
    var sentKB: Int
    var receivedKB: Int
    var destinations: [Destination]
    var blockedCount: Int { destinations.filter(\.blocked).count }
}

struct WiFiInfo: Hashable {
    var ssid: String
    var security: String
    var encrypted: Bool
    var gatewayChanged: Bool
}

struct AllowRule: Identifiable, Hashable {
    enum Scope: String { case file = "This file only", developer = "This developer", folder = "This folder" }
    let id = UUID()
    var name: String
    var scope: Scope
    var value: String
    var created: Date
    var expires: Date?
}

enum ConnectionMode: Equatable { case connecting, live, demo }

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
    var allowRules: [AllowRule] = []
    var ignoredChecks: Set<String> = []
    var dismissedRecommendations: Set<String> = []
    var pausedUntil: Date?
    var lastError: String?
    var definitionsUpdated: Date?
    var isUpdatingDefinitions = false
    var fixingChecks: Set<String> = []
    var hasFullDiskAccess = FDAProbe.check()
    /// Last 14 days, oldest first (charts).
    var daily: [DayStat] = []
    /// Most recent scanned paths, newest first (scan animation), updated at most 5×/s.
    var recentScanPaths: [String] = []
    @ObservationIgnored private var lastPathNote = Date.distantPast

    @ObservationIgnored let client = DaemonClient()
    @ObservationIgnored private var scanHandle: DaemonClient.StreamHandle?
    @ObservationIgnored private var eventHandle: DaemonClient.StreamHandle?
    @ObservationIgnored private var demoTimer: Timer?
    @ObservationIgnored private var pollTimer: Timer?
    @ObservationIgnored private var started = false

    var isDemo: Bool { mode == .demo }
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
            return DayStat(day: day, filesChecked: files, sitesBlocked: items.filter { $0.kind == .network }.count,
                           threats: items.filter { $0.kind == .threat }.count)
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
        Task { await connect() }
        pollTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { _ in
            Task { @MainActor in await AppModel.shared.periodic() }
        }
    }

    private func periodic() async {
        hasFullDiskAccess = FDAProbe.check()
        if mode == .demo, ProcessInfo.processInfo.arguments.contains("--demo") { return }
        if await client.isReachable() {
            if mode != .live { await connect() } else { await refresh() }
        } else if mode != .demo {
            enterDemo()
        }
    }

    func connect() async {
        if await client.isReachable() {
            mode = .live
            demoTimer?.invalidate()
            await refresh()
            subscribe()
        } else {
            enterDemo()
        }
    }

    func refresh() async {
        guard mode == .live else { return }
        do {
            if case .status(let s) = try await client.request(.status) { status = s; definitionsUpdated = s.lastScan ?? definitionsUpdated }
            if case .detections(let d) = try await client.request(.listDetections) { detections = d.sorted { $0.date > $1.date } }
            if case .quarantine(let q) = try await client.request(.listQuarantine) { quarantine = q.sorted { $0.date > $1.date } }
            if case .posture(let p) = try await client.request(.posture, timeout: 30) { posture = p }
            if case .persistence(let p) = try? await client.request(.persistence, timeout: 30) { persistence = p }
            rebuildLiveActivity()
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
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

    enum Overall { case protected, recommendations(Int), threat(Int), off, limited, paused(Date) }
    var overall: Overall {
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
                    guard case .running(var p) = m.scanPhase else { return true }
                    let now = Date()
                    if now.timeIntervalSince(lastUI) < 0.1 { return true }   // throttle to 10 Hz
                    lastUI = now
                    p.scanned = scanned; p.total = total; p.current = current
                    m.scanPhase = .running(p)
                    m.noteScanPath(current)
                    return true
                case .scanFinished(let scanned, let found, let seconds):
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
    }

    func stopScan() {
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
        if allow {
            allowRules.insert(AllowRule(name: (r.originalPath as NSString).lastPathComponent, scope: .file, value: r.sha256, created: Date(), expires: nil), at: 0)
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

    func allow(_ d: Detection, scope: AllowRule.Scope) async {
        if mode == .live, let h = d.sha256 {
            do { _ = try await client.request(.allow(sha256: h)) } catch { lastError = error.localizedDescription; return }
        }
        let value: String
        switch scope {
        case .file: value = d.sha256 ?? d.path ?? d.name
        case .developer: value = d.evidence.first { $0.source == .signing }?.detail ?? "Unknown developer"
        case .folder: value = ((d.path ?? "/") as NSString).deletingLastPathComponent
        }
        allowRules.insert(AllowRule(name: (d.path.map { ($0 as NSString).lastPathComponent }) ?? d.name, scope: scope, value: value, created: Date(), expires: nil), at: 0)
        mark(d.id, resolved: true)
        activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Allowed \(d.name) (\(scope.rawValue.lowercased()))", outcome: "Rule added"), at: 0)
        if mode == .live { await refresh() }
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
            if let i = posture.firstIndex(where: { $0.id == c.id }) { posture[i].state = .pass; posture[i].detail = "Turned on by Rampart just now." }
        }
        activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Fixed: \(c.title)", outcome: "Done"), at: 0)
    }

    func setWebProtection(_ on: Bool) async {
        if mode == .live {
            do { _ = try await client.request(.setWebProtection(on: on)); await refresh() } catch { lastError = error.localizedDescription; return }
        } else { status.webProtectionOn = on }
        activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Web protection turned \(on ? "on" : "off")", outcome: "Changed"), at: 0)
    }

    func setRealtime(_ on: Bool, pauseFor minutes: Int? = nil) {
        if let minutes { pausedUntil = Date().addingTimeInterval(Double(minutes) * 60) } else { pausedUntil = nil }
        if mode != .live { status.realtimeOn = on || minutes != nil }
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

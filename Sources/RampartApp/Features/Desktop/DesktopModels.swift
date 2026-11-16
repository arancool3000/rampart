import SwiftUI
import AppKit
import CoreWLAN
import RampartShared

// MARK: - System info (sampled only while the desktop layer is visible)

@MainActor
@Observable
final class DesktopInfo {
    static let shared = DesktopInfo()

    struct WiFi: Equatable { var connected: Bool; var name: String?; var security: String; var weak: Bool }

    private(set) var cpu: Double?                       // 0…1
    private(set) var cpuHistory: [Double] = []
    private(set) var memory: MemoryReading?
    private(set) var disk: DiskReading?
    private(set) var battery: BatteryReading?
    private(set) var down: Double = 0   // bytes per second
    private(set) var up: Double = 0
    private(set) var netHistory: [Double] = []
    private(set) var wifi: WiFi?
    private(set) var bootDate: Date? = Uptime.bootDate()
    private(set) var interval: TimeInterval?

    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var lastCPU: CPUTicks?
    @ObservationIgnored private var lastNet: [String: NetCounters] = [:]
    @ObservationIgnored private var lastNetAt = Date()
    @ObservationIgnored private var ticks = 0
    @ObservationIgnored private var active = false

    /// Starts (2–5 s cadence) or stops sampling. Called by DesktopMode whenever visibility changes.
    func setActive(_ on: Bool) {
        active = on
        reschedule()
    }

    private func reschedule() {
        let onBattery = battery.map { !$0.onAC } ?? false
        let want = DesktopCadence.interval(visible: active, onBattery: onBattery, lowPower: ProcessInfo.processInfo.isLowPowerModeEnabled)
        guard want != interval || (want != nil && timer == nil) else { return }
        interval = want
        timer?.invalidate(); timer = nil
        guard let want else { return }
        let t = Timer(timeInterval: want, repeats: true) { _ in MainActor.assumeIsolated { DesktopInfo.shared.sample() } }
        t.tolerance = want * 0.25   // lets macOS coalesce wake-ups
        RunLoop.main.add(t, forMode: .common)
        timer = t
        sample()   // after the timer exists, so sample() → reschedule() can't recurse
    }

    /// One sample. Cheap reads only (host statistics, getifaddrs, IOKit); disk and Wi-Fi less often.
    func sample() {
        if let c = CPUTicks.read() {
            if let p = lastCPU, let u = CPUTicks.usage(from: p, to: c) { cpu = u; push(&cpuHistory, u) }
            lastCPU = c
        }
        memory = MemoryReading.read()
        let now = Date(), n = NetCounters.readPerInterface()
        if !lastNet.isEmpty {
            let r = NetCounters.rates(from: lastNet, to: n, seconds: now.timeIntervalSince(lastNetAt))
            down = r.down; up = r.up; push(&netHistory, r.down + r.up)
        }
        lastNet = n; lastNetAt = now
        if ticks % 15 == 0 { disk = DiskReading.read() }
        let tick = ticks
        ticks += 1
        if tick % 5 == 0 {
            battery = BatteryReading.read()
            refreshWiFi()
            reschedule()
        }
    }

    @ObservationIgnored private var wifiInFlight = false

    /// CoreWiFi talks to a system daemon with a synchronous XPC call; never do that on the main thread.
    private func refreshWiFi() {
        guard !wifiInFlight else { return }
        wifiInFlight = true
        DispatchQueue.global(qos: .utility).async {
            let w = Self.readWiFi()
            DispatchQueue.main.async { MainActor.assumeIsolated {
                DesktopInfo.shared.wifi = w
                DesktopInfo.shared.wifiInFlight = false
            } }
        }
    }

    private func push(_ a: inout [Double], _ v: Double) { a.append(v); if a.count > 30 { a.removeFirst(a.count - 30) } }

    /// Network name needs Location access on recent macOS; RamPart never asks for it, so the name may be hidden.
    nonisolated private static func readWiFi() -> WiFi? {
        guard !Headless.active, let i = CWWiFiClient.shared().interface() else { return nil }
        guard i.powerOn(), i.wlanChannel() != nil else { return WiFi(connected: false, name: nil, security: "Not connected", weak: false) }
        let (label, weak) = describe(i.security())
        return WiFi(connected: true, name: i.ssid(), security: label, weak: weak)
    }

    nonisolated static func describe(_ s: CWSecurity) -> (String, Bool) {
        switch s {
        case .none: return ("Open network, not encrypted", true)
        case .WEP, .dynamicWEP: return ("WEP (weak)", true)
        case .wpaPersonal, .wpaPersonalMixed, .wpaEnterprise, .wpaEnterpriseMixed: return ("WPA", true)
        case .wpa2Personal, .personal: return ("WPA2", false)
        case .wpa2Enterprise, .enterprise: return ("WPA2 Enterprise", false)
        case .wpa3Personal, .wpa3Transition: return ("WPA3", false)
        case .wpa3Enterprise: return ("WPA3 Enterprise", false)
        case .OWE, .oweTransition: return ("Enhanced Open", false)
        default: return ("Encrypted", false)
        }
    }
}

// MARK: - Launcher model

@MainActor
@Observable
final class LauncherModel {
    static let shared = LauncherModel()

    private(set) var apps: [LauncherApp] = []
    private(set) var layout: LauncherLayout
    private(set) var loaded = false
    @ObservationIgnored private var icons: [String: NSImage] = [:]
    @ObservationIgnored private var lastScan = Date.distantPast
    @ObservationIgnored private let store = LauncherStore(defaults: .standard)

    private init() { layout = store.load() }

    var arranged: (favorites: [LauncherApp], others: [LauncherApp]) { layout.arrange(apps) }

    /// Re-reads the Applications folders at most every 5 minutes (off the main thread).
    func refreshIfStale() {
        guard Date().timeIntervalSince(lastScan) > 300 else { return }
        lastScan = Date()
        Task.detached(priority: .utility) {
            let found = LauncherCatalog.discover()
            await MainActor.run { LauncherModel.shared.apply(found) }
        }
    }

    /// Synchronous load for previews / first paint.
    func loadNow() { lastScan = Date(); apply(LauncherCatalog.discover()) }

    private func apply(_ found: [LauncherApp]) {
        apps = found
        var l = layout
        l.seedIfNeeded(apps: found)
        l.prune(existing: Set(found.map(\.path)))
        setLayout(l)
        loaded = true
    }

    private func setLayout(_ l: LauncherLayout) {
        guard l != layout || !loaded else { return }
        layout = l
        if !Headless.active { store.save(l) }
    }

    func icon(_ app: LauncherApp) -> NSImage {
        if let i = icons[app.path] { return i }
        let i = NSWorkspace.shared.icon(forFile: app.path)
        i.size = NSSize(width: 128, height: 128)
        icons[app.path] = i
        return i
    }

    func togglePin(_ app: LauncherApp) { var l = layout; l.toggle(app.path); setLayout(l) }
    func move(_ path: String, before target: String?, inFavorites: Bool) {
        // o8: drops can carry any string from any app; only paths of listed apps can be pinned or moved.
        guard apps.contains(where: { $0.path == path }) else { return }
        var l = layout
        l.move(path, before: target, inFavorites: inFavorites, allPaths: arranged.others.map(\.path))
        setLayout(l)
    }

    /// User click only. Never called by previews or tests.
    func launch(_ app: LauncherApp) {
        guard !Headless.active, LauncherCatalog.stillSame(app) else { refreshIfStale(); return }
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: app.path), configuration: NSWorkspace.OpenConfiguration()) { _, _ in }
    }
    func reveal(_ app: LauncherApp) {
        guard !Headless.active else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: app.path)])
    }
}

// MARK: - Actions and search catalogue

enum DesktopAction: String, CaseIterable, Identifiable {
    case quickScan, protectEverything, refresh, killSwitch
    var id: String { rawValue }
    var title: String {
        switch self {
        case .quickScan: return "Quick Scan"
        case .protectEverything: return "Protect Everything"
        case .refresh: return "Refresh clean-up"
        case .killSwitch: return "Super Kill Switch"
        }
    }
    var subtitle: String {
        switch self {
        case .quickScan: return "About a minute"
        case .protectEverything: return "Every safeguard on"
        case .refresh: return "Free up space"
        case .killSwitch: return "Cut off everything"
        }
    }
    var symbol: String {
        switch self {
        case .quickScan: return "bolt.fill"
        case .protectEverything: return "checkmark.shield.fill"
        case .refresh: return "sparkles"
        case .killSwitch: return "power"
        }
    }
    var tint: Color {
        switch self {
        case .quickScan: return Palette.teal
        case .protectEverything: return Palette.mint
        case .refresh: return Color(red: 0.55, green: 0.55, blue: 1.0)
        case .killSwitch: return Palette.coral
        }
    }
    var keywords: [String] {
        switch self {
        case .quickScan: return ["scan", "malware", "virus", "check"]
        case .protectEverything: return ["protect", "secure", "harden", "all"]
        case .refresh: return ["clean", "cleanup", "space", "storage", "junk", "speed"]
        case .killSwitch: return ["emergency", "panic", "disconnect", "lockdown", "kill"]
        }
    }

    /// Quick Scan runs in place (progress shows in the hero). The others open their screen in RamPart,
    /// where the user confirms: nothing drastic happens from a single click on the desktop.
    @MainActor func perform() {
        let m = AppModel.shared
        switch self {
        case .quickScan:
            if m.hasData { m.startScan(.quick) } else { DesktopMode.shared.openMain(.scan) }
        case .protectEverything: DesktopMode.shared.openMain(.emergency)
        case .refresh: DesktopMode.shared.openMain(.refreshSmart)
        case .killSwitch: DesktopMode.shared.openMain(.emergency)
        }
    }
}

enum DesktopCatalog {
    static let featureKeywords: [SidebarItem: [String]] = [
        .dashboard: ["overview", "home", "status", "score"], .scan: ["scan", "malware", "virus"],
        .threats: ["quarantine", "virus", "detections"], .activity: ["log", "history", "events"],
        .network: ["web", "blocked", "sites", "dns"], .posture: ["privacy", "settings", "score", "firewall"],
        .rules: ["allow", "exceptions"], .settings: ["preferences", "options"],
        .scamCheck: ["phishing", "link", "scam", "message"], .passwords: ["vault", "login"],
        .authenticator: ["2fa", "otp", "code"], .passwordChecker: ["breach", "strength"],
        .networkScan: ["devices", "router", "lan"], .aiAssistant: ["ai", "chat", "help", "gemini"],
        .remoteAccess: ["anydesk", "teamviewer", "screen sharing"], .emergency: ["lockdown", "kill switch", "panic"],
        .catAndMouse: ["decoy", "honeypot", "trap", "maze"], .refreshSmart: ["clean", "cleanup", "junk"],
    ]

    @MainActor static func items(apps: [LauncherApp]) -> [DesktopSearchItem] {
        var out = DesktopAction.allCases.map { DesktopSearchItem(id: "action:" + $0.rawValue, kind: .action, title: $0.title, keywords: $0.keywords) }
        out.append(DesktopSearchItem(id: "action:desktopOff", kind: .action, title: "Turn off Desktop Mode", keywords: ["desktop", "hide", "exit"]))
        let features = SidebarItem.core + SidebarItem.tools + SidebarItem.refreshItems
        out += features.map { DesktopSearchItem(id: "feature:" + $0.rawValue, kind: .feature, title: $0.title, keywords: featureKeywords[$0] ?? []) }
        out += apps.map { DesktopSearchItem(id: "app:" + $0.path, kind: .app, title: $0.name, keywords: [$0.bundleID ?? ""]) }
        return out
    }

    @MainActor static func open(_ item: DesktopSearchItem) {
        let parts = item.id.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return }
        switch parts[0] {
        case "action":
            if parts[1] == "desktopOff" { DesktopMode.shared.setOn(false) }
            else { DesktopAction(rawValue: parts[1])?.perform() }
        case "feature": if let s = SidebarItem(rawValue: parts[1]) { DesktopMode.shared.openMain(s) }
        case "app": if let a = LauncherModel.shared.apps.first(where: { $0.path == parts[1] }) { LauncherModel.shared.launch(a) }
        default: break
        }
    }

    static func symbol(for item: DesktopSearchItem) -> String {
        let parts = item.id.split(separator: ":", maxSplits: 1).map(String.init)
        switch item.kind {
        case .action: return DesktopAction(rawValue: parts.last ?? "")?.symbol ?? "rectangle.on.rectangle.slash"
        case .feature: return SidebarItem(rawValue: parts.last ?? "")?.symbol ?? "shield"
        case .app: return "app"
        }
    }
}

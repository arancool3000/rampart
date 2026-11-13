import Foundation
import AppKit
import WebKit
import Observation
import RampartShared

/// Session state: tabs, the data store policy (Banking mode = non-persistent), the compiled content
/// rules, and the activity log shown in the shield menu.
@MainActor
@Observable
final class BrowserModel {
    static let shared = BrowserModel()

    struct Activity: Identifiable, Equatable {
        let id = UUID()
        let date = Date()
        let host: String
        let text: String
        let severe: Bool
    }

    var tabs: [BrowserTab] = []
    var selectedTabID: UUID?
    /// Non-persistent data store per session. Off = an isolated persistent profile (still separate from Safari).
    var bankingMode: Bool = UserDefaults.standard.object(forKey: "browser.bankingMode") as? Bool ?? true {
        didSet { UserDefaults.standard.set(bankingMode, forKey: "browser.bankingMode") }
    }
    var developerMode = CommandLine.arguments.contains("--developer")
    var contentRules: WKContentRuleList?
    var rulesStatus = "Compiling tracker rules…"
    var daemonReachable: Bool?
    var activity: [Activity] = []
    var blockedCount = 0
    var showDownloads = false
    var showIdentity = false
    var showFind = false
    var showShieldMenu = false
    var addressFocusToken = 0
    @ObservationIgnored private var sessionStore: WKWebsiteDataStore?
    @ObservationIgnored private let processPool = WKProcessPool()

    var selectedTab: BrowserTab? { tabs.first { $0.id == selectedTabID } ?? tabs.first }
    var blocklistSummary: String {
        let e = WebEngineAdapter.shared
        return e.blocklistDomains == 0 ? "No RamPart block lists found yet (the background service downloads them)." : "\(e.blocklistDomains.formatted()) blocked domains from \(e.blocklistNames.count) lists."
    }

    func start() {
        Task {
            contentRules = await ContentRules.compile()
            rulesStatus = contentRules == nil ? "Tracker rules unavailable" : "\(ContentRules.ruleCount) tracker and miner rules active"
            for t in tabs { apply(rules: contentRules, to: t) }
        }
        Task { daemonReachable = await BrowserDaemonClient.shared.isReachable() }
    }

    private func apply(rules: WKContentRuleList?, to tab: BrowserTab) {
        guard let rules else { return }
        tab.webView.configuration.userContentController.add(rules)
    }

    /// Data store for the current mode. Banking: one ephemeral store per app session (shared across tabs so
    /// a bank's login survives opening a second tab, gone when the app quits). Otherwise an isolated profile.
    func dataStore() -> WKWebsiteDataStore {
        if bankingMode {
            if let s = sessionStore { return s }
            let s = WKWebsiteDataStore.nonPersistent(); sessionStore = s; return s
        }
        let key = "browser.profileID"
        let id: UUID
        if let s = UserDefaults.standard.string(forKey: key), let u = UUID(uuidString: s) { id = u }
        else { id = UUID(); UserDefaults.standard.set(id.uuidString, forKey: key) }
        if #available(macOS 14, *) { return WKWebsiteDataStore(forIdentifier: id) }
        return .default()
    }

    func configuration() -> WKWebViewConfiguration {
        let c = WKWebViewConfiguration()
        c.processPool = processPool
        c.websiteDataStore = dataStore()
        c.defaultWebpagePreferences.allowsContentJavaScript = true
        c.preferences.javaScriptCanOpenWindowsAutomatically = false
        c.preferences.isFraudulentWebsiteWarningEnabled = true   // WebKit's own Safe Browsing check, on top of ours
        c.preferences.isElementFullscreenEnabled = false
        c.allowsAirPlayForMediaPlayback = false
        c.suppressesIncrementalRendering = false
        c.limitsNavigationsToAppBoundDomains = false
        c.upgradeKnownHostsToHTTPS = true
        c.applicationNameForUserAgent = UserAgentPolicy.current   // wms-o3: look like Safari, not a bare web view
        if let r = contentRules { c.userContentController.add(r) }
        return c
    }

    @discardableResult
    func newTab(url: URL? = nil, select: Bool = true) -> BrowserTab {
        let tab = BrowserTab(model: self, configuration: configuration())
        tabs.append(tab)
        if select { selectedTabID = tab.id }
        if let url { tab.load(url) } else { addressFocusToken += 1 }
        return tab
    }

    func close(_ tab: BrowserTab) {
        guard let i = tabs.firstIndex(where: { $0.id == tab.id }) else { return }
        if let p = tab.permissionPrompt { tab.permissionPrompt = nil; p.decide(false) }   // hx6: answer, don't drop
        if let d = tab.dialog { tab.dialog = nil; d.finish(false, nil) }
        tab.webView.stopLoading()
        tab.webView.navigationDelegate = nil
        tabs.remove(at: i)
        if selectedTabID == tab.id { selectedTabID = tabs.isEmpty ? nil : tabs[min(i, tabs.count - 1)].id }
        if tabs.isEmpty { newTab() }
    }
    func closeSelected() { if let t = selectedTab { close(t) } }
    func selectNext(_ delta: Int) {
        guard let t = selectedTab, let i = tabs.firstIndex(where: { $0.id == t.id }), !tabs.isEmpty else { return }
        selectedTabID = tabs[(i + delta + tabs.count) % tabs.count].id
    }

    /// Switching modes starts a fresh session. hx6: existing tabs are re-opened on the new mode's data
    /// store (they used to keep the old one, so a tab opened before Banking mode kept writing cookies to
    /// the persistent profile while the shield said Banking mode was on, and vice versa).
    func toggleBankingMode() {
        bankingMode.toggle()
        sessionStore = nil
        let old = tabs, selectedIndex = tabs.firstIndex { $0.id == selectedTabID } ?? 0
        let urls = old.map { t -> URL? in
            guard let u = t.blockedURL ?? t.url, let s = u.scheme?.lowercased(), s == "https" || s == "http" else { return nil }
            return u
        }
        tabs = []
        for t in old {
            if let p = t.permissionPrompt { t.permissionPrompt = nil; p.decide(false) }
            if let d = t.dialog { t.dialog = nil; d.finish(false, nil) }
            t.webView.stopLoading(); t.webView.navigationDelegate = nil; t.webView.uiDelegate = nil
        }
        for u in urls { newTab(url: u, select: false) }
        if tabs.isEmpty { newTab() }
        selectedTabID = tabs[min(selectedIndex, tabs.count - 1)].id
        if bankingMode { Task { await WKWebsiteDataStore.default().removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(), modifiedSince: .distantPast) } }
    }

    func recordBlocked(_ url: URL, decision: NavigationDecision) {
        blockedCount += 1
        let severe: Bool = { if case .block = decision { return true }; return false }()
        activity.insert(Activity(host: url.host ?? url.absoluteString, text: decision.risks.first?.title ?? "Stopped", severe: severe), at: 0)
        if activity.count > 50 { activity.removeLast() }
    }
    func recordFindings(_ f: [PageFinding], url: URL?) {
        for x in f { activity.insert(Activity(host: url?.host ?? "", text: x.title, severe: x.severity >= 80), at: 0) }
        if activity.count > 50 { activity.removeLast(activity.count - 50) }
    }
}

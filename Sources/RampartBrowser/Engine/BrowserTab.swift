import Foundation
import AppKit
import WebKit
import Observation
import Security
import RampartShared
import RampartWeb

/// Permission request from a page (camera/mic). Always surfaced to the user; never auto-granted.
struct PermissionPrompt: Identifiable {
    enum Kind: String { case camera = "Camera", microphone = "Microphone", cameraAndMicrophone = "Camera and microphone" }
    let id = UUID()
    let kind: Kind
    let origin: String
    let decide: (Bool) -> Void
}

/// JavaScript dialog (alert/confirm/prompt) rendered in-window instead of as an NSAlert, so a page can
/// neither steal focus nor dress itself up as a system dialog.
struct PageDialog: Identifiable {
    enum Kind { case alert, confirm, prompt(defaultText: String) }
    let id = UUID()
    let kind: Kind
    let origin: String
    let message: String
    let finish: (Bool, String?) -> Void
}

@MainActor
@Observable
final class BrowserTab: Identifiable {
    let id = UUID()
    let webView: WKWebView
    unowned let model: BrowserModel

    var url: URL?
    var title = "New Tab"
    var isLoading = false
    var progress: Double = 0
    var canGoBack = false
    var canGoForward = false
    var display = DomainDisplay.make(url: nil)
    var facts = URLFacts()
    /// Set when a navigation was stopped; the page shows the interstitial instead of the web view.
    var interstitial: Interstitial?
    var blockedURL: URL?
    var blockedDecision: NavigationDecision?
    var pageVerdict: PageVerdict = .clean
    var identity: IdentitySummary?
    var permissionPrompt: PermissionPrompt?
    var dialog: PageDialog?
    var loadError: String?
    var findQuery = ""
    var findMatches: Int?
    /// http hosts where the https upgrade already failed this tab (policy then warns instead of looping).
    @ObservationIgnored var upgradeFailedHosts: Set<String> = []
    @ObservationIgnored private var upgradedFrom: [URL: URL] = [:]     // https → original http
    @ObservationIgnored private var observations: [NSKeyValueObservation] = []
    @ObservationIgnored private var delegate: TabDelegate!
    @ObservationIgnored var policy = URLDecisionPolicy()

    init(model: BrowserModel, configuration: WKWebViewConfiguration) {
        self.model = model
        webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 1024, height: 700), configuration: configuration)
        webView.allowsBackForwardNavigationGestures = true
        webView.allowsMagnification = true
        webView.customUserAgent = nil
        let d = TabDelegate(tab: self)
        delegate = d
        webView.navigationDelegate = d
        webView.uiDelegate = d
        configuration.userContentController.removeAllScriptMessageHandlers()
        ContentScript.install(into: configuration.userContentController, handler: d)
        observe()
    }

    private func observe() {
        observations = [
            webView.observe(\.title) { [weak self] w, _ in Task { @MainActor in self?.title = (w.title?.isEmpty == false ? w.title! : self?.display.domain) ?? "New Tab" } },
            webView.observe(\.url) { [weak self] w, _ in Task { @MainActor in self?.urlChanged(w.url) } },
            webView.observe(\.isLoading) { [weak self] w, _ in Task { @MainActor in self?.isLoading = w.isLoading } },
            webView.observe(\.estimatedProgress) { [weak self] w, _ in Task { @MainActor in self?.progress = w.estimatedProgress } },
            webView.observe(\.canGoBack) { [weak self] w, _ in Task { @MainActor in self?.canGoBack = w.canGoBack } },
            webView.observe(\.canGoForward) { [weak self] w, _ in Task { @MainActor in self?.canGoForward = w.canGoForward } },
            webView.observe(\.serverTrust) { [weak self] w, _ in Task { @MainActor in self?.updateIdentity(w.serverTrust) } },
        ]
    }

    func urlChanged(_ u: URL?) {
        url = u
        facts = u.map { WebEngineAdapter.shared.facts(for: $0) } ?? URLFacts()
        display = DomainDisplay.make(url: u, brandMatch: facts.allowlisted ? nil : facts.brandMatch)
        if title.isEmpty || title == "New Tab" { title = display.domain.isEmpty ? "New Tab" : display.domain }
    }

    // MARK: Navigation

    func load(_ u: URL) {
        interstitial = nil; blockedURL = nil; loadError = nil; pageVerdict = .clean
        webView.load(URLRequest(url: u, cachePolicy: .useProtocolCachePolicy, timeoutInterval: 30))
    }
    func loadTyped(_ text: String) { if let u = URLDecisionPolicy.resolveTyped(text) { load(u) } }
    func reload() { if let b = blockedURL { load(b) } else { webView.reload() } }
    func stop() { webView.stopLoading() }
    func goBack() { interstitial = nil; blockedURL = nil; if webView.canGoBack { webView.goBack() } else { webView.load(URLRequest(url: URL(string: "about:blank")!)) } }
    func goForward() { interstitial = nil; webView.goForward() }

    /// "Continue anyway" from a warning interstitial: remember the host for this session and load.
    func continueAnyway() {
        guard let u = blockedURL else { return }
        let host = (u.host ?? "").lowercased()
        if let d = blockedDecision, d.risks.contains(.plainHTTP) { policy.httpAllowedHosts.insert(host) }
        else { WebEngineAdapter.shared.allow(host: host) }
        load(u)
    }

    func find(_ q: String, forward: Bool = true) {
        findQuery = q
        guard !q.isEmpty else { findMatches = nil; return }
        let c = WKFindConfiguration(); c.backwards = !forward; c.caseSensitive = false; c.wraps = true
        webView.find(q, configuration: c) { [weak self] r in Task { @MainActor in self?.findMatches = r.matchFound ? 1 : 0 } }
    }

    // MARK: Decisions

    fileprivate func decide(_ action: WKNavigationAction) -> WKNavigationActionPolicy {
        guard let u = action.request.url else { return .cancel }
        let main = action.targetFrame?.isMainFrame ?? true
        let f = WebEngineAdapter.shared.facts(for: u)
        let host = (u.host ?? "").lowercased()
        let decision = policy.decide(url: u, facts: f, isMainFrame: main, httpUpgradeFailed: upgradeFailedHosts.contains(host))
        switch decision {
        case .allow:
            if action.shouldPerformDownload { return .download }
            return .allow
        case .upgrade(let https):
            if main { upgradedFrom[https] = u; webView.load(URLRequest(url: https)) }
            return .cancel
        case .warn, .block:
            guard main else { return .cancel }
            blockedURL = u; blockedDecision = decision
            interstitial = Interstitial.select(for: decision, host: display(for: u), developerMode: model.developerMode)
            model.recordBlocked(u, decision: decision)
            return .cancel
        }
    }
    private func display(for u: URL) -> String { DomainDisplay.make(url: u).domain }

    fileprivate func provisionalFailed(_ error: Error, url failing: URL?) {
        let ns = error as NSError
        if ns.domain == NSURLErrorDomain, ns.code == NSURLErrorCancelled { return }
        // The https upgrade failed: fall back to http through the policy, which now warns.
        if let failing, let original = upgradedFrom.removeValue(forKey: failing) {
            upgradeFailedHosts.insert((original.host ?? "").lowercased())
            webView.load(URLRequest(url: original)); return
        }
        loadError = ns.localizedDescription
    }

    fileprivate func findingsArrived(_ findings: [PageFinding]) {
        guard !findings.isEmpty else { return }
        let all = Array(Set(pageVerdict.findings + findings))
        pageVerdict = PageFindingPolicy.verdict(all, bankingMode: model.bankingMode)
        model.recordFindings(findings, url: url)
        if case .block = pageVerdict {
            // ClickFix / drainer pages: stop scripts and replace the page.
            webView.stopLoading()
            blockedURL = url; blockedDecision = .block([.likelyScam], score: 100)
            interstitial = Interstitial(tone: .danger, symbol: "hand.raised.fill", title: findings.first?.title ?? "This page is attacking your Mac",
                                        body: findings.first?.explanation ?? "", reasons: all.map(\.title), primaryLabel: "Go back",
                                        secondaryLabel: nil, showsContinue: false)
            webView.loadHTMLString("<html><body style='background:#070d1c'></body></html>", baseURL: nil)
        }
    }

    fileprivate func formsArrived(_ body: Any) {
        guard let dict = body as? [String: Any], let forms = dict["forms"] as? [[String: Any]], !forms.isEmpty else { return }
        let hints = (dict["brandHints"] as? [String]) ?? []
        let pageHost = (url?.host ?? "").lowercased()
        let pageReg = PublicSuffix.split(pageHost)?.registrable ?? pageHost
        var findings: [PageFinding] = []
        if let b = facts.brandMatch, !facts.allowlisted {
            findings.append(PageFinding(kind: .credentialForm, detail: "looks like \(b) but is \(pageReg)", sample: nil))
        }
        for h in hints {
            guard let brand = BrandList.brand(forKeyword: h), !brand.domains.contains(pageReg) else { continue }
            // Brand mentioned prominently on a password page whose domain isn't the brand's.
            for form in forms {
                let actionHost = (form["action"] as? String).flatMap { URL(string: $0)?.host?.lowercased() } ?? pageHost
                let actionReg = PublicSuffix.split(actionHost)?.registrable ?? actionHost
                if !brand.domains.contains(actionReg) {
                    findings.append(PageFinding(kind: .credentialForm, detail: "\(brand.name) sign-in on \(pageReg)", sample: dict["title"] as? String)); break
                }
            }
        }
        if !findings.isEmpty { findingsArrived(findings) }
    }

    func updateIdentity(_ trust: SecTrust?) {
        guard let u = url, let host = u.host else { identity = nil; return }
        guard let trust else { identity = IdentitySummary(host: host, encrypted: u.scheme == "https"); return }
        var subject: String? = nil, issuer: String? = nil
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
            subject = SecCertificateCopySubjectSummary(leaf) as String?
            if chain.count > 1 { issuer = SecCertificateCopySubjectSummary(chain[1]) as String? }
        }
        var err: CFError?
        let ok = SecTrustEvaluateWithError(trust, &err)
        identity = IdentitySummary(host: host, encrypted: true, subject: subject, issuer: issuer, validUntil: nil, evaluatedOK: ok)
    }
}

// MARK: - WebKit delegate (kept out of the observable so WebKit's NSObject plumbing stays simple)

final class TabDelegate: NSObject, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
    weak var tab: BrowserTab?
    init(tab: BrowserTab) { self.tab = tab }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, preferences: WKWebpagePreferences) async -> (WKNavigationActionPolicy, WKWebpagePreferences) {
        preferences.allowsContentJavaScript = true
        guard let tab else { return (.cancel, preferences) }
        return (tab.decide(navigationAction), preferences)
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse) async -> WKNavigationResponsePolicy {
        navigationResponse.canShowMIMEType ? .allow : .download
    }
    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) { start(download, response: nil, request: navigationAction.request) }
    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) { start(download, response: navigationResponse.response, request: nil) }
    private func start(_ download: WKDownload, response: URLResponse?, request: URLRequest?) {
        guard let tab else { download.cancel(); return }
        let u = response?.url ?? request?.url
        let host = (u?.host ?? "").lowercased()
        let name = response?.suggestedFilename ?? u?.lastPathComponent ?? "download"
        let risky = tab.facts.scamVerdict != .likelySafe || tab.facts.blocklistHit != nil
        _ = DownloadManager.shared.begin(download, suggestedFilename: name, mimeType: response?.mimeType, sourceHost: host, risky: risky, bankingMode: tab.model.bankingMode)
        tab.model.showDownloads = true
    }
    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) { tab?.loadError = nil; tab?.pageVerdict = .clean; tab?.findMatches = nil }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        tab?.provisionalFailed(error, url: (error as NSError).userInfo[NSURLErrorFailingURLErrorKey] as? URL)
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        let ns = error as NSError
        if ns.code != NSURLErrorCancelled { tab?.loadError = ns.localizedDescription }
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { tab?.updateIdentity(webView.serverTrust) }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) { tab?.loadError = "The page's process stopped unexpectedly. Reload to try again." }

    // Certificate problems are never clicked through: the system decision stands.
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.performDefaultHandling, nil)
    }

    // MARK: UI delegate
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        // Pop-ups open as a tab in our chrome so they go through the same policy; never a bare window.
        if let u = navigationAction.request.url, let tab { tab.model.newTab(url: u, select: true) }
        return nil
    }
    func webView(_ webView: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo, type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        let kind: PermissionPrompt.Kind = type == .camera ? .camera : type == .microphone ? .microphone : .cameraAndMicrophone
        guard let tab, frame.isMainFrame else { decisionHandler(.deny); return }
        tab.permissionPrompt = PermissionPrompt(kind: kind, origin: origin.host) { decisionHandler($0 ? .grant : .deny) }
    }
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        guard let tab else { completionHandler(); return }
        tab.dialog = PageDialog(kind: .alert, origin: frame.securityOrigin.host, message: message) { _, _ in completionHandler() }
    }
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        guard let tab else { completionHandler(false); return }
        tab.dialog = PageDialog(kind: .confirm, origin: frame.securityOrigin.host, message: message) { ok, _ in completionHandler(ok) }
    }
    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String, defaultText: String?, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (String?) -> Void) {
        guard let tab else { completionHandler(nil); return }
        tab.dialog = PageDialog(kind: .prompt(defaultText: defaultText ?? ""), origin: frame.securityOrigin.host, message: prompt) { ok, text in completionHandler(ok ? text : nil) }
    }
    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        // File uploads are allowed but always through the system panel, which the page cannot pre-fill.
        let p = NSOpenPanel(); p.allowsMultipleSelection = parameters.allowsMultipleSelection; p.canChooseDirectories = parameters.allowsDirectories
        p.begin { completionHandler($0 == .OK ? p.urls : nil) }
    }

    // MARK: Script messages (isolated world only)
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let tab else { return }
        switch message.name {
        case ContentScript.findingsHandler, ContentScript.clipboardHandler:
            tab.findingsArrived(PageFindingPolicy.decode(message.body))
        case ContentScript.formsHandler:
            tab.formsArrived(message.body)
        default: break
        }
    }
}

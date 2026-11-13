import Foundation
import JavaScriptCore
import RampartShared
import RampartWeb

// wms-o3: browser attack surface (extensions, native messaging host, Secure Browser).
// The extension's JS runs in JavaScriptCore with minimal stubs for chrome.* and the DOM, driven by a
// "hostile page" / "spoofed sender". Nothing here touches a real browser, the pasteboard or the network.
extension SelfTest {
    static func wmsO3Checks() {
        let root = wmsO3RepoRoot()
        func read(_ rel: String) -> String { (try? String(contentsOfFile: root + "/" + rel, encoding: .utf8)) ?? "" }

        wmsO3Sanitizer()
        wmsO3FrameCap()
        wmsO3Manifests(read)
        wmsO3Heuristics(read("Extensions/chromium/shared/heuristics.js"))
        wmsO3ClipboardMain(read("Extensions/chromium/shared/clipboard-main.js"))
        wmsO3Background(heuristics: read("Extensions/chromium/shared/heuristics.js"), background: read("Extensions/chromium/background.js"))
        wmsO3NMHProcess()
    }

    // MARK: Native host request cleaning (all transports go through WebVerdictService.handle)

    static func wmsO3Sanitizer() {
        let svc = WebVerdictService(seenStore: MemorySeenDomainStore(), allowlist: FileWebAllowlist(url: FileManager.default.temporaryDirectory.appendingPathComponent("wms-o3-allow-\(getpid()).txt")))
        for bad in ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "chrome://settings", "https://", String(repeating: "a", count: 9000)] {
            check(svc.handle(NMRequest(type: .checkURL, url: bad)).ok == false, "wms-o3 nmh rejects url \(bad.prefix(20))")
        }
        check(svc.handle(NMRequest(id: String(repeating: "i", count: 500), type: .ping)).ok == false, "wms-o3 nmh rejects oversized id")
        check(svc.handle(NMRequest(id: String(repeating: "i", count: 500), type: .ping)).id == nil, "wms-o3 nmh never echoes an oversized id")
        check(svc.handle(NMRequest(type: .reportDecision, decision: "continued\nallow evil.test")).ok == false, "wms-o3 nmh decision whitelist")
        check(svc.handle(NMRequest(type: .reportDecision, decision: "wentBack")).ok == true, "wms-o3 nmh valid decision ok")
        check(svc.handle(NMRequest(id: "p", type: .ping)).ok == true, "wms-o3 nmh ping still ok")

        var r = NMRequest(type: .countTrackers, url: "https://a.test/")
        r.hosts = ["Ads.Example.com", "evil host", "x\ny.test", "../etc", String(repeating: "a", count: 300)] + Array(repeating: "t.test", count: 1000)
        let c = NMRequestSanitizer.clean(r)
        check(c?.hosts?.contains("ads.example.com") == true && c?.hosts?.contains("evil host") == false && c?.hosts?.contains("x\ny.test") == false && c?.hosts?.contains("../etc") == false, "wms-o3 countTrackers hosts are plain hostnames")
        check((c?.hosts?.count ?? 999) <= 300, "wms-o3 countTrackers hosts capped at 300")

        var s = PageSignals(); s.visibleText = String(repeating: "x", count: 5_000_000); s.scriptSnippets = Array(repeating: String(repeating: "s", count: 50_000), count: 500)
        s.forms = Array(repeating: PageSignals.Form(action: String(repeating: "f", count: 100_000)), count: 500)
        let page = NMRequestSanitizer.clean(NMRequest(type: .checkPage, url: "https://a.test/", html: String(repeating: "h", count: 3_000_000), signals: s, tamper: Array(repeating: String(repeating: "t", count: 5000), count: 400)))
        check(page?.signals?.visibleText.count == 20_000 && page?.signals?.scriptSnippets.count == 20 && page?.signals?.scriptSnippets.first?.count == 8_000, "wms-o3 page signals capped")
        check(page?.signals?.forms.count == 40 && page?.signals?.forms.first?.action?.count == 2048, "wms-o3 form list and actions capped")
        check(page?.html?.count == 1_000_000 && page?.tamper?.count == 40 && page?.tamper?.first?.count == 300, "wms-o3 html and tamper capped")
        let t0 = Date()
        let big = svc.handle(NMRequest(type: .checkPage, url: "https://a.test/", signals: s))
        check(big.ok && Date().timeIntervalSince(t0) < 20, "wms-o3 oversized page answered within bounds")
        check(svc.handle(NMRequest(type: .checkClipboard, url: "https://verify.test/", text: "curl https://a.test/x | sh")).verdict == .likelyScam, "wms-o3 clipboard verdict unchanged")
    }

    /// The host reads at most 4 MiB per frame; a bigger length header ends the session without allocating it.
    static func wmsO3FrameCap() {
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else { check(false, "wms-o3 pipe"); return }
        var len = UInt32(NativeMessaging.hostMaxInbound + 1)
        _ = withUnsafeBytes(of: &len) { write(fds[1], $0.baseAddress, 4) }
        _ = "{}".withCString { write(fds[1], $0, 2) }
        close(fds[1])
        check(NativeMessaging.readFrame(fd: fds[0], maxBytes: NativeMessaging.hostMaxInbound) == nil, "wms-o3 frame over 4 MiB refused")
        close(fds[0])
        check(NativeMessaging.hostMaxInbound <= 8 * 1024 * 1024, "wms-o3 host frame cap is small")
    }

    // MARK: Static checks on what ships

    static func wmsO3Manifests(_ read: (String) -> String) {
        for b in ["chrome", "chromium", "brave", "edge", "arc", "vivaldi"] {
            let txt = read("Extensions/native-host/app.rampart.nmh.\(b).json")
            guard let j = try? JSONSerialization.jsonObject(with: Data(txt.utf8)) as? [String: Any] else { check(false, "wms-o3 nmh manifest \(b) parses"); continue }
            let origins = j["allowed_origins"] as? [String] ?? []
            check(origins == ["chrome-extension://__EXTENSION_ID__/"], "wms-o3 nmh manifest \(b) pins exactly one extension origin")
            check(j["type"] as? String == "stdio" && j["allowed_extensions"] == nil && !txt.contains("*"), "wms-o3 nmh manifest \(b) stdio, no wildcard")
        }
        for m in ["Extensions/chromium/manifest.json", "Extensions/safari/manifest.json"] {
            let txt = read(m)
            guard let j = try? JSONSerialization.jsonObject(with: Data(txt.utf8)) as? [String: Any] else { check(false, "wms-o3 \(m) parses"); continue }
            check(j["externally_connectable"] == nil, "wms-o3 \(m): no page or other extension can message the background")
            check(!txt.contains("content.css") && !txt.contains("\"css\""), "wms-o3 \(m): no stylesheet injected into every page (fingerprint)")
            let war = j["web_accessible_resources"] as? [[String: Any]] ?? []
            check(war.count == 1 && (war.first?["resources"] as? [String]) == ["interstitial.html"] && war.first?["use_dynamic_url"] as? Bool == true, "wms-o3 \(m): only the interstitial is web-accessible, at a per-session URL")
            let csp = (j["content_security_policy"] as? [String: String])?["extension_pages"] ?? ""
            check(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'") && !csp.contains("unsafe"), "wms-o3 \(m): popup/interstitial CSP blocks injection and framing")
            let cs = j["content_scripts"] as? [[String: Any]] ?? []
            check(cs.allSatisfy { $0["all_frames"] as? Bool == false }, "wms-o3 \(m): content scripts top frame only")
        }
        let content = read("Extensions/chromium/content.js")
        check(!content.contains("rampart-locked") && content.contains("lockScroll()"), "wms-o3 scroll lock is inline, not a page-detectable class")
        check(content.contains("H.uiClickAllowed(") && content.contains("\"toggle\", \"fullscreenchange\"") && content.contains("raiseSurfaces()"), "wms-o3 in-page warning re-raised above page top-layer elements")
        check(content.contains("document.exitFullscreen()"), "wms-o3 page fullscreen ended under a block")
        check(!read("Extensions/chromium/shared/tamper.js").contains("__rampartClipboardHooked"), "wms-o3 tamper.js no longer references the old page global")
        for f in ["popup.js", "interstitial.js", "content.js"] {
            let js = read("Extensions/chromium/" + f)
            check(!js.contains("innerHTML") && !js.contains("insertAdjacentHTML") && !js.contains("document.write") && !js.contains("eval("), "wms-o3 \(f) builds UI with textContent only")
        }
        let model = read("Sources/RampartBrowser/Engine/BrowserModel.swift")
        check(model.contains("applicationNameForUserAgent = UserAgentPolicy.current"), "wms-o3 Secure Browser presents a Safari user agent")
        check(!model.contains("isInspectable = true") && !model.contains("allowFileAccessFromFileURLs"), "wms-o3 Secure Browser: not inspectable, no file URL access")
        let cscript = read("Sources/RampartBrowser/Engine/ContentScript.swift")
        check(cscript.contains("controller.add(handler, contentWorld: world, name: name)") && !cscript.contains("contentWorld: .page"), "wms-o3 Secure Browser message handlers only in the isolated world")
        let validator = read("Sources/RampartSafariExtension/MessageValidator.swift")
        check(validator.contains("\"countTrackers\"") && validator.contains("payload[\"hosts\"]"), "wms-o3 Safari validator handles countTrackers with hostname-only hosts")
    }

    // MARK: JavaScriptCore

    static func wmsO3Context() -> JSContext {
        let ctx = JSContext()!
        ctx.exceptionHandler = { _, e in print("  wms-o3 JS exception: \(e?.toString() ?? "?")") }
        // Minimal web APIs JSC lacks.
        ctx.evaluateScript("""
        var __timers = []; function setTimeout(f, ms) { __timers.push(f); return __timers.length; } function clearTimeout() {} function setInterval() { return 0; } function clearInterval() {}
        var crypto = { getRandomValues(a) { for (let i = 0; i < a.length; i++) a[i] = (i * 37 + 11) & 255; return a; } };
        class URL { constructor(u) { const m = /^([a-z][a-z0-9+.-]*:)\\/\\/([^\\/?#@]*@)?([^\\/?#:]*)(:\\d+)?([^?#]*)(\\?[^#]*)?(#.*)?$/i.exec(String(u)); if (!m || !m[3]) throw new TypeError("bad url");
          this.protocol = m[1].toLowerCase(); this.hostname = m[3].toLowerCase(); this.host = this.hostname + (m[4] || ""); this.port = (m[4] || "").slice(1);
          this.pathname = m[5] || "/"; this.search = m[6] || ""; this.hash = m[7] || ""; this.href = String(u); this.origin = this.protocol + "//" + this.host; } toString() { return this.href; } }
        class DOMException extends Error { constructor(m, n) { super(m); this.name = n; } }
        """)
        return ctx
    }

    static func wmsO3Heuristics(_ src: String) {
        let ctx = wmsO3Context()
        ctx.evaluateScript(src)
        func allowed(_ now: Double, _ shown: Double, _ foreign: Double) -> Bool {
            ctx.evaluateScript("RampartHeuristics.uiClickAllowed(\(now), \(shown), \(foreign))")?.toBool() ?? true
        }
        check(!allowed(1200, 1000, -1), "wms-o3 click within 500 ms of the warning appearing ignored")
        check(allowed(1600, 1000, -1), "wms-o3 click after 500 ms accepted")
        check(!allowed(5000, 1000, 4800), "wms-o3 click right after a page top-layer change ignored")
        check(allowed(5000, 1000, 4000), "wms-o3 click well after a page top-layer change accepted")
        check(ctx.evaluateScript("RampartHeuristics.uiClickAllowed(NaN, 0, -1) || RampartHeuristics.uiClickAllowed('9999', 0, -1)")?.toBool() == false, "wms-o3 click guard fails closed on junk")
    }

    /// clipboard-main.js runs in the page's own world, so a hostile page sees and pokes at it directly.
    static func wmsO3ClipboardMain(_ src: String) {
        let ctx = wmsO3Context()
        ctx.evaluateScript("""
        var __listeners = []; var __written = [];
        var window = globalThis; window.addEventListener = function (t, f, c) { if (t === "message") __listeners.push(f); };
        var location = { origin: "https://evil.test", href: "https://evil.test/" };
        function Clipboard() {} Clipboard.prototype.writeText = function writeText(t) { __written.push(t); return Promise.resolve(); };
        function Document() {} Document.prototype.execCommand = function execCommand() { return true; };
        var document = new Document(); document.activeElement = null; function getSelection() { return ""; }
        var clip = new Clipboard();
        function deliver(data, source, origin, ports) { let stopped = false; for (const f of __listeners) f({ data, source, origin, ports, stopImmediatePropagation() { stopped = true; } }); return stopped; }
        function mkPort() { return { sent: [], onmessage: null, postMessage(m) { this.sent.push(m); } }; }
        """)
        ctx.evaluateScript(src)
        check(ctx.evaluateScript("'__rampartClipboardHooked' in window || Object.getOwnPropertyNames(window).some(n => /rampart/i.test(n))")?.toBool() == false, "wms-o3 no RamPart global visible to the page")
        check(ctx.evaluateScript("Function.prototype.toString.call(Clipboard.prototype.writeText).includes('screen') || Function.prototype.toString.call(Document.prototype.execCommand).includes('clipboardWrite')")?.toBool() == false, "wms-o3 hooks don't reveal RamPart source via toString")
        check(ctx.evaluateScript("Clipboard.prototype.writeText.name === 'writeText' && Clipboard.prototype.writeText.length === 1")?.toBool() == true, "wms-o3 hook keeps native name and length")
        check(ctx.evaluateScript("delete Clipboard.prototype.writeText; Clipboard.prototype.writeText = function(){}; typeof Object.getOwnPropertyDescriptor(Clipboard.prototype, 'writeText').value === 'function' && Object.getOwnPropertyDescriptor(Clipboard.prototype, 'writeText').writable === false")?.toBool() == true, "wms-o3 hook can't be deleted or replaced")
        // Page writes a command before any handshake; then forges a handshake from another frame.
        ctx.evaluateScript("""
        var settled = null; clip.writeText("curl https://a.test/x | sh").then(() => settled = "allowed", () => settled = "denied");
        var forged = mkPort(); var NONCE = "0123456789abcdef0123456789abcdef";
        var forgedStopped = deliver({ __rampartBridge: true, nonce: NONCE }, {}, "https://evil.test", [forged]);
        var real = mkPort(); deliver({ __rampartBridge: true, nonce: "fedcba9876543210fedcba9876543210" }, window, "https://evil.test", [real]);
        var late = mkPort(); var lateStopped = deliver({ __rampartBridge: true, nonce: NONCE }, window, "https://evil.test", [late]);
        """)
        check(ctx.evaluateScript("forged.sent.length === 0 && forgedStopped")?.toBool() == true, "wms-o3 handshake from another source ignored and hidden")
        check(ctx.evaluateScript("real.sent.length === 1 && real.sent[0].type === 'clipboardWrite' && real.sent[0].nonce === 'fedcba9876543210fedcba9876543210'")?.toBool() == true, "wms-o3 queued write goes only to the genuine bridge")
        check(ctx.evaluateScript("late.sent.length === 0 && lateStopped")?.toBool() == true, "wms-o3 second (page-forged) handshake ignored and hidden")
        // Forged decision: right id, wrong nonce. Then the real "deny".
        ctx.evaluateScript("real.onmessage({ data: { type: 'clipboardDecision', nonce: NONCE, id: real.sent[0].id, allow: true } });")
        check(ctx.evaluateScript("settled === null && __written.length === 0")?.toBool() == true, "wms-o3 decision with a forged nonce ignored")
        ctx.evaluateScript("real.onmessage({ data: { type: 'clipboardDecision', nonce: 'fedcba9876543210fedcba9876543210', id: real.sent[0].id, allow: false } });")
        check(ctx.evaluateScript("settled === 'denied' && __written.length === 0")?.toBool() == true, "wms-o3 genuine deny rejects the page's write")
        ctx.evaluateScript("""
        var s2 = null; clip.writeText("hello").then(() => s2 = "allowed");
        real.onmessage({ data: { type: 'clipboardDecision', nonce: 'fedcba9876543210fedcba9876543210', id: real.sent[1].id, allow: true } });
        """)
        check(ctx.evaluateScript("s2 === 'allowed' && __written[0] === 'hello'")?.toBool() == true, "wms-o3 genuine allow lets ordinary text through")
    }

    /// background.js with a spoofed-sender harness: hostile pages, other extensions and the wrong contexts.
    static func wmsO3Background(heuristics: String, background: String) {
        let ctx = wmsO3Context()
        ctx.evaluateScript("""
        var L = {}; var __activeTab = { id: 5, url: "https://other.test/" }; var __updates = [];
        var navigator = { vendor: "Google Inc." };
        function importScripts() {}
        var chrome = {
          runtime: { id: "EXT", getURL: (p) => "chrome-extension://EXT/" + p, connectNative() { throw new Error("no host"); }, onMessage: { addListener(f) { L.msg = f; } }, lastError: null },
          tabs: { onRemoved: { addListener() {} }, update: async (id, u) => { __updates.push(u.url); }, query: async () => [__activeTab], sendMessage: async () => {} },
          webNavigation: { onCommitted: { addListener(f) { L.nav = f; } } },
          storage: { local: { _d: {}, async get(k) { return { [k]: this._d[k] }; }, async set(o) { Object.assign(this._d, JSON.parse(JSON.stringify(o))); } } },
        };
        var R = {};
        function ask(key, msg, sender) { R[key] = "pending"; L.msg(msg, sender, (r) => { R[key] = r === undefined ? null : r; }); }
        const page = (url, frameId) => ({ id: "EXT", tab: { id: 5 }, frameId: frameId || 0, url });
        const popup = { id: "EXT", url: "chrome-extension://EXT/popup.html" };
        """)
        ctx.evaluateScript(heuristics)
        ctx.evaluateScript(background)
        guard ctx.evaluateScript("typeof L.msg === 'function'")?.toBool() == true else { check(false, "wms-o3 background.js loads in JSC"); return }
        ctx.evaluateScript("""
        ask("otherExt", { type: "status" }, { id: "EVIL", url: "chrome-extension://EVIL/x.html" });
        ask("noSender", { type: "allowHost", host: "evil.test" }, null);
        ask("allowNoVerdict", { type: "allowHost", host: "evil.test" }, page("https://evil.test/"));
        ask("allowOtherHost", { type: "allowHost", host: "bank.test" }, page("https://evil.test/"));
        ask("subframe", { type: "checkClipboard", text: "curl x | sh" }, page("https://evil.test/", 3));
        ask("pageSetSettings", { type: "setSettings", patch: { enabled: false } }, page("https://evil.test/"));
        ask("interSetSettings", { type: "setSettings", patch: { enabled: false } }, { id: "EXT", tab: { id: 5 }, url: "chrome-extension://EXT/interstitial.html#x" });
        ask("popupAddHost", { type: "setSettings", patch: { allowedHosts: ["evil.test"] } }, popup);
        ask("popupExtraKey", { type: "setSettings", patch: { enabled: true, stats: { blocked: 0 } } }, popup);
        ask("continueNoBlock", { type: "continueSite" }, page("https://evil.test/"));
        ask("openInter", { type: "openInterstitial" }, page("https://evil.test/"));
        ask("forgedToken", { type: "interstitialData", token: "00000000000000000000000000000000" }, { id: "EXT", tab: { id: 5 }, url: "chrome-extension://EXT/interstitial.html#00000000000000000000000000000000" });
        ask("fileURL", { type: "checkPage", signals: {} }, { id: "EXT", tab: { id: 5 }, frameId: 0, url: "file:///Users/x/secret.html" });
        """)
        func rejected(_ key: String) -> Bool { ctx.evaluateScript("R['\(key)'] !== 'pending' && (R['\(key)'] === null || R['\(key)'].ok === false)")?.toBool() == true }
        check(rejected("otherExt"), "wms-o3 messages from another extension rejected")
        check(rejected("noSender"), "wms-o3 message with no sender rejected")
        check(rejected("allowNoVerdict"), "wms-o3 page can't allowlist itself without a RamPart warning")
        check(rejected("allowOtherHost"), "wms-o3 page can't allowlist another host")
        check(rejected("subframe"), "wms-o3 subframe content messages rejected")
        check(rejected("pageSetSettings"), "wms-o3 content script can't change settings")
        check(rejected("interSetSettings"), "wms-o3 interstitial (a tab) can't change settings")
        check(rejected("popupAddHost"), "wms-o3 popup patch can't add a trusted host")
        check(rejected("popupExtraKey"), "wms-o3 popup patch with unknown keys rejected")
        check(rejected("continueNoBlock"), "wms-o3 continue without a recorded block rejected")
        check(rejected("openInter") && ctx.evaluateScript("__updates.length === 0")?.toBool() == true, "wms-o3 page can't trigger tab navigation")
        check(rejected("forgedToken"), "wms-o3 forged interstitial token gets nothing")
        check(rejected("fileURL"), "wms-o3 non-http sender URL treated as no content script")
        check(ctx.evaluateScript("JSON.stringify(chrome.storage.local._d.settings || {}).includes('evil.test') === false && (chrome.storage.local._d.settings || {}).enabled !== false")?.toBool() == true, "wms-o3 stored settings untouched by hostile senders")
        // Tracker count: shown only for the site the active tab is on now.
        ctx.evaluateScript("""
        tabState(5).trackers = { host: "a.test", count: 3, companies: ["AdCo"] };
        ask("statusOther", { type: "status" }, popup);
        """)
        check(ctx.evaluateScript("R.statusOther && R.statusOther.settings && R.statusOther.trackers === null")?.toBool() == true, "wms-o3 popup never shows another site's tracker count")
        ctx.evaluateScript("__activeTab = { id: 5, url: 'https://a.test/page' }; ask('statusSame', { type: 'status' }, popup);")
        check(ctx.evaluateScript("R.statusSame && R.statusSame.trackers && R.statusSame.trackers.count === 3")?.toBool() == true, "wms-o3 popup shows the current site's tracker count")
        check(ctx.evaluateScript("ask('popupStatusFromTab', { type: 'status' }, { id: 'EXT', tab: { id: 5 }, url: 'chrome-extension://EXT/interstitial.html' }); R.popupStatusFromTab === null")?.toBool() == true, "wms-o3 status (settings, trusted hosts) only to the popup")
    }

    /// End to end against the built host: a huge length header and a junk id don't hurt it.
    static func wmsO3NMHProcess() {
        guard let nmh = findNMH() else { print("  wms-o3: rampart-nmh not built; skipping stdio checks"); return }
        let p = Process(); p.executableURL = URL(fileURLWithPath: nmh)
        var env = ProcessInfo.processInfo.environment; env["RAMPART_NO_PRIVILEGED_TOOLS"] = "1"; p.environment = env
        let inPipe = Pipe(), outPipe = Pipe(); p.standardInput = inPipe; p.standardOutput = outPipe; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { check(false, "wms-o3 launch rampart-nmh"); return }
        var payload = NativeMessaging.frame(Data("{\"id\":\"\(String(repeating: "x", count: 5000))\",\"type\":\"bogus\"}".utf8))
        payload += try! NativeMessaging.encode(NMRequest(id: "u", type: .checkURL, url: "file:///etc/passwd"))
        var huge = UInt32(60 * 1024 * 1024); payload += Data(bytes: &huge, count: 4)
        inPipe.fileHandleForWriting.write(payload)
        let deadline = Date().addingTimeInterval(10)
        while p.isRunning && Date() < deadline { usleep(50_000) }
        let exited = !p.isRunning
        if !exited { p.terminate() }
        try? inPipe.fileHandleForWriting.close()
        let out = outPipe.fileHandleForReading.readDataToEndOfFile()
        let rs = NativeMessaging.unframe(out).compactMap { try? JSONDecoder().decode(NMResponse.self, from: $0) }
        check(exited, "wms-o3 nmh stops on an oversized frame instead of waiting for 60 MiB")
        check(rs.count == 2 && rs[0].ok == false && rs[0].id == nil, "wms-o3 nmh doesn't echo a 5 KB id")
        check(rs.count == 2 && rs[1].ok == false && rs[1].id == "u", "wms-o3 nmh refuses file: URLs")
    }

    private static func wmsO3RepoRoot() -> String {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<4 { dir.deleteLastPathComponent(); if FileManager.default.fileExists(atPath: dir.appendingPathComponent("Package.swift").path) { return dir.path } }
        return FileManager.default.currentDirectoryPath
    }
}

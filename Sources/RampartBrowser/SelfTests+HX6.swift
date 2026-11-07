import Foundation
import RampartWeb

/// hx6 hardening regressions (navigation policy, address bar, downloads, prompts, content scripts).
/// Pure: no WebKit objects, no windows. The vault checks use a scratch directory under $TMPDIR.
extension BrowserSelfTests {
    static func hx6() {
        let p = URLDecisionPolicy(), safe = URLFacts()
        func blocked(_ s: String, main: Bool = true) -> Bool {
            guard let u = URL(string: s) else { return true }
            if case .block = p.decide(url: u, facts: safe, isMainFrame: main) { return true }; return false
        }
        // Schemes
        for s in ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,<script>1</script>", "blob:https://x.test/abc", "file:///etc/passwd",
                  "vbscript:x", "ftp://x.test/", "rampart:settings", "rampart://fake-alert", "about:Your-Mac-is-infected", "about:srcdoc", "x-apple.systempreferences:x", "ms-msdt:x", "tel:123"] {
            check(blocked(s), "hx6 scheme blocked at top level: \(s)")
        }
        for s in ["data:text/html,x", "javascript:void(0)", "blob:https://x.test/1", "file:///x", "rampart:x"] { check(blocked(s, main: false), "hx6 scheme blocked in frames: \(s)") }
        check(!blocked("about:blank"), "hx6 about:blank allowed")
        check(!blocked("about:blank#anything"), "hx6 about:blank#frag allowed (still blank)")
        check(!blocked("about:srcdoc", main: false), "hx6 about:srcdoc allowed in a frame")
        check(URLDecisionPolicy.resolveTyped("rampart:fake").map { $0.scheme != "rampart" || blocked($0.absoluteString) } ?? true, "hx6 typed rampart: never loads")
        // Userinfo spoof and numeric hosts
        if case .warn(let r, _) = p.decide(url: URL(string: "https://www.paypal.com@evil.test/login")!, facts: safe) { check(r.contains(.suspiciousURL), "hx6 userinfo warns") } else { check(false, "hx6 userinfo warns") }
        for h in ["0x7f.0.0.1", "2130706433", "127.1", "0177.0.0.1", "1.2.3.4"] { check(URLDecisionPolicy.isRawIP(h), "hx6 numeric host is an IP: \(h)") }
        check(!URLDecisionPolicy.isRawIP("1password.com") && !URLDecisionPolicy.isRawIP("123.example"), "hx6 digit-led names are not IPs")
        check(!URLDecisionPolicy.isLoopback("127.evil.test"), "hx6 127.* name is not loopback")
        check(p.decide(url: URL(string: "http://127.evil.test/")!, facts: safe) != .allow, "hx6 127.* name still upgraded")

        // Address bar: no page text next to the local identity, no bidi tricks in the path
        let frag = DomainDisplay.make(url: URL(string: "about:blank#Your-Mac-is-infected-call-1-800")!)
        check(frag.domain == "New tab" && !frag.domain.contains("infected"), "hx6 about:blank#text shows New tab")
        let odd = DomainDisplay.make(url: URL(string: "about:security-alert")!)
        check(odd.identity != .local, "hx6 unknown about: page is not 'RamPart page'")
        let rlo = DomainDisplay.make(url: URL(string: "https://evil.test/invoice%E2%80%AEfdp.exe")!)
        check(!rlo.suffixPath.unicodeScalars.contains("\u{202E}"), "hx6 bidi override not rendered in path")
        let rloHost = DomainDisplay.sanitized("pay\u{202E}lap\u{200B}.com")
        check(rloHost == "paylap.com", "hx6 sanitizer strips bidi and zero-width")
        let ui = DomainDisplay.make(url: URL(string: "https://www.paypal.com@evil.test/")!)
        check(ui.domain == "evil.test" && !ui.prefix.contains("paypal"), "hx6 userinfo never shown as the host")
        let long = DomainDisplay.make(url: URL(string: "https://evil.test/" + String(repeating: "a", count: 2000))!)
        check(long.suffixPath.count <= 121, "hx6 long path truncated")
        let puny = DomainDisplay.make(url: URL(string: "https://xn--80ak6aa92e.com/")!)   // Cyrillic "apple" look-alike
        check(puny.isWarning && puny.asciiHost == "xn--80ak6aa92e.com", "hx6 whole-script IDN flagged with ASCII form")

        // Prompts
        check(PromptText.origin("") == "A page with no web address", "hx6 empty origin named")
        check(PromptText.origin("xn--80ak6aa92e.com").contains("(xn--80ak6aa92e.com)"), "hx6 punycode origin shows ASCII")
        check(!PromptText.origin("bank\u{202E}moc.evil.test").unicodeScalars.contains("\u{202E}"), "hx6 origin sanitized")
        check(PromptText.message(String(repeating: "x", count: 5000)).count <= 1001, "hx6 dialog text capped")
        check(PromptText.message("a\nb") == "a\nb", "hx6 dialog keeps newlines")

        // Downloads: names
        let names: [(String, (String) -> Bool)] = [
            ("../../../../Library/LaunchAgents/x.plist", { !$0.contains("/") }),
            ("..", { $0 != ".." && !$0.hasPrefix(".") }),
            ("invoice\u{202E}fdp.app", { !$0.unicodeScalars.contains("\u{202E}") && $0.hasSuffix(".app") }),
            ("a\u{0}b.sh", { !$0.unicodeScalars.contains("\u{0}") }),
            ("report.pdf   .", { !$0.hasSuffix(".") && !$0.hasSuffix(" ") }),
            ("-rf", { !$0.hasPrefix("-") }),
            ("C:\\evil\\x.exe", { !$0.contains("\\") }),
            (String(repeating: "\u{1F600}", count: 200) + ".dmg", { $0.utf8.count <= 240 && $0.hasSuffix(".dmg") }),
            (String(repeating: "a", count: 400), { $0.utf8.count <= 240 }),
        ]
        for (n, ok) in names { check(ok(DownloadPolicy.safeFilename(n)), "hx6 safe filename: \(n.prefix(30).debugDescription)") }
        for e in ["mobileconfig", "scptd", "prefPane", "html", "svg", "docm", "osax", "saver"] {
            check(DownloadClass.classify(filename: "x.\(e)", mimeType: nil).canExecute, "hx6 .\(e) treated as runnable")
        }
        check(DownloadClass.classify(filename: "x", mimeType: "text/html").canExecute, "hx6 html mime runnable")
        check(DownloadClass.classify(filename: "x", mimeType: "image/svg+xml").canExecute, "hx6 svg mime runnable")

        // Downloads: chain risk (10-hop look-alike chain ending in a .dmg)
        let look = URLFacts(brandMatch: "Apple")
        check(DownloadPolicy.isRiskySource(hops: [safe, safe, look, safe], redirectCount: 3), "hx6 look-alike hop makes source risky")
        check(DownloadPolicy.isRiskySource(hops: Array(repeating: safe, count: 10), redirectCount: 10), "hx6 long clean chain is risky")
        check(!DownloadPolicy.isRiskySource(hops: [safe, safe], redirectCount: 1), "hx6 short clean chain not risky")
        check(!DownloadPolicy.isRiskySource(hops: [URLFacts(brandMatch: "Apple", allowlisted: true)], redirectCount: 0), "hx6 allowlisted brand host not risky")
        let chainAction = DownloadPolicy().decide(class: DownloadClass.classify(filename: "Update.dmg", mimeType: nil), outcome: .clean,
                                                  fromRiskySite: DownloadPolicy.isRiskySource(hops: [safe] + Array(repeating: look, count: 9), redirectCount: 10))
        if case .holdForConfirmation = chainAction { check(true, "hx6 10-hop look-alike chain download held") } else { check(false, "hx6 10-hop look-alike chain download held") }
        check(DownloadPolicy.maxRedirects == 10 && DownloadPolicy.maxCleanRedirects < DownloadPolicy.maxRedirects, "hx6 redirect caps")

        // Vault: quarantine on a symlink is refused; release never overwrites or follows a planted symlink
        vaultChecks()

        // Content scripts: prototype-level, locked, realm-aware shim; observer-based report; throttled scan
        let shim = ContentScript.pageWorldShim, scan = ContentScript.scanner
        check(shim.contains("w.Clipboard.prototype") && shim.contains("Document.prototype") && shim.contains("configurable:false, writable:false"), "hx6 shim patches prototypes, locked")
        check(shim.contains("contentWindow") && shim.contains("sweep()"), "hx6 shim hardens child realms")
        check(!shim.contains("dispatchEvent"), "hx6 shim no longer signals through a cancellable event")
        check(scan.contains("attributeOldValue:true") && !scan.contains("addEventListener('rampart-clipboard-blocked'"), "hx6 scanner reads removal records")
        check(scan.contains("if (timer) return") && scan.contains("++n > 4000"), "hx6 scan throttled and bounded")
    }

    static func vaultChecks() {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("rampart-hx6-\(UUID().uuidString)")
        let vault = root.appendingPathComponent("vault/\(UUID().uuidString)"), dl = root.appendingPathComponent("Downloads")
        defer { try? fm.removeItem(at: root) }
        guard (try? fm.createDirectory(at: vault, withIntermediateDirectories: true)) != nil, (try? fm.createDirectory(at: dl, withIntermediateDirectories: true)) != nil else { check(false, "hx6 scratch dirs"); return }
        let file = vault.appendingPathComponent("setup.dmg")
        fm.createFile(atPath: file.path, contents: Data("inert".utf8), attributes: [.posixPermissions: 0o755])
        check(DownloadManager.applyQuarantine(file), "hx6 quarantine applied")
        let len = getxattr(file.path, "com.apple.quarantine", nil, 0, 0, 0)
        check(len > 0, "hx6 quarantine xattr present")
        let mode = ((try? fm.attributesOfItem(atPath: file.path))?[.posixPermissions] as? NSNumber)?.intValue ?? 0
        check(mode & 0o111 == 0, "hx6 exec bits stripped")
        // Symlink in the vault: refused, target untouched
        let target = root.appendingPathComponent("target.txt"); fm.createFile(atPath: target.path, contents: Data("t".utf8), attributes: [.posixPermissions: 0o644])
        let link = vault.appendingPathComponent("link.dmg"); try? fm.createSymbolicLink(at: link, withDestinationURL: target)
        check(!DownloadManager.applyQuarantine(link), "hx6 quarantine refuses a symlink")
        check(getxattr(target.path, "com.apple.quarantine", nil, 0, 0, 0) < 0, "hx6 symlink target not modified")
        // Planted symlink in Downloads under the same name: not followed, not replaced
        let victim = root.appendingPathComponent("victim.txt"); fm.createFile(atPath: victim.path, contents: Data("keep".utf8))
        try? fm.createSymbolicLink(at: dl.appendingPathComponent("setup.dmg"), withDestinationURL: victim)
        let out = DownloadManager.release(file, downloads: dl)
        check(out?.lastPathComponent == "setup 2.dmg", "hx6 release picks a fresh name")
        check((try? String(contentsOf: victim, encoding: .utf8)) == "keep", "hx6 planted symlink target untouched")
        if let out { check(getxattr(out.path, "com.apple.quarantine", nil, 0, 0, 0) > 0, "hx6 quarantine survives release") }
    }
}

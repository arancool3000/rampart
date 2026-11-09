import Foundation
import RampartShared
import RampartNetwork

// App Firewall, content filter / parental controls / SafeSearch, privacy report, email breach check (NetGuard).
// No network, no privileged tools: pf commands are dry runs into a temp directory.

extension SelfTest {
    static func netGuardChecks() {
        netGuardSchedules()
        netGuardSafeSearch()
        netGuardPolicy()
        netGuardDNSServer()
        netGuardFirewall()
        netGuardReport()
        netGuardBreach()
        netGuardProtocol()
    }

    private static var utc: Calendar { var c = Calendar(identifier: .gregorian); c.timeZone = TimeZone(identifier: "UTC")!; return c }
    /// 2026-11-09 is a Monday (weekday 2).
    private static func at(_ h: Int, _ m: Int, day: Int = 9) -> Date {
        utc.date(from: DateComponents(year: 2026, month: 11, day: day, hour: h, minute: m))!
    }

    static func netGuardSchedules() {
        let night = FilterWindow((22, 0), (7, 0))
        check(night.contains(at(23, 0), calendar: utc) && night.contains(at(6, 59), calendar: utc), "netguard: 22:00–07:00 covers 23:00 and 06:59")
        check(!night.contains(at(7, 0), calendar: utc) && !night.contains(at(12, 0), calendar: utc) && night.contains(at(22, 0), calendar: utc),
              "netguard: 22:00–07:00 excludes 07:00 and noon, includes 22:00")
        let lunch = FilterWindow((12, 0), (13, 0), weekdays: [2])
        check(lunch.contains(at(12, 30), calendar: utc) && !lunch.contains(at(12, 30, day: 10), calendar: utc), "netguard: weekday-limited window (Monday only)")
        // Sunday-night window (weekday 1) still applies early Monday morning.
        let sunNight = FilterWindow((22, 0), (7, 0), weekdays: [1])
        check(sunNight.contains(at(3, 0), calendar: utc) && !sunNight.contains(at(23, 0), calendar: utc), "netguard: overnight window belongs to the day it starts")
        check(!FilterWindow(start: 600, end: 600).contains(at(10, 0), calendar: utc), "netguard: empty window never matches")
        check(night.label.hasPrefix("22:00–07:00"), "netguard: window label")
        let r = CategoryRule(mode: .scheduled, windows: [night])
        check(r.isActive(at: at(23, 30), calendar: utc) && !r.isActive(at: at(15, 0), calendar: utc), "netguard: scheduled rule follows its window")
        check(CategoryRule(mode: .always).isActive(at: at(15, 0)) && !CategoryRule(mode: .off).isActive(at: at(15, 0)), "netguard: always/off modes")

        let d = ContentFilterConfig.defaults
        check(d.isActive(.malware) && d.isActive(.phishing) && !d.isActive(.social) && !d.isActive(.trackers), "netguard: defaults = malware + phishing only")
        var on = d; on.rules["social"] = CategoryRule(mode: .always); on.safeSearch = true
        check(ContentFilterConfig.weakens(old: on, new: d) && !ContentFilterConfig.weakens(old: d, new: on), "netguard: turning filters off weakens, on doesn't")
        var sched = on; sched.rules["social"] = CategoryRule(mode: .scheduled, windows: [night])
        check(ContentFilterConfig.weakens(old: on, new: sched), "netguard: always -> scheduled is weakening")
        check(on.wantedDownloads == [.social] && d.wantedDownloads.isEmpty, "netguard: only switched-on categories download lists")
        check(ContentCategory.social.source?.url.host == "cdn.jsdelivr.net" && BlocklistUpdater.hostAllowed(ContentCategory.adult.source!),
              "netguard: category lists come from the pinned HaGeZi mirror")
        check(BlocklistUpdater.categoryUpdater(for: on, directory: FileManager.default.temporaryDirectory).sources.map(\.id) == ["cat-social"],
              "netguard: category updater only has wanted lists")
    }

    static func netGuardSafeSearch() {
        check(SafeSearch.target(for: "www.google.com", youtubeStrict: false) == SafeSearch.googleTarget, "safesearch: www.google.com")
        check(SafeSearch.target(for: "google.co.uk.", youtubeStrict: false) == SafeSearch.googleTarget, "safesearch: google.co.uk")
        check(SafeSearch.target(for: "www.google.de", youtubeStrict: false) == SafeSearch.googleTarget, "safesearch: www.google.de")
        check(SafeSearch.target(for: "mail.google.com", youtubeStrict: false) == nil && SafeSearch.target(for: "google.evil.com", youtubeStrict: false) == nil,
              "safesearch: Gmail and lookalikes untouched")
        check(SafeSearch.target(for: "www.youtube.com", youtubeStrict: true) == SafeSearch.youtubeStrictTarget
              && SafeSearch.target(for: "m.youtube.com", youtubeStrict: false) == SafeSearch.youtubeModerateTarget, "safesearch: YouTube strict / moderate")
        check(SafeSearch.target(for: "www.bing.com", youtubeStrict: false) == SafeSearch.bingTarget
              && SafeSearch.target(for: "duckduckgo.com", youtubeStrict: false) == SafeSearch.duckTarget, "safesearch: Bing and DuckDuckGo")
    }

    static func netGuardPolicy() {
        let p = ContentFilterPolicy(config: .defaults, calendar: utc)
        let now = at(23, 0)
        check(p.decide(name: "www.facebook.com", type: 1, listVerdict: .allowed, now: now) == .useList, "policy: social off -> no block")
        var c = ContentFilterConfig.defaults
        c.rules["social"] = CategoryRule(mode: .scheduled, windows: [FilterWindow((22, 0), (7, 0))])
        p.config = c
        check(p.decide(name: "www.facebook.com", type: 1, listVerdict: .allowed, now: now) == .block(rule: "facebook.com", source: "category:social"),
              "policy: social blocked during 22:00–07:00 (built-in seed)")
        check(p.decide(name: "www.facebook.com", type: 1, listVerdict: .allowed, now: at(15, 0)) == .useList, "policy: social allowed outside the schedule")
        check(p.decide(name: "www.facebook.com", type: 1, listVerdict: .allowlisted(rule: "facebook.com"), now: now) == .useList, "policy: user allowlist wins")
        check(p.category(of: "connect.facebook.net") == nil && p.category(of: "x.instagram.com") == .social && p.category(of: "www.google-analytics.com") == .trackers,
              "policy: category lookup")
        check(p.decide(name: "evil.example", type: 1, listVerdict: .blocked(rule: "evil.example", source: "urlhaus"), now: now) == .useList,
              "policy: malware block kept while malware is on")
        c.rules["malware"] = CategoryRule(mode: .off); p.config = c
        check(p.decide(name: "evil.example", type: 1, listVerdict: .blocked(rule: "evil.example", source: "urlhaus"), now: now) == .pass,
              "policy: malware category off -> URLhaus block passes")
        check(p.decide(name: "phish.example", type: 1, listVerdict: .blocked(rule: "phish.example", source: "hagezi-tif"), now: now) == .useList,
              "policy: phishing still on")
        c.safeSearch = true; p.config = c
        check(p.decide(name: "www.google.com", type: 1, listVerdict: .allowed, now: now) == .rewrite(target: SafeSearch.googleTarget, rule: "safesearch"),
              "policy: SafeSearch rewrite")
        check(p.decide(name: SafeSearch.googleTarget, type: 1, listVerdict: .allowed, now: now) == .useList, "policy: rewrite target itself isn't rewritten")
        p.setFirewallDomains(["telemetry.badapp.example": "BadApp"])
        check(p.decide(name: "x.telemetry.badapp.example", type: 1, listVerdict: .allowed, now: now) == .block(rule: "telemetry.badapp.example", source: "app-firewall:BadApp"),
              "policy: app-firewall domain blocked")
        check(ContentFilterPolicy.category(forListSource: "category:adult") == .adult && ContentFilterPolicy.category(forListSource: "urlhaus") == .malware
              && ContentFilterPolicy.category(forListSource: "user") == nil, "policy: list source -> category")
    }

    /// The policy hook inside the real resolver (no upstream needed: blocked and non-address answers never leave the Mac).
    static func netGuardDNSServer() {
        var cfg = DNSFilterConfig(port: 0)
        cfg.upstreams = [URL(string: "https://127.0.0.1:9/dns-query")!]; cfg.upstreamTimeout = 1
        let srv = DNSFilterServer(config: cfg, blocklist: DomainBlocklist())
        var fc = ContentFilterConfig.defaults
        fc.rules["social"] = CategoryRule(mode: .always); fc.safeSearch = true
        srv.policy = ContentFilterPolicy(config: fc)
        func ask(_ name: String, _ type: UInt16) -> DNSMessage? {
            let sem = DispatchSemaphore(value: 0)
            final class Box: @unchecked Sendable { var d: Data? }
            let box = Box()
            srv.resolve(DNSWire.buildQuery(name: name, type: type)) { box.d = $0; sem.signal() }
            _ = sem.wait(timeout: .now() + 5)
            return box.d.flatMap { try? DNSMessage.parse($0) }
        }
        let fb = ask("www.tiktok.com", DNSType.a)
        check(fb?.answers.first?.value == "0.0.0.0", "dns policy: social category answered with the null address")
        let https = ask("www.google.com", DNSType.https)
        check(https != nil && https!.rcode == 0 && https!.answers.isEmpty, "dns policy: SafeSearch name gets empty HTTPS answer (no address hints)")
        check(srv.stats["blocked", default: 0] >= 0, "dns policy: stats readable")
    }

    static func netGuardFirewall() {
        let nt = AppFirewall.parseNettop(",bytes_in,bytes_out,\napsd.390,265610,311761,\nCom.Helper.v2.1234,10,20,\ngarbage\n")
        check(nt[390]?.0 == 265610 && nt[390]?.1 == 311761 && nt[1234]?.1 == 20 && nt.count == 2, "firewall: nettop CSV parse (dotted names)")
        check(AppFirewall.appKey(path: "/Applications/Google Chrome.app/Contents/Frameworks/X.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper", name: "x")
              == "/Applications/Google Chrome.app", "firewall: helpers roll up to the outer app")
        check(AppFirewall.appKey(path: "/tmp/tool", name: "tool") == "/tmp/tool" && AppFirewall.appKey(path: nil, name: "tool") == "tool", "firewall: bare executables")
        check(AppFirewall.displayName(key: "/Applications/Foo.app", fallback: "f") == "Foo", "firewall: display name")
        check(AppFirewall.protectedKey("/usr/sbin/mDNSResponder") != nil && AppFirewall.protectedKey("/Applications/RamPart.app") != nil
              && AppFirewall.protectedKey("/tmp/tool") == nil, "firewall: macOS and RamPart can't be blocked")
        check(AppFirewall.killCommands(local: "192.168.1.5", remote: "93.184.216.34").first?.arguments == ["-k", "192.168.1.5", "-k", "93.184.216.34"],
              "firewall: pfctl -k state kill by local + remote")
        check(AppFirewall.killCommands(local: "0.0.0.0", remote: "93.184.216.34").first?.arguments == ["-k", "0.0.0.0/0", "-k", "93.184.216.34"]
              && AppFirewall.killCommands(local: "1.2.3.4", remote: "192.168.1.1").isEmpty, "firewall: wildcard local, LAN remote refused")
        check(AppFirewall.isUntrusted(SigningInfo(status: .unsigned)) && AppFirewall.isUntrusted(SigningInfo(status: .adHoc))
              && !AppFirewall.isUntrusted(SigningInfo(status: .developerID)) && !AppFirewall.isUntrusted(nil), "firewall: untrusted = unsigned / ad-hoc / invalid")

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.netguard-\(getpid())")
        try? FileManager.default.removeItem(at: dir)
        defer { try? FileManager.default.removeItem(at: dir) }
        let fw = AppFirewall(stateURL: dir.appendingPathComponent("fw.json"), pfDirectory: dir.appendingPathComponent("pf"), dryRun: true) { path in
            path.hasPrefix("/tmp/") ? SigningInfo(status: .unsigned) : SigningInfo(status: .developerID, teamID: "TEAM123456")
        }
        func conn(_ pid: Int32, _ path: String, _ remote: String, _ port: UInt16 = 443, local: String = "192.168.1.20") -> NetworkConnection {
            NetworkConnection(pid: pid, processName: (path as NSString).lastPathComponent, processPath: path, proto: "tcp", localAddress: local,
                              localPort: 50000 + UInt16(pid), remoteAddress: remote, remotePort: port, state: "ESTABLISHED", source: "test")
        }
        fw.noteDNS(name: "api.badtool.example", answers: ["203.0.113.10", "not-an-ip"])
        fw.noteDNS(name: "cdn.shared.example", answers: ["198.51.100.7"])
        let first = fw.update(connections: [conn(10, "/Applications/Browser.app/Contents/MacOS/Browser", "198.51.100.7")])
        check(first.isEmpty, "firewall: first snapshot is the baseline (no prompts for apps already running)")
        let prompts = fw.update(connections: [conn(10, "/Applications/Browser.app/Contents/MacOS/Browser", "198.51.100.7"),
                                              conn(20, "/tmp/badtool", "203.0.113.10"), conn(20, "/tmp/badtool", "198.51.100.7"),
                                              conn(20, "/tmp/badtool", "192.168.1.1", 80)],
                                bytes: [20: (1000, 2000)])
        check(prompts.count == 1 && prompts.first?.name == "badtool" && prompts.first?.host == "api.badtool.example", "firewall: first connection by unsigned app prompts once")
        check(fw.update(connections: [conn(20, "/tmp/badtool", "203.0.113.10")]).isEmpty, "firewall: no second prompt for the same app")
        _ = fw.update(connections: [conn(10, "/Applications/Browser.app/Contents/MacOS/Browser", "198.51.100.7"),
                                    conn(20, "/tmp/badtool", "203.0.113.10"), conn(20, "/tmp/badtool", "198.51.100.7")], bytes: [20: (1000, 2000)])
        let st = fw.status()
        let bad = st.apps.first { $0.key == "/tmp/badtool" }
        check(bad?.untrusted == true && bad?.signerLabel == "Unsigned" && bad?.bytesOut == 2000 && st.apps.first?.key == "/tmp/badtool",
              "firewall: per-app traffic with signer and bytes, untrusted first")
        check(st.apps.first { $0.name == "Browser" }?.signerLabel == "Developer ID (TEAM123456)", "firewall: Developer ID signer label")
        check(bad?.endpoints.allSatisfy { $0.country == nil } == true && !st.enforcing, "firewall: no country (no offline DB), preview mode")

        let plan = fw.plan(key: "/tmp/badtool")
        check(plan.addresses == ["203.0.113.10"] && plan.sharedAddresses == ["198.51.100.7"] && plan.localAddresses == ["192.168.1.1"],
              "firewall: plan blocks own destinations, skips shared and LAN")
        check(plan.domains == ["api.badtool.example"] && plan.sharedDomains == ["cdn.shared.example"], "firewall: plan DNS names (shared names skipped)")
        var domains: [String: String] = [:]
        fw.onDomains = { domains = $0 }
        let after = try? fw.decide(key: "/tmp/badtool", decision: .block)
        check(after?.rules.first?.decision == .block && after?.prompts.isEmpty == true, "firewall: Block recorded, prompt cleared")
        check(domains == ["api.badtool.example": "badtool"], "firewall: blocked app's names go to the DNS filter")
        let table = (try? String(contentsOf: fw.pf.tableURL, encoding: .utf8)) ?? ""
        let anchor = (try? String(contentsOf: fw.pf.anchorURL, encoding: .utf8)) ?? ""
        check(table.contains("203.0.113.10") && !table.contains("198.51.100.7") && anchor.contains("rampart_appfw"),
              "firewall: pf table written with only the app's own destinations")
        check(after?.lastCommands.contains { $0.contains("-k") && $0.contains("203.0.113.10") && $0.hasPrefix("[dry run]") } == true,
              "firewall: open connection killed by state (dry run)")
        check(after?.lastCommands.contains { $0.contains("251.RampartFirewall") } == true, "firewall: own pf anchor, separate from web protection")
        check(after?.rules.first?.notes.contains { $0.contains("198.51.100.7") } == true, "firewall: rule explains what wasn't blocked")
        // New destination appears for a blocked app: added on the next tick (best effort).
        _ = fw.update(connections: [conn(20, "/tmp/badtool", "203.0.113.99")])
        check(fw.status().rules.first?.blockedAddresses.contains("203.0.113.99") == true, "firewall: blocked app's new server is added")
        var refused = false
        do { try fw.decide(key: "/usr/sbin/mDNSResponder", decision: .block) } catch { refused = true }
        check(refused, "firewall: refuses to block macOS components")
        _ = try? fw.decide(key: "/tmp/badtool", decision: .allow)
        check(domains.isEmpty && fw.status().rules.first?.decision == .allow, "firewall: Allow lifts DNS + pf blocks")
        _ = try? fw.decide(key: "/tmp/other", decision: .askLater)
        check(fw.status().rules.contains { $0.key == "/tmp/other" && $0.decision == .askLater && $0.until != nil }, "firewall: Ask later snoozes 24 h")
        let reloaded = AppFirewall(stateURL: dir.appendingPathComponent("fw.json"), pfDirectory: dir.appendingPathComponent("pf"), dryRun: true) { _ in nil }
        check(reloaded.status().rules.count == 2, "firewall: rules persist")
        check(AppFirewallStatus.limitation.contains("Network Extension") && AppFirewallStatus.limitation.contains("changes servers"),
              "firewall: UI states the destination-only limit")
    }

    static func netGuardReport() {
        check(TrackerCompanies.company(for: "stats.g.doubleclick.net") == "Google" && TrackerCompanies.company(for: "graph.facebook.com") == "Meta"
              && TrackerCompanies.company(for: "example.org") == nil, "report: tracker owner lookup")
        let l = PrivacyLedger(url: nil)
        let now = Date()
        for _ in 0..<3 { l.record(name: "www.google-analytics.com", blocked: true, isTracker: true, blockedCategory: .trackers, date: now) }
        l.record(name: "pixel.facebook.com", blocked: false, isTracker: true, blockedCategory: nil, date: now)
        l.record(name: "casino.example", blocked: true, isTracker: false, blockedCategory: .gambling, date: now)
        l.record(name: "www.google.com", blocked: false, isTracker: false, blockedCategory: nil, safeSearch: true, date: now)
        l.recordApp("Weather Widget", date: now)
        let r = l.report(days: 7, trackerBlockingOn: true, now: now)
        check(r.trackersBlocked == 3 && r.trackersSeen == 1 && r.trackersByDay.last == 3 && r.trackersByDay.count == 7, "report: tracker counts by day")
        check(r.topCompanies.first?.name == "Google" && r.categoryBlocks.contains { $0.name == "Trackers & ads" } && r.categoryBlocks.contains { $0.name == "Gambling" },
              "report: companies and category blocks")
        check(r.safeSearchRewrites == 1 && r.appsContactingTrackers.first?.name == "Weather Widget" && r.note == nil, "report: SafeSearch + apps")
        check(l.report(days: 7, trackerBlockingOn: false, now: now).note?.contains("off") == true, "report: honest note when tracker blocking is off")
        let p = ContentFilterPolicy()
        let cls = TrackerClassifier.classify(hosts: ["www.google-analytics.com", "cdn.example.com", "news.example", "connect.facebook.net", "www.googletagmanager.com"],
                                             pageHost: "news.example", policy: p)
        check(cls.count == 2 && cls.companies == ["Google"], "report: per-site tracker count for the extension")
    }

    static func netGuardBreach() {
        check(HIBPEmailClient.isValidEmail("a.b+c@example.co.uk") && !HIBPEmailClient.isValidEmail("nope") && !HIBPEmailClient.isValidEmail("a@b@c.com")
              && !HIBPEmailClient.isValidEmail("a@example.com/../x"), "breach: email validation")
        let c = HIBPEmailClient(apiKey: "0123456789abcdef0123456789abcdef")
        let req = try? c.request(for: "Me+tag@Example.com")
        check(req?.value(forHTTPHeaderField: "hibp-api-key") == "0123456789abcdef0123456789abcdef" && req?.value(forHTTPHeaderField: "User-Agent") != nil
              && req?.url?.absoluteString == "https://haveibeenpwned.com/api/v3/breachedaccount/me+tag@example.com?truncateResponse=false",
              "breach: HIBP v3 request with the user's key")
        var noKey = false
        do { _ = try HIBPEmailClient(apiKey: "  ").request(for: "a@b.com") } catch let e as EmailBreachError { noKey = e == .noKey } catch {}
        check(noKey, "breach: no key -> no request (email API needs the user's own paid key)")
        let json = #"[{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":152445165,"DataClasses":["Email addresses","Passwords"],"IsVerified":true},{"Name":"Old","BreachDate":"2010-01-01"}]"#
        if case .success(let b) = HIBPEmailClient.interpret(status: 200, data: Data(json.utf8), retryAfter: nil) {
            check(b.count == 2 && b.first?.name == "Adobe" && b.first?.dataClasses.contains("Passwords") == true && b.last?.title == "Old", "breach: parse HIBP JSON (newest first, lenient)")
        } else { check(false, "breach: parse HIBP JSON") }
        if case .success(let b) = HIBPEmailClient.interpret(status: 404, data: Data(), retryAfter: nil) { check(b.isEmpty, "breach: 404 = not breached") } else { check(false, "breach: 404") }
        if case .failure(let e) = HIBPEmailClient.interpret(status: 401, data: Data(), retryAfter: nil) { check(e == .badKey, "breach: 401 = bad key") } else { check(false, "breach: 401") }
        if case .failure(let e) = HIBPEmailClient.interpret(status: 429, data: Data(), retryAfter: "7") { check(e == .rateLimited(retryAfter: 7), "breach: 429 rate limit") } else { check(false, "breach: 429") }
        let old = EmailBreachResult(email: "a@b.com", checked: Date(timeIntervalSinceNow: -90_000), breaches: [EmailBreach(name: "Adobe", title: "Adobe", domain: "", breachDate: "", pwnCount: 1, dataClasses: [], isVerified: true)])
        var new = old; new.checked = Date()
        new.breaches.append(EmailBreach(name: "New", title: "New", domain: "", breachDate: "", pwnCount: 1, dataClasses: [], isVerified: true))
        check(HIBPEmailClient.newBreaches(old: old, new: new).map(\.name) == ["New"], "breach: only new breaches notify")
        check(HIBPEmailClient.isDue(old) && !HIBPEmailClient.isDue(new) && HIBPEmailClient.isDue(nil), "breach: daily schedule")
        check(HIBPEmailClient.caveat.contains("paid API key") && HIBPEmailClient.caveat.contains("your own key"), "breach: UI states the paid-key caveat")
    }

    static func netGuardProtocol() {
        let read = NetGuardCommand(op: .status), block = NetGuardCommand(op: .firewallDecide, key: "/tmp/x", decision: .block)
        let later = NetGuardCommand(op: .firewallDecide, key: "/tmp/x", decision: .askLater), cls = NetGuardCommand(op: .classifyHosts, hosts: ["a.com"])
        check(NetGuardCommand.access(of: read.encoded()) == .read && NetGuardCommand.access(of: block.encoded()) == .change
              && NetGuardCommand.access(of: later.encoded()) == .read && NetGuardCommand.access(of: cls.encoded()) == .anyLocal
              && NetGuardCommand.access(of: Data("junk".utf8)) == .change, "protocol: access levels (undecodable = strictest)")
        check(IPCAuthz.level(.netGuard(read.encoded())) == .sessionUser && IPCAuthz.level(.netGuard(block.encoded()), settingsWeakens: false) == .adminClient
              && IPCAuthz.level(.netGuard(NetGuardCommand(op: .filterSet, config: .defaults).encoded()), settingsWeakens: true) == .adminClientWeakening,
              "protocol: IPC authorization for netGuard")
        let rt = try? JSONDecoder.rampart.decode(IPCRequest.self, from: JSONEncoder.rampart.encode(IPCRequest.netGuard(block.encoded())))
        if case .netGuard(let d)? = rt, let c = try? JSONDecoder.rampart.decode(NetGuardCommand.self, from: d) {
            check(c.op == .firewallDecide && c.decision == .block && c.key == "/tmp/x", "protocol: IPC round trip")
        } else { check(false, "protocol: IPC round trip") }
    }
}

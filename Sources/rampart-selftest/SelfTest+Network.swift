import Foundation
import RampartShared
import RampartNetwork

// Owned by the network build agent. Add checks with check(cond, "name").

/// Runs an async operation to completion from synchronous self-test code.
fileprivate final class NetAwaitBox<T>: @unchecked Sendable { var value: T? }
fileprivate func netAwait<T>(_ op: @escaping @Sendable () async -> T) -> T {
    let box = NetAwaitBox<T>(), sem = DispatchSemaphore(value: 0)
    Task.detached { box.value = await op(); sem.signal() }
    sem.wait()
    return box.value!
}

fileprivate func netRun(_ path: String, _ args: [String]) -> String {
    let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = args
    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
    guard (try? p.run()) != nil else { return "" }
    let d = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return String(decoding: d, as: UTF8.self)
}

extension SelfTest {
    static func network() {
        networkBlocklist()
        networkDNSWire()
        networkServer()
        networkPF()
        networkSwitcher()
        networkWiFi()
        networkUpdater()
        networkPwned()
    }

    // MARK: Blocklist formats

    static func networkBlocklist() {
        let hosts = """
        # StevenBlack-style hosts
        127.0.0.1 localhost
        ::1 localhost
        0.0.0.0 0.0.0.0
        0.0.0.0 ads.hosts-fixture.example   # trailing comment
        127.0.0.1\tmalware.hosts-fixture.example
        """
        let adblock = """
        ! Title: fixture
        [Adblock Plus]
        ||tracker.adblock-fixture.example^
        ||evil.adblock-fixture.example^$important
        ||cosmetic.adblock-fixture.example^$third-party
        @@||good.tracker.adblock-fixture.example^
        example.com##.banner
        """
        let plain = """
        # plain / wildcard
        phish.plain-fixture.example
        *.wild.plain-fixture.example
        NOT A DOMAIN
        UPPER.Plain-Fixture.Example.
        """
        let bl = DomainBlocklist()
        let s1 = bl.load(text: hosts, format: .hosts, source: "hosts")
        let s2 = bl.load(text: adblock, format: .auto, source: "adblock")
        let s3 = bl.load(text: plain, format: .plain, source: "plain")
        check(s1.added == 2, "hosts format: 2 domains (localhost, 0.0.0.0 skipped)")
        check(s2.added == 2 && s2.allowAdded == 1, "adblock format: 2 blocks + 1 @@ exception")
        check(s3.added == 3, "plain format: 3 domains")
        check(bl.isBlocked("ads.hosts-fixture.example"), "hosts entry blocked")
        check(bl.isBlocked("deep.sub.malware.hosts-fixture.example"), "hosts subdomain blocked (suffix)")
        check(!bl.isBlocked("hosts-fixture.example"), "parent of blocked name not blocked")
        check(!bl.isBlocked("localhost"), "localhost never blocked")
        check(bl.isBlocked("x.tracker.adblock-fixture.example"), "adblock ||domain^ suffix")
        check(bl.isBlocked("evil.adblock-fixture.example"), "adblock $important accepted")
        check(!bl.isBlocked("cosmetic.adblock-fixture.example"), "adblock rule with options skipped")
        check(bl.verdict(for: "good.tracker.adblock-fixture.example") == .allowlisted(rule: "good.tracker.adblock-fixture.example"),
              "adblock @@ allow overrides block")
        check(bl.isBlocked("a.wild.plain-fixture.example") && bl.isBlocked("wild.plain-fixture.example"), "plain *.wildcard")
        check(bl.isBlocked("upper.plain-fixture.example"), "plain lowercased + trailing dot")
        if case .blocked(let rule, let src) = bl.verdict(for: "PHISH.plain-fixture.example.") {
            check(rule == "phish.plain-fixture.example" && src == "plain", "verdict reports rule and source")
        } else { check(false, "verdict reports rule and source") }
        bl.allow("hosts-fixture.example")
        check(!bl.isBlocked("ads.hosts-fixture.example"), "user allowlist overrides subdomain block")
    }

    // MARK: DNS wire format

    static func networkDNSWire() {
        let q = DNSWire.buildQuery(name: "Www.Example.COM.", type: DNSType.aaaa, id: 0xBEEF)
        let pq = try? DNSMessage.parse(q)
        check(pq?.id == 0xBEEF && pq?.recursionDesired == true && pq?.isResponse == false, "query header round-trip")
        check(pq?.questions.first == DNSQuestion(name: "www.example.com", type: DNSType.aaaa), "query question round-trip")
        check(pq.map { $0.serialize() == q } ?? false, "serialize(parse(x)) == x")

        let aq = try! DNSMessage.parse(DNSWire.buildQuery(name: "blocked.example", type: DNSType.a, id: 7))
        let br = try? DNSMessage.parse(DNSWire.buildBlockedResponse(for: aq, mode: .nullAddress, ttl: 60))
        check(br?.isResponse == true && br?.id == 7 && br?.rcode == 0, "blocked response header")
        check(br?.answers.first?.value == "0.0.0.0" && br?.answers.first?.ttl == 60, "blocked A -> 0.0.0.0 TTL 60")
        let nx = try? DNSMessage.parse(DNSWire.buildBlockedResponse(for: aq, mode: .nxdomain, ttl: 60))
        check(nx?.rcode == DNSRCode.nxDomain && nx?.answers.isEmpty == true, "nxdomain mode")

        // Hand-built upstream answer with compression pointers: CNAME then A.
        var r: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]
        r += DNSWire.encodeName("www.example.com") + [0, 1, 0, 1]                      // question at offset 12
        r += [0xC0, 12, 0, 5, 0, 1, 0, 0, 0x0E, 0x10, 0, 6] + [3] + Array("cdn".utf8) + [0xC0, 16] // CNAME -> cdn.example.com
        let cnameTarget = 12 + 17 + 4 + 12                                               // offset of "cdn" label
        r += [0xC0, UInt8(cnameTarget), 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 93, 184, 215, 14]
        let m = try? DNSMessage.parse(Data(r))
        check(m?.answers.count == 2, "compressed response parsed")
        check(m?.answers.first?.value == "cdn.example.com", "CNAME target decompressed")
        check(m?.answers.last?.name == "cdn.example.com" && m?.answers.last?.value == "93.184.215.14", "A via pointer")
        // Pointer loop must not hang.
        let loop: [UInt8] = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1]
        check((try? DNSMessage.parse(Data(loop))) == nil, "pointer loop rejected")
        check((try? DNSMessage.parse(Data([1, 2, 3]))) == nil, "short packet rejected")

        // Cache: TTL = min answer TTL, decremented on the way out, ID rewritten.
        let cache = DNSResponseCache()
        let qn = DNSQuestion(name: "www.example.com", type: DNSType.a)
        let t0 = Date()
        cache.store(Data(r), for: qn, now: t0)
        let hit = cache.lookup(qn, id: 0x9999, now: t0.addingTimeInterval(10)).flatMap { try? DNSMessage.parse($0) }
        check(hit?.id == 0x9999, "cache hit rewrites ID")
        check(hit?.answers.last?.ttl == 20 && hit?.answers.first?.ttl == 3590, "cache decrements TTLs")
        check(cache.lookup(qn, id: 1, now: t0.addingTimeInterval(31)) == nil, "cache expires at min TTL")
    }

    // MARK: Live server + dig

    static func networkServer() {
        let bl = DomainBlocklist()
        bl.add("blocked.rampart-selftest.example", source: "selftest")
        let logBox = LogCounter()
        // Port 0 = ephemeral high port; never 53 and never a system DNS change.
        let server = DNSFilterServer(config: DNSFilterConfig(listenAddress: "127.0.0.1", port: 0), blocklist: bl)
        server.queryLog = { logBox.add($0) }
        do { try server.start() } catch { check(false, "DNS server start: \(error)"); return }
        defer { server.stop() }
        let port = String(server.boundPort)
        check(server.boundPort > 1024, "server bound high port \(port)")

        func dig(_ args: [String]) -> String {
            netRun("/usr/bin/dig", ["@127.0.0.1", "-p", port, "+time=6", "+tries=1"] + args)
        }
        let a = dig(["+short", "blocked.rampart-selftest.example", "A"]).trimmingCharacters(in: .whitespacesAndNewlines)
        check(a == "0.0.0.0", "dig UDP blocked A -> 0.0.0.0 (got '\(a)')")
        let sub = dig(["+short", "x.y.blocked.rampart-selftest.example", "AAAA"]).trimmingCharacters(in: .whitespacesAndNewlines)
        check(sub == "::", "dig UDP blocked subdomain AAAA -> :: (got '\(sub)')")
        let tcp = dig(["+tcp", "+short", "blocked.rampart-selftest.example", "A"]).trimmingCharacters(in: .whitespacesAndNewlines)
        check(tcp == "0.0.0.0", "dig TCP blocked A -> 0.0.0.0 (got '\(tcp)')")
        let canary = dig(["use-application-dns.net", "A"])
        check(canary.contains("status: NXDOMAIN"), "use-application-dns.net -> NXDOMAIN")

        let ex = dig(["example.com", "A"])
        let exShort = dig(["+short", "example.com", "A"]).split(whereSeparator: \.isNewline).map(String.init)
        if ex.contains("status: NOERROR"), !exShort.isEmpty {
            print("  example.com via DoH: \(exShort.joined(separator: ", "))")
            check(exShort.allSatisfy { $0 != "0.0.0.0" }, "example.com real answer")
            let again = dig(["example.com", "A"])
            check(again.contains("status: NOERROR"), "example.com second query (cache)")
        } else {
            let status = ex.components(separatedBy: "status: ").dropFirst().first?.prefix(while: { $0 != "," }) ?? "no reply"
            print("  NOTE example.com upstream not reachable (status \(status)); DoH may be blocked by the network filter. Tolerated.")
        }

        // ConnectionMonitor: hold a TCP connection to our own server so at least one exists.
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        var sin = sockaddr_in(); sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sin.sin_family = sa_family_t(AF_INET); sin.sin_port = server.boundPort.bigEndian
        inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr)
        let rc = withUnsafePointer(to: &sin) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        check(rc == 0, "self TCP connect")
        let mon = ConnectionMonitor()
        let conns = mon.snapshot()
        print("  ConnectionMonitor: \(conns.count) connections, \(Set(conns.map(\.pid)).count) processes (\(conns.first?.source ?? "-"))")
        for c in conns.prefix(3) { print("    \(c.processName)[\(c.pid)] \(c.proto) \(c.remoteAddress):\(c.remotePort) \(c.state ?? "")") }
        check(!conns.isEmpty, "ConnectionMonitor lists at least one connection")
        check(conns.contains { $0.pid == getpid() && $0.remotePort == server.boundPort && $0.state == "ESTABLISHED" },
              "ConnectionMonitor sees own connection with process + remote endpoint")
        let lsof = mon.lsofSnapshot()
        check(lsof.contains { $0.pid == getpid() && $0.remotePort == server.boundPort }, "lsof fallback sees own connection")
        close(fd)
        let parsed = ConnectionMonitor.parseLsof("p42\ncSafari\nf7\nPTCP\nn[fe80::1]:5000->[2606:4700::1]:443\nTST=ESTABLISHED\nf8\nPUDP\nn*:5353\n")
        check(parsed.count == 2 && parsed[0].remoteAddress == "2606:4700::1" && parsed[0].remotePort == 443
              && parsed[0].state == "ESTABLISHED" && parsed[1].localPort == 5353 && !parsed[1].hasRemote, "lsof -F parser")

        Thread.sleep(forTimeInterval: 0.2)
        let verdicts = logBox.verdicts
        check(verdicts.filter { $0 == .blocked }.count >= 3, "query log saw blocked queries")
        check(verdicts.contains(.canary), "query log saw canary")
        let ev = logBox.first?.securityEvent
        check(ev?.kind == .dnsQuery && ev?.source == "dns", "log entry -> SecurityEvent")
        print("  server stats: \(server.stats)")
    }

    final class LogCounter: @unchecked Sendable {
        private let lock = NSLock()
        private var entries: [DNSQueryLogEntry] = []
        func add(_ e: DNSQueryLogEntry) { lock.lock(); entries.append(e); lock.unlock() }
        var verdicts: [DNSQueryLogEntry.Verdict] { lock.lock(); defer { lock.unlock() }; return entries.map(\.verdict) }
        var first: DNSQueryLogEntry? { lock.lock(); defer { lock.unlock() }; return entries.first }
    }

    // MARK: pf

    static func networkPF() {
        let ips = PFManager.parseIPList("""
        ; Spamhaus-ish
        {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
        # Feodo
        185.220.101.5
        10.0.0.1
        192.168.1.0/24
        0.0.0.0/0
        2001:db8::/32
        fe80::1
        185.220.101.5
        """)
        check(ips == ["1.10.16.0/20", "185.220.101.5", "2001:db8::/32"], "pf IP parse strips private/dupes (\(ips))")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.pf-\(getpid())")
        let pf = PFManager(directory: dir, dryRun: true, blockDoT: true)
        check(pf.anchorRules().contains("table <rampart_block> persist file") && pf.anchorRules().contains("port 853"), "pf anchor rules")
        let res = try? pf.apply(ips: ips)
        check(res?.allSatisfy(\.dryRun) == true && res?.count == 3, "pf apply is dry-run only")
        check((try? String(contentsOf: pf.tableURL, encoding: .utf8))?.contains("185.220.101.5") == true, "pf table file written")
        check(PFManager.parseToken("No ALTQ support in kernel\npf enabled\nToken : 12345678901\n") == "12345678901", "pf token parse")
        check(pf.loadCommands().first?.description.contains("-a com.apple/250.Rampart -f") == true, "pf load command")
        try? FileManager.default.removeItem(at: dir)
    }

    // MARK: DNS switch (read-only + dry-run)

    static func networkSwitcher() {
        let svcs = DNSSwitcher.parseServices("""
        An asterisk (*) denotes that a network service is disabled.
        Wi-Fi
        *Thunderbolt Bridge
        USB 10/100/1000 LAN
        """)
        check(svcs.map(\.name) == ["Wi-Fi", "Thunderbolt Bridge", "USB 10/100/1000 LAN"] && svcs[1].enabled == false, "networksetup service parse")
        check(DNSSwitcher.parseDNSServers("There aren't any DNS Servers set on Wi-Fi.").isEmpty, "no DNS servers parse")
        check(DNSSwitcher.parseDNSServers("1.1.1.1\n2606:4700:4700::1111\n") == ["1.1.1.1", "2606:4700:4700::1111"], "DNS servers parse")
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.dns-\(getpid()).json")
        let sw = DNSSwitcher(snapshotURL: tmp, dryRun: true)
        let snap = [DNSSwitcher.ServiceDNS(service: "Wi-Fi", enabled: true, servers: []),
                    DNSSwitcher.ServiceDNS(service: "USB LAN", enabled: true, servers: ["9.9.9.9", "127.0.0.1"]),
                    DNSSwitcher.ServiceDNS(service: "Off", enabled: false, servers: [])]
        let apply = sw.applyCommands(for: snap).map(\.description)
        check(apply.first == "/usr/sbin/networksetup -setdnsservers Wi-Fi 127.0.0.1 ::1", "apply command (\(apply.first ?? ""))")
        check(apply.contains("/usr/sbin/networksetup -setdnsservers 'USB LAN' 127.0.0.1 ::1") && apply.count == 4, "apply skips disabled, flushes")
        let restore = sw.restoreCommands(for: snap).map(\.description)
        check(restore.prefix(2) == ["/usr/sbin/networksetup -setdnsservers Wi-Fi empty",
                                    "/usr/sbin/networksetup -setdnsservers 'USB LAN' 9.9.9.9"], "restore commands (\(restore))")
        let current = sw.currentConfiguration()
        print("  network services: " + current.map { "\($0.service)=\($0.servers.isEmpty ? "DHCP" : $0.servers.joined(separator: ","))" }.joined(separator: "; "))
        let dry = (try? sw.apply()) ?? []
        check(dry.allSatisfy(\.dryRun) && !FileManager.default.fileExists(atPath: tmp.path), "apply dry-run: no commands run, no snapshot")
    }

    // MARK: Wi-Fi

    static func networkWiFi() {
        let arp = WiFiGuard.parseARP("""
        ? (192.168.1.1) at 0:1b:2c:3d:4e:5f on en0 ifscope [ethernet]
        ? (192.168.1.20) at (incomplete) on en0 ifscope [ethernet]
        ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
        """)
        check(arp == [WiFiGuard.ARPEntry(ip: "192.168.1.1", mac: "00:1b:2c:3d:4e:5f", interface: "en0")], "arp -an parse")
        check(WiFiGuard.parseDefaultGateway("   route to: default\n    gateway: 10.0.0.1\n  interface: en0\n") == "10.0.0.1", "route gateway parse")
        let g = WiFiGuard(stateURL: nil)
        check(g.evaluate(gateway: "192.168.1.1", arp: arp).isEmpty, "first sighting learns gateway MAC")
        let spoofed = [WiFiGuard.ARPEntry(ip: "192.168.1.1", mac: "66:66:66:66:66:66", interface: "en0"),
                       WiFiGuard.ARPEntry(ip: "192.168.1.66", mac: "66:66:66:66:66:66", interface: "en0")]
        let alerts = g.evaluate(gateway: "192.168.1.1", arp: spoofed).map(\.kind)
        check(alerts.contains(.gatewayMACChanged) && alerts.contains(.duplicateMAC), "gateway MAC change + duplicate detected")
        if let s = g.currentStatus() {
            print("  Wi-Fi: \(s.interface ?? "-") power=\(s.poweredOn) security=\(s.security) weak=\(s.isWeak) ssid=\(s.ssid ?? "(needs Location)")")
        } else { print("  Wi-Fi: no interface") }
        print("  gateway: \(g.defaultGateway() ?? "-"), arp entries: \(g.arpTable().count)")
    }

    // MARK: List updater

    static func networkUpdater() {
        let src = BlocklistUpdater.Source(id: "fixture", url: URL(string: "https://example.invalid/list.txt")!,
                                          format: .plain, minimumEntries: 3, refreshInterval: 3600)
        let html = Data("<!DOCTYPE html><html><head><title>Securly</title></head><body>Login</body></html>".utf8)
        let good = Data("a.example\nb.example\nc.example\nd.example\n".utf8)
        let isRejected: (Result<Int, BlocklistUpdater.Rejection>) -> Bool = { if case .failure = $0 { return true }; return false }
        check(isRejected(BlocklistUpdater.validate(data: html, statusCode: 200, contentType: "text/plain", source: src)), "updater rejects HTML body")
        check(isRejected(BlocklistUpdater.validate(data: good, statusCode: 200, contentType: "text/html; charset=utf-8", source: src)), "updater rejects text/html")
        check(isRejected(BlocklistUpdater.validate(data: good, statusCode: 403, contentType: "text/plain", source: src)), "updater rejects non-200")
        check(isRejected(BlocklistUpdater.validate(data: Data("a.example\n".utf8), statusCode: 200, contentType: "text/plain", source: src)), "updater rejects short list")
        if case .success(let n) = BlocklistUpdater.validate(data: good, statusCode: 200, contentType: "text/plain", source: src) {
            check(n == 4, "updater accepts valid list")
        } else { check(false, "updater accepts valid list") }

        // Live fetch into a temp dir (reported, not asserted: the network filter may block these hosts).
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.lists-\(getpid())")
        let up = BlocklistUpdater(directory: dir, timeout: 20)
        let outcomes = netAwait { await up.updateAll(force: true) }
        for (k, v) in outcomes.sorted(by: { $0.key < $1.key }) { print("  live list \(k): \(v)") }
        if outcomes.values.contains(where: \.isSuccess) {
            let bl = up.buildBlocklist()
            check(bl.blockedCount > 0, "live lists load into blocklist (\(bl.blockedCount) domains)")
        }
        try? FileManager.default.removeItem(at: dir)
    }

    // MARK: Pwned Passwords

    static func networkPwned() {
        check(PwnedPasswords.sha1Hex("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", "SHA-1 of 'password'")
        check(PwnedPasswords.count(in: "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n0000000000000000000000000000000000A:0\r\n",
                                   suffix: "1e4c9b93f3f0682250b6cf8331b7ee68fd8") == 42, "range body parse")
        let api = PwnedPasswords()
        let r: Result<Int, Error> = netAwait {
            do { return .success(try await api.breachCount(for: "password")) } catch { return .failure(error) }
        }
        switch r {
        case .success(let n):
            print("  'password' seen \(n) times")
            check(n > 0, "PwnedPasswords: 'password' is pwned")
        case .failure(let e):
            print("  NOTE Pwned Passwords API unreachable: \(e). Tolerated.")
        }
    }
}

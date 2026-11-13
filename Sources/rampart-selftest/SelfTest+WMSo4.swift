import Foundation
import RampartShared
import RampartNetwork

/// Mock DoH upstream for o4: answers from a closure over the decoded query, optionally after a delay, and records
/// every query body it saw. No real network.
final class O4MockDoH: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var answer: ((DNSMessage) -> DNSMessage?)?
    nonisolated(unsafe) static var delay: TimeInterval = 0
    nonisolated(unsafe) static var seen: [Data] = []
    static let lock = NSLock()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    static func body(_ r: URLRequest) -> Data {
        if let b = r.httpBody { return b }
        guard let s = r.httpBodyStream else { return Data() }
        s.open(); defer { s.close() }
        var out = Data(); var buf = [UInt8](repeating: 0, count: 4096)
        while s.hasBytesAvailable { let n = s.read(&buf, maxLength: buf.count); if n <= 0 { break }; out.append(buf, count: n) }
        return out
    }
    override func startLoading() {
        let body = Self.body(request)
        Self.lock.lock(); Self.seen.append(body); let f = Self.answer; let d = Self.delay; Self.lock.unlock()
        let go = { [self] in
            guard let q = try? DNSMessage.parse(body), let r = f?(q) else {
                client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost)); return
            }
            let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": "application/dns-message"])!
            client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: r.serialize())
            client?.urlProtocolDidFinishLoading(self)
        }
        if d > 0 { DispatchQueue.global().asyncAfter(deadline: .now() + d, execute: go) } else { go() }
    }
    override func stopLoading() {}
}

// o4 ("world's most secure" pass): DNS filter, rebinding, EDNS, upstream query hygiene, flood isolation, TCP
// slow-loris, IPv6 loopback claim, pf injection fuzz, App Firewall collateral blocking.
// Fixtures + loopback sockets on ephemeral ports only: no system DNS change, no pfctl, no real network.
extension SelfTest {
    static func wmsO4Checks() {
        o4Parser()
        o4EDNSAndUpstreamQuery()
        o4Rebinding()
        o4ServerEndToEnd()
        o4Flood()
        o4TCPSlowLoris()
        o4IPv6Loopback()
        o4PF()
        o4Firewall()
    }

    // MARK: helpers

    static func o4Response(_ q: DNSMessage, _ answers: [DNSResourceRecord], additionals: [DNSResourceRecord] = []) -> DNSMessage {
        var r = DNSMessage(id: q.id, flags: 0x8180)
        r.questions = q.questions; r.answers = answers; r.additionals = additionals
        return r
    }
    static func o4A(_ name: String, _ ip: String) -> DNSResourceRecord {
        var v4 = in_addr(); var v6 = in6_addr()
        if inet_pton(AF_INET, ip, &v4) == 1 {
            return DNSResourceRecord(name: name, type: DNSType.a, ttl: 300, rdata: withUnsafeBytes(of: &v4) { Data($0) }, value: ip)
        }
        _ = inet_pton(AF_INET6, ip, &v6)
        return DNSResourceRecord(name: name, type: DNSType.aaaa, ttl: 300, rdata: withUnsafeBytes(of: &v6) { Data($0) }, value: ip)
    }
    static func o4Ask(_ srv: DNSFilterServer, _ packet: Data, timeout: TimeInterval = 5) -> DNSMessage? {
        final class Box: @unchecked Sendable { var d: Data? }
        let box = Box(), sem = DispatchSemaphore(value: 0)
        srv.resolve(packet) { box.d = $0; sem.signal() }
        _ = sem.wait(timeout: .now() + timeout)
        return box.d.flatMap { try? DNSMessage.parse($0) }
    }
    static func o4Query(_ name: String, _ type: UInt16, flags: UInt16 = 0x0100, additionals: [DNSResourceRecord] = [],
                        answers: [DNSResourceRecord] = []) -> Data {
        var m = DNSMessage(id: 0x4242, flags: flags)
        m.questions = [DNSQuestion(name: name, type: type)]; m.additionals = additionals; m.answers = answers
        return m.serialize()
    }
    static func o4Server(answer: @escaping (DNSMessage) -> DNSMessage?, delay: TimeInterval = 0,
                         blocklist: DomainBlocklist = DomainBlocklist()) -> DNSFilterServer {
        O4MockDoH.lock.lock(); O4MockDoH.answer = answer; O4MockDoH.delay = delay; O4MockDoH.seen = []; O4MockDoH.lock.unlock()
        var cfg = DNSFilterConfig(port: 0); cfg.upstreamTimeout = 3
        let doh = DoHClient(upstreams: [URL(string: "https://doh.o4.test/dns-query")!], timeout: 3,
                            protocolClasses: [O4MockDoH.self], pins: DoHPinStore(stateURL: nil))
        return DNSFilterServer(config: cfg, blocklist: blocklist, doh: doh)
    }

    // MARK: parser

    static func o4Parser() {
        // Crafted: self-pointer, forward pointer, 64-byte label (0x40 is a reserved label type), >255-byte name.
        let hdr: [UInt8] = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        check((try? DNSMessage.parse(Data(hdr + [0xC0, 12, 0, 1, 0, 1]))) == nil, "o4 parser: self-pointer rejected")
        check((try? DNSMessage.parse(Data(hdr + [0xC0, 14, 0, 0, 1, 0, 1]))) == nil, "o4 parser: forward pointer rejected")
        check((try? DNSMessage.parse(Data(hdr + [64] + [UInt8](repeating: 0x61, count: 64) + [0, 0, 1, 0, 1]))) == nil,
              "o4 parser: oversized (64-byte) label rejected")
        var long: [UInt8] = []
        for _ in 0..<5 { long += [63] + [UInt8](repeating: 0x62, count: 63) }
        check((try? DNSMessage.parse(Data(hdr + long + [0, 0, 1, 0, 1]))) == nil, "o4 parser: name over 255 bytes rejected")
        // Pointer chain that only ever goes backwards but is long: still bounded.
        var chain: [UInt8] = hdr + [1, 0x61, 0]
        for i in 0..<100 { let target = i == 0 ? 12 : 12 + 3 + (i - 1) * 2; chain += [0xC0 | UInt8(target >> 8), UInt8(target & 0xFF)] }
        check((try? DNSWire.readName(chain, at: chain.count - 2)) == nil, "o4 parser: long backwards pointer chain capped")

        // Mutation fuzz on a real compressed response (A + CNAME + OPT + HTTPS), 25k cases: never crashes, never
        // returns a name longer than 255 wire bytes, never loops.
        var base = DNSMessage(id: 7, flags: 0x8180)
        base.questions = [DNSQuestion(name: "www.example.com", type: DNSType.a)]
        base.answers = [DNSResourceRecord(name: "www.example.com", type: DNSType.cname, ttl: 60,
                                          rdata: Data([3, 0x63, 0x64, 0x6E, 0xC0, 16]), value: nil),
                        o4A("cdn.example.com", "93.184.216.34")]
        base.additionals = [DNSResourceRecord(name: "", type: DNSType.opt, rclass: 1232, ttl: 0, rdata: Data())]
        let seed = [UInt8](base.serialize())
        var rng = SystemRandomNumberGenerator()
        var ok = true
        let t0 = Date()
        for i in 0..<25_000 {
            var b = seed
            let flips = Int.random(in: 1...6, using: &rng)
            for _ in 0..<flips { b[Int.random(in: 0..<b.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng) }
            if i % 5 == 0 { b = Array(b.prefix(Int.random(in: 0...b.count, using: &rng))) }
            if i % 7 == 0 { b += (0..<Int.random(in: 1...40, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) } }
            if let m = try? DNSMessage.parse(Data(b)) {
                for n in m.questions.map(\.name) + m.answers.map(\.name) where DNSWire.encodeName(n).count > 255 { ok = false }
                _ = DNSRebindGuard.strip(Data(b), question: m.questions.first ?? DNSQuestion(name: "x.example", type: 1))
                _ = DNSWire.upstreamQuery(for: m)
            }
        }
        check(ok && Date().timeIntervalSince(t0) < 30, "o4 parser: 25k mutated packets parse/strip/rebuild safely")
    }

    // MARK: EDNS + upstream query hygiene

    static func o4EDNSAndUpstreamQuery() {
        func opt(_ size: UInt16, do dnssec: Bool = false, rdata: Data = Data(), name: String = "") -> DNSResourceRecord {
            DNSResourceRecord(name: name, type: DNSType.opt, rclass: size, ttl: dnssec ? 0x8000 : 0, rdata: rdata)
        }
        let big = try? DNSMessage.parse(o4Query("a.example", 1, additionals: [opt(65_535)]))
        let tiny = try? DNSMessage.parse(o4Query("a.example", 1, additionals: [opt(100)]))
        check(big?.ednsPayloadSize == 4096 && tiny?.ednsPayloadSize == 512, "o4 edns: payload size clamped to 512...4096")
        let two = try? DNSMessage.parse(o4Query("a.example", 1, additionals: [opt(1232), opt(1232)]))
        let named = try? DNSMessage.parse(o4Query("a.example", 1, additionals: [opt(1232, name: "evil.example")]))
        let withAns = try? DNSMessage.parse(o4Query("a.example", 1, answers: [o4A("a.example", "127.0.0.1")]))
        check(two?.isWellFormedQuery == false && named?.isWellFormedQuery == false && withAns?.isWellFormedQuery == false
              && big?.isWellFormedQuery == true, "o4 edns: duplicate OPT, non-root OPT and queries carrying answers are malformed")

        // ECS option (code 8) + CD bit + a junk additional record from the client: none of it goes upstream.
        let ecs = Data([0, 8, 0, 7, 0, 1, 24, 0, 192, 168, 1])
        let raw = o4Query("Mixed.Example.COM", DNSType.a, flags: 0x0110,
                          additionals: [opt(1232, do: true, rdata: ecs), o4A("junk.example", "10.0.0.1")])
        guard let q = try? DNSMessage.parse(raw) else { check(false, "o4 upstream: fixture parses"); return }
        let up = try? DNSMessage.parse(DNSWire.upstreamQuery(for: q))
        check(up?.questions.first?.name == "mixed.example.com" && up?.answers.isEmpty == true && up?.authorities.isEmpty == true,
              "o4 upstream: only the question is forwarded")
        check(up?.additionals.count == 1 && up?.additionals.first?.type == DNSType.opt && up?.additionals.first?.rdata.isEmpty == true
              && up?.ednsPayloadSize == 4096 && up?.dnssecOK == true, "o4 upstream: fresh OPT (no ECS/options), DO bit kept")
        check(up.map { $0.flags & 0x0010 == 0 && $0.recursionDesired } == true, "o4 upstream: CD cleared (upstream always validates), RD set")
        let plain = try? DNSMessage.parse(DNSWire.upstreamQuery(for: DNSMessage.parse(o4Query("a.example", 1))))
        check(plain?.additionals.isEmpty == true, "o4 upstream: no OPT added when the client sent none")
    }

    // MARK: rebinding

    static func o4Rebinding() {
        let priv = ["127.0.0.1", "127.8.9.10", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
                    "0.0.0.0", "224.0.0.251", "255.255.255.255", "192.0.0.8", "::", "::1", "fe80::1", "fc00::1", "fd12::1",
                    "ff02::1", "::ffff:127.0.0.1", "::ffff:192.168.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "fec0::1"]
        let pub = ["93.184.216.34", "172.32.0.1", "172.15.0.1", "8.8.8.8", "100.64.0.1", "2606:4700:4700::1111",
                   "::ffff:93.184.216.34", "64:ff9b::5db8:d822", "2001:db8::1"]
        check(priv.allSatisfy { DNSRebindGuard.isPrivate(address: $0) }, "o4 rebind: loopback/RFC1918/link-local/ULA/mapped are private")
        check(pub.allSatisfy { !DNSRebindGuard.isPrivate(address: $0) }, "o4 rebind: public addresses (and CGNAT) are not")
        check(["printer.local", "nas", "router.home.arpa", "app.localhost", "10-0-0-1.nip.io", "x.lvh.me", "abc.plex.direct",
               "host.tailnet.ts.net"].allSatisfy(DNSRebindGuard.isExempt)
              && !DNSRebindGuard.isExempt("attacker.example") && !DNSRebindGuard.isExempt("evil-local.com"),
              "o4 rebind: local names and dev domains exempt; lookalikes are not")

        let q = DNSQuestion(name: "rebind.attacker.example", type: DNSType.a)
        var qm = DNSMessage(id: 0, flags: 0x0100); qm.questions = [q]
        let resp = o4Response(qm, [DNSResourceRecord(name: q.name, type: DNSType.cname, ttl: 60,
                                                     rdata: Data(DNSWire.encodeName("edge.attacker.example")), value: "edge.attacker.example"),
                                   o4A("edge.attacker.example", "93.184.216.34"), o4A("edge.attacker.example", "127.0.0.1")],
                              additionals: [o4A("glue.attacker.example", "192.168.1.1")])
        let s = DNSRebindGuard.strip(resp.serialize(), question: q)
        let m = s.flatMap { try? DNSMessage.parse($0.0) }
        check(m?.answers.compactMap(\.value) == ["edge.attacker.example", "93.184.216.34"] && m?.additionals.isEmpty == true
              && s?.1.contains("127.0.0.1") == true, "o4 rebind: private A and glue stripped, CNAME and public A kept")
        check(DNSRebindGuard.strip(resp.serialize(), question: DNSQuestion(name: "dev.lvh.me", type: DNSType.a)) == nil,
              "o4 rebind: exempt name untouched")
        let clean = o4Response(qm, [o4A(q.name, "93.184.216.34")])
        check(DNSRebindGuard.strip(clean.serialize(), question: q) == nil, "o4 rebind: public-only answer untouched")
        // HTTPS RR with ipv4hint 127.0.0.1 / ipv6hint ::1.
        func svcb(_ key: UInt16, _ addr: [UInt8]) -> DNSResourceRecord {
            var rd: [UInt8] = [0, 1, 0]   // priority 1, target "."
            rd += [UInt8(key >> 8), UInt8(key & 0xFF), 0, UInt8(addr.count)] + addr
            return DNSResourceRecord(name: q.name, type: DNSType.https, ttl: 60, rdata: Data(rd))
        }
        let h4 = o4Response(qm, [svcb(4, [127, 0, 0, 1])]), h6 = o4Response(qm, [svcb(6, [UInt8](repeating: 0, count: 15) + [1])])
        let hp = o4Response(qm, [svcb(4, [93, 184, 216, 34])])
        check(DNSRebindGuard.strip(h4.serialize(), question: q) != nil && DNSRebindGuard.strip(h6.serialize(), question: q) != nil
              && DNSRebindGuard.strip(hp.serialize(), question: q) == nil, "o4 rebind: HTTPS ipv4hint/ipv6hint to loopback stripped, public hint kept")
    }

    // MARK: server end to end (mock DoH)

    static func o4ServerEndToEnd() {
        let allow = DomainBlocklist()
        _ = allow.load(text: "@@||intranet.example.org^\n", format: .adblock, source: "user", acceptAllowRules: true)
        let srv = o4Server(answer: { q in
            guard let name = q.questions.first?.name else { return nil }
            if name == "public.o4.example" { return o4Response(q, [o4A(name, "93.184.216.34")]) }
            return o4Response(q, [o4A(name, "127.0.0.1")])   // everything else rebinds to loopback
        }, blocklist: allow)
        let r = o4Ask(srv, o4Query("evil.o4.example", DNSType.a))
        check(r != nil && r!.rcode == 0 && r!.answers.isEmpty && r!.id == 0x4242, "o4 server: rebinding answer stripped (empty NOERROR, client ID)")
        let r2 = o4Ask(srv, o4Query("evil.o4.example", DNSType.a))
        check(r2 != nil && r2!.answers.isEmpty && O4MockDoH.seen.count == 1, "o4 server: cached copy is the sanitised one")
        let ok = o4Ask(srv, o4Query("public.o4.example", DNSType.a))
        check(ok?.answers.first?.value == "93.184.216.34", "o4 server: public answer passes")
        let user = o4Ask(srv, o4Query("intranet.example.org", DNSType.a))
        check(user?.answers.first?.value == "127.0.0.1", "o4 server: user-allowlisted name may resolve privately")
        let local = o4Ask(srv, o4Query("dev.lvh.me", DNSType.a))
        check(local?.answers.first?.value == "127.0.0.1", "o4 server: dev loopback domain not broken")
        // Upstream never sees CD or client EDNS options.
        _ = o4Ask(srv, o4Query("public2.o4.example", DNSType.a, flags: 0x0110,
                               additionals: [DNSResourceRecord(name: "", type: DNSType.opt, rclass: 1232, ttl: 0,
                                                               rdata: Data([0, 8, 0, 7, 0, 1, 24, 0, 192, 168, 1]))]))
        let last = O4MockDoH.seen.last.flatMap { try? DNSMessage.parse($0) }
        check(last?.questions.first?.name == "public2.o4.example" && last.map { $0.flags & 0x0010 == 0 } == true
              && last?.additionals.first?.rdata.isEmpty == true, "o4 server: upstream query rebuilt (no CD, no ECS)")
        // Malformed EDNS gets FORMERR without an upstream call.
        let before = O4MockDoH.seen.count
        let opt = DNSResourceRecord(name: "", type: DNSType.opt, rclass: 1232, ttl: 0, rdata: Data())
        let fe = o4Ask(srv, o4Query("x.o4.example", DNSType.a, additionals: [opt, opt]))
        check(fe?.rcode == DNSRCode.formErr && O4MockDoH.seen.count == before, "o4 server: duplicate OPT -> FORMERR, nothing sent upstream")
    }

    // MARK: flood isolation

    static func o4Flood() {
        let bl = DomainBlocklist(); bl.add("blocked.o4.example", source: "test")
        let srv = o4Server(answer: { q in o4Response(q, [o4A(q.questions[0].name, "93.184.216.34")]) }, delay: 2.5, blocklist: bl)
        // Pre-cache the name the watchdog probes.
        var pq = DNSMessage(id: 0, flags: 0x0100); pq.questions = [DNSQuestion(name: "apple.com", type: DNSType.a)]
        srv.cache.store(o4Response(pq, [o4A("apple.com", "17.253.144.10")]).serialize(), for: pq.questions[0])
        // Saturate every upstream slot with random names (the mock holds each for 2.5 s).
        for i in 0..<(DNSFilterServer.maxInFlight + 40) {
            srv.resolve(o4Query("r\(i)-\(UInt32.random(in: 0...UInt32.max)).flood.example", DNSType.a)) { _ in }
        }
        Thread.sleep(forTimeInterval: 0.2)
        let t0 = Date()
        let cached = o4Ask(srv, o4Query("apple.com", DNSType.a), timeout: 1)
        let blocked = o4Ask(srv, o4Query("blocked.o4.example", DNSType.a), timeout: 1)
        let fresh = o4Ask(srv, o4Query("new.flood2.example", DNSType.a), timeout: 1)
        check(cached?.answers.first?.value == "17.253.144.10" && blocked?.answers.first?.value == "0.0.0.0"
              && Date().timeIntervalSince(t0) < 1.5, "o4 flood: cached (watchdog probe) and blocked names still answered while upstream is saturated")
        check(fresh?.rcode == DNSRCode.servFail && srv.droppedOverload > 0, "o4 flood: over-limit upstream work refused fast, counted")
        Thread.sleep(forTimeInterval: 2.8)   // let the mock drain
    }

    // MARK: TCP slow loris

    static func o4TCPSlowLoris() {
        var fds: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { check(false, "o4 tcp: socketpair"); return }
        defer { close(fds[0]); close(fds[1]) }
        let writer = fds[1]
        DispatchQueue.global().async {
            for _ in 0..<20 { var b: UInt8 = 0x41; _ = write(writer, &b, 1); Thread.sleep(forTimeInterval: 0.1) }
        }
        let t0 = Date()
        let got = DNSFilterServer.readExactlyForTest(fds[0], 100, deadline: Date().addingTimeInterval(0.5))
        let took = Date().timeIntervalSince(t0)
        check(got == nil && took < 1.2, "o4 tcp: trickled message cut off at the absolute deadline (\(String(format: "%.2f", took)) s)")
        check(DNSFilterServer.tcpMessageSeconds <= 5 && DNSFilterServer.tcpIdleSeconds <= 10, "o4 tcp: bounded per-message and idle deadlines")
    }

    // MARK: IPv6 loopback claim

    static func o4IPv6Loopback() {
        var cfg = DNSFilterConfig(port: 0); cfg.upstreams = [URL(string: "https://127.0.0.1:9/dns-query")!]; cfg.upstreamTimeout = 1
        let srv = DNSFilterServer(config: cfg)
        do { try srv.start() } catch { check(false, "o4 v6: server starts (\(error))"); return }
        defer { srv.stop() }
        let port = srv.boundPort
        guard srv.ipv6LoopbackBound else {
            check(true, "o4 v6: IPv6 loopback unavailable on this host (skipped)"); return
        }
        // A squatter (even with SO_REUSEADDR/SO_REUSEPORT) cannot take [::1]:port.
        let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, socklen_t(MemoryLayout<Int32>.size))
        var a = sockaddr_in6(); a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); a.sin6_family = sa_family_t(AF_INET6)
        a.sin6_port = port.bigEndian; a.sin6_addr = in6addr_loopback
        let rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        check(rc != 0, "o4 v6: [::1] DNS port already claimed by RamPart (no squatting)")
        // And it answers there (bootstrap name: no upstream needed).
        var tv = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let q = [UInt8](o4Query("dns.quad9.net", DNSType.a))
        let sent = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            sendto(fd, q, q.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        var buf = [UInt8](repeating: 0, count: 1500)
        let n = sent == q.count ? recv(fd, &buf, buf.count, 0) : -1
        close(fd)
        let m = n > 12 ? try? DNSMessage.parse(Data(buf[0..<n])) : nil
        check(m?.answers.first?.value == "9.9.9.9", "o4 v6: filter answers on [::1] too")
    }

    // MARK: pf

    static func o4PF() {
        // Fuzz: whatever a feed or a connection list supplies, sanitize() only ever emits address characters.
        let alphabet = Array("0123456789abcdefABCDEF:./ \n\t\"'{}<>#;-+!xX%\\\u{0}\u{202E}")
        var safe = true
        for _ in 0..<20_000 {
            let s = String((0..<Int.random(in: 0...24)).map { _ in alphabet.randomElement()! })
            if let o = PFManager.sanitize(s), !o.allSatisfy({ "0123456789abcdef:./".contains($0) }) { safe = false }
        }
        check(safe, "o4 pf: 20k fuzzed entries never emit pf syntax characters")
        let inj = ["1.2.3.4\npass out quick all", "1.2.3.4 } pass", "1.2.3.4/24\"", "evil.example", "1.2.3.4/+8", "1.2.3.4/08x"]
        check(inj.allSatisfy { PFManager.sanitize($0) == nil }, "o4 pf: injection attempts rejected")
        check(["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "64:ff9b::/96", "64:ff9b::5db8:d822", "64:ff9b:1::/48", "0:64::/16"]
                .allSatisfy { PFManager.sanitize($0) == nil }, "o4 pf: public resolvers and NAT64 space can never be blocked")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.o4pf-\(getpid())")
        defer { try? FileManager.default.removeItem(at: dir) }
        let pf = PFManager(anchor: "x\npass all", table: "t;pass", directory: dir, dryRun: true)
        pf.alsoProtect = ["203.0.113.53"]
        let table = pf.tableContents(["203.0.113.53", "203.0.113.0/24", "198.51.100.9"])
        check(table == "198.51.100.9\n" && pf.anchor == "com.apple/250.Rampart" && pf.table == "rampart_block",
              "o4 pf: run-time protected DNS server (and ranges covering it) kept out of the table")
        check(pf.loadCommands().allSatisfy { $0.arguments.allSatisfy { !$0.contains("\n") } }, "o4 pf: no newline reaches pfctl arguments")
    }

    // MARK: App Firewall collateral

    static func o4Firewall() {
        check(AppFirewall.protectedKey("/Users/x/Downloads/Rampart.app") == nil && AppFirewall.protectedKey("/tmp/a/Rampart.app/Contents/MacOS/x") == nil
              && AppFirewall.protectedKey("/tmp/rampartd") == nil && AppFirewall.protectedKey("/usr/local/bin/evil") == nil
              && AppFirewall.protectedKey("/usr/../tmp/evil") == nil,
              "o4 firewall: malware can't make itself unblockable by name or /usr/local")
        check(AppFirewall.protectedKey("/Applications/Rampart.app") != nil && AppFirewall.protectedKey("/Library/PrivilegedHelperTools/app.rampart.daemon") != nil
              && AppFirewall.protectedKey("/usr/libexec/trustd") != nil && AppFirewall.protectedKey("/System/Library/x") != nil,
              "o4 firewall: installed RamPart and macOS stay protected")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.o4fw-\(getpid())")
        try? FileManager.default.removeItem(at: dir)
        defer { try? FileManager.default.removeItem(at: dir) }
        let fw = AppFirewall(stateURL: dir.appendingPathComponent("fw.json"), pfDirectory: dir.appendingPathComponent("pf"), dryRun: true) { path in
            path.hasPrefix("/tmp/") ? SigningInfo(status: .unsigned) : SigningInfo(status: .apple)
        }
        func conn(_ remote: String, _ path: String = "/tmp/o4mal") -> NetworkConnection {
            NetworkConnection(pid: 77, processName: (path as NSString).lastPathComponent, processPath: path, proto: "tcp", localAddress: "192.168.1.20",
                              localPort: 50077, remoteAddress: remote, remotePort: 443, state: "ESTABLISHED", source: "test")
        }
        // The malware first touches what macOS and RamPart need (before any other app was seen using them).
        fw.noteDNS(name: "swscan.apple.com", answers: ["203.0.113.80"])
        fw.noteDNS(name: "cdn.jsdelivr.net", answers: ["203.0.113.81"])
        fw.noteDNS(name: "c2.o4bad.example", answers: ["203.0.113.99"])
        fw.extraProtectedAddresses = ["198.51.100.53"]   // the user's original DNS server
        _ = fw.update(connections: [])
        _ = fw.update(connections: ["17.253.144.10", "203.0.113.80", "203.0.113.81", "8.8.8.8", "1.1.1.2", "198.51.100.53", "203.0.113.99"].map { conn($0) })
        var domains: [String: String] = [:]
        fw.onDomains = { domains = $0 }
        let st = try? fw.decide(key: "/tmp/o4mal", decision: .block)
        let rule = st?.rules.first { $0.key == "/tmp/o4mal" }
        check(rule?.blockedAddresses == ["203.0.113.99"], "o4 firewall: only the app's own C2 is blocked (Apple 17/8, update/feed CDN IPs, resolvers, original DNS kept)")
        check(domains == ["c2.o4bad.example": "o4mal"], "o4 firewall: apple.com / jsdelivr names never reach the DNS block list")
        check(rule?.notes.contains { $0.contains("swscan.apple.com") && $0.contains("macOS or RamPart") } == true, "o4 firewall: rule explains protected destinations")
        let table = (try? String(contentsOf: fw.pf.tableURL, encoding: .utf8)) ?? ""
        check(table == "203.0.113.99\n", "o4 firewall: pf table holds only the C2 address")
        var refused = false
        do { try fw.decide(key: "/Applications/Safari.app", decision: .block) } catch { refused = true }
        check(refused, "o4 firewall: Apple-signed apps can't be blocked")
    }
}

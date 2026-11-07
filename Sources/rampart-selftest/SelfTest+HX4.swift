import Foundation
import CryptoKit
import Security
import RampartShared
import RampartNetwork

/// Mock DoH upstream for hx4: answers per host from a static table. No real network.
final class HX4MockDoH: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var replies: [String: (Int, String, Data)] = [:]
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let host = request.url?.host ?? ""
        guard let (status, ctype, body) = Self.replies[host] else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost)); return
        }
        let resp = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
                                   headerFields: ["Content-Type": ctype])!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

// Web protection hardening (hx4): DNS parser fuzzing, loopback-only server, DoH validation, cache
// poisoning, blocklist integrity, DNS restore, pf injection, Wi-Fi disconnect abuse, scanner SSRF.
// Fixtures only: no system DNS change, no pfctl, no real network, no disassociate.
extension SelfTest {
    static func hx4Checks() {
        hx4Parser()
        hx4Server()
        hx4DoH()
        hx4Cache()
        hx4PF()
        hx4Switcher()
        hx4Lists()
        hx4WiFi()
        hx4Scanner()
        hx4Pinning()
        hx4SignedFeeds()
    }

    static func hx4Pinning() {
        let st = DoHPinStore(stateURL: nil, staticPins: ["pinned.hx4.test": ["PIN-A"]])
        check(st.evaluate(host: "pinned.hx4.test", chain: ["leaf", "PIN-A"]) == .match, "hx4 static pin matches anywhere in chain")
        check(st.evaluate(host: "PINNED.hx4.test", chain: ["evil-leaf", "evil-root"]) == .mismatch, "hx4 static pin mismatch rejected")
        check(st.evaluate(host: "tofu.hx4.test", chain: ["leaf1", "inter", "root"]) == .learned, "hx4 TOFU learns first chain")
        check(st.evaluate(host: "tofu.hx4.test", chain: ["leaf2", "inter", "root"]) == .match, "hx4 TOFU survives leaf rotation")
        check(st.evaluate(host: "tofu.hx4.test", chain: ["mitm-leaf", "rogue-root"]) == .mismatch, "hx4 TOFU detects rogue-root interception")
        check(st.evaluate(host: "x.hx4.test", chain: []) == .mismatch, "hx4 empty chain never passes")
        st.forget(host: "tofu.hx4.test")
        check(st.evaluate(host: "tofu.hx4.test", chain: ["new"]) == .learned, "hx4 user re-pin after forget")
        // Persistence round trip in a scratch file.
        let f = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.hx4pins-\(getpid()).json")
        defer { try? FileManager.default.removeItem(at: f) }
        _ = DoHPinStore(stateURL: f, staticPins: [:]).evaluate(host: "p.hx4.test", chain: ["k1"])
        check(DoHPinStore(stateURL: f, staticPins: [:]).evaluate(host: "p.hx4.test", chain: ["k2"]) == .mismatch, "hx4 learned pins persist")
        // keyHash on an in-memory key (never touches the keychain).
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 256,
                                    kSecAttrIsPermanent as String: false]
        if let priv = SecKeyCreateRandomKey(attrs as CFDictionary, nil), let pub = SecKeyCopyPublicKey(priv) {
            let h = DoHPinStore.keyHash(pub)
            check(h != nil && Data(base64Encoded: h!)?.count == 32 && h == DoHPinStore.keyHash(pub), "hx4 key hash is stable SHA-256")
        } else { check(false, "hx4 in-memory key generation") }
        // A pin failure surfaces as an alert-able error, never a silent switch.
        check(DoHError.pinMismatch(URL(string: "https://dns.quad9.net/dns-query")!).description.contains("pinned"), "hx4 pin error text")
    }

    static func hx4SignedFeeds() {
        let priv = Curve25519.Signing.PrivateKey()
        let pk = priv.publicKey.rawRepresentation.base64EncodedString()
        let body = Data("bad1.hx4.test\nbad2.hx4.test\n".utf8)
        let sig = try! priv.signature(for: body)
        check(BlocklistUpdater.verifySignature(data: body, signature: sig, publicKeyBase64: pk), "hx4 Ed25519 raw signature verifies")
        check(BlocklistUpdater.verifySignature(data: body, signature: Data(sig.base64EncodedString().utf8), publicKeyBase64: pk), "hx4 Ed25519 base64 signature verifies")
        var tampered = body; tampered.append(Data("google.com\n".utf8))
        check(!BlocklistUpdater.verifySignature(data: tampered, signature: sig, publicKeyBase64: pk), "hx4 tampered feed fails signature")
        check(!BlocklistUpdater.verifySignature(data: body, signature: sig, publicKeyBase64: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()), "hx4 wrong key fails")
        check(!BlocklistUpdater.verifySignature(data: body, signature: Data(count: 10), publicKeyBase64: "junk"), "hx4 junk key/sig fails")
        // Host pinning for unsigned feeds.
        let pinned = BlocklistUpdater.Source(id: "a", url: URL(string: "https://cdn.jsdelivr.net/x.txt")!, format: .plain, minimumEntries: 1, refreshInterval: 60)
        let lookalike = BlocklistUpdater.Source(id: "b", url: URL(string: "https://cdn.jsdelivr.net.evil.test/x.txt")!, format: .plain, minimumEntries: 1, refreshInterval: 60)
        let signed = BlocklistUpdater.Source(id: "c", url: URL(string: "https://mirror.hx4.test/x.txt")!, format: .plain, minimumEntries: 1, refreshInterval: 60, publicKey: pk)
        check(BlocklistUpdater.hostAllowed(pinned) && !BlocklistUpdater.hostAllowed(lookalike) && BlocklistUpdater.hostAllowed(signed), "hx4 feed host pinning")
        check(signed.effectiveSignatureURL.absoluteString == "https://mirror.hx4.test/x.txt.sig", "hx4 default signature URL")
        // Feeds may only add blocks: allow rules inside a downloaded feed are ignored.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.hx4feed-\(getpid())")
        defer { try? FileManager.default.removeItem(at: dir) }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let src = BlocklistUpdater.Source(id: "feed", url: URL(string: "https://cdn.jsdelivr.net/f.txt")!, format: .adblock, minimumEntries: 1, refreshInterval: 60)
        try? Data("||evil.hx4.test^\n@@||evil.hx4.test^\n@@||malware.hx4.test^\n||malware.hx4.test^\n".utf8).write(to: dir.appendingPathComponent("feed.txt"))
        let bl = BlocklistUpdater(sources: [src], directory: dir).buildBlocklist(userAllow: ["mine.hx4.test"])
        check(bl.isBlocked("evil.hx4.test") && bl.isBlocked("malware.hx4.test"), "hx4 feed allow rules cannot unblock")
        check(bl.allowedCount == 1, "hx4 only the user's own allowlist entries apply")
    }

    private static func header(qd: UInt16 = 1, an: UInt16 = 0, flags: UInt16 = 0x0100, id: UInt16 = 0x1234) -> [UInt8] {
        [UInt8(id >> 8), UInt8(id & 0xFF), UInt8(flags >> 8), UInt8(flags & 0xFF),
         UInt8(qd >> 8), UInt8(qd & 0xFF), UInt8(an >> 8), UInt8(an & 0xFF), 0, 0, 0, 0]
    }

    static func hx4Parser() {
        // Random fuzz: never crash, never hang.
        var rng = SystemRandomNumberGenerator()
        let base = [UInt8](DNSWire.buildQuery(name: "a.b.example.test", type: DNSType.a, id: 7))
        let t0 = Date()
        for i in 0..<30_000 {
            var b: [UInt8]
            if i % 2 == 0 {
                b = (0..<Int.random(in: 0...96, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) }
                if b.count >= 12, i % 4 == 0 { b[4] = 0; b[5] = 1 }
            } else {
                b = base
                for _ in 0..<Int.random(in: 1...6, using: &rng) { b[Int.random(in: 0..<b.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng) }
                if i % 3 == 0 { b.append(contentsOf: [0xC0, UInt8.random(in: 0...255, using: &rng)]) }
            }
            _ = try? DNSMessage.parse(Data(b))
        }
        check(Date().timeIntervalSince(t0) < 20, "hx4 parser fuzz 30k inputs completes")

        // Self-pointer, forward pointer and two-pointer loop are all rejected.
        let selfPtr = header() + [0xC0, 12, 0, 1, 0, 1]
        check((try? DNSMessage.parse(Data(selfPtr))) == nil, "hx4 self-referencing pointer rejected")
        let fwd = header() + [0xC0, 14, 1, 0x61, 0, 0, 1, 0, 1]
        check((try? DNSMessage.parse(Data(fwd))) == nil, "hx4 forward pointer rejected")
        let loop = header() + [1, 0x61, 0xC0, 16, 0xC0, 12, 0, 1, 0, 1]
        check((try? DNSMessage.parse(Data(loop))) == nil, "hx4 pointer loop rejected")
        // Backward pointer still works (normal compression).
        var good = header(qd: 1, an: 1, flags: 0x8180)
        good += [7] + Array("example".utf8) + [4] + Array("test".utf8) + [0, 0, 1, 0, 1]
        good += [0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]
        let gm = try? DNSMessage.parse(Data(good))
        check(gm?.answers.first?.name == "example.test" && gm?.answers.first?.value == "93.184.216.34", "hx4 backward compression ok")
        // Overlong name (>255 bytes on the wire) via many labels.
        var long = header()
        for _ in 0..<5 { long += [63] + [UInt8](repeating: 0x61, count: 63) }
        long += [0, 0, 1, 0, 1]
        check((try? DNSMessage.parse(Data(long))) == nil, "hx4 name > 255 bytes rejected")
        // Label length overrunning the packet.
        check((try? DNSMessage.parse(Data(header() + [40, 0x61, 0x62]))) == nil, "hx4 label overrun rejected")
        // Huge counts with no data: fails fast.
        check((try? DNSMessage.parse(Data(header(qd: 0xFFFF, an: 0xFFFF)))) == nil, "hx4 bogus counts rejected")
        // RDLENGTH beyond packet.
        var rd = header(qd: 0, an: 1, flags: 0x8180) + [0, 0, 1, 0, 1, 0, 0, 0, 1, 0xFF, 0xFF, 1, 2]
        check((try? DNSMessage.parse(Data(rd))) == nil, "hx4 rdlength overrun rejected"); rd.removeAll()

        // Embedded dot / control bytes are escaped, never reinterpreted.
        let dotted = header() + [11] + Array("evil.ex\nam".utf8) + [0x5C] + [4] + Array("TEST".utf8) + [0, 0, 1, 0, 1]
        let dn = (try? DNSMessage.parse(Data(dotted)))?.questions.first?.name
        check(dn == "evil\\.ex\\010am\\\\.test", "hx4 label escaping (got \(dn ?? "nil"))")
        check(!(dn ?? "\n").contains("\n"), "hx4 no raw newline in parsed name")
        // Round trip: re-encoding yields the original two labels.
        if let dn {
            let enc = DNSWire.encodeName(dn)
            check(enc == [11] + Array("evil.ex\nam".utf8) + [0x5C] + [4] + Array("test".utf8) + [0], "hx4 escaped name re-encodes to wire")
        }
        check(DNSWire.encodeName("a.b.test") == [1, 0x61, 1, 0x62, 4] + Array("test".utf8) + [0], "hx4 plain encode unchanged")
    }

    static func hx4Server() {
        check(DNSFilterServer.isLoopbackAddress("127.0.0.1") && DNSFilterServer.isLoopbackAddress("::1"), "hx4 loopback addresses accepted")
        check(!DNSFilterServer.isLoopbackAddress("0.0.0.0") && !DNSFilterServer.isLoopbackAddress("192.168.1.2")
              && !DNSFilterServer.isLoopbackAddress("::") && !DNSFilterServer.isLoopbackAddress("fe80::1"), "hx4 non-loopback rejected")
        let open = DNSFilterServer(config: DNSFilterConfig(listenAddress: "0.0.0.0", port: 0))
        var refused = false
        do { try open.start() } catch let e as DNSFilterServerError { if case .notLoopback = e { refused = true } } catch {}
        open.stop()
        check(refused && !open.isRunning, "hx4 server refuses to bind 0.0.0.0 (open resolver)")

        // In-process pipeline with an unreachable upstream (mock-free: .test host never answers).
        let bl = DomainBlocklist(); bl.add("ads.hx4.test", source: "t")
        let srv = DNSFilterServer(config: DNSFilterConfig(listenAddress: "127.0.0.1", port: 0,
                                                          upstreams: [URL(string: "https://doh.invalid.test/dns-query")!],
                                                          upstreamTimeout: 1), blocklist: bl)
        func ask(_ q: Data, wait: Double = 3) -> Data? {
            let sem = DispatchSemaphore(value: 0); let box = HX4Box()
            srv.resolve(q) { box.data = $0; sem.signal() }
            return sem.wait(timeout: .now() + wait) == .success ? box.data : nil
        }
        // Bootstrap names are answered locally (no self-dependency loop).
        let boot = ask(DNSWire.buildQuery(name: "security.cloudflare-dns.com", type: DNSType.a, id: 99))
        let bm = boot.flatMap { try? DNSMessage.parse($0) }
        check(bm?.id == 99 && bm?.answers.compactMap(\.value).contains("1.1.1.2") == true, "hx4 DoH upstream name answered from pinned bootstrap")
        let blocked = ask(DNSWire.buildQuery(name: "ads.hx4.test", type: DNSType.a))
        check(blocked.flatMap { try? DNSMessage.parse($0) }?.answers.first?.value == "0.0.0.0", "hx4 blocking still works")
        // A message with QR=1 gets no reply at all (no reflection loops).
        var resp = [UInt8](DNSWire.buildQuery(name: "x.hx4.test", type: DNSType.a)); resp[2] |= 0x80
        check(ask(Data(resp), wait: 0.5) == nil, "hx4 responses are dropped, never answered")
        // Upstream failure -> SERVFAIL and health tracking.
        for _ in 0..<5 { _ = ask(DNSWire.buildQuery(name: "up\(Int.random(in: 0...99999)).hx4.test", type: DNSType.a)) }
        check(!srv.upstreamHealthy, "hx4 upstream health flips after repeated DoH failures")
        // Non-https upstreams are discarded.
        let d = DoHClient(upstreams: [URL(string: "http://plain.hx4.test/dns-query")!, URL(string: "https://u:p@x.hx4.test/q")!])
        check(d.upstreams == DoHClient.defaultUpstreams, "hx4 http/credentialed upstreams replaced by TLS defaults")
    }

    static func hx4DoH() {
        let q = DNSQuestion(name: "www.hx4.test", type: DNSType.a)
        let url = URL(string: "https://doh.hx4.test/dns-query")!
        func reply(_ body: Data, ct: String = "application/dns-message") -> Result<Data, DoHError> {
            let r = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": ct])
            return DoHClient.validate(data: body, response: r, error: nil, url: url, question: q)
        }
        func msg(id: UInt16 = 0, qname: String = "www.hx4.test", answers: [DNSResourceRecord]) -> Data {
            var m = DNSMessage(id: id, flags: 0x8180)
            m.questions = [DNSQuestion(name: qname, type: DNSType.a)]
            m.answers = answers
            return m.serialize()
        }
        let a = DNSResourceRecord(name: "www.hx4.test", type: DNSType.a, ttl: 60, rdata: Data([192, 0, 2, 1]))
        if case .success = reply(msg(answers: [a])) { check(true, "hx4 DoH valid reply accepted") } else { check(false, "hx4 DoH valid reply accepted") }
        func rejected(_ r: Result<Data, DoHError>) -> Bool { if case .failure = r { return true }; return false }
        check(rejected(reply(msg(qname: "other.hx4.test", answers: []))), "hx4 DoH question mismatch rejected")
        check(rejected(reply(msg(id: 0x4242, answers: [a]))), "hx4 DoH non-zero ID rejected")
        let stray = DNSResourceRecord(name: "bank.hx4.test", type: DNSType.a, ttl: 86400, rdata: Data([203, 0, 113, 9]))
        check(rejected(reply(msg(answers: [a, stray]))), "hx4 DoH out-of-bailiwick answer rejected")
        // CNAME chain is in bailiwick (rdata uncompressed).
        let cn = DNSResourceRecord(name: "www.hx4.test", type: DNSType.cname, ttl: 60, rdata: Data(DNSWire.encodeName("cdn.hx4.test")))
        let ca = DNSResourceRecord(name: "cdn.hx4.test", type: DNSType.a, ttl: 60, rdata: Data([192, 0, 2, 7]))
        check(!rejected(reply(msg(answers: [ca, cn]))), "hx4 DoH CNAME chain (any order) accepted")
        check(rejected(reply(msg(answers: [a]), ct: "text/html")), "hx4 DoH wrong content-type rejected")
        check(rejected(reply(Data(count: 70_000))), "hx4 DoH oversize reply rejected")
        var query = [UInt8](msg(answers: [])); query[2] &= 0x7F
        check(rejected(reply(Data(query))), "hx4 DoH non-response rejected")

        // End to end over a mock URLProtocol: first upstream poisons, second is honest -> honest wins.
        let poisonedHost = "poison.hx4.test", honestHost = "honest.hx4.test"
        HX4MockDoH.replies = [poisonedHost: (200, "application/dns-message", msg(answers: [a, stray])),
                              honestHost: (200, "application/dns-message", msg(answers: [a]))]
        let client = DoHClient(upstreams: [URL(string: "https://\(poisonedHost)/dns-query")!, URL(string: "https://\(honestHost)/dns-query")!],
                               timeout: 2, protocolClasses: [HX4MockDoH.self])
        let sem = DispatchSemaphore(value: 0); let box = HX4Box(); let hostBox = HX4Box()
        client.resolve(DNSWire.buildQuery(name: "www.hx4.test", type: DNSType.a, id: 0x5151)) { r in
            if case .success(let (d, u)) = r { box.data = d; hostBox.data = Data((u.host ?? "").utf8) }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 5)
        let got = box.data.flatMap { try? DNSMessage.parse($0) }
        check(got?.id == 0x5151 && got?.answers.count == 1 && String(decoding: hostBox.data ?? Data(), as: UTF8.self) == honestHost,
              "hx4 poisoned upstream skipped, honest upstream used, ID restored")
    }

    static func hx4Cache() {
        let c = DNSResponseCache()
        let q = DNSQuestion(name: "a.hx4.test", type: DNSType.a)
        var m = DNSMessage(id: 1, flags: 0x8180)
        m.questions = [DNSQuestion(name: "victim.hx4.test", type: DNSType.a)]
        m.answers = [DNSResourceRecord(name: "victim.hx4.test", type: DNSType.a, ttl: 600, rdata: Data([203, 0, 113, 1]))]
        c.store(m.serialize(), for: q)
        check(c.count == 0, "hx4 cache refuses a reply whose question differs from the key")
        var big = DNSMessage(id: 1, flags: 0x8180)
        big.questions = [q]
        big.answers = [DNSResourceRecord(name: q.name, type: DNSType.txt, ttl: 600, rdata: Data(count: 9000))]
        c.store(big.serialize(), for: q)
        check(c.count == 0, "hx4 cache skips oversize replies (memory bound)")
    }

    static func hx4PF() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.hx4pf-\(getpid())")
        defer { try? FileManager.default.removeItem(at: dir) }
        let evil = PFManager(anchor: "x\npass all\n#", table: "t> pass in all #", directory: dir, dryRun: true)
        check(evil.anchor == "com.apple/250.Rampart" && evil.table == "rampart_block", "hx4 pf injected anchor/table names fall back to defaults")
        check(!evil.anchorRules().contains("pass all") && !evil.anchorRules().contains("pass in all"), "hx4 pf rules carry no injected text")
        let quoted = PFManager(directory: URL(fileURLWithPath: "/tmp/x\" pass in all \""), dryRun: true)
        check(!quoted.anchorRules().contains("pass in all"), "hx4 pf quote in path cannot break the rule")
        check(PFManager.isSafeAnchor("com.apple/251.RampartRemote") && !PFManager.isSafeAnchor("../x") && !PFManager.isSafeAnchor("-F"), "hx4 pf anchor validator")
        for bad in ["172.0.0.0/8", "192.0.0.0/8", "100.0.0.0/8", "169.0.0.0/8", "fe80::/16", "fd12:3456::/32", "::ffff:10.0.0.0/104",
                    "::/16", "1.1.1.0/24", "9.0.0.0/8", "1.2.3.4/+24", "1.2.3.4/", "1.2.3.4/24/1", "2620:fe::/32"] {
            check(PFManager.sanitize(bad) == nil, "hx4 pf rejects \(bad)")
        }
        check(PFManager.sanitize("185.220.101.77/24") == "185.220.101.0/24", "hx4 pf canonicalises host bits")
        check(PFManager.sanitize("185.220.101.5") == "185.220.101.5", "hx4 pf single address kept")
        check(PFManager.parseIPList("185.220.101.5\nlol; rm -rf /\n\"1.2.3.4\"\n").count == 1, "hx4 pf junk lines dropped")
    }

    static func hx4Switcher() {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.hx4dns-\(getpid()).json")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let sw = DNSSwitcher(snapshotURL: tmp, dryRun: true)
        let tampered = [DNSSwitcher.ServiceDNS(service: "-setv6off", enabled: true, servers: ["1.1.1.1"]),
                        DNSSwitcher.ServiceDNS(service: "Wi-Fi", enabled: true, servers: ["evil; rm", "127.0.0.9", "::1", "0.0.0.0"]),
                        DNSSwitcher.ServiceDNS(service: "USB\nLAN", enabled: true, servers: ["9.9.9.9"]),
                        DNSSwitcher.ServiceDNS(service: "Ethernet", enabled: true, servers: ["192.168.1.1"])]
        let cmds = sw.restoreCommands(for: tampered).map(\.arguments)
        check(!cmds.contains { $0.contains("-setv6off") } && !cmds.contains { $0.contains("USB\nLAN") }, "hx4 restore skips flag-like / control-char service names")
        check(cmds.contains(["-setdnsservers", "Wi-Fi", "empty"]), "hx4 restore drops invalid/loopback servers -> DHCP")
        check(cmds.contains(["-setdnsservers", "Ethernet", "192.168.1.1"]), "hx4 restore keeps real servers")
        check(!sw.needsRecovery(filterRunning: false), "hx4 no snapshot -> no recovery")
        try? sw.saveSnapshot(tampered)
        check(sw.needsRecovery(filterRunning: false) && !sw.needsRecovery(filterRunning: true), "hx4 stale snapshot -> crash recovery needed")
    }

    static func hx4Lists() {
        let src = BlocklistUpdater.Source(id: "hx4", url: URL(string: "https://lists.hx4.test/l.txt")!, format: .plain,
                                          minimumEntries: 2, refreshInterval: 60)
        var nul = Data("a.hx4.test\nb.hx4.test\n".utf8); nul.append(0)
        if case .failure = BlocklistUpdater.validate(data: nul, statusCode: 200, contentType: "text/plain", source: src) {
            check(true, "hx4 updater rejects binary body")
        } else { check(false, "hx4 updater rejects binary body") }
        check(BlocklistUpdater.checkShrink(new: 100, previous: 100_000) != nil, "hx4 updater rejects truncated list")
        check(BlocklistUpdater.checkShrink(new: 90_000, previous: 100_000) == nil, "hx4 updater accepts normal churn")
        let httpSrc = BlocklistUpdater.Source(id: "plain", url: URL(string: "http://lists.hx4.test/l.txt")!, format: .plain, minimumEntries: 1, refreshInterval: 60)
        let travSrc = BlocklistUpdater.Source(id: "../../etc/x", url: URL(string: "https://lists.hx4.test/l.txt")!, format: .plain, minimumEntries: 1, refreshInterval: 60)
        let u = BlocklistUpdater(sources: [httpSrc, travSrc, src], directory: FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.hx4bl"))
        check(u.sources.map(\.id) == ["hx4"], "hx4 updater drops http and path-traversal sources")
        let bl = DomainBlocklist()
        bl.load(text: "co.uk\ngithub.io\nbad.hx4.test\n", format: .plain, source: "t")
        check(!bl.isBlocked("bbc.co.uk") && !bl.isBlocked("x.github.io") && bl.isBlocked("bad.hx4.test"), "hx4 public suffixes cannot be blocked wholesale")
    }

    static func hx4WiFi() {
        let s = PublicWiFiGuard.displaySSID("RamPart:\nThis network is safe\u{202E}\u{200B}")
        check(s == "\u{201C}RamPart: This network is safe\u{201D}", "hx4 SSID display is one quoted line without bidi/zero-width (got \(s ?? "nil"))")
        check(PublicWiFiGuard.displaySSID(String(repeating: "A", count: 40))?.count == 35, "hx4 SSID display capped")
        let now = Date()
        check(!PublicWiFiGuard.disconnectBudgetExhausted([now.addingTimeInterval(-60)], now: now), "hx4 first repeat disconnect allowed")
        check(PublicWiFiGuard.disconnectBudgetExhausted([now.addingTimeInterval(-60), now.addingTimeInterval(-30)], now: now), "hx4 disconnect budget exhausted after 2/hour")
        check(!PublicWiFiGuard.disconnectBudgetExhausted([now.addingTimeInterval(-7200), now.addingTimeInterval(-4000)], now: now), "hx4 old disconnects expire")

        // Live guard with a fake disassociator: a network that keeps "attacking" is disconnected at most twice.
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.hx4wifi-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let fake = DryRunDisassociator()
        let g = PublicWiFiGuard(store: KnownWiFiNetworkStore(url: tmp), settings: PublicWiFiSettings(), disassociator: fake)
        let snap = PublicWiFiSnapshot(interface: "en0", ssid: "Free\u{202E}WiFi", bssid: nil, security: .open, gateway: "10.9.0.1",
                                      arp: [], dnsServers: [])
        for _ in 0..<4 {
            _ = g.handle(snap, known: g.store.network(PublicWiFiGuard.networkKey(ssid: snap.ssid, gatewayMAC: nil, gateway: snap.gateway, security: .open)))
            g.firePendingNow()
        }
        check(fake.calls.count == 2, "hx4 repeated forced disconnects capped (got \(fake.calls.count))")
    }

    static func hx4Scanner() {
        let sub = NetSubnet(interface: "en0", address: "192.168.1.107", netmask: "255.255.255.0", prefix: 24, network: "192.168.1.0", gateway: "192.168.1.1")
        check(NetScanSSRF.safeDescriptionURL("http://192.168.1.20:49152/desc.xml", subnet: sub) != nil, "hx4 LAN UPnP URL allowed")
        for bad in ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/", "https://192.168.1.20/x",
                    "http://router.local/desc.xml", "http://8.8.8.8/", "http://u:p@192.168.1.20/", "http://192.168.1.107:631/",
                    "http://192.168.001.020/", "file:///etc/passwd", "http://0x7f000001/"] {
            check(NetScanSSRF.safeDescriptionURL(bad, subnet: sub) == nil, "hx4 SSRF blocked: \(bad)")
        }
    }
}

private final class HX4Box: @unchecked Sendable { var data: Data? }

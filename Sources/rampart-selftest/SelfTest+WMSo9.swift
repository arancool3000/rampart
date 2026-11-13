import Foundation
import Darwin
import RampartShared
import RampartGuard
import RampartVPN

// WMS-o9: the Cat & Mouse network lure (attacker on the LAN) and the non-crypto VPN layer (malicious .conf,
// malicious peer, leaks, crash cleanup). Everything runs on loopback / in memory / with DryRunVPNRunner.
// The live sandbox check runs the real rampart-lure helper under the generated profile on 127.0.0.1 only.
extension SelfTest {
    static func wmso9Checks() {
        o9LureContainment()
        o9LureLimits()
        o9LureBanners()
        o9LureLiveSandbox()
        o9VPNConfigInjection()
        o9VPNPlan()
        o9VPNCrashCleanup()
        o9VPNTunnelFraming()
        o9VPNMaliciousPeer()
    }

    // MARK: lure — containment output

    static func o9LureContainment() {
        let prof = LureContainment.sandboxProfile(port: 5000, workDir: "/L/jail", helperPath: "/L/bin/rampart-lure")
        let lines = prof.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        check(!lines.contains("(allow file-read-metadata)"), "o9.sandbox.metadataNotUnrestricted")
        check(!prof.contains("system-socket"), "o9.sandbox.noSystemSocket")
        check(prof.contains("(global-name \"com.apple.logd\")"), "o9.sandbox.logdReachable")
        check(prof.contains("(deny sysctl-read (sysctl-name-prefix \"kern.proc\")") && prof.contains("kern.hostname"), "o9.sandbox.noProcessListOrHostname")
        check(!prof.contains("/Users") && !prof.contains("network-outbound (") && prof.contains("(deny network-outbound)"), "o9.sandbox.noHomeNoOutbound")
        check(prof.filter { $0 == "(" }.count == prof.filter { $0 == ")" }.count, "o9.sandbox.balanced")

        // pf rule injection through a subnet string (only the part before "/" used to be checked).
        let evil = ["192.168.1.0/24 }\npass in quick all", "10.0.0.0/8", "172.16.0.0/12 flags", "+1.2.3.4/8", "1.2.3.4/+8"]
        let anchor = LureContainment.pfAnchor(port: 5000, scope: .localSubnet, localSubnets: evil)
        check(!anchor.contains("pass in quick all") && !anchor.contains("flags S/SA keep state (max-src-conn 8, max-src-conn-rate 6/60)\npass in quick all"), "o9.pf.subnetInjection")
        check(anchor.contains("{ 10.0.0.0/8 }") && anchor.split(separator: "\n").count == 5, "o9.pf.onlyValidSubnets")
        check(LureAccessFilter.canonicalCIDR("192.168.1.77/24") == "192.168.1.0/24" && LureAccessFilter.canonicalCIDR("1.2.3.4/33") == nil
              && LureAccessFilter.canonicalCIDR("+1.2.3.4/8") == nil && LureAccessFilter.canonicalCIDR("1.2.3.4/+8") == nil
              && LureAccessFilter.canonicalCIDR("1.2.3.4/8 x") == nil && LureAccessFilter.canonicalCIDR("1.2.3.4") == nil, "o9.pf.canonicalCIDR")
        check(!LureAccessFilter.allows(peerIPv4: "+1.2.3.4", scope: .anywhere, localSubnets: []), "o9.scope.signedOctetRefused")
        let args = LureHelperArgs(port: 5000, scope: .localSubnet, localSubnets: evil).arguments
        check(args.filter { $0 == "--subnet" }.count == 1 && args.contains("10.0.0.0/8") && !args.contains { $0.contains("\n") }, "o9.args.onlyValidSubnets")
        check((try? LureHelperArgs.parse(["--lure", "--port", "5000", "--subnet", "1.2.3.4/+8"])) == nil, "o9.args.strictSubnet")
        check((try? TarpitServer(port: 0, scope: .localSubnet, localSubnets: ["192.168.1.0/24 }"])) == nil, "o9.tarpit.invalidSubnetsRefused")

        if let lp = try? LureContainment.plan(port: 5000, scope: .loopback, localSubnets: []),
           let pl = (try? PropertyListSerialization.propertyList(from: lp.launchdPlist, format: nil)) as? [String: Any] {
            let hard = pl["HardResourceLimits"] as? [String: Any]
            check((hard?["NumberOfFiles"] as? Int ?? 999) <= 64 && (hard?["FileSize"] as? Int) == 0 && (hard?["Core"] as? Int) == 0, "o9.launchd.limits")
            check((pl["KeepAlive"] as? Bool) == false && (pl["ThrottleInterval"] as? Int ?? 0) >= 10, "o9.launchd.noRespawnStorm")
            check(lp.pfAnchor.contains("block out quick user _rampartlure") && lp.pfAnchor.contains("block in quick on ! lo0"), "o9.pf.loopbackAnchor")
        } else { check(false, "o9.launchd.plan") }
    }

    // MARK: lure — resource exhaustion and log flooding

    static func o9LureLimits() {
        let rl = LureRateLimiter(perMinute: 3, maxPeers: 64)
        let t0 = Date()
        for i in 0..<500 { _ = rl.allow("10.0.\(i / 250).\(i % 250)", now: t0) }
        check(rl.trackedPeers <= 64, "o9.rate.tableBounded (\(rl.trackedPeers))")
        check(!rl.allow("10.9.9.9", now: t0.addingTimeInterval(1)), "o9.rate.fullTableFailsClosed")
        check(rl.allow("10.9.9.9", now: t0.addingTimeInterval(61)) && rl.trackedPeers <= 64, "o9.rate.recoversAfterWindow")

        let th = LureRefusalThrottle(globalPerMinute: 20)
        let samePeer = (0..<100).compactMap { _ in th.admit("10.0.0.1", now: t0) }.count
        check(samePeer == 1, "o9.refusal.perPeerOncePerMinute")
        let many = (0..<100).compactMap { th.admit("10.1.0.\($0)", now: t0) }.count
        check(many == 19, "o9.refusal.globalCap (\(many))")
        let later = th.admit("10.0.0.1", now: t0.addingTimeInterval(61))
        check(later == 81, "o9.refusal.suppressedCountReported (\(later ?? -1))")

        // Live: a connect flood from one address yields one recorded refusal, not one per connection.
        var limits = LureLimits(); limits.maxPerPeerPerMinute = 1; limits.idleTimeout = 1; limits.maxSessionSeconds = 3
        guard let tp = try? TarpitServer(port: 0, proto: .nasLogin, lineDelay: 0, limits: limits) else { check(false, "o9.flood.server"); return }
        let logged = NSLock(); var callbacks = 0
        tp.onAttempt = { _ in logged.lock(); callbacks += 1; logged.unlock() }
        do { try tp.start() } catch { check(false, "o9.flood.start \(error)"); return }
        defer { tp.stop() }
        for _ in 0..<60 {
            let s = socket(AF_INET, SOCK_STREAM, 0)
            var a = sockaddr_in(); a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); a.sin_family = sa_family_t(AF_INET)
            a.sin_port = tp.boundPort.bigEndian; inet_pton(AF_INET, "127.0.0.1", &a.sin_addr)
            _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            close(s)
        }
        for _ in 0..<100 where tp.recorded.filter({ $0.refused != nil }).count + tp.suppressedRefusals < 59 { usleep(20_000) }
        let refusedRecords = tp.recorded.filter { $0.refused != nil }.count
        check(refusedRecords == 1 && tp.suppressedRefusals >= 55, "o9.flood.refusalsThrottled (\(refusedRecords) recorded, \(tp.suppressedRefusals) suppressed)")
        logged.lock(); let cb = callbacks; logged.unlock()
        check(cb <= 2, "o9.flood.fewAlerts (\(cb))")
    }

    // MARK: lure — banners never leak anything real, never echo, bounded output

    static func o9LureBanners() {
        var hb = [CChar](repeating: 0, count: 256); gethostname(&hb, hb.count)
        let host = String(cString: hb).split(separator: ".").first.map(String.init) ?? "§none§"
        let user = NSUserName()
        let marker = "O9MARK\u{1b}[31m"
        let inputs = ["admin", "\(marker)", "GET /\(marker) HTTP/1.1", "POST /login HTTP/1.1", "SSH-2.0-\(marker)",
                      String(repeating: "A", count: 2000), "\u{0}\u{7}\u{8}", "root", "toor", "x", "y", "z"]
        var worstBytes = 0
        var leaked: [String] = []
        for proto in LureProtocol.allCases {
            for seed in 0..<12 {
                var sm = LureStateMachine(proto, seed: seed)
                var out = sm.greeting()
                for i in inputs { out += sm.input(i).lines }
                let text = out.joined(separator: "\r\n")
                worstBytes = max(worstBytes, text.utf8.count)
                for bad in [marker, "O9MARK", user, "RamPart", "rampart", "Rampart"] + (host.count >= 3 ? [host] : []) where text.contains(bad) {
                    leaked.append("\(proto.rawValue):\(bad)")
                }
                if text.unicodeScalars.contains(where: { $0.value == 0x1b || $0.value == 0 }) { leaked.append("\(proto.rawValue):control") }
            }
        }
        check(leaked.isEmpty, "o9.banner.noLeaksNoEcho \(Set(leaked).sorted())")
        // Amplification: a session's total reply is small and fixed (TCP only, so not spoofable / reflectable).
        check(worstBytes <= 2048, "o9.banner.boundedReply (\(worstBytes) bytes)")
    }

    // MARK: lure — the real helper under the generated sandbox profile (loopback only)

    static func o9LureLiveSandbox() {
        let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent().appendingPathComponent("rampart-lure").path
        guard FileManager.default.isExecutableFile(atPath: exe), FileManager.default.isExecutableFile(atPath: "/usr/bin/sandbox-exec"), getuid() != 0 else {
            check(true, "o9.live.skipped (no rampart-lure next to the selftest)"); return
        }
        let base = NSTemporaryDirectory() + "com.rampart.test.o9-\(getpid())-\(UInt32.random(in: 0...UInt32.max))"
        let work = base + "/jail", helper = base + "/rampart-lure", profile = base + "/lure.sb"
        try? FileManager.default.createDirectory(atPath: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: base) }
        // realpath, not resolvingSymlinksInPath (that strips "/private", and SBPL matches the real vnode path).
        guard let rp = realpath(base, nil) else { check(false, "o9.live.realpath"); return }
        let realBase = String(cString: rp); free(rp)
        guard (try? FileManager.default.copyItem(atPath: exe, toPath: helper)) != nil else { check(false, "o9.live.copy"); return }
        // A free loopback port.
        var port: UInt16 = 0
        do {
            let s = socket(AF_INET, SOCK_STREAM, 0)
            var a = sockaddr_in(); a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); a.sin_family = sa_family_t(AF_INET); inet_pton(AF_INET, "127.0.0.1", &a.sin_addr)
            _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
            port = UInt16(bigEndian: a.sin_port); close(s)
        }
        guard port >= 1024 else { check(true, "o9.live.skipped (no high port)"); return }
        let rHelper = realBase + "/rampart-lure", rWork = realBase + "/jail"
        try? LureContainment.sandboxProfile(port: port, workDir: rWork, helperPath: rHelper).write(toFile: profile, atomically: true, encoding: .utf8)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        p.arguments = ["-f", profile, rHelper] + LureHelperArgs(port: port, scope: .loopback).arguments
        p.currentDirectoryURL = URL(fileURLWithPath: rWork)
        p.environment = ["PATH": "/nonexistent", "RAMPART_NO_PRIVILEGED_TOOLS": "1"]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { check(false, "o9.live.launch"); return }
        defer { if p.isRunning { p.terminate() }; p.waitUntilExit() }
        var first = ""
        for _ in 0..<40 where first.isEmpty {
            usleep(100_000)
            first = o9FirstLine(port: port)
        }
        check(first.hasPrefix("BackupNAS"), "o9.live.servesUnderGeneratedProfile [\(first)]")
        check(p.isRunning, "o9.live.notKilledBySandbox")
    }

    static func o9FirstLine(port: UInt16) -> String {
        let s = socket(AF_INET, SOCK_STREAM, 0); guard s >= 0 else { return "" }
        defer { close(s) }
        var a = sockaddr_in(); a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); a.sin_family = sa_family_t(AF_INET)
        a.sin_port = port.bigEndian; inet_pton(AF_INET, "127.0.0.1", &a.sin_addr)
        guard withUnsafePointer(to: &a, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }) == 0 else { return "" }
        var tv = timeval(tv_sec: 2, tv_usec: 0); setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var buf = [UInt8](repeating: 0, count: 256)
        let n = recv(s, &buf, buf.count, 0)
        return n > 0 ? String(decoding: buf[0..<n], as: UTF8.self).components(separatedBy: "\r\n").first ?? "" : ""
    }

    // MARK: VPN — a .conf that tries to sneak things into ifconfig / route / scutil / pf

    static func o9VPNConfigInjection() {
        let priv = WGKey.base64(WGCrypto.generatePrivateKey()), pub = WGKey.base64(WGCrypto.randomBytes(32))
        func conf(address: String = "10.66.66.2/32", dns: String = "1.1.1.1", endpoint: String = "203.0.113.5:51820", allowed: String = "0.0.0.0/0") -> String {
            "[Interface]\nPrivateKey = \(priv)\nAddress = \(address)\nDNS = \(dns)\n\n[Peer]\nPublicKey = \(pub)\nEndpoint = \(endpoint)\nAllowedIPs = \(allowed)\n"
        }
        check((try? WGQuickConfig.parse(conf())) != nil, "o9.conf.baselineParses")
        let badEndpoints = ["1.2.3.4%x port 0:65535 to any:51820", "1.2.3.4%en0:51820", "[::1%lo0 port 1]:51820", "[fe80::1%en0]:51820",
                            "1.2.3.4:+51820", "1.2.3.4: 51820", "999.1.1.1:51820", "1.2.3.4\u{0}:51820"]
        for e in badEndpoints { check(WGQuickConfig.parseEndpoint(e) == nil && (try? WGQuickConfig.parse(conf(endpoint: e))) == nil, "o9.conf.endpointRefused \(e.debugDescription)") }
        check(WGQuickConfig.parseEndpoint("[2001:DB8:0::1]:51820").map { $0.host == "2001:db8::1" } == true, "o9.conf.endpointCanonical")
        for d in ["1.1.1.1%x 9.9.9.9", "1.1.1.1%x", "[1.1.1.1]"] { check((try? WGQuickConfig.parse(conf(dns: d))) == nil, "o9.conf.dnsRefused \(d)") }
        for a in ["10.0.0.2%x/32", "10.0.0.2/+32", "10.0.0.2/32 alias"] { check((try? WGQuickConfig.parse(conf(address: a))) == nil, "o9.conf.addressRefused \(a)") }
        for a in ["0.0.0.0/+0", "0.0.0.0%x/0", "::/0 -interface en0"] { check((try? WGQuickConfig.parse(conf(allowed: a))) == nil, "o9.conf.allowedRefused \(a)") }
        let many = (0..<300).map { "10.\($0 / 250).\($0 % 250).0/24" }.joined(separator: ", ")
        check((try? WGQuickConfig.parse(conf(allowed: many))) == nil, "o9.conf.allowedIPsCapped")
        check((try? WGQuickConfig.parse(conf() + "PostUp = /bin/sh -c 'touch /tmp/o9'\n"))?.warnings.contains { $0.contains("PostUp") } == true, "o9.conf.scriptsIgnored")
        check((try? HomeServerSetup.generate(endpointHost: "1.2.3.4%en0 x")) == nil && (try? HomeServerSetup.generate(endpointHost: "203.0.113.9")) != nil, "o9.home.strictHost")
    }

    // MARK: VPN — plan: tampered profile fails closed, IPv6 leak, kill-switch shape

    static func o9VPNPlan() {
        var c = WGQuickConfig(privateKey: WGCrypto.generatePrivateKey(), peerPublicKey: WGCrypto.randomBytes(32), endpointHost: "203.0.113.5", endpointPort: 51820)
        c.addresses = ["10.66.66.2/32"]; c.dnsServers = ["1.1.1.1\nset State:/Network/Global/DNS", "9.9.9.9"]; c.dnsSearch = ["ok.lan", "bad name\nquit"]
        c.allowedIPs = ["0.0.0.0/0"]
        // Tampered endpoint / interface (as if profile.json had been edited): no widened pass rule, still block all.
        let t = VPNNetworkPlan(interface: "utun7; pass all", config: c, endpointIP: "203.0.113.5 port 0:65535", localUDPPort: 40000,
                               gateway4: "192.168.1.1", gateway6: nil, dnsFilterActive: false, killSwitch: true)
        let tr = t.killSwitchRules()
        check(!tr.contains("pass all") && !tr.contains("0:65535") && !tr.contains("pass out quick inet proto udp from any port 40000")
              && tr.contains("block drop out quick all") && tr.contains("block drop in quick all"), "o9.plan.tamperedFailsClosed")
        let p = VPNNetworkPlan(interface: "utun7", config: c, endpointIP: "203.0.113.5", localUDPPort: 40000, gateway4: "192.168.1.1", gateway6: "fe80::1%en0",
                               dnsFilterActive: false, killSwitch: true)
        let dns = p.dnsUpCommand()?.stdin ?? ""
        check(!dns.contains("Global") && !dns.contains("bad name") && dns.contains("ServerAddresses * 9.9.9.9") && dns.contains("ok.lan"), "o9.plan.scutilInjection")
        // IPv4-only full tunnel: IPv6 must not leave through Wi-Fi.
        let up = p.routeUpCommands().map(\.description)
        check(up.contains("route -q -n add -inet6 ::/1 -interface utun7") && up.contains("route -q -n add -inet6 8000::/1 -interface utun7"), "o9.plan.ipv6LeakBlocked")
        check(p.routeDownCommands().count == up.count, "o9.plan.leakRoutesRemoved")
        let p6 = VPNNetworkPlan(interface: "utun7", config: c, endpointIP: "2001:db8::5", localUDPPort: 40000, gateway4: nil, gateway6: "fe80::1%en0",
                                dnsFilterActive: false, killSwitch: true)
        check(!p6.routeUpCommands().contains { $0.arguments.contains("::/1") }, "o9.plan.noLoopForV6Endpoint")
        // Kill switch: no LAN, no plain DNS, no IPv6 except ND / DHCPv6; the WireGuard flow only to the endpoint.
        let rules = p.killSwitchRules()
        check(!rules.contains("port 53") && !rules.contains("192.168.") && !rules.contains("10.0.0.0") && !rules.contains("pass out quick inet6 proto udp from any port 40000")
              && rules.contains("to 203.0.113.5 port 51820") && rules.hasSuffix("block drop in quick all\n\n"), "o9.plan.killSwitchShape")
        let passLines = rules.split(separator: "\n").filter { $0.hasPrefix("pass") }
        check(passLines.allSatisfy { $0.contains("lo0") || $0.contains("utun7") || $0.contains("port 67") || $0.contains("port 68") || $0.contains("port 547") || $0.contains("icmp6-type") || $0.contains("203.0.113.5") }, "o9.plan.killSwitchPassList")
    }

    // MARK: VPN — crash cleanup

    static func o9VPNCrashCleanup() {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory() + "com.rampart.test.o9vpn-\(getpid())-\(UInt32.random(in: 0...UInt32.max))")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try? Data(#"{"endpointIP":"203.0.113.5","endpointHostRoute":true}"#.utf8).write(to: dir.appendingPathComponent("system-state.json"))
        let runner = DryRunVPNRunner()
        let svc = VPNService(directory: dir, keyStore: MemoryVPNKeyStore(), runner: runner, live: false)
        svc.sweepStaleState()
        let log = runner.log.map(\.description)
        check(log.contains("route -q -n delete -inet 203.0.113.5"), "o9.crash.endpointRouteRemoved")
        check(log.contains { $0.hasPrefix("scutil") } && log.contains { $0.contains("pfctl -a com.apple/252.RampartVPN -F all") }, "o9.crash.dnsAndPfRemoved")
        check(!FileManager.default.fileExists(atPath: dir.appendingPathComponent("system-state.json").path), "o9.crash.stateCleared")
        runner.clear()
        try? Data(#"{"endpointIP":"1.2.3.4 -ifscope en0","endpointHostRoute":true}"#.utf8).write(to: dir.appendingPathComponent("system-state.json"))
        svc.sweepStaleState()
        check(!runner.log.contains { $0.executable.hasSuffix("route") }, "o9.crash.tamperedStateIgnored")
    }

    // MARK: VPN — utun framing

    static func o9VPNTunnelFraming() {
        let v4 = ipv4([10, 9, 0, 1], [10, 9, 0, 2], [1, 2, 3])
        let v6 = ipv6("fd00::1", "fd00::2", [1])
        check(UTunDevice.frame(v4).map { Array($0.prefix(4)) } == [0, 0, 0, UInt8(AF_INET)], "o9.utun.frameV4")
        check(UTunDevice.frame(v6).map { Array($0.prefix(4)) } == [0, 0, 0, UInt8(AF_INET6)], "o9.utun.frameV6")
        check(UTunDevice.frame([0x50] + [UInt8](repeating: 0, count: 40)) == nil && UTunDevice.frame([]) == nil && UTunDevice.frame([0x45, 0, 0]) == nil, "o9.utun.frameRejectsJunk")
        check(UTunDevice.unframe(ArraySlice(UTunDevice.frame(v4)!)) == v4 && UTunDevice.unframe(ArraySlice(UTunDevice.frame(v6)!)) == v6, "o9.utun.roundTrip")
        check(UTunDevice.unframe(ArraySlice([0, 0, 0, UInt8(AF_INET)] + v6)) == nil, "o9.utun.familyMismatch")
        check(UTunDevice.unframe([0, 0, 0, 2, 0x45]) == nil && UTunDevice.unframe([0, 0, 0, 2]) == nil, "o9.utun.shortFrame")
        check(UTunDevice.maxPacketsPerEvent > 0 && UTunDevice.maxPacketsPerEvent <= 1024, "o9.utun.boundedDrain")
    }

    // MARK: VPN — malicious peer packets (oversized, malformed, replayed, spoofed inner source)

    static func o9VPNMaliciousPeer() {
        let clock = VPNFakeClock()
        let ka = WGCrypto.generatePrivateKey(), kb = WGCrypto.generatePrivateKey()
        guard let pa = try? WGCrypto.publicKey(ka), let pb = try? WGCrypto.publicKey(kb),
              let a = try? WireGuardPeer(privateKey: ka, peer: WGPeerConfig(publicKey: pb, endpoint: WGEndpoint(host: "192.0.2.2", port: 51820),
                                                                            allowedIPs: [IPPrefix("0.0.0.0/0")!]), now: { clock.t }, jitter: { 0 }),
              let b = try? WireGuardPeer(privateKey: kb, peer: WGPeerConfig(publicKey: pa, endpoint: nil, allowedIPs: [IPPrefix("10.9.0.1/32")!]),
                                         now: { clock.t }, jitter: { 0 })
        else { check(false, "o9.peer.setup"); return }
        var toA: [[UInt8]] = [], toB: [[UInt8]] = [], gotB: [[UInt8]] = []
        a.sendUDP = { m, _ in toB.append(m) }; b.sendUDP = { m, _ in toA.append(m) }
        b.deliverPacket = { gotB.append($0) }
        func pump() {
            var n = 0
            while (!toA.isEmpty || !toB.isEmpty) && n < 100 {
                n += 1
                if !toB.isEmpty { b.receiveUDP(toB.removeFirst(), from: WGEndpoint(host: "192.0.2.1", port: 40000)) }
                if !toA.isEmpty { a.receiveUDP(toA.removeFirst(), from: WGEndpoint(host: "192.0.2.2", port: 51820)) }
            }
        }
        a.sendPacket(ipv4([10, 9, 0, 1], [10, 9, 0, 2], [1])); pump()
        guard b.stats.rxPackets == 1 else { check(false, "o9.peer.handshake"); return }
        let dropped0 = b.stats.droppedPackets
        // Junk from anyone on the internet: oversized, truncated, wrong types. Never delivered, never crash.
        var junk: [[UInt8]] = [[UInt8](repeating: 4, count: 65535), [4, 0, 0, 0] + [UInt8](repeating: 0xff, count: 65531),
                               [1, 0, 0, 0] + [UInt8](repeating: 0, count: 143), [1, 0, 0, 0] + [UInt8](repeating: 0, count: 200),
                               [2, 0, 0, 0] + [UInt8](repeating: 0, count: 87), [3, 0, 0, 0], [4, 0, 0, 0], [], [9, 9, 9, 9], [4, 1, 0, 0] + [UInt8](repeating: 0, count: 60)]
        for _ in 0..<50 { junk.append(WGCrypto.randomBytes(Int.random(in: 0...200))) }
        for j in junk { b.receiveUDP(j, from: WGEndpoint(host: "198.51.100.66", port: 1)) }
        check(gotB.count == 1 && b.stats.droppedPackets >= dropped0 + UInt64(junk.count) - 2 && b.endpoint?.host == "192.0.2.1", "o9.peer.junkDroppedEndpointKept")
        // Replay of a captured, valid data message.
        var captured: [[UInt8]] = []
        a.sendUDP = { m, _ in captured.append(m) }
        a.sendPacket(ipv4([10, 9, 0, 1], [10, 9, 0, 2], [2]))
        if let m = captured.last {
            b.receiveUDP(m, from: WGEndpoint(host: "192.0.2.1", port: 40000))
            b.receiveUDP(m, from: WGEndpoint(host: "198.51.100.66", port: 1))
            check(gotB.count == 2 && b.endpoint?.host == "192.0.2.1", "o9.peer.replayDroppedNoEndpointHijack")
        } else { check(false, "o9.peer.capture") }
        // Inner source outside the peer's AllowedIPs (a compromised server spoofing a LAN address).
        a.sendPacket(ipv4([192, 168, 1, 10], [10, 9, 0, 2], [3]))
        if let m = captured.last { b.receiveUDP(m, from: WGEndpoint(host: "192.0.2.1", port: 40000)) }
        check(gotB.count == 2, "o9.peer.spoofedInnerSourceDropped")
        // Inner packet claiming a longer IP length than it carries.
        var lying = ipv4([10, 9, 0, 1], [10, 9, 0, 2], [4]); lying[2] = 0xff; lying[3] = 0xff
        a.sendPacket(lying)
        if let m = captured.last { b.receiveUDP(m, from: WGEndpoint(host: "192.0.2.1", port: 40000)) }
        check(gotB.count == 2, "o9.peer.lyingLengthDropped")
    }
}

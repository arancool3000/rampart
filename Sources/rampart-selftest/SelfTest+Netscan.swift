import Foundation
import RampartShared
import RampartNetwork

// Owned by the netscan build agent (N1). Pure parser/fixture checks only. A live LAN scan sends multicast and
// unicast packets, which pops the macOS Local Network permission dialog for a fresh binary, so it only runs
// when RAMPART_NETSCAN_LIVE=1 is set explicitly.

fileprivate final class NetscanBox<T>: @unchecked Sendable { var value: T? }
fileprivate func netscanAwait<T>(_ op: @escaping @Sendable () async -> T) -> T {
    let box = NetscanBox<T>(), sem = DispatchSemaphore(value: 0)
    Task.detached { box.value = await op(); sem.signal() }
    sem.wait()
    return box.value!
}

extension SelfTest {
    static func netscan() {
        netscanOUI()
        netscanRouteTable()
        netscanSubnetScope()
        netscanRateLimiter()
        netscanSSDP()
        netscanMDNS()
        netscanParsers()
        netscanFindingsAndScore()
        netscanKnownDevices()
        netscanCodable()
        netscanLoopbackProbe()
        if ProcessInfo.processInfo.environment["RAMPART_NETSCAN_LIVE"] == "1" { netscanLive() }
        else { print("   (live subnet scan skipped: set RAMPART_NETSCAN_LIVE=1 to run it; it triggers the Local Network prompt)") }
    }

    // MARK: OUI + device type

    static func netscanOUI() {
        check(OUITable.count > 800, "oui table has a useful number of prefixes (\(OUITable.count))")
        check(OUITable.vendor(for: "B8:27:EB:12:34:56") == "Raspberry Pi", "oui raspberry pi")
        check(OUITable.vendor(for: "3c:07:54:aa:bb:cc") == "Apple", "oui apple")
        check(OUITable.vendor(for: "0:17:88:1:2:3") == "Philips Hue", "oui unpadded octets normalised")
        check(OUITable.vendor(for: "00-17-88-01-02-03") == "Philips Hue", "oui dash separators")
        check(OUITable.vendor(for: "ff:ff:ff:00:00:00") == nil, "oui unknown prefix → nil")
        check(OUITable.vendor(for: "garbage") == nil, "oui malformed → nil")
        check(OUITable.isLocallyAdministered("0a:64:ba:c8:9d:63"), "locally administered bit detected")
        check(!OUITable.isLocallyAdministered("b8:27:eb:00:00:01"), "globally unique MAC not flagged")
        check(OUITable.normalize("A:B:C:D:E:F") == "0a:0b:0c:0d:0e:0f", "normalize pads and lowercases")

        check(DeviceTypeGuesser.guess(vendor: "Apple", hostname: nil, mdnsName: nil, model: "MacBookPro18,3", services: [], ssdpServer: nil, openPorts: [], isGateway: false) == .laptop, "type: macbook model")
        check(DeviceTypeGuesser.guess(vendor: "Apple", hostname: "Living-Room.local", mdnsName: nil, model: nil, services: ["_airplay._tcp", "_raop._tcp"], ssdpServer: nil, openPorts: [], isGateway: false) == .appleTV, "type: apple + airplay")
        check(DeviceTypeGuesser.guess(vendor: "Apple", hostname: nil, mdnsName: nil, model: nil, services: ["_companion-link._tcp"], ssdpServer: nil, openPorts: [], isGateway: false) == .iPhone, "type: apple companion-link → iPhone")
        check(DeviceTypeGuesser.guess(vendor: "HP", hostname: nil, mdnsName: nil, model: nil, services: ["_ipp._tcp"], ssdpServer: nil, openPorts: [], isGateway: false) == .printer, "type: ipp → printer")
        check(DeviceTypeGuesser.guess(vendor: "Hikvision", hostname: nil, mdnsName: nil, model: nil, services: [], ssdpServer: nil, openPorts: [554], isGateway: false) == .camera, "type: hikvision → camera")
        check(DeviceTypeGuesser.guess(vendor: "TP-Link", hostname: nil, mdnsName: nil, model: nil, services: [], ssdpServer: nil, openPorts: [80], isGateway: true) == .router, "type: gateway → router")
        check(DeviceTypeGuesser.guess(vendor: nil, hostname: nil, mdnsName: nil, model: nil, services: [], ssdpServer: "Roku/12.0 UPnP/1.0", openPorts: [], isGateway: false) == .streamingStick, "type: ssdp server roku")
        check(DeviceTypeGuesser.guess(vendor: "Espressif", hostname: nil, mdnsName: nil, model: nil, services: [], ssdpServer: nil, openPorts: [], isGateway: false) == .iot, "type: espressif → iot")
        check(DeviceTypeGuesser.guess(vendor: nil, hostname: nil, mdnsName: nil, model: nil, services: [], ssdpServer: nil, openPorts: [], isGateway: false) == .unknown, "type: nothing known → unknown")
    }

    // MARK: Route table (ARP) parsing from fixture bytes

    static func netscanRouteTable() {
        let r1 = ARPTable.fixtureRecord(ip: "192.168.1.1", mac: [0xb8, 0x27, 0xeb, 0x01, 0x02, 0x03], ifIndex: 4)
        let r2 = ARPTable.fixtureRecord(ip: "192.168.1.254", mac: [0x3c, 0x84, 0x6a, 0xaa, 0xbb, 0xcc], ifIndex: 4, flags: RTF_HOST | RTF_LLINFO | RTF_STATIC)
        let incomplete = ARPTable.fixtureRecord(ip: "192.168.1.77", mac: [], ifIndex: 4)              // alen 0: unresolved
        let bcast = ARPTable.fixtureRecord(ip: "192.168.1.255", mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff], ifIndex: 4)
        let parsed = ARPTable.parse(r1 + incomplete + r2 + bcast)
        check(parsed.count == 2, "route table: 2 resolved entries (incomplete + broadcast skipped), got \(parsed.count)")
        check(parsed.first?.ip == "192.168.1.1" && parsed.first?.mac == "b8:27:eb:01:02:03", "route table: dst + lladdr decoded")
        check(parsed.last?.permanent == true && parsed.first?.permanent == false, "route table: RTF_STATIC → permanent")
        check(parsed.first?.interfaceIndex == 4, "route table: interface index")
        check(ARPTable.parse([]).isEmpty, "route table: empty input")
        check(ARPTable.parse(Array(r1.prefix(30))).isEmpty, "route table: truncated record ignored")
        var corrupt = r1; corrupt[0] = 0; corrupt[1] = 0
        check(ARPTable.parse(corrupt).isEmpty, "route table: zero msglen stops the walk")
        // Passive read of the live table must never crash (it may be empty under Local Network privacy).
        _ = ARPTable.parse(ARPTable.sysctlBytes())
        check(true, "route table: live sysctl read is safe")
        let viaArp = WiFiGuard.parseARP("? (192.168.1.67) at c4:b3:1:a0:f0:c on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]")
        check(viaArp.count == 1 && viaArp[0].mac == "c4:b3:01:a0:f0:0c", "arp -an fallback parse reused from WiFiGuard")
    }

    // MARK: Scope

    static func netscanSubnetScope() {
        func sub(_ net: String, _ prefix: Int) -> NetSubnet { NetSubnet(interface: "en0", address: net, netmask: "", prefix: prefix, network: net) }
        check(sub("192.168.1.0", 24).scopeError() == nil, "scope: 192.168.1.0/24 allowed")
        check(sub("10.20.0.0", 22).scopeError() == nil, "scope: /22 allowed (largest)")
        check(sub("10.20.0.0", 21).scopeError() == .tooLarge(prefix: 21), "scope: /21 refused")
        check(sub("10.0.0.0", 8).scopeError() == .tooLarge(prefix: 8), "scope: 10/8 refused")
        check(sub("8.8.8.0", 24).scopeError() == .notPrivate("8.8.8.0/24"), "scope: public range refused")
        check(sub("100.64.0.0", 24).scopeError() == .notPrivate("100.64.0.0/24"), "scope: CGNAT refused")
        check(sub("172.16.5.0", 24).scopeError() == nil && sub("172.32.0.0", 24).scopeError() != nil, "scope: 172.16/12 boundary")
        check(sub("169.254.0.0", 16).scopeError() == .linkLocal, "scope: link-local refused")
        check(sub("127.0.0.0", 8).scopeError() == .loopback, "scope: loopback refused")
        check(sub("not.an.ip", 24).scopeError() == .invalid, "scope: invalid")
        let s = NetSubnet.make(interface: "en0", address: "192.168.1.107", netmask: "255.255.255.0", gateway: "192.168.1.254", isWiFi: true)
        check(s?.network == "192.168.1.0" && s?.prefix == 24 && s?.cidr == "192.168.1.0/24", "subnet: network from address+mask")
        check(s?.hostAddresses().count == 254 && s?.hostAddresses().first == "192.168.1.1" && s?.hostAddresses().last == "192.168.1.254", "subnet: 254 hosts")
        check(s?.contains("192.168.1.9") == true && s?.contains("192.168.2.9") == false, "subnet: contains")
        check(NetSubnet.make(interface: "en0", address: "10.0.0.5", netmask: "255.255.0.255", gateway: nil, isWiFi: false) == nil, "subnet: non-contiguous mask rejected")
        check(IPv4.prefixLength(mask: 0xFFFFFC00) == 22, "ipv4: /22 mask")
        let route = NetInterfaces.parseDefaultRoute("   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.254\n  interface: en0\n      flags: <UP,GATEWAY>")
        check(route.gateway == "192.168.1.254" && route.interface == "en0", "route -n get default parsed")
    }

    // MARK: Rate limiter (pure: simulated clock)

    static func netscanRateLimiter() {
        let l = ProbeRateLimiter(rate: 50)
        let t0: TimeInterval = 1000
        var waits: [TimeInterval] = []
        for _ in 0..<101 { waits.append(l.reserve(now: t0)) }
        check(waits[0] == 0, "limiter: first probe immediate")
        check(abs(waits[50] - 1.0) < 0.001, "limiter: 51st probe waits 1 s at 50/s")
        check(abs(waits[100] - 2.0) < 0.001, "limiter: 101st probe waits 2 s")
        check(l.issued == 101, "limiter: counts issued probes")
        let later = l.reserve(now: t0 + 10)
        check(later == 0, "limiter: idle period frees slots without bursting")
        check(ProbeRateLimiter(rate: 500).rate == 50, "limiter: hard ceiling 50/s")
        check(ProbeRateLimiter(rate: 0).rate == 1, "limiter: floor 1/s")
    }

    // MARK: SSDP / UPnP

    static func netscanSSDP() {
        let resp = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://192.168.1.254:1900/igd.xml\r\nSERVER: Linux/3.10 UPnP/1.0 MiniUPnPd/2.1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:1234::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        let r = SSDPResponse.parse(resp)
        check(r?.location == "http://192.168.1.254:1900/igd.xml", "ssdp: LOCATION")
        check(r?.server == "Linux/3.10 UPnP/1.0 MiniUPnPd/2.1", "ssdp: SERVER")
        check(r?.isInternetGateway == true, "ssdp: IGD recognised")
        check(SSDPResponse.parse("HTTP/1.1 404 Not Found\r\n\r\n") == nil, "ssdp: non-200 ignored")
        check(SSDPResponse.parse("garbage") == nil, "ssdp: garbage ignored")
        let notify = "NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\nSERVER: Roku/12.0 UPnP/1.0\r\n\r\n"
        check(SSDPResponse.parse(notify)?.st == "urn:dial-multiscreen-org:service:dial:1", "ssdp: NOTIFY uses NT")
        check(SSDPResponse.parse(notify)?.isInternetGateway == false, "ssdp: non-IGD")
        let xml = """
        <?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
        <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
        <friendlyName>Home Hub</friendlyName><manufacturer>Sagemcom</manufacturer><modelName>Fast 5364</modelName>
        <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType></service></serviceList>
        </device></deviceList></device></root>
        """
        let d = UPnPDescription.parse(xml)
        check(d.friendlyName == "Home Hub" && d.modelName == "Fast 5364" && d.manufacturer == "Sagemcom", "upnp: description fields")
        check(d.deviceTypes.count == 2 && d.serviceTypes.count == 1 && d.isInternetGateway, "upnp: nested device/service types + IGD")
        check(!UPnPDescription.parse("<root><device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType></device></root>").isInternetGateway, "upnp: media renderer not IGD")
    }

    // MARK: mDNS

    static func netscanMDNS() {
        var m = DNSMessage(id: 0, flags: 0x8400)
        // Case-preserving wire encoder (DNSWire.encodeName lowercases; real responders keep the instance's case).
        func name(_ s: String) -> Data {
            var out = Data()
            for label in s.split(separator: ".") { let b = Array(label.utf8); out.append(UInt8(b.count)); out.append(contentsOf: b) }
            out.append(0); return out
        }
        m.answers.append(DNSResourceRecord(name: "_airplay._tcp.local", type: DNSType.ptr, ttl: 4500, rdata: name("Living\\032Room._airplay._tcp.local")))
        m.answers.append(DNSResourceRecord(name: "_services._dns-sd._udp.local", type: DNSType.ptr, ttl: 4500, rdata: name("_raop._tcp.local")))
        m.additionals.append(DNSResourceRecord(name: "Living\\032Room._airplay._tcp.local", type: DNSType.srv, ttl: 120,
                                               rdata: Data([0, 0, 0, 0, 0x1b, 0x58]) + name("Living-Room.local")))
        var txt = Data()
        for kv in ["model=AppleTV14,1", "srcvers=670.6.2", "flags=0x244"] { txt.append(UInt8(kv.utf8.count)); txt.append(contentsOf: Array(kv.utf8)) }
        m.additionals.append(DNSResourceRecord(name: "Living\\032Room._airplay._tcp.local", type: DNSType.txt, ttl: 4500, rdata: txt))
        m.additionals.append(DNSResourceRecord(name: "Living-Room.local", type: DNSType.a, ttl: 120, rdata: Data([192, 168, 1, 40])))
        m.answers.append(DNSResourceRecord(name: "40.1.168.192.in-addr.arpa", type: DNSType.ptr, ttl: 120, rdata: name("Living-Room.local")))
        let data = m.serialize()
        guard let info = MDNSParser.parse(data) else { check(false, "mdns: parse response"); return }
        check(info.services.contains("_airplay._tcp") && info.services.contains("_raop._tcp"), "mdns: service types from PTR + _services enumeration")
        check(info.instances.contains("Living Room"), "mdns: instance name unescaped (\\032 → space): \(info.instances)")
        check(info.hostnames.contains("living-room.local"), "mdns: hostname from SRV target / A / reverse PTR")
        check(info.model == "AppleTV14,1", "mdns: model from TXT")
        check(info.txt["srcvers"] == "670.6.2", "mdns: TXT key/values")
        check(MDNSParser.parseTXT(Data([0])) .isEmpty, "mdns: empty TXT")
        check(MDNSParser.parseTXT(Data([3, 0x61, 0x3d, 0x62, 2, 0x63, 0x64])) == ["a": "b", "cd": ""], "mdns: TXT flag without value")
        check(MDNSParser.parse(MDNSParser.query(names: ["_http._tcp.local"])) == nil, "mdns: a query is not a response")
        check(MDNSParser.reverseName("192.168.1.40") == "40.1.168.192.in-addr.arpa", "mdns: reverse name")
        let q = try? DNSMessage.parse(MDNSParser.query(names: ["_airplay._tcp.local", "_ipp._tcp.local"]))
        check(q?.questions.count == 2 && q?.questions.first?.type == DNSType.ptr && q?.isResponse == false, "mdns: query serialises as 2 PTR questions")
    }

    // MARK: Firewall / DNS parsers

    static func netscanParsers() {
        check(FirewallCheck.parseGlobalState("Firewall is enabled. (State = 1)") == true, "fw: enabled")
        check(FirewallCheck.parseGlobalState("Firewall is disabled. (State = 0)") == false, "fw: disabled")
        check(FirewallCheck.parseStealth("Firewall stealth mode is on") == false && FirewallCheck.parseStealth("Stealth mode enabled") == true, "fw: stealth")
        check(FirewallCheck.parseBlockAll("Block all DISABLED!") == false, "fw: block all disabled")
        check(FirewallCheck.parseAllowSigned("Automatically allow signed built-in software ENABLED\nAutomatically allow downloaded signed software ENABLED") == true, "fw: allow signed")
        let apps = FirewallCheck.parseListApps("ALF: total number of apps = 2 \n\n1 :  /Applications/Zoom.app \n \t ( Allow incoming connections ) \n2 :  /Users/me/tool \n \t ( Block incoming connections ) \n")
        check(apps.allowed == ["/Applications/Zoom.app"] && apps.blocked == ["/Users/me/tool"], "fw: listapps parsed \(apps)")
        let st = AppFirewallState(enabled: true, blockAll: false, stealth: true, allowSigned: true, blockedApps: ["/Users/me/tool"], allowedApps: ["/Applications/Zoom.app"])
        check(FirewallCheck.verdict(for: "/Users/me/tool", signing: .adHoc, exposure: .network, state: st) == .blocked, "fw verdict: explicit block")
        check(FirewallCheck.verdict(for: "/Applications/Zoom.app/Contents/MacOS/zoom", signing: .developerID, exposure: .network, state: st) == .allowed, "fw verdict: bundle prefix allowed")
        check(FirewallCheck.verdict(for: "/usr/sbin/sshd", signing: .apple, exposure: .network, state: st) == .allowedBuiltIn, "fw verdict: apple built-in")
        check(FirewallCheck.verdict(for: "/tmp/x", signing: .unsigned, exposure: .loopback, state: st) == .allowedBuiltIn, "fw verdict: loopback never crosses the firewall")
        check(FirewallCheck.verdict(for: "/tmp/x", signing: .unsigned, exposure: .network, state: AppFirewallState(enabled: false)) == .firewallOff, "fw verdict: firewall off")
        check(FirewallCheck.verdict(for: "/tmp/x", signing: .unsigned, exposure: .network, state: st) == .unknown, "fw verdict: unsigned unknown (macOS will ask)")
        check(FirewallCheck.verdict(for: "/tmp/x", signing: .unsigned, exposure: .network, state: AppFirewallState(enabled: true, blockAll: true)) == .blocked, "fw verdict: block all")

        let scutil = """
        DNS configuration

        resolver #1
          search domain[0] : home
          nameserver[0] : 192.168.1.254
          nameserver[1] : 1.1.1.1
          if_index : 14 (en0)
          flags    : Request A records
          reach    : 0x00020002 (Reachable,Directly Reachable Address)

        resolver #2
          domain   : local
          options  : mdns
          nameserver[0] : 203.0.113.9

        DNS configuration (for scoped queries)

        resolver #1
          nameserver[0] : 10.9.9.9
        """
        let servers = DNSResolverCheck.parseScutil(scutil)
        check(servers == ["192.168.1.254", "1.1.1.1"], "dns: scutil resolver #1 servers only: \(servers)")
        let sub = NetSubnet(interface: "en0", address: "192.168.1.107", netmask: "255.255.255.0", prefix: 24, network: "192.168.1.0", gateway: "192.168.1.254")
        check(DNSResolverCheck.verdict("192.168.1.254", subnet: sub, gateway: "192.168.1.254").status == .router, "dns verdict: router")
        check(DNSResolverCheck.verdict("1.1.1.1", subnet: sub, gateway: "192.168.1.254").status == .knownGood, "dns verdict: cloudflare")
        check(DNSResolverCheck.verdict("9.9.9.9", subnet: sub, gateway: nil).name == "Quad9", "dns verdict: quad9 named")
        check(DNSResolverCheck.verdict("127.0.0.1", subnet: sub, gateway: nil).status == .local, "dns verdict: local resolver (RamPart web protection)")
        check(DNSResolverCheck.verdict("203.0.113.9", subnet: sub, gateway: nil).status == .unknown, "dns verdict: unknown public resolver flagged")
        check(DNSResolverCheck.verdict("2606:4700:4700::1111", subnet: sub, gateway: nil).status == .knownGood, "dns verdict: ipv6 cloudflare")
        check(DNSResolverCheck.verdict("fe80::1%en0", subnet: sub, gateway: nil).status == .local, "dns verdict: link-local v6")

        check(RiskyPort.catalogue.count == 13 && RiskyPort.tcpPorts == [21, 23, 445, 3389, 5900, 1883, 554, 8080, 8443, 7547, 9100, 32400], "risky port list is exactly the agreed set")
        check(RiskyPort.find(23)?.severity == .critical && RiskyPort.find(1900, proto: "udp") != nil && RiskyPort.find(22) == nil, "risky port lookup")
        check(RiskyPort.catalogue.allSatisfy { !$0.explanation.isEmpty && !$0.fix.isEmpty }, "every risky port has an explanation and a fix")
        check(ICMPProbe.isEchoReply(Data([0x45, 0, 0, 0x1c, 0, 0, 0, 0, 64, 1, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0])), "icmp: echo reply after ip header")
        check(!ICMPProbe.isEchoReply(Data([0x45, 0, 0, 0x1c, 0, 0, 0, 0, 64, 1, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 3, 1, 0, 0])), "icmp: unreachable is not a reply")
        check(ICMPProbe.checksum([8, 0, 0, 0, 0, 1, 0, 1]) == 0xF7FD, "icmp: checksum")
    }

    // MARK: Findings + score

    static func netscanFindingsAndScore() {
        check(NetScanScoring.score(findings: [], newUntrustedDevices: 0) == 100, "score: clean network 100")
        func f(_ id: String, _ k: NetFinding.Kind, _ s: Severity) -> NetFinding { NetFinding(id: id, kind: k, severity: s, title: id, detail: "", fix: "") }
        check(NetScanScoring.score(findings: [f("a", .device, .critical)], newUntrustedDevices: 0) == 70, "score: one critical → 70")
        check(NetScanScoring.score(findings: [f("a", .device, .medium), f("b", .device, .medium), f("c", .device, .medium)], newUntrustedDevices: 0) == 84, "score: same-kind decay 9 + 4.5 + 2.25")
        check(NetScanScoring.score(findings: [f("a", .router, .medium), f("b", .dns, .high)], newUntrustedDevices: 0) == 73, "score: different kinds add fully")
        check(NetScanScoring.score(findings: [], newUntrustedDevices: 9) == 90, "score: new devices cost max 10")
        check(NetScanScoring.score(findings: (0..<20).map { f("\($0)", .init(rawValue: ["router", "dns", "upnp", "device", "wifi"][$0 % 5])!, .critical) }, newUntrustedDevices: 0) == 0, "score: clamps at 0")
        check(NetScanScoring.label(for: 95) == "Looks good" && NetScanScoring.label(for: 40) == "At risk", "score labels")

        var r = RouterReport(ip: "192.168.1.254", httpOpen: true, httpsOpen: false, upnpIGD: true,
                             dnsServers: ["192.168.1.254", "203.0.113.9"],
                             dnsVerdicts: [DNSResolverVerdict(server: "192.168.1.254", status: .router), DNSResolverVerdict(server: "203.0.113.9", status: .unknown)])
        var rf = NetworkScanner.routerFindings(r)
        check(rf.contains { $0.id == "router.http" } && rf.contains { $0.id == "router.upnp" } && rf.contains { $0.id == "dns.203.0.113.9" }, "router findings: http-only, upnp, unknown dns")
        check(!rf.contains { $0.id == "router.macchanged" }, "router findings: no mac change")
        r.httpRedirectsToHTTPS = true; r.upnpIGD = false; r.dnsVerdicts = [DNSResolverVerdict(server: "1.1.1.1", status: .knownGood)]; r.gatewayMACChanged = true
        rf = NetworkScanner.routerFindings(r)
        check(rf.map(\.id) == ["router.macchanged"], "router findings: redirect to https is fine; mac change flagged: \(rf.map(\.id))")
        check(rf.allSatisfy { !$0.fix.isEmpty && !$0.detail.isEmpty }, "router findings carry fix advice")

        let listeners = [
            LocalListener(port: 5900, proto: "tcp", address: "0.0.0.0", pid: 1, processName: "screensharingd", processPath: "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle", signing: .apple, exposure: .network, firewall: .allowedBuiltIn),
            LocalListener(port: 8000, proto: "tcp", address: "127.0.0.1", pid: 2, processName: "python3", processPath: "/usr/bin/python3", signing: .apple, exposure: .loopback, firewall: .allowedBuiltIn),
            LocalListener(port: 4444, proto: "tcp", address: "*", pid: 3, processName: "mystery", processPath: "/tmp/mystery", signing: .unsigned, exposure: .network, firewall: .unknown),
            LocalListener(port: 445, proto: "tcp", address: "*", pid: 4, processName: "smbd", processPath: "/usr/sbin/smbd", signing: .apple, exposure: .network, firewall: .blocked),
        ]
        let lf = NetworkScanner.listenerFindings(listeners, firewall: AppFirewallState(enabled: false))
        check(lf.contains { $0.id == "mac.firewall" }, "listener findings: firewall off")
        check(lf.first { $0.id == "mac.port.tcp.5900" }?.severity == .high, "listener findings: screen sharing high")
        check(lf.contains { $0.id == "mac.unsigned.tcp.4444" }, "listener findings: unsigned network listener")
        check(lf.first { $0.id == "mac.port.tcp.445" }?.severity == .low, "listener findings: firewall-blocked SMB downgraded to low")
        check(!lf.contains { $0.id.contains("8000") }, "listener findings: loopback listener ignored")
    }

    // MARK: Known devices

    static func netscanKnownDevices() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rampart-netscan-\(getpid())")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("known.json")
        let store = KnownDeviceStore(url: url)
        let me = NetDevice(id: "aa:aa:aa:aa:aa:01", ip: "192.168.1.107", mac: "aa:aa:aa:aa:aa:01", isThisMac: true)
        let gw = NetDevice(id: "aa:aa:aa:aa:aa:02", ip: "192.168.1.254", mac: "aa:aa:aa:aa:aa:02", isGateway: true)
        let first = store.merge([me, gw], at: Date(timeIntervalSinceNow: -3600))
        check(first.allSatisfy { !$0.isNew }, "known: first scan marks nothing new")
        let stranger = NetDevice(id: "aa:aa:aa:aa:aa:03", ip: "192.168.1.9", mac: "aa:aa:aa:aa:aa:03", vendor: "Espressif")
        let second = store.merge([me, gw, stranger])
        check(second.first { $0.id == stranger.id }?.isNew == true && second.first { $0.id == gw.id }?.isNew == false, "known: second scan flags the newcomer only")
        check(store.device(id: gw.id)?.seenCount == 2, "known: seen count increments")
        store.rename(id: stranger.id, name: "Garden sensor"); store.setTrusted(id: stranger.id, true)
        let reloaded = KnownDeviceStore(url: url)
        check(reloaded.device(id: stranger.id)?.name == "Garden sensor" && reloaded.device(id: stranger.id)?.trusted == true, "known: name + trust persisted")
        let third = reloaded.merge([me, gw, stranger])
        check(third.first { $0.id == stranger.id }?.displayName == "Garden sensor" && third.first { $0.id == stranger.id }?.trusted == true, "known: merge applies name and trust")
        check(third.first { $0.id == stranger.id }?.isNew == false, "known: no longer new on the third scan")
        reloaded.forget(id: stranger.id)
        check(reloaded.device(id: stranger.id) == nil, "known: forget")
        check(NetDevice(id: "x", ip: "10.0.0.5", vendor: "Sonos", type: .speaker).displayName == "Sonos speaker", "display name: vendor + type")
        check(NetDevice(id: "x", ip: "10.0.0.5", hostname: "printer.local").displayName == "printer", "display name: hostname without .local")
        check(NetDevice(id: "x", ip: "10.0.0.5").displayName == "10.0.0.5", "display name: falls back to ip")
    }

    // MARK: Codable

    static func netscanCodable() {
        let sub = NetSubnet(interface: "en0", address: "192.168.1.107", netmask: "255.255.255.0", prefix: 24, network: "192.168.1.0", gateway: "192.168.1.254", isWiFi: true)
        let dev = NetDevice(id: "aa:bb:cc:dd:ee:ff", ip: "192.168.1.40", mac: "aa:bb:cc:dd:ee:ff", vendor: "Apple", mdnsName: "Living Room", services: ["_airplay._tcp"],
                            type: .appleTV, openPorts: [RiskyPort.find(8080)!.finding()], discoveredBy: ["arp", "mdns"])
        let report = NetScanReport(duration: 12.5, subnet: sub, devices: [dev], router: RouterReport(ip: "192.168.1.254", httpOpen: true),
                                   localListeners: [], firewall: AppFirewallState(enabled: true), findings: NetworkScanner.routerFindings(RouterReport(ip: "192.168.1.254", httpOpen: true)),
                                   score: 91, probesSent: 300, limitations: ["x"], wifiSecurity: "WPA3 Personal")
        guard let data = try? JSONEncoder.rampart.encode(report), let back = try? JSONDecoder.rampart.decode(NetScanReport.self, from: data) else {
            check(false, "report codable roundtrip"); return
        }
        check(back.id == report.id && back.devices.map(\.id) == report.devices.map(\.id) && back.devices.first?.openPorts == report.devices.first?.openPorts && back.devices.first?.services == ["_airplay._tcp"] && back.findings == report.findings && back.score == 91 && back.subnet == report.subnet && back.router == report.router, "report codable roundtrip equal")
        check(back.devices.first?.type == .appleTV && back.devices.first?.openPorts.first?.port == 8080, "report codable nested types")
        check(back.gateway == nil && back.newDevices.isEmpty, "report helpers")
    }

    // MARK: Loopback-only probe (no LAN traffic, no prompt)

    static func netscanLoopbackProbe() {
        // Bind a listener on loopback, then connect to it and to a closed port.
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        var sin = sockaddr_in(); sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = 0; sin.sin_addr.s_addr = UInt32(0x7F000001).bigEndian
        _ = withUnsafePointer(to: &sin) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        listen(fd, 4)
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        let port = Int(UInt16(bigEndian: bound.sin_port))
        defer { close(fd) }
        let open = netscanAwait { await TCPProbe.connect(ip: "127.0.0.1", port: port, timeout: 1) }
        check(open == .open, "tcp probe: loopback listener reported open (\(open))")
        let closed = netscanAwait { await TCPProbe.connect(ip: "127.0.0.1", port: 1, timeout: 1) }
        check(closed == .closed, "tcp probe: closed loopback port reported closed (\(closed))")
        let bad = netscanAwait { await TCPProbe.connect(ip: "not-an-ip", port: 80, timeout: 1) }
        check(bad == .error, "tcp probe: invalid address → error")
        let candidates = NetworkScanner.candidateSubnets()
        check(true, "candidate subnets enumerated: \(candidates.map { "\($0.0.cidr) via \($0.0.interface)\($0.1.map { " (refused: \($0))" } ?? "")" })")
    }

    // MARK: Live (opt-in only)

    static func netscanLive() {
        var opts = NetworkScanner.Options()
        opts.maxDuration = 45; opts.tcpTimeout = 0.7
        let o = opts
        let scanner = NetworkScanner(knownDevices: KnownDeviceStore(url: nil), reportURL: nil)
        let result: Result<NetScanReport, Error> = netscanAwait {
            do { return .success(try await scanner.scan(options: o) { p in print("   \(p.phase.rawValue) \(Int(p.fraction * 100))% \(p.message)") }) }
            catch { return .failure(error) }
        }
        switch result {
        case .success(let r):
            check(r.subnet.scopeError() == nil, "live: scanned subnet within scope")
            check(r.devices.contains { $0.isThisMac }, "live: this Mac listed")
            check(r.probesSent <= Int(o.maxDuration * 50) + 10, "live: probes within rate ceiling")
            print("   live: \(r.devices.count) devices (\(r.devices.filter { $0.mac != nil }.count) with MAC, \(r.devices.filter { $0.vendor != nil }.count) with vendor), " +
                  "\(r.findings.count) findings, \(r.localListeners.count) local listeners, score \(r.score), \(r.probesSent) probes in \(Int(r.duration)) s")
            for f in r.findings { print("   - [\(f.severity.label)] \(f.title)") }
            for l in r.limitations { print("   ! \(l)") }
        case .failure(let e):
            check(false, "live scan failed: \(e)")
        }
    }
}

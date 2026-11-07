import Foundation
import RampartShared

/// Home-network security scanner. Consent-based: nothing is sent until `scan()` is called, and only the
/// Mac's own directly connected private IPv4 subnet (/22 or smaller) is ever probed, at ≤ 50 probes/s.
///
/// Note for development: a live scan sends multicast (mDNS/SSDP) and unicast LAN packets, which triggers the
/// macOS Local Network permission prompt for a freshly built binary. Only the app, at the user's request,
/// should call `scan()`.
public final class NetworkScanner: @unchecked Sendable {
    public struct Options: Sendable {
        public var probesPerSecond: Double = 50
        public var maxDuration: TimeInterval = 90
        public var tcpTimeout: TimeInterval = 1.0
        public var sweepPorts: [Int] = [80, 443]            // discovery-only connect probes (plus ICMP)
        public var riskyPorts: [Int] = RiskyPort.tcpPorts
        public var useMDNS = true
        public var useSSDP = true
        public var useICMP = true
        public var checkLocalListeners = true
        public var checkRouter = true
        public var subnet: NetSubnet? = nil                // nil: pick the default-route interface
        public init() {}
    }

    public let knownDevices: KnownDeviceStore
    public let wifiGuard: WiFiGuard
    public let reportURL: URL?

    public init(knownDevices: KnownDeviceStore = KnownDeviceStore(), wifiGuard: WiFiGuard = WiFiGuard(),
                reportURL: URL? = Paths.effectiveRoot.appendingPathComponent("netscan-last.json")) {
        self.knownDevices = knownDevices; self.wifiGuard = wifiGuard; self.reportURL = reportURL
    }

    // MARK: Scope

    /// Subnets this Mac could scan right now, each with its scope verdict (nil = allowed).
    public static func candidateSubnets() -> [(NetSubnet, NetScopeError?)] {
        let route = NetInterfaces.defaultRoute()
        return NetInterfaces.directlyConnectedSubnets(defaultGateway: route.gateway, defaultInterface: route.interface).map { ($0, $0.scopeError()) }
    }

    public func lastReport() -> NetScanReport? {
        guard let u = reportURL, let d = try? Data(contentsOf: u) else { return nil }
        return try? JSONDecoder.rampart.decode(NetScanReport.self, from: d)
    }

    // MARK: Scan

    public func scan(options: Options = Options(), progress: @escaping @Sendable (NetScanProgress) -> Void = { _ in }) async throws -> NetScanReport {
        let started = Date()
        let deadline = started.addingTimeInterval(options.maxDuration)
        var limitations: [String] = []
        progress(NetScanProgress(phase: .preparing, fraction: 0.02, message: "Checking which network to scan"))

        // 1. Scope.
        let subnet: NetSubnet
        if let s = options.subnet { subnet = s } else {
            let candidates = Self.candidateSubnets()
            guard let ok = candidates.first(where: { $0.1 == nil })?.0 else {
                if let (s, err) = candidates.first, let err { throw err }
                throw NetScopeError.invalid
            }
            subnet = ok
        }
        if let err = subnet.scopeError() { throw err }
        let limiter = ProbeRateLimiter(rate: options.probesPerSecond)
        let gatewayIP = subnet.gateway ?? NetInterfaces.defaultRoute().gateway
        let hosts = subnet.hostAddresses().filter { $0 != subnet.address }

        // 2. Discovery.
        var found: [String: NetDevice] = [:]   // keyed by IP during the scan
        func touch(_ ip: String, by source: String) {
            guard subnet.contains(ip) else { return }
            var d = found[ip] ?? NetDevice(id: "ip:\(ip)", ip: ip)
            if !d.discoveredBy.contains(source) { d.discoveredBy.append(source) }
            found[ip] = d
        }
        touch(subnet.address, by: "self"); found[subnet.address]?.isThisMac = true
        if let g = gatewayIP { touch(g, by: "route"); found[g]?.isGateway = true }

        for e in ARPTable.read().entries where e.interface == nil || e.interface == subnet.interface {
            touch(e.ip, by: "arp"); found[e.ip]?.mac = e.mac
        }
        progress(NetScanProgress(phase: .discovering, fraction: 0.08, message: "Listening for Bonjour and UPnP devices", devicesSoFar: found.count))

        var mdns: [String: MDNSInfo] = [:]
        var ssdp: [String: [SSDPResponse]] = [:]
        if options.useMDNS { mdns = await MDNSDiscovery.browse(interfaceAddress: subnet.address, limiter: limiter) }
        for ip in mdns.keys { touch(ip, by: "mdns") }
        if options.useSSDP { ssdp = await SSDPDiscovery.discover(interfaceAddress: subnet.address, limiter: limiter) }
        for ip in ssdp.keys { touch(ip, by: "ssdp") }
        progress(NetScanProgress(phase: .discovering, fraction: 0.15, message: "Gently sweeping \(hosts.count) addresses", devicesSoFar: found.count))

        if options.useICMP {
            let total = hosts.count, soFar = found.count
            let replies = await ICMPProbe.sweep(hosts: hosts, limiter: limiter, deadline: deadline) { sent in
                progress(NetScanProgress(phase: .discovering, fraction: 0.15 + 0.25 * Double(sent) / Double(max(1, total)), message: "Sweeping addresses (\(sent)/\(total))", devicesSoFar: soFar))
            }
            for ip in replies { touch(ip, by: "icmp") }
        }
        // TCP connect sweep on the discovery ports (also warms the ARP cache for silent hosts).
        if !options.sweepPorts.isEmpty && Date() < deadline {
            let targets = hosts.flatMap { ip in options.sweepPorts.map { (ip, $0) } }
            let soFar = found.count
            let hits = await Self.connectMany(targets, limiter: limiter, timeout: options.tcpTimeout, deadline: deadline, concurrency: 24) { done in
                progress(NetScanProgress(phase: .discovering, fraction: 0.40 + 0.2 * Double(done) / Double(max(1, targets.count)), message: "Checking for quiet devices (\(done)/\(targets.count))", devicesSoFar: soFar))
            }
            for (k, r) in hits where r == .open || r == .closed { touch(k.ip, by: "tcp") }
        }
        // Re-read ARP: the sweep populated it for every host that exists at layer 2.
        let arp = ARPTable.read()
        for e in arp.entries where e.interface == nil || e.interface == subnet.interface { touch(e.ip, by: "arp"); found[e.ip]?.mac = e.mac }
        if arp.source == .none {
            limitations.append("The ARP table wasn't readable (macOS Local Network privacy), so hardware addresses and vendors may be missing.")
        }
        progress(NetScanProgress(phase: .identifying, fraction: 0.62, message: "Identifying devices", devicesSoFar: found.count))

        // 3. Identification.
        for ip in found.keys.sorted() {
            guard var d = found[ip], Date() < deadline else { continue }
            if d.isThisMac { d.hostname = Host.current().localizedName.map { $0 + ".local" } ?? d.hostname }
            if let info = mdns[ip] { apply(info, to: &d) }
            if d.hostname == nil || (d.mdnsName == nil && !d.isThisMac) {
                if let info = await MDNSDiscovery.probe(ip: ip, hostname: d.hostname, interfaceAddress: subnet.address, limiter: limiter, window: 0.8) { apply(info, to: &d) }
            }
            if d.hostname == nil, let h = await ReverseDNS.lookup(ip) { d.hostname = h }
            if let rs = ssdp[ip] {
                d.services.append(contentsOf: rs.compactMap(\.st).map { "ssdp:" + $0 })
                d.services = Array(Set(d.services)).sorted()
                if d.model == nil { d.model = rs.compactMap(\.server).first }
            }
            if let m = d.mac {
                d.vendor = OUITable.vendor(for: m)
                if d.vendor == nil && OUITable.isLocallyAdministered(m) { d.vendor = "Private address" }
            }
            found[ip] = d
        }
        progress(NetScanProgress(phase: .checkingPorts, fraction: 0.72, message: "Checking risky ports", devicesSoFar: found.count))

        // 4. Risky ports on every device except this Mac.
        let others = found.values.filter { !$0.isThisMac }.map(\.ip)
        let portTargets = others.flatMap { ip in options.riskyPorts.map { (ip, $0) } }
        let deviceCount = found.count
        let open = await Self.connectMany(portTargets, limiter: limiter, timeout: options.tcpTimeout, deadline: deadline, concurrency: 24) { done in
            progress(NetScanProgress(phase: .checkingPorts, fraction: 0.72 + 0.14 * Double(done) / Double(max(1, portTargets.count)), message: "Checking risky ports (\(done)/\(portTargets.count))", devicesSoFar: deviceCount))
        }
        for (k, r) in open where r == .open {
            guard let rp = RiskyPort.find(k.port) else { continue }
            found[k.ip]?.openPorts.append(rp.finding())
        }
        for ip in ssdp.keys where found[ip] != nil && !(found[ip]!.isThisMac) {
            if let rp = RiskyPort.find(1900, proto: "udp") { found[ip]?.openPorts.append(rp.finding()) }
        }
        for ip in found.keys {
            guard var d = found[ip] else { continue }
            d.openPorts.sort { $0.severity > $1.severity }
            let ssdpServer = ssdp[ip]?.compactMap(\.server).first
            d.type = DeviceTypeGuesser.guess(vendor: d.vendor, hostname: d.hostname, mdnsName: d.mdnsName, model: d.model, services: d.services,
                                             ssdpServer: ssdpServer, openPorts: d.openPorts.map(\.port), isGateway: d.isGateway)
            if d.isThisMac { d.type = .mac }
            if let m = d.mac { d.id = m }
            found[ip] = d
        }

        // 5. Router.
        progress(NetScanProgress(phase: .checkingRouter, fraction: 0.88, message: "Checking the router", devicesSoFar: found.count))
        var router: RouterReport?
        var findings: [NetFinding] = []
        // Scope (hx4): only probe a gateway that is a dotted-quad on the scanned subnet.
        if options.checkRouter, let g = gatewayIP, IPv4.parse(g) != nil, subnet.contains(g), Date() < deadline {
            var r = RouterReport(ip: g, mac: found[g]?.mac, vendor: found[g]?.vendor)
            await limiter.acquire(); r.httpOpen = await TCPProbe.connect(ip: g, port: 80, timeout: options.tcpTimeout) == .open
            await limiter.acquire(); r.httpsOpen = await TCPProbe.connect(ip: g, port: 443, timeout: options.tcpTimeout) == .open
            if r.httpOpen {
                await limiter.acquire()
                let (redirect, server) = await Self.httpHead("http://\(g)/", timeout: 3)
                r.httpRedirectsToHTTPS = redirect; r.httpServerHeader = server
            }
            if let rs = ssdp[g] {
                if let igd = rs.first(where: \.isInternetGateway) { r.upnpIGD = true; r.upnpLocation = igd.location }
                else if let loc = rs.compactMap(\.location).first, let desc = await SSDPDiscovery.fetchDescription(loc, subnet: subnet) {
                    r.upnpIGD = desc.isInternetGateway; r.upnpLocation = loc
                    if found[g]?.model == nil { found[g]?.model = desc.modelName }
                }
            }
            r.dnsServers = DNSResolverCheck.currentServers()
            r.dnsVerdicts = r.dnsServers.map { DNSResolverCheck.verdict($0, subnet: subnet, gateway: g) }
            let arpEntries = arp.entries.map { WiFiGuard.ARPEntry(ip: $0.ip, mac: $0.mac, interface: $0.interface) }
            let alerts = wifiGuard.evaluate(gateway: g, arp: arpEntries)
            if let a = alerts.first(where: { $0.kind == .gatewayMACChanged }) { r.gatewayMACChanged = true; r.macChangeDetail = a.message }
            if let a = alerts.first(where: { $0.kind == .duplicateMAC }) {
                findings.append(NetFinding(id: "router.dupmac", kind: .router, severity: .medium, title: "Another device uses the router's hardware address",
                                           detail: a.message, fix: "If you didn't add a second router or mesh unit, reconnect to the network and run the scan again. Persistent duplicates can mean ARP spoofing."))
            }
            router = r
            findings += Self.routerFindings(r)
        } else if gatewayIP == nil {
            limitations.append("No default gateway was found, so router checks were skipped.")
        }

        // 6. This Mac.
        progress(NetScanProgress(phase: .checkingThisMac, fraction: 0.93, message: "Checking this Mac's open ports", devicesSoFar: found.count))
        var firewall = AppFirewallState()
        var listeners: [LocalListener] = []
        if options.checkLocalListeners {
            firewall = FirewallCheck.current()
            listeners = LocalListenerCheck.listeners(firewall: firewall)
            findings += Self.listenerFindings(listeners, firewall: firewall)
            if getuid() != 0 { limitations.append("Listening ports of other users' processes and system daemons aren't visible without the full system service.") }
        }

        // 7. Wi-Fi, known devices, device findings, score.
        let wifi = wifiGuard.currentStatus()
        if let w = wifi, w.isWeak {
            findings.append(NetFinding(id: "wifi.weak", kind: .wifi, severity: .medium, title: "Wi-Fi uses weak security (\(w.security))",
                                       detail: "Traffic on this network can be read or tampered with by anyone nearby.",
                                       fix: "In the router's Wi-Fi settings choose WPA2 or WPA3 (AES) with a long passphrase."))
        }
        var devices = knownDevices.merge(Array(found.values), at: started)
        devices.sort { a, b in
            if a.isGateway != b.isGateway { return a.isGateway }
            if a.isThisMac != b.isThisMac { return a.isThisMac }
            return (IPv4.parse(a.ip) ?? 0) < (IPv4.parse(b.ip) ?? 0)
        }
        for d in devices {
            for p in d.openPorts where p.severity >= .medium {
                findings.append(NetFinding(id: "device.\(d.id).\(p.id)", kind: .device, severity: p.severity, title: "\(d.displayName): \(p.service) is open",
                                           detail: p.explanation, fix: p.fix, deviceID: d.id))
            }
            if d.isNew && !d.trusted {
                findings.append(NetFinding(id: "new.\(d.id)", kind: .newDevice, severity: .low, title: "New device: \(d.displayName)",
                                           detail: "\(d.ip)\(d.vendor.map { " · \($0)" } ?? "") joined since the last scan.",
                                           fix: "If you recognise it, give it a name and mark it trusted. If not, change the Wi-Fi password and check the router's device list.", deviceID: d.id))
            }
        }
        if found.count <= 2 && (arp.source == .none) {
            limitations.append("Very few devices answered. If macOS asked about Local Network access, allow it and scan again.")
        }
        let newUntrusted = devices.filter { $0.isNew && !$0.trusted && !$0.isThisMac }.count
        let score = NetScanScoring.score(findings: findings, newUntrustedDevices: newUntrusted)
        let report = NetScanReport(date: started, duration: Date().timeIntervalSince(started), subnet: subnet, devices: devices, router: router,
                                   localListeners: listeners, firewall: firewall, findings: findings.sorted { $0.severity > $1.severity },
                                   score: score, probesSent: limiter.issued, limitations: limitations,
                                   wifiSecurity: wifi?.security, wifiWeak: wifi?.isWeak ?? false)
        if let u = reportURL {
            try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? JSONEncoder.rampart.encode(report).write(to: u, options: .atomic)
        }
        progress(NetScanProgress(phase: .finishing, fraction: 1, message: "Done", devicesSoFar: devices.count))
        return report
    }

    // MARK: Pure finding builders (fixture-testable)

    public static func routerFindings(_ r: RouterReport) -> [NetFinding] {
        var out: [NetFinding] = []
        if r.gatewayMACChanged {
            out.append(NetFinding(id: "router.macchanged", kind: .router, severity: .high, title: "The router's hardware address changed",
                                  detail: r.macChangeDetail ?? "The gateway answers from a different MAC address than before.",
                                  fix: "If you replaced the router or added mesh units this is expected: mark it trusted. Otherwise it could be ARP spoofing: disconnect, and reconnect to a trusted network."))
        }
        if r.adminHTTPOnly {
            out.append(NetFinding(id: "router.http", kind: .router, severity: .medium, title: "Router admin page is served over plain HTTP only",
                                  detail: "The router's settings page on \(r.ip) is not encrypted. Anyone on the network could capture the admin password when you log in.",
                                  fix: "Look for an HTTPS/secure management option in the router settings, log in only from a trusted device, and make sure remote (WAN) management is off."))
        }
        if r.upnpIGD {
            out.append(NetFinding(id: "router.upnp", kind: .upnp, severity: .medium, title: "UPnP port forwarding is enabled on the router",
                                  detail: "Any device or app on the network can ask the router to open ports from the internet without a password. Malware and misconfigured smart devices use this to expose themselves.",
                                  fix: "Disable UPnP (sometimes 'automatic port forwarding') in the router's settings and add manual port forwards only for things you need."))
        }
        for v in r.dnsVerdicts where v.status == .unknown {
            out.append(NetFinding(id: "dns.\(v.server)", kind: .dns, severity: .high, title: "Unrecognised DNS server \(v.server)",
                                  detail: "Your Mac sends website lookups to \(v.server), which isn't your router or a well-known resolver. A hijacked DNS setting can silently redirect you to fake sites.",
                                  fix: "Check System Settings > Network > Wi-Fi > Details > DNS and the router's DNS settings. If you didn't set this server yourself, remove it and change the router's admin password."))
        }
        if r.dnsServers.isEmpty {
            out.append(NetFinding(id: "dns.none", kind: .dns, severity: .low, title: "No DNS servers reported", detail: "The system resolver configuration couldn't be read.",
                                  fix: "Nothing to do unless websites fail to load."))
        }
        return out
    }

    public static func listenerFindings(_ listeners: [LocalListener], firewall: AppFirewallState) -> [NetFinding] {
        var out: [NetFinding] = []
        if firewall.enabled == false {
            out.append(NetFinding(id: "mac.firewall", kind: .localListener, severity: .medium, title: "The macOS firewall is off",
                                  detail: "Without the firewall, every app that listens on a port is reachable from other devices on this network.",
                                  fix: "Turn it on in System Settings > Network > Firewall. Stealth mode is a good extra."))
        }
        for l in listeners where l.exposure == .network {
            if let rp = RiskyPort.find(l.port), rp.severity >= .medium {
                let blocked = l.firewall == .blocked
                out.append(NetFinding(id: "mac.port.\(l.proto).\(l.port)", kind: .localListener, severity: blocked ? .low : rp.severity,
                                      title: "This Mac: \(rp.service) is listening (\(l.processName))",
                                      detail: rp.explanation + (blocked ? " The firewall is blocking it, so other devices can't reach it." : ""),
                                      fix: rp.fix))
            } else if l.signing == .unsigned || l.signing == .adHoc || l.signing == .invalid, l.firewall != .blocked {
                out.append(NetFinding(id: "mac.unsigned.\(l.proto).\(l.port)", kind: .localListener, severity: .low,
                                      title: "This Mac: unsigned program \(l.processName) accepts network connections on port \(l.port)",
                                      detail: "A program without a developer signature is listening for connections from the network. Development tools often do this; malware does too.",
                                      fix: "If you recognise it (a dev server, a local tool), nothing to do. If not, quit it and run a RamPart scan."))
            }
        }
        return out
    }

    // MARK: Helpers

    static func connectMany(_ targets: [(String, Int)], limiter: ProbeRateLimiter, timeout: TimeInterval, deadline: Date, concurrency: Int,
                            progress: @escaping @Sendable (Int) -> Void) async -> [PortKey: TCPProbe.Result] {
        var results: [PortKey: TCPProbe.Result] = [:]
        var done = 0
        await withTaskGroup(of: (PortKey, TCPProbe.Result).self) { group in
            var it = targets.makeIterator()
            var inFlight = 0
            func launch() -> Bool {
                guard Date() < deadline, let (ip, port) = it.next() else { return false }
                group.addTask {
                    await limiter.acquire()
                    return (PortKey(ip: ip, port: port), await TCPProbe.connect(ip: ip, port: port, timeout: timeout))
                }
                return true
            }
            while inFlight < concurrency, launch() { inFlight += 1 }
            while let (k, r) = await group.next() {
                results[k] = r; done += 1
                if done % 25 == 0 { progress(done) }
                if !launch() { inFlight -= 1 }
            }
        }
        progress(done)
        return results
    }

    /// (redirects to https?, Server header)
    static func httpHead(_ urlString: String, timeout: TimeInterval) async -> (Bool, String?) {
        guard let url = URL(string: urlString) else { return (false, nil) }
        var req = URLRequest(url: url); req.timeoutInterval = timeout; req.httpMethod = "GET"
        final class NoRedirect: NSObject, URLSessionTaskDelegate {
            func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
        }
        let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        guard let (_, resp) = try? await session.data(for: req), let http = resp as? HTTPURLResponse else { return (false, nil) }
        let loc = http.value(forHTTPHeaderField: "Location")?.lowercased() ?? ""
        let redirect = (300..<400).contains(http.statusCode) && loc.hasPrefix("https://")
        return (redirect, http.value(forHTTPHeaderField: "Server"))
    }

    public struct PortKey: Hashable, Sendable { public var ip: String; public var port: Int }

    private func apply(_ info: MDNSInfo, to d: inout NetDevice) {
        if d.mdnsName == nil, let inst = info.instances.sorted(by: { $0.count < $1.count }).first { d.mdnsName = inst }
        if d.hostname == nil, let h = info.hostnames.first(where: { $0.hasSuffix(".local") }) ?? info.hostnames.first { d.hostname = h }
        if d.model == nil { d.model = info.model }
        d.services = Array(Set(d.services).union(info.services)).sorted()
    }
}

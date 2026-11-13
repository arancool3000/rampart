import Foundation

/// A system command the VPN needs (ifconfig / route / scutil / pfctl). Generated as data so it can be tested,
/// shown in dry runs, and executed only by the installed root daemon.
public struct VPNCommand: Equatable, CustomStringConvertible, Sendable {
    public var executable: String
    public var arguments: [String]
    public var stdin: String?
    public var tolerateFailure: Bool
    public init(_ executable: String, _ arguments: [String], stdin: String? = nil, tolerateFailure: Bool = false) {
        self.executable = executable; self.arguments = arguments; self.stdin = stdin; self.tolerateFailure = tolerateFailure
    }
    public var description: String {
        ([(executable as NSString).lastPathComponent] + arguments).joined(separator: " ") + (stdin.map { " <<< \($0.split(separator: "\n").count) lines" } ?? "")
    }
    static let ifconfig = "/sbin/ifconfig", route = "/sbin/route", scutil = "/usr/sbin/scutil", pfctl = "/sbin/pfctl"
}

public protocol VPNCommandRunner: AnyObject {
    /// Returns (exit status, combined output).
    func run(_ c: VPNCommand) -> (status: Int32, output: String)
    var isLive: Bool { get }
}

/// Records commands; never executes anything. Used in development, user mode and self-tests.
public final class DryRunVPNRunner: VPNCommandRunner {
    private let lock = NSLock()
    private var _log: [VPNCommand] = []
    /// Canned output for read-only queries (route get / scutil show) in tests.
    public var responses: [String: String] = [:]
    public var isLive: Bool { false }
    public init() {}
    public var log: [VPNCommand] { lock.lock(); defer { lock.unlock() }; return _log }
    public func clear() { lock.lock(); _log.removeAll(); lock.unlock() }
    public func run(_ c: VPNCommand) -> (status: Int32, output: String) {
        lock.lock(); _log.append(c); lock.unlock()
        return (0, responses[c.arguments.joined(separator: " ")] ?? "")
    }
}

/// Executes commands. Refuses unless root and RAMPART_NO_PRIVILEGED_TOOLS is unset (ZERO POP-UPS RULE).
public final class LiveVPNRunner: VPNCommandRunner {
    public static var allowed: Bool {
        let v = ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] ?? ""
        return getuid() == 0 && (v.isEmpty || v == "0")
    }
    public var isLive: Bool { Self.allowed }
    public init() {}
    public func run(_ c: VPNCommand) -> (status: Int32, output: String) {
        guard Self.allowed else { return (-1, "refused: VPN system changes need the installed system service") }
        let allowedTools: Set<String> = [VPNCommand.ifconfig, VPNCommand.route, VPNCommand.scutil, VPNCommand.pfctl]
        guard allowedTools.contains(c.executable) else { return (-1, "refused: \(c.executable) is not a VPN tool") }
        let p = Process(); let out = Pipe(); let inp = Pipe()
        p.executableURL = URL(fileURLWithPath: c.executable); p.arguments = c.arguments
        p.standardOutput = out; p.standardError = out
        if c.stdin != nil { p.standardInput = inp }
        do { try p.run() } catch { return (-1, error.localizedDescription) }
        if let s = c.stdin { inp.fileHandleForWriting.write(Data(s.utf8)); try? inp.fileHandleForWriting.close() }
        let deadline = Date().addingTimeInterval(10)
        while p.isRunning && Date() < deadline { usleep(20_000) }
        if p.isRunning { p.terminate(); return (-1, "timed out") }
        return (p.terminationStatus, String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
    }
}

/// Everything the tunnel changes on the system, as commands: addresses, routes, DNS (scutil) and the pf kill switch.
public struct VPNNetworkPlan: Equatable {
    public static let pfAnchor = "com.apple/252.RampartVPN"   // after 249.RampartEmergency: a lockdown always wins
    public static let scutilService = "app.rampart.vpn"

    public var interface: String
    public var config: WGQuickConfig
    public var endpointIP: String
    public var localUDPPort: UInt16
    public var gateway4: String?
    public var gateway6: String?
    /// RamPart's DNS filter is on: point the tunnel's DNS at it (127.0.0.1), it then forwards over the tunnel.
    public var dnsFilterActive: Bool
    public var killSwitch: Bool

    public init(interface: String, config: WGQuickConfig, endpointIP: String, localUDPPort: UInt16, gateway4: String?, gateway6: String?,
                dnsFilterActive: Bool, killSwitch: Bool) {
        self.interface = interface; self.config = config; self.endpointIP = endpointIP; self.localUDPPort = localUDPPort
        self.gateway4 = gateway4; self.gateway6 = gateway6; self.dnsFilterActive = dnsFilterActive; self.killSwitch = killSwitch
    }

    var endpointIsV6: Bool { endpointIP.contains(":") }

    /// The endpoint as a canonical literal, or nil. Everything written into pf rules uses this, never the raw text
    /// (a profile.json edited on disk, or a resolver quirk, must not be able to widen the kill switch).
    var safeEndpointIP: String? { IPPrefix.strictLiteral(endpointIP).map(IPPrefix.format) }
    /// Interface names that are safe inside a pf rule / scutil line.
    static func safeInterfaceName(_ s: String) -> Bool {
        (1...15).contains(s.count) && s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
    }

    /// Full tunnel for one family only: the other family would leave through the physical interface while the user
    /// believes everything is tunnelled (classic IPv6 leak). Route it into the tunnel too; the peer drops anything
    /// outside AllowedIPs, so it is blackholed rather than leaked. Skipped for the endpoint's own family.
    public var leakBlockRoutes: [String] {
        let full = config.isFullTunnel
        if full.v4 && !full.v6 && !endpointIsV6 { return ["::/1", "8000::/1"] }
        if full.v6 && !full.v4 && endpointIsV6 { return ["0.0.0.0/1", "128.0.0.0/1"] }
        return []
    }

    public func addressCommands() -> [VPNCommand] {
        var c: [VPNCommand] = []
        for a in config.addresses {
            guard let h = IPPrefix.hostAddress(a) else { continue }
            let ip = IPPrefix.format(h.address)
            if h.address.count == 4 { c.append(VPNCommand(VPNCommand.ifconfig, [interface, "inet", "\(ip)/\(h.length)", ip, "alias"])) }
            else { c.append(VPNCommand(VPNCommand.ifconfig, [interface, "inet6", "\(ip)/\(h.length)", "alias"])) }
        }
        c.append(VPNCommand(VPNCommand.ifconfig, [interface, "mtu", String(config.mtuOrDefault)]))
        c.append(VPNCommand(VPNCommand.ifconfig, [interface, "up"]))
        return c
    }

    /// Prefixes routed into the tunnel. A /0 is split into two halves so the original default route stays intact.
    public var tunnelRoutes: [String] {
        var out: [String] = []
        for s in config.allowedIPs {
            guard let p = IPPrefix(s) else { continue }
            if p.length == 0 { out += p.isIPv6 ? ["::/1", "8000::/1"] : ["0.0.0.0/1", "128.0.0.0/1"] }
            else { out.append(p.description) }
        }
        var seen = Set<String>(); return out.filter { seen.insert($0).inserted }
    }

    /// The endpoint must keep using the real network, or the encrypted packets would loop into the tunnel.
    var endpointCoveredByTunnel: Bool {
        guard let ip = IPPrefix.parseAddress(endpointIP) else { return false }
        return config.allowedIPs.compactMap(IPPrefix.init).contains { $0.contains(ip) }
    }

    public func routeUpCommands() -> [VPNCommand] {
        var c: [VPNCommand] = []
        if endpointCoveredByTunnel {
            if endpointIsV6, let g = gateway6 { c.append(VPNCommand(VPNCommand.route, ["-q", "-n", "add", "-inet6", endpointIP, "-gateway", g], tolerateFailure: true)) }
            if !endpointIsV6, let g = gateway4 { c.append(VPNCommand(VPNCommand.route, ["-q", "-n", "add", "-inet", endpointIP, "-gateway", g], tolerateFailure: true)) }
        }
        for r in tunnelRoutes {
            c.append(VPNCommand(VPNCommand.route, ["-q", "-n", "add", r.contains(":") ? "-inet6" : "-inet", r, "-interface", interface]))
        }
        for r in leakBlockRoutes {
            c.append(VPNCommand(VPNCommand.route, ["-q", "-n", "add", r.contains(":") ? "-inet6" : "-inet", r, "-interface", interface], tolerateFailure: true))
        }
        return c
    }

    public func routeDownCommands() -> [VPNCommand] {
        var c: [VPNCommand] = (tunnelRoutes + leakBlockRoutes).map {
            VPNCommand(VPNCommand.route, ["-q", "-n", "delete", $0.contains(":") ? "-inet6" : "-inet", $0, "-interface", interface], tolerateFailure: true)
        }
        if endpointCoveredByTunnel {
            c.append(VPNCommand(VPNCommand.route, ["-q", "-n", "delete", endpointIsV6 ? "-inet6" : "-inet", endpointIP], tolerateFailure: true))
        }
        return c
    }

    /// DNS servers the system should use while connected.
    public var effectiveDNS: [String] {
        dnsFilterActive ? ["127.0.0.1"] : config.dnsServers.compactMap { IPPrefix.strictLiteral($0).map(IPPrefix.format) }
    }

    /// scutil script: a service of our own whose IPv4 entry overrides the primary service (full tunnel), so its DNS
    /// becomes the system resolver. Removing the two keys restores everything (no backup of other services needed).
    public func dnsUpCommand() -> VPNCommand? {
        let dns = effectiveDNS
        guard !dns.isEmpty, Self.safeInterfaceName(interface) else { return nil }
        let search = config.dnsSearch.filter(WGQuickConfig.isHostname)
        let v4 = config.addresses.compactMap(IPPrefix.hostAddress).first { $0.address.count == 4 }.map { IPPrefix.format($0.address) }
        let key = "State:/Network/Service/\(Self.scutilService)"
        var s = "open\n"
        if let v4 {
            s += "d.init\nd.add Addresses * \(v4)\nd.add DestAddresses * \(v4)\nd.add InterfaceName \(interface)\nd.add Router \(v4)\n"
            if config.isFullTunnel.v4 { s += "d.add OverridePrimary # 1\n" }
            s += "set \(key)/IPv4\n"
        }
        s += "d.init\nd.add ServerAddresses * \(dns.joined(separator: " "))\n"
        if !search.isEmpty { s += "d.add SearchDomains * \(search.joined(separator: " "))\n" }
        if !config.isFullTunnel.v4 && !search.isEmpty { s += "d.add SupplementalMatchDomains * \(search.joined(separator: " "))\n" }
        s += "set \(key)/DNS\nclose\nquit\n"
        return VPNCommand(VPNCommand.scutil, [], stdin: s)
    }

    public static func dnsDownCommand() -> VPNCommand {
        let key = "State:/Network/Service/\(scutilService)"
        return VPNCommand(VPNCommand.scutil, [], stdin: "open\nremove \(key)/IPv4\nremove \(key)/DNS\nclose\nquit\n", tolerateFailure: true)
    }

    /// pf rules: only the tunnel, loopback, DHCP / neighbour discovery and our one WireGuard UDP flow may pass.
    /// Fails closed: an endpoint or interface that isn't a plain literal / name drops its pass rule (block all).
    public func killSwitchRules() -> String {
        let fam = endpointIsV6 ? "inet6" : "inet"
        var r = ["# RamPart VPN kill switch (generated; pfctl -a \(Self.pfAnchor)). Only the WireGuard tunnel may carry traffic.",
                 "pass quick on lo0 all"]
        if Self.safeInterfaceName(interface) { r.append("pass quick on \(interface) all") }
        r += ["pass out quick inet proto udp from any port 68 to any port 67 keep state",
              "pass in quick inet proto udp from any port 67 to any port 68 keep state",
              "pass out quick inet6 proto udp from any port 546 to any port 547 keep state",
              "pass quick inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv, routersol, routeradv }"]
        if let ep = safeEndpointIP, localUDPPort > 0, config.endpointPort > 0 {
            r.append("pass out quick \(fam) proto udp from any port \(localUDPPort) to \(ep) port \(config.endpointPort) keep state")
        }
        r += ["block drop out quick all", "block drop in quick all", ""]
        return r.joined(separator: "\n") + "\n"
    }

    public func killSwitchLoadCommands() -> [VPNCommand] {
        [VPNCommand(VPNCommand.pfctl, ["-E"], tolerateFailure: true),
         VPNCommand(VPNCommand.pfctl, ["-a", Self.pfAnchor, "-f", "-"], stdin: killSwitchRules())]
    }

    public static func killSwitchUnloadCommands(token: String?) -> [VPNCommand] {
        var c = [VPNCommand(pfctlPath, ["-a", pfAnchor, "-F", "all"], tolerateFailure: true)]
        if let t = token, !t.isEmpty, t.allSatisfy(\.isNumber) { c.append(VPNCommand(pfctlPath, ["-X", t], tolerateFailure: true)) }
        return c
    }
    static let pfctlPath = VPNCommand.pfctl

    /// "Token : 1234567" from `pfctl -E`.
    public static func parsePFToken(_ output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) where line.lowercased().contains("token") {
            let t = line.split(separator: ":").last?.trimmingCharacters(in: .whitespaces) ?? ""
            if !t.isEmpty, t.allSatisfy(\.isNumber) { return t }
        }
        return nil
    }

    /// Parses `route -n get default` (gateway / interface).
    public static func parseRouteGet(_ output: String) -> (gateway: String?, interface: String?) {
        var g: String?, i: String?
        for line in output.split(whereSeparator: \.isNewline) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("gateway:") { g = t.dropFirst("gateway:".count).trimmingCharacters(in: .whitespaces) }
            if t.hasPrefix("interface:") { i = t.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces) }
        }
        return (g.flatMap { $0.isEmpty ? nil : $0 }, i.flatMap { $0.isEmpty ? nil : $0 })
    }

    public static func defaultRouteCommands() -> [VPNCommand] {
        [VPNCommand(VPNCommand.route, ["-n", "get", "default"], tolerateFailure: true),
         VPNCommand(VPNCommand.route, ["-n", "get", "-inet6", "default"], tolerateFailure: true)]
    }
}

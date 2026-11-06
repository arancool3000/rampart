import Foundation
import Darwin

// Subnet scope rules, interface enumeration, IPv4 helpers and the probe rate limiter.

public enum IPv4 {
    public static func parse(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var v: UInt32 = 0
        for p in parts {
            guard let n = UInt8(p) else { return nil }
            v = v << 8 | UInt32(n)
        }
        return v
    }

    public static func string(_ v: UInt32) -> String {
        "\(v >> 24 & 255).\(v >> 16 & 255).\(v >> 8 & 255).\(v & 255)"
    }

    public static func prefixLength(mask: UInt32) -> Int? {
        // Must be contiguous ones followed by zeros.
        let ones = mask.nonzeroBitCount
        guard ones == 32 || mask == (ones == 0 ? 0 : ~UInt32(0) << (32 - ones)) else { return nil }
        return ones
    }

    /// RFC 1918 private, CGNAT (100.64/10) is NOT treated as home-private.
    public static func isPrivate(_ v: UInt32) -> Bool {
        (v >> 24) == 10 || (v >> 20) == 0xAC1 || (v >> 16) == 0xC0A8
    }
    public static func isLinkLocal(_ v: UInt32) -> Bool { (v >> 16) == 0xA9FE }
    public static func isLoopback(_ v: UInt32) -> Bool { (v >> 24) == 127 }
}

public extension NetSubnet {
    /// Largest subnet RamPart will scan.
    static let maxPrefixSpan = 22

    /// Scope rules: directly connected, private, /22 or smaller. Returns nil when the subnet is fine.
    func scopeError() -> NetScopeError? {
        guard let net = IPv4.parse(network), prefix >= 0, prefix <= 32 else { return .invalid }
        if IPv4.isLoopback(net) { return .loopback }
        if IPv4.isLinkLocal(net) { return .linkLocal }
        guard IPv4.isPrivate(net) else { return .notPrivate(cidr) }
        if prefix < Self.maxPrefixSpan { return .tooLarge(prefix: prefix) }
        return nil
    }

    /// All host addresses in the subnet (excluding network/broadcast for /30 and larger).
    func hostAddresses() -> [String] {
        guard let net = IPv4.parse(network), prefix <= 32 else { return [] }
        let size = UInt32(1) << UInt32(32 - prefix)
        if prefix >= 31 { return (0..<size).map { IPv4.string(net + $0) } }
        guard size > 2 else { return [] }
        return (1..<(size - 1)).map { IPv4.string(net + $0) }
    }

    func contains(_ ip: String) -> Bool {
        guard let a = IPv4.parse(ip), let net = IPv4.parse(network), prefix <= 32 else { return false }
        let mask: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << UInt32(32 - prefix)
        return a & mask == net
    }

    static func make(interface: String, address: String, netmask: String, gateway: String?, isWiFi: Bool) -> NetSubnet? {
        guard let a = IPv4.parse(address), let m = IPv4.parse(netmask), let p = IPv4.prefixLength(mask: m) else { return nil }
        return NetSubnet(interface: interface, address: address, netmask: netmask, prefix: p, network: IPv4.string(a & m), gateway: gateway, isWiFi: isWiFi)
    }
}

public enum NetInterfaces {
    /// Every up, non-loopback IPv4 interface with its netmask (getifaddrs). The default gateway is attached
    /// to the interface that owns the default route.
    public static func directlyConnectedSubnets(defaultGateway: String? = nil, defaultInterface: String? = nil) -> [NetSubnet] {
        var ptr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ptr) == 0, let first = ptr else { return [] }
        defer { freeifaddrs(ptr) }
        var out: [NetSubnet] = []
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cur {
            defer { cur = ifa.pointee.ifa_next }
            guard let addr = ifa.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET),
                  let mask = ifa.pointee.ifa_netmask else { continue }
            let flags = Int32(ifa.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, flags & IFF_POINTOPOINT == 0 else { continue }
            let name = String(cString: ifa.pointee.ifa_name)
            // Skip virtual/tunnel interfaces: utun (VPN), bridge, awdl, llw, vmnet, p2p.
            if name.hasPrefix("utun") || name.hasPrefix("awdl") || name.hasPrefix("llw") || name.hasPrefix("bridge") ||
                name.hasPrefix("vmnet") || name.hasPrefix("p2p") || name.hasPrefix("gif") || name.hasPrefix("stf") || name.hasPrefix("ap") { continue }
            let a = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let m = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let gw = (defaultInterface == nil || defaultInterface == name) && defaultGateway.map { IPv4.parse($0).map { g in (g & m) == (a & m) } ?? false } == true ? defaultGateway : nil
            if let s = NetSubnet.make(interface: name, address: IPv4.string(a), netmask: IPv4.string(m), gateway: gw, isWiFi: name == "en0" || isWiFiInterface(name)) {
                out.append(s)
            }
        }
        // Prefer the interface with the default route first.
        return out.sorted { ($0.gateway != nil ? 0 : 1, $0.interface) < ($1.gateway != nil ? 0 : 1, $1.interface) }
    }

    static func isWiFiInterface(_ name: String) -> Bool {
        // Cheap heuristic without CoreWLAN: the Wi-Fi interface on Macs is almost always en0/en1.
        name == "en0" || name == "en1"
    }

    /// `route -n get default` → (gateway, interface).
    public static func defaultRoute() -> (gateway: String?, interface: String?) {
        let (_, out, _) = NetShell.run("/sbin/route", ["-n", "get", "default"], timeout: 5)
        return parseDefaultRoute(out)
    }

    public static func parseDefaultRoute(_ text: String) -> (gateway: String?, interface: String?) {
        var gw: String?, iface: String?
        for line in text.split(whereSeparator: \.isNewline) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("gateway:") { gw = t.dropFirst(8).trimmingCharacters(in: .whitespaces) }
            if t.hasPrefix("interface:") { iface = t.dropFirst(10).trimmingCharacters(in: .whitespaces) }
        }
        return (gw, iface)
    }
}

/// Evenly spaced probe scheduler: at most `rate` probes per second, no bursts. Shared by every probe type
/// (ICMP, TCP connect, UDP) so the whole scan never exceeds the ceiling.
public final class ProbeRateLimiter: @unchecked Sendable {
    public let rate: Double
    private var nextSlot: TimeInterval
    private let lock = NSLock()
    public private(set) var issued = 0

    public init(rate: Double = 50) {
        self.rate = max(1, min(rate, 50))   // hard ceiling: never more than 50/s
        nextSlot = 0
    }

    /// Returns how long the caller must wait before sending (0 when a slot is free now).
    public func reserve(now: TimeInterval = Date().timeIntervalSinceReferenceDate) -> TimeInterval {
        lock.lock(); defer { lock.unlock() }
        let slot = max(now, nextSlot)
        nextSlot = slot + 1 / rate
        issued += 1
        return slot - now
    }

    public func acquire() async {
        let wait = reserve()
        if wait > 0 { try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000)) }
    }
}

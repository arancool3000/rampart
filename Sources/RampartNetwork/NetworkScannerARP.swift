import Foundation
import Darwin

/// ARP (neighbour) table via the routing socket sysctl, with `arp -an` as a fallback.
///
/// On macOS 15+ Local Network privacy filters the ARP entries a process may see: a fresh, unapproved
/// binary gets an empty `NET_RT_FLAGS`/`RTF_LLINFO` answer (no error), while Apple's own `/usr/sbin/arp`
/// is exempt. We try the sysctl first, then fall back to spawning `arp -an` (parsed by WiFiGuard).
public enum ARPTable {
    public struct Entry: Codable, Hashable, Sendable {
        public var ip: String
        public var mac: String
        public var interfaceIndex: Int
        public var interface: String?
        public var permanent: Bool
        public init(ip: String, mac: String, interfaceIndex: Int, interface: String? = nil, permanent: Bool = false) {
            self.ip = ip; self.mac = mac; self.interfaceIndex = interfaceIndex; self.interface = interface; self.permanent = permanent
        }
    }

    public enum Source: String, Sendable { case sysctl, arpCommand, none }

    /// Reads the live table. Returns the entries and which source produced them.
    public static func read() -> (entries: [Entry], source: Source) {
        let s = readSysctl()
        if !s.isEmpty { return (s, .sysctl) }
        let (status, out, _) = NetShell.run("/usr/sbin/arp", ["-an"], timeout: 5)
        if status == 0 {
            let parsed = WiFiGuard.parseARP(out).map { Entry(ip: $0.ip, mac: $0.mac, interfaceIndex: 0, interface: $0.interface) }
            return (parsed, parsed.isEmpty ? .none : .arpCommand)
        }
        return ([], .none)
    }

    /// `sysctl net.route.0.inet.flags.llinfo` raw bytes, or empty when filtered/unavailable.
    public static func sysctlBytes() -> [UInt8] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO]
        var len = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &len, nil, 0) == 0, len > 0 else { return [] }
        var buf = [UInt8](repeating: 0, count: len)
        let ok = buf.withUnsafeMutableBytes { sysctl(&mib, UInt32(mib.count), $0.baseAddress, &len, nil, 0) } == 0
        guard ok else { return [] }
        return Array(buf.prefix(len))
    }

    public static func readSysctl() -> [Entry] {
        var entries = parse(sysctlBytes())
        guard !entries.isEmpty else { return [] }
        var names: [Int: String] = [:]
        for i in entries.indices {
            let idx = entries[i].interfaceIndex
            if names[idx] == nil {
                var buf = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
                names[idx] = if_indextoname(UInt32(idx), &buf) != nil ? String(cString: buf) : ""
            }
            if let n = names[idx], !n.isEmpty { entries[i].interface = n }
        }
        return entries
    }

    /// Pure parser for the routing-socket dump: a sequence of `rt_msghdr` records, each followed by the
    /// socket addresses named in `rtm_addrs` (RTA_DST first, RTA_GATEWAY second), each padded to 4 bytes.
    /// Entries with an AF_INET destination and an AF_LINK gateway holding a 6-byte address are ARP entries.
    public static func parse(_ b: [UInt8]) -> [Entry] {
        let hdr = MemoryLayout<rt_msghdr>.size
        var out: [Entry] = []
        var off = 0
        func u16(_ o: Int) -> Int { Int(b[o]) | Int(b[o + 1]) << 8 }
        func u32(_ o: Int) -> UInt32 { UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24 }
        while off + hdr <= b.count {
            let msglen = u16(off)
            guard msglen >= hdr, off + msglen <= b.count else { break }
            let flags = Int32(bitPattern: u32(off + 8))
            let addrs = Int32(bitPattern: u32(off + 12))
            let ifIndex = u16(off + 4)
            var p = off + hdr
            var dst: String?, mac: String?
            for bit in 0..<8 where addrs & (1 << bit) != 0 {
                guard p + 2 <= off + msglen else { break }
                let saLen = Int(b[p]), family = Int32(b[p + 1])
                let step = saLen == 0 ? 4 : (saLen + 3) & ~3
                if bit == 0, family == AF_INET, saLen >= 8, p + 8 <= b.count {       // RTA_DST
                    dst = "\(b[p + 4]).\(b[p + 5]).\(b[p + 6]).\(b[p + 7])"
                } else if bit == 1, family == AF_LINK, saLen >= 8, p + 8 <= b.count { // RTA_GATEWAY as sockaddr_dl
                    let nlen = Int(b[p + 5]), alen = Int(b[p + 6])
                    let start = p + 8 + nlen
                    if alen == 6, start + 6 <= b.count {
                        mac = (0..<6).map { String(format: "%02x", b[start + $0]) }.joined(separator: ":")
                    }
                }
                p += step
            }
            if let ip = dst, let mac, mac != "00:00:00:00:00:00", mac != "ff:ff:ff:ff:ff:ff" {
                out.append(Entry(ip: ip, mac: mac, interfaceIndex: ifIndex, permanent: flags & RTF_STATIC != 0))
            }
            off += msglen
        }
        return out
    }

    /// Builds one routing-socket record for fixtures/tests: AF_INET destination + AF_LINK gateway.
    public static func fixtureRecord(ip: String, mac: [UInt8], ifIndex: Int = 4, flags: Int32 = RTF_HOST | RTF_LLINFO) -> [UInt8] {
        let hdr = MemoryLayout<rt_msghdr>.size
        var sin = [UInt8](repeating: 0, count: 16)
        sin[0] = 16; sin[1] = UInt8(AF_INET)
        if let v = IPv4.parse(ip) { sin[4] = UInt8(v >> 24); sin[5] = UInt8(v >> 16 & 255); sin[6] = UInt8(v >> 8 & 255); sin[7] = UInt8(v & 255) }
        var sdl = [UInt8](repeating: 0, count: 20)
        sdl[0] = 20; sdl[1] = UInt8(AF_LINK); sdl[2] = UInt8(ifIndex & 255); sdl[3] = UInt8(ifIndex >> 8)
        sdl[4] = UInt8(IFT_ETHER); sdl[5] = 0; sdl[6] = UInt8(mac.count); sdl[7] = 0
        for (i, byte) in mac.prefix(6).enumerated() { sdl[8 + i] = byte }
        var rec = [UInt8](repeating: 0, count: hdr)
        let total = hdr + sin.count + sdl.count
        rec[0] = UInt8(total & 255); rec[1] = UInt8(total >> 8)
        rec[2] = UInt8(RTM_VERSION); rec[3] = UInt8(RTM_GET)
        rec[4] = UInt8(ifIndex & 255); rec[5] = UInt8(ifIndex >> 8)
        let f = UInt32(bitPattern: flags)
        rec[8] = UInt8(f & 255); rec[9] = UInt8(f >> 8 & 255); rec[10] = UInt8(f >> 16 & 255); rec[11] = UInt8(f >> 24)
        let a = UInt32(RTA_DST | RTA_GATEWAY)
        rec[12] = UInt8(a & 255); rec[13] = UInt8(a >> 8 & 255)
        return rec + sin + sdl
    }
}

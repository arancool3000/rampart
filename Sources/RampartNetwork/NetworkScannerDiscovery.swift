import Foundation
import Darwin

// Gentle host discovery: ICMP echo (unprivileged SOCK_DGRAM), TCP connect, legacy-unicast mDNS, SSDP and
// reverse DNS. Everything that sends a packet goes through the shared ProbeRateLimiter.

// MARK: - Sockets

/// Minimal BSD UDP socket (IPv4) for multicast/unicast discovery with a deadline-bounded receive loop.
final class UDPProbeSocket: @unchecked Sendable {
    let fd: Int32
    init?(interfaceAddress: String? = nil, ttl: Int32 = 1) {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var t = UInt8(clamping: ttl)
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &t, socklen_t(MemoryLayout<UInt8>.size))
        if let a = interfaceAddress, let v = IPv4.parse(a) {
            var ina = in_addr(s_addr: v.bigEndian)
            setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ina, socklen_t(MemoryLayout<in_addr>.size))
        }
        var tv = timeval(tv_sec: 0, tv_usec: 200_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var sin = sockaddr_in(); sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = 0; sin.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &sin) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard bound == 0 else { close(fd); return nil }
    }
    deinit { close(fd) }

    @discardableResult
    func send(_ data: Data, to ip: String, port: UInt16) -> Bool {
        guard let v = IPv4.parse(ip) else { return false }
        var sin = sockaddr_in(); sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = port.bigEndian; sin.sin_addr.s_addr = v.bigEndian
        let n = data.withUnsafeBytes { raw in
            withUnsafePointer(to: &sin) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, raw.baseAddress, raw.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        return n == data.count
    }

    /// Receives until `deadline`, calling `handler(sourceIP, payload)` for each datagram. Blocking; run off the main thread.
    func receive(until deadline: Date, handler: (String, Data) -> Void) {
        var buf = [UInt8](repeating: 0, count: 9000)
        while Date() < deadline {
            var from = sockaddr_in(); var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &fromLen) } }
            if n > 0 {
                handler(IPv4.string(UInt32(bigEndian: from.sin_addr.s_addr)), Data(buf[0..<n]))
            } else if n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR { break }
        }
    }
}

/// ICMP echo over an unprivileged datagram socket (macOS allows SOCK_DGRAM/IPPROTO_ICMP without root).
public enum ICMPProbe {
    public static func checksum(_ b: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < b.count { sum += UInt32(b[i]) << 8 | UInt32(b[i + 1]); i += 2 }
        if i < b.count { sum += UInt32(b[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return ~UInt16(sum & 0xFFFF)
    }

    static func echoRequest(id: UInt16, seq: UInt16) -> Data {
        var p: [UInt8] = [8, 0, 0, 0, UInt8(id >> 8), UInt8(id & 255), UInt8(seq >> 8), UInt8(seq & 255)]
        p += Array("rampart-netscan".utf8)
        let c = checksum(p); p[2] = UInt8(c >> 8); p[3] = UInt8(c & 255)
        return Data(p)
    }

    /// True when `payload` (as delivered by the socket; macOS prepends the IP header) is an echo reply.
    public static func isEchoReply(_ data: Data) -> Bool {
        let b = [UInt8](data)
        guard !b.isEmpty else { return false }
        var off = 0
        if b[0] >> 4 == 4 { off = Int(b[0] & 0x0F) * 4 }
        return b.count > off && b[off] == 0
    }

    /// Sweeps `hosts`; returns the addresses that answered. Sends through the limiter, listens `replyWindow`
    /// seconds after the last send.
    static func sweep(hosts: [String], limiter: ProbeRateLimiter, replyWindow: TimeInterval = 1.5, deadline: Date,
                      progress: ((Int) -> Void)? = nil) async -> Set<String> {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return [] }
        var tv = timeval(tv_sec: 0, tv_usec: 200_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let box = ReplyBox()
        let id = UInt16(truncatingIfNeeded: getpid())
        let reader = Task.detached(priority: .utility) {
            var buf = [UInt8](repeating: 0, count: 1500)
            while !Task.isCancelled && Date() < deadline {
                var from = sockaddr_in(); var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                let n = withUnsafeMutablePointer(to: &from) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &fromLen) } }
                if n > 0, isEchoReply(Data(buf[0..<n])) {
                    box.insert(IPv4.string(UInt32(bigEndian: from.sin_addr.s_addr)))
                } else if n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR { break }
            }
        }
        var sent = 0
        for (i, ip) in hosts.enumerated() {
            if Date() > deadline || Task.isCancelled { break }
            await limiter.acquire()
            guard let v = IPv4.parse(ip) else { continue }
            var sin = sockaddr_in(); sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET)
            sin.sin_addr.s_addr = v.bigEndian
            let pkt = echoRequest(id: id, seq: UInt16(truncatingIfNeeded: i))
            _ = pkt.withUnsafeBytes { raw in
                withUnsafePointer(to: &sin) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, raw.baseAddress, raw.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            }
            sent += 1
            if sent % 16 == 0 { progress?(sent) }
        }
        let end = min(deadline, Date().addingTimeInterval(replyWindow))
        while Date() < end && !Task.isCancelled { try? await Task.sleep(nanoseconds: 100_000_000) }
        reader.cancel()
        _ = await reader.result
        close(fd)
        return box.values
    }

    final class ReplyBox: @unchecked Sendable {
        private var set = Set<String>(); private let lock = NSLock()
        func insert(_ s: String) { lock.lock(); set.insert(s); lock.unlock() }
        var values: Set<String> { lock.lock(); defer { lock.unlock() }; return set }
    }
}

/// Non-blocking TCP connect with a timeout. Returns `.open`, `.closed` (RST) or `.filtered` (timeout).
public enum TCPProbe {
    public enum Result: String, Sendable { case open, closed, filtered, error }

    public static func connect(ip: String, port: Int, timeout: TimeInterval) async -> Result {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async { cont.resume(returning: connectSync(ip: ip, port: port, timeout: timeout)) }
        }
    }

    static func connectSync(ip: String, port: Int, timeout: TimeInterval) -> Result {
        guard let v = IPv4.parse(ip), port > 0, port < 65536 else { return .error }
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return .error }
        defer { close(fd) }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
        var sin = sockaddr_in(); sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = UInt16(port).bigEndian; sin.sin_addr.s_addr = v.bigEndian
        let r = withUnsafePointer(to: &sin) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        if r == 0 { return .open }
        guard errno == EINPROGRESS else { return errno == ECONNREFUSED ? .closed : .error }
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let pr = poll(&pfd, 1, Int32(timeout * 1000))
        if pr == 0 { return .filtered }
        guard pr > 0 else { return .error }
        var err: Int32 = 0; var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
        switch err {
        case 0: return .open
        case ECONNREFUSED, ECONNRESET: return .closed
        case ETIMEDOUT, EHOSTUNREACH, EHOSTDOWN: return .filtered
        default: return .error
        }
    }
}

// MARK: - mDNS (legacy unicast queries; responses come back unicast to our ephemeral port)

public struct MDNSInfo: Sendable, Hashable {
    public var services: Set<String> = []        // "_airplay._tcp"
    public var instances: Set<String> = []       // "Living Room"
    public var hostnames: Set<String> = []       // "living-room.local"
    public var txt: [String: String] = [:]       // merged TXT key/values
    public var model: String?                    // _device-info TXT "model=" or TXT "md="/"model="
    public init() {}
}

public enum MDNSParser {
    public static let serviceTypes = [
        "_services._dns-sd._udp", "_airplay._tcp", "_raop._tcp", "_companion-link._tcp", "_googlecast._tcp", "_http._tcp", "_https._tcp",
        "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_smb._tcp", "_afpovertcp._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
        "_rfb._tcp", "_hap._tcp", "_homekit._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_amzn-wplay._tcp", "_workstation._tcp",
        "_device-info._tcp", "_rdlink._tcp", "_sleep-proxy._udp", "_nvstream._tcp", "_androidtvremote2._tcp", "_matter._tcp", "_hue._tcp",
        "_printer._tcp", "_scanner._tcp", "_uscan._tcp", "_adisk._tcp", "_nfs._tcp", "_daap._tcp", "_touch-able._tcp", "_mqtt._tcp", "_rtsp._tcp",
    ]

    /// Query for a set of PTR names (legacy unicast, flags 0, class IN).
    public static func query(names: [String], type: UInt16 = DNSType.ptr, id: UInt16 = 0) -> Data {
        var m = DNSMessage(id: id, flags: 0)
        for n in names { m.questions.append(DNSQuestion(name: n, type: type, qclass: 1)) }
        return m.serialize()
    }

    public static func reverseName(_ ip: String) -> String {
        ip.split(separator: ".").reversed().joined(separator: ".") + ".in-addr.arpa"
    }

    /// TXT rdata: sequence of length-prefixed `key=value` strings.
    public static func parseTXT(_ rdata: Data) -> [String: String] {
        let b = [UInt8](rdata)
        var out: [String: String] = [:]
        var i = 0
        while i < b.count {
            let len = Int(b[i]); i += 1
            guard len > 0, i + len <= b.count else { i += len; continue }
            let s = String(decoding: b[i..<(i + len)], as: UTF8.self); i += len
            if let eq = s.firstIndex(of: "=") {
                out[String(s[..<eq]).lowercased()] = String(s[s.index(after: eq)...])
            } else { out[s.lowercased()] = "" }
        }
        return out
    }

    /// SRV rdata: priority, weight, port, target (uncompressed or compressed name relative to the whole message).
    static func parseSRVTarget(_ rr: DNSResourceRecord, message: Data) -> String? {
        // The rdata of an SRV record may hold a compressed name pointing into the full message; locate the
        // record's rdata inside the message by ttlOffset (+4 ttl +2 rdlen) and read from there.
        let b = [UInt8](message)
        let start = rr.ttlOffset + 6 + 6
        guard rr.ttlOffset > 0, start < b.count, rr.rdata.count >= 7 else { return nil }
        return try? DNSWire.readName(b, at: start).0
    }

    /// Pure: folds one response message into an MDNSInfo.
    public static func parse(_ data: Data) -> MDNSInfo? {
        guard let m = try? DNSMessage.parse(data), m.isResponse else { return nil }
        var info = MDNSInfo()
        for rr in m.answers + m.additionals {
            let name = rr.name.lowercased()
            switch rr.type {
            case DNSType.ptr:
                guard let v = rr.value?.lowercased() else { continue }
                let rawValue = readRawName([UInt8](data), at: rr.ttlOffset + 6) ?? v
                if name == "_services._dns-sd._udp.local" {
                    info.services.insert(v.replacingOccurrences(of: ".local", with: ""))
                } else if name.hasSuffix(".in-addr.arpa") {
                    info.hostnames.insert(v)
                } else if let svc = serviceType(in: name) {
                    info.services.insert(svc)
                    if let inst = instanceName(rawValue, service: svc) { info.instances.insert(inst) }
                }
            case DNSType.srv:
                if let svc = serviceType(in: name) {
                    info.services.insert(svc)
                    if info.instances.isEmpty, let inst = instanceName(name, service: svc) { info.instances.insert(inst) }
                }
                if let t = parseSRVTarget(rr, message: data) { info.hostnames.insert(t.lowercased()) }
            case DNSType.a, DNSType.aaaa:
                if name.hasSuffix(".local") { info.hostnames.insert(name) }
            case DNSType.txt:
                let kv = parseTXT(rr.rdata)
                if let svc = serviceType(in: name) { info.services.insert(svc) }
                for (k, v) in kv where !v.isEmpty { info.txt[k] = v }
                if name.hasSuffix("._device-info._tcp.local"), let model = kv["model"] { info.model = model }
                else if info.model == nil, let md = kv["md"] ?? kv["model"] ?? kv["am"] { info.model = md }
            default: break
            }
        }
        if let m = info.txt["model"], info.model == nil { info.model = m }
        return info
    }

    /// Case-preserving name reader (DNSWire lowercases; Bonjour instance names are user-visible).
    static func readRawName(_ b: [UInt8], at start: Int, depth: Int = 0) -> String? {
        var labels: [String] = []
        var i = start
        while i < b.count, depth < 8 {
            let len = Int(b[i])
            if len == 0 { break }
            if len & 0xC0 == 0xC0 {
                guard i + 1 < b.count else { return nil }
                let ptr = (len & 0x3F) << 8 | Int(b[i + 1])
                guard let rest = readRawName(b, at: ptr, depth: depth + 1) else { return nil }
                labels.append(rest); return labels.joined(separator: ".")
            }
            guard i + 1 + len <= b.count else { return nil }
            var label = ""
            for c in b[(i + 1)..<(i + 1 + len)] {
                let ch = Character(UnicodeScalar(c))
                if ch == "." { label += "\\." } else if c < 0x20 || c == 0x7F { label += String(format: "\\%03d", c) } else { label.append(ch) }
            }
            labels.append(label)
            i += 1 + len
        }
        return labels.joined(separator: ".")
    }

    static func serviceType(in name: String) -> String? {
        // "Living Room._airplay._tcp.local" → "_airplay._tcp"
        let labels = name.split(separator: ".").map(String.init)
        guard labels.count >= 3, labels.last == "local" else { return nil }
        let proto = labels[labels.count - 2], svc = labels[labels.count - 3]
        guard proto == "_tcp" || proto == "_udp", svc.hasPrefix("_") else { return nil }
        return "\(svc).\(proto)"
    }

    static func instanceName(_ fullName: String, service: String) -> String? {
        let suffix = "." + service + ".local"
        guard fullName.lowercased().hasSuffix(suffix), fullName.count > suffix.count else { return nil }
        let raw = String(fullName.dropLast(suffix.count))
        // DNS escapes: "\032" → space, "\." → "."
        var out = ""; var i = raw.startIndex
        while i < raw.endIndex {
            if raw[i] == "\\" {
                let next = raw.index(after: i)
                if next < raw.endIndex, raw[next].isNumber, let end = raw.index(next, offsetBy: 3, limitedBy: raw.endIndex), let code = UInt8(raw[next..<end]) {
                    out.append(Character(UnicodeScalar(code))); i = end; continue
                }
                if next < raw.endIndex { out.append(raw[next]); i = raw.index(after: next); continue }
            }
            out.append(raw[i]); i = raw.index(after: i)
        }
        return out.isEmpty ? nil : out
    }
}

enum MDNSDiscovery {
    /// Multicast browse: one legacy-unicast query per batch of service types; collect for `window` seconds.
    static func browse(interfaceAddress: String, limiter: ProbeRateLimiter, window: TimeInterval = 2.5) async -> [String: MDNSInfo] {
        guard let sock = UDPProbeSocket(interfaceAddress: interfaceAddress, ttl: 255) else { return [:] }
        let names = MDNSParser.serviceTypes.map { $0 + ".local" }
        for chunk in stride(from: 0, to: names.count, by: 6).map({ Array(names[$0..<min($0 + 6, names.count)]) }) {
            await limiter.acquire()
            sock.send(MDNSParser.query(names: chunk), to: "224.0.0.251", port: 5353)
        }
        return await collect(sock, window: window)
    }

    /// Direct unicast to one host: reverse PTR + a few service PTRs (+ _device-info TXT when the host is known).
    static func probe(ip: String, hostname: String?, interfaceAddress: String, limiter: ProbeRateLimiter, window: TimeInterval = 1.0) async -> MDNSInfo? {
        guard let sock = UDPProbeSocket(interfaceAddress: interfaceAddress, ttl: 255) else { return nil }
        var m = DNSMessage(id: 0, flags: 0)
        m.questions.append(DNSQuestion(name: MDNSParser.reverseName(ip), type: DNSType.ptr))
        m.questions.append(DNSQuestion(name: "_services._dns-sd._udp.local", type: DNSType.ptr))
        if let h = hostname, h.hasSuffix(".local") {
            let base = String(h.dropLast(6))
            m.questions.append(DNSQuestion(name: "\(base)._device-info._tcp.local", type: DNSType.txt))
        }
        await limiter.acquire()
        sock.send(m.serialize(), to: ip, port: 5353)
        return await collect(sock, window: window)[ip]
    }

    private static func collect(_ sock: UDPProbeSocket, window: TimeInterval) async -> [String: MDNSInfo] {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                var out: [String: MDNSInfo] = [:]
                sock.receive(until: Date().addingTimeInterval(window)) { ip, data in
                    guard let info = MDNSParser.parse(data) else { return }
                    var cur = out[ip] ?? MDNSInfo()
                    cur.services.formUnion(info.services); cur.instances.formUnion(info.instances); cur.hostnames.formUnion(info.hostnames)
                    cur.txt.merge(info.txt) { a, _ in a }
                    if cur.model == nil { cur.model = info.model }
                    out[ip] = cur
                }
                cont.resume(returning: out)
            }
        }
    }
}

// MARK: - SSDP / UPnP

public struct SSDPResponse: Codable, Hashable, Sendable {
    public var location: String?
    public var server: String?
    public var st: String?
    public var usn: String?
    public var headers: [String: String]

    /// Pure parser for an HTTP/1.1 200 OK (M-SEARCH response) or NOTIFY.
    public static func parse(_ text: String) -> SSDPResponse? {
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard let first = lines.first, first.uppercased().hasPrefix("HTTP/1.1 200") || first.uppercased().hasPrefix("NOTIFY") else { return nil }
        var h: [String: String] = [:]
        for l in lines.dropFirst() {
            guard let c = l.firstIndex(of: ":") else { continue }
            let k = l[..<c].trimmingCharacters(in: .whitespaces).uppercased()
            let v = l[l.index(after: c)...].trimmingCharacters(in: .whitespaces)
            if !k.isEmpty { h[k] = v }
        }
        guard !h.isEmpty else { return nil }
        return SSDPResponse(location: h["LOCATION"], server: h["SERVER"], st: h["ST"] ?? h["NT"], usn: h["USN"], headers: h)
    }

    public var isInternetGateway: Bool {
        let s = ((st ?? "") + " " + (usn ?? "")).lowercased()
        return s.contains("internetgatewaydevice") || s.contains("wanipconnection") || s.contains("wanpppconnection")
    }
}

/// Minimal UPnP device-description XML reader (no XML parser needed; tags are simple).
public struct UPnPDescription: Codable, Hashable, Sendable {
    public var friendlyName: String?
    public var manufacturer: String?
    public var modelName: String?
    public var deviceTypes: [String]
    public var serviceTypes: [String]

    public var isInternetGateway: Bool {
        deviceTypes.contains { $0.lowercased().contains("internetgatewaydevice") } ||
        serviceTypes.contains { let s = $0.lowercased(); return s.contains("wanipconnection") || s.contains("wanpppconnection") }
    }

    public static func parse(_ xml: String) -> UPnPDescription {
        func all(_ tag: String) -> [String] {
            var out: [String] = []
            var search = xml.startIndex
            while let open = xml.range(of: "<\(tag)>", range: search..<xml.endIndex),
                  let close = xml.range(of: "</\(tag)>", range: open.upperBound..<xml.endIndex) {
                out.append(xml[open.upperBound..<close.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines))
                search = close.upperBound
            }
            return out
        }
        return UPnPDescription(friendlyName: all("friendlyName").first, manufacturer: all("manufacturer").first,
                               modelName: all("modelName").first, deviceTypes: all("deviceType"), serviceTypes: all("serviceType"))
    }
}

enum SSDPDiscovery {
    static let msearch = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"

    static func discover(interfaceAddress: String, limiter: ProbeRateLimiter, window: TimeInterval = 2.5) async -> [String: [SSDPResponse]] {
        guard let sock = UDPProbeSocket(interfaceAddress: interfaceAddress, ttl: 2) else { return [:] }
        for _ in 0..<2 {   // two M-SEARCHes 300 ms apart: UPnP stacks often miss the first
            await limiter.acquire()
            sock.send(Data(msearch.utf8), to: "239.255.255.250", port: 1900)
            try? await Task.sleep(nanoseconds: 300_000_000)
        }
        return await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                var out: [String: [SSDPResponse]] = [:]
                sock.receive(until: Date().addingTimeInterval(window)) { ip, data in
                    if let r = SSDPResponse.parse(String(decoding: data, as: UTF8.self)) { out[ip, default: []].append(r) }
                }
                cont.resume(returning: out)
            }
        }
    }

    /// Direct unicast M-SEARCH to one host (checks whether it answers SSDP at all).
    static func probe(ip: String, limiter: ProbeRateLimiter, window: TimeInterval = 1.0) async -> [SSDPResponse] {
        guard let sock = UDPProbeSocket(ttl: 2) else { return [] }
        await limiter.acquire()
        sock.send(Data(msearch.utf8), to: ip, port: 1900)
        return await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                var out: [SSDPResponse] = []
                sock.receive(until: Date().addingTimeInterval(window)) { from, data in
                    if from == ip, let r = SSDPResponse.parse(String(decoding: data, as: UTF8.self)) { out.append(r) }
                }
                cont.resume(returning: out)
            }
        }
    }

    /// Fetches a device description XML with a short timeout (LAN only, http only).
    static func fetchDescription(_ location: String, timeout: TimeInterval = 3, subnet: NetSubnet) async -> UPnPDescription? {
        guard let url = URL(string: location), url.scheme == "http", let host = url.host, subnet.contains(host) else { return nil }
        var req = URLRequest(url: url); req.timeoutInterval = timeout
        req.setValue("RamPart/\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1")", forHTTPHeaderField: "User-Agent")
        guard let (data, resp) = try? await URLSession.shared.data(for: req), (resp as? HTTPURLResponse)?.statusCode == 200,
              data.count < 512_000 else { return nil }
        return UPnPDescription.parse(String(decoding: data, as: UTF8.self))
    }
}

// MARK: - Reverse DNS

enum ReverseDNS {
    /// System resolver PTR lookup with a timeout; many routers answer from their DHCP lease table.
    static func lookup(_ ip: String, timeout: TimeInterval = 1.5) async -> String? {
        await withTaskGroup(of: String?.self) { group in
            group.addTask {
                await withCheckedContinuation { cont in
                    DispatchQueue.global(qos: .utility).async {
                        guard let v = IPv4.parse(ip) else { cont.resume(returning: nil); return }
                        var sin = sockaddr_in(); sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET)
                        sin.sin_addr.s_addr = v.bigEndian
                        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                        let r = withUnsafePointer(to: &sin) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) } }
                        cont.resume(returning: r == 0 ? String(cString: host) : nil)
                    }
                }
            }
            group.addTask { try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000)); return nil }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }
}

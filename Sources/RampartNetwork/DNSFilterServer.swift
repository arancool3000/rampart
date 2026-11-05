import Foundation
import RampartShared

public struct DNSFilterConfig: Sendable {
    public enum BlockMode: String, Codable, Sendable { case nullAddress, nxdomain }

    /// IPv4 or IPv6 literal to bind (e.g. "127.0.0.1", "::1").
    public var listenAddress: String
    /// 0 picks an ephemeral port (see `DNSFilterServer.boundPort`).
    public var port: UInt16
    public var enableTCP: Bool
    public var blockMode: BlockMode
    public var blockedTTL: UInt32
    public var upstreams: [URL]
    public var upstreamTimeout: TimeInterval
    public var cacheCapacity: Int
    /// Names answered NXDOMAIN regardless of lists (Firefox DoH canary).
    public var canaryDomains: [String]
    /// Also NXDOMAIN `mask.icloud.com`/`mask-h2.icloud.com` (iCloud Private Relay opt-out signal).
    public var blockPrivateRelay: Bool
    /// Block when an upstream answer's CNAME chain points at a blocked domain (CNAME cloaking).
    public var inspectCNAMEs: Bool

    /// Default: 127.0.0.1:53 as root, 127.0.0.1:5353 for development (non-root).
    public init(listenAddress: String = "127.0.0.1",
                port: UInt16 = getuid() == 0 ? 53 : 5353,
                enableTCP: Bool = true,
                blockMode: BlockMode = .nullAddress,
                blockedTTL: UInt32 = 60,
                upstreams: [URL] = DoHClient.defaultUpstreams,
                upstreamTimeout: TimeInterval = 4,
                cacheCapacity: Int = 4096,
                canaryDomains: [String] = ["use-application-dns.net"],
                blockPrivateRelay: Bool = false,
                inspectCNAMEs: Bool = true) {
        self.listenAddress = listenAddress; self.port = port; self.enableTCP = enableTCP
        self.blockMode = blockMode; self.blockedTTL = blockedTTL; self.upstreams = upstreams
        self.upstreamTimeout = upstreamTimeout; self.cacheCapacity = cacheCapacity
        self.canaryDomains = canaryDomains; self.blockPrivateRelay = blockPrivateRelay
        self.inspectCNAMEs = inspectCNAMEs
    }
}

/// One resolved query, for telemetry / the Network screen.
public struct DNSQueryLogEntry: Codable, Sendable {
    public enum Verdict: String, Codable, Sendable {
        case forwarded, cached, blocked, allowlisted, canary, servfail, refused, formerr
    }
    public var date: Date
    public var name: String
    public var type: String
    public var verdict: Verdict
    public var rule: String?          // matching blocklist/allowlist rule
    public var listSource: String?    // which list the rule came from
    public var upstream: String?      // DoH host used
    public var answers: [String]      // A/AAAA/CNAME values
    public var rcode: Int
    public var client: String
    public var transport: String      // "udp" / "tcp"
    public var milliseconds: Double
    public var error: String?

    /// Converts to the shared event model (`SecurityEventKind.dnsQuery`).
    public var securityEvent: SecurityEvent {
        var d: [String: String] = ["name": name, "type": type, "verdict": verdict.rawValue,
                                   "rcode": String(rcode), "client": client, "transport": transport]
        if let rule { d["rule"] = rule }
        if let listSource { d["list"] = listSource }
        if let upstream { d["upstream"] = upstream }
        if !answers.isEmpty { d["answers"] = answers.joined(separator: ",") }
        return SecurityEvent(date: date, kind: .dnsQuery, detail: d, source: "dns")
    }
}

public enum DNSFilterServerError: Error, CustomStringConvertible {
    case badAddress(String), socket(String, Int32)
    public var description: String {
        switch self {
        case .badAddress(let a): return "invalid listen address \(a)"
        case .socket(let op, let e): return "\(op) failed: \(String(cString: strerror(e))) (errno \(e))"
        }
    }
}

/// Local filtering DNS resolver: UDP + TCP listener (BSD sockets), blocklist, canaries, cache, DoH upstream.
public final class DNSFilterServer: @unchecked Sendable {
    public let config: DNSFilterConfig
    public let cache: DNSResponseCache
    public let doh: DoHClient
    /// Called (on a background queue) for every query handled.
    public var queryLog: (@Sendable (DNSQueryLogEntry) -> Void)?

    private let blocklistLock = NSLock()
    private var _blocklist: DomainBlocklist
    public var blocklist: DomainBlocklist {
        get { blocklistLock.lock(); defer { blocklistLock.unlock() }; return _blocklist }
        set { blocklistLock.lock(); _blocklist = newValue; blocklistLock.unlock(); cache.clear() }
    }

    private let log = RLog.logger("dns")
    private let work = DispatchQueue(label: "app.rampart.dns.work", attributes: .concurrent)
    private let stateLock = NSLock()
    private var running = false
    private var udpFD: Int32 = -1
    private var tcpFD: Int32 = -1
    private var threads: [Thread] = []
    public private(set) var boundPort: UInt16 = 0
    private var statsStore: [DNSQueryLogEntry.Verdict: Int] = [:]

    public init(config: DNSFilterConfig = DNSFilterConfig(), blocklist: DomainBlocklist = DomainBlocklist()) {
        self.config = config
        self._blocklist = blocklist
        self.cache = DNSResponseCache(capacity: config.cacheCapacity)
        self.doh = DoHClient(upstreams: config.upstreams, timeout: config.upstreamTimeout)
    }

    deinit { stop() }

    public var isRunning: Bool { stateLock.lock(); defer { stateLock.unlock() }; return running }

    public var stats: [String: Int] {
        stateLock.lock(); defer { stateLock.unlock() }
        var out = Dictionary(uniqueKeysWithValues: statsStore.map { ($0.key.rawValue, $0.value) })
        out["cacheEntries"] = cache.count
        return out
    }

    // MARK: Lifecycle

    public func start() throws {
        stateLock.lock(); defer { stateLock.unlock() }
        guard !running else { return }
        let (addr, len, family) = try Self.makeSockaddr(config.listenAddress, port: config.port)
        let u = try Self.openSocket(family: family, type: SOCK_DGRAM, addr: addr, len: len)
        var port = Self.localPort(u)
        if config.enableTCP {
            let (addr2, len2, _) = try Self.makeSockaddr(config.listenAddress, port: port)
            do {
                let t = try Self.openSocket(family: family, type: SOCK_STREAM, addr: addr2, len: len2)
                guard listen(t, 64) == 0 else { let e = errno; close(t); throw DNSFilterServerError.socket("listen", e) }
                tcpFD = t
            } catch { close(u); throw error }
        }
        udpFD = u; port = Self.localPort(u); boundPort = port
        running = true
        let ut = Thread { [weak self] in self?.udpLoop(fd: u) }
        ut.name = "rampart-dns-udp"; ut.start(); threads.append(ut)
        if tcpFD >= 0 {
            let fd = tcpFD
            let tt = Thread { [weak self] in self?.tcpAcceptLoop(fd: fd) }
            tt.name = "rampart-dns-tcp"; tt.start(); threads.append(tt)
        }
        log.info("DNS filter listening on \(self.config.listenAddress, privacy: .public):\(port) (tcp: \(self.tcpFD >= 0))")
    }

    public func stop() {
        stateLock.lock()
        guard running else { stateLock.unlock(); return }
        running = false
        let u = udpFD, t = tcpFD
        udpFD = -1; tcpFD = -1; threads = []
        stateLock.unlock()
        // Loops poll with a short timeout and exit when `running` is false; close after they notice.
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.6) {
            if u >= 0 { close(u) }
            if t >= 0 { close(t) }
        }
    }

    // MARK: Socket helpers

    static func makeSockaddr(_ address: String, port: UInt16) throws -> (sockaddr_storage, socklen_t, Int32) {
        var ss = sockaddr_storage()
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            withUnsafeMutablePointer(to: &ss) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in
                    p.pointee.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    p.pointee.sin_family = sa_family_t(AF_INET)
                    p.pointee.sin_port = port.bigEndian
                    p.pointee.sin_addr = v4
                }
            }
            return (ss, socklen_t(MemoryLayout<sockaddr_in>.size), AF_INET)
        }
        if inet_pton(AF_INET6, address, &v6) == 1 {
            withUnsafeMutablePointer(to: &ss) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in
                    p.pointee.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    p.pointee.sin6_family = sa_family_t(AF_INET6)
                    p.pointee.sin6_port = port.bigEndian
                    p.pointee.sin6_addr = v6
                }
            }
            return (ss, socklen_t(MemoryLayout<sockaddr_in6>.size), AF_INET6)
        }
        throw DNSFilterServerError.badAddress(address)
    }

    static func openSocket(family: Int32, type: Int32, addr: sockaddr_storage, len: socklen_t) throws -> Int32 {
        let fd = socket(family, type, type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP)
        guard fd >= 0 else { throw DNSFilterServerError.socket("socket", errno) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        if family == AF_INET6 { setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, socklen_t(MemoryLayout<Int32>.size)) }
        var a = addr
        let rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) } }
        guard rc == 0 else { let e = errno; close(fd); throw DNSFilterServerError.socket("bind", e) }
        return fd
    }

    static func localPort(_ fd: Int32) -> UInt16 {
        var ss = sockaddr_storage(); var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        _ = withUnsafeMutablePointer(to: &ss) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        let family = Int32(ss.ss_family)
        return withUnsafePointer(to: &ss) { p -> UInt16 in
            if family == AF_INET {
                return p.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin_port) }
            }
            return p.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin6_port) }
        }
    }

    static func describe(_ ss: sockaddr_storage) -> String {
        var s = ss
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let rc = withUnsafePointer(to: &s) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, socklen_t(ss.ss_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            }
        }
        return rc == 0 ? String(cString: host) : "?"
    }

    private func waitReadable(_ fd: Int32, ms: Int32) -> Bool {
        var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        return poll(&p, 1, ms) > 0 && (p.revents & Int16(POLLIN)) != 0
    }

    // MARK: UDP

    private func udpLoop(fd: Int32) {
        var buf = [UInt8](repeating: 0, count: 65_535)
        while isRunning {
            guard waitReadable(fd, ms: 250) else { continue }
            var from = sockaddr_storage(); var fromLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &from) { fp in
                fp.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &fromLen) }
            }
            guard n > 0 else { continue }
            let packet = Data(buf[0..<n])
            let client = from, clientLen = fromLen
            work.async { [weak self] in
                self?.handle(packet, client: Self.describe(client), transport: "udp") { reply, limit in
                    let out = limit.map { DNSWire.truncateIfNeeded(reply.data, limit: $0, query: reply.query) } ?? reply.data
                    var c = client
                    _ = out.withUnsafeBytes { raw in
                        withUnsafePointer(to: &c) { cp in
                            cp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, raw.baseAddress, out.count, 0, $0, clientLen) }
                        }
                    }
                }
            }
        }
    }

    // MARK: TCP (RFC 7766: 2-byte length prefix, multiple queries per connection)

    private func tcpAcceptLoop(fd: Int32) {
        while isRunning {
            guard waitReadable(fd, ms: 250) else { continue }
            var from = sockaddr_storage(); var fromLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let c = withUnsafeMutablePointer(to: &from) { fp in
                fp.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(fd, $0, &fromLen) }
            }
            guard c >= 0 else { continue }
            var tv = timeval(tv_sec: 10, tv_usec: 0)
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            var one: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            let clientName = Self.describe(from)
            DispatchQueue.global().async { [weak self] in
                self?.tcpConnection(c, client: clientName)
                close(c)
            }
        }
    }

    private func readExactly(_ fd: Int32, _ n: Int) -> Data? {
        var buf = [UInt8](repeating: 0, count: n); var got = 0
        while got < n {
            let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, n - got) }
            if r <= 0 { return nil }
            got += r
        }
        return Data(buf)
    }

    private func tcpConnection(_ fd: Int32, client: String) {
        while isRunning, let head = readExactly(fd, 2) {
            let len = Int(head[0]) << 8 | Int(head[1])
            guard len >= 12, let msg = readExactly(fd, len) else { return }
            let sem = DispatchSemaphore(value: 0)
            let box = ReplyBox()
            handle(msg, client: client, transport: "tcp") { reply, _ in box.data = reply.data; sem.signal() }
            guard sem.wait(timeout: .now() + config.upstreamTimeout * 3) == .success, let out = box.data,
                  out.count <= 65_535 else { return }
            var frame = Data([UInt8(out.count >> 8), UInt8(out.count & 0xFF)]); frame.append(out)
            let ok = frame.withUnsafeBytes { raw -> Bool in
                var off = 0
                while off < frame.count {
                    let w = write(fd, raw.baseAddress! + off, frame.count - off)
                    if w <= 0 { return false }
                    off += w
                }
                return true
            }
            if !ok { return }
        }
    }

    // MARK: Query pipeline

    struct Reply { let data: Data; let query: DNSMessage }
    private final class ReplyBox: @unchecked Sendable { var data: Data? }

    /// Resolves one wire-format query without any socket (also used by tests and by a future in-process API).
    public func resolve(_ packet: Data, client: String = "local", completion: @escaping @Sendable (Data?) -> Void) {
        handle(packet, client: client, transport: "api") { reply, _ in completion(reply.data) }
    }

    /// `respond(reply, udpLimit)`; udpLimit is the max UDP payload for this client (nil for TCP).
    func handle(_ packet: Data, client: String, transport: String, respond: @escaping @Sendable (Reply, Int?) -> Void) {
        let started = Date()
        guard let query = try? DNSMessage.parse(packet), !query.isResponse else {
            if let fe = DNSWire.buildFormErr(raw: packet), let fq = try? DNSMessage.parse(fe) {
                record(DNSQueryLogEntry(date: started, name: "", type: "", verdict: .formerr, answers: [],
                                        rcode: Int(DNSRCode.formErr), client: client, transport: transport,
                                        milliseconds: 0))
                respond(Reply(data: fe, query: fq), nil)
            }
            return
        }
        let udpLimit: Int? = transport == "udp" ? (query.ednsPayloadSize ?? 512) : nil
        guard let q = query.questions.first, query.questions.count == 1, query.opcode == 0 else {
            let rc = query.opcode != 0 ? DNSRCode.notImp : DNSRCode.formErr
            respond(Reply(data: DNSWire.buildError(for: query, rcode: rc), query: query), udpLimit)
            return
        }

        @Sendable func finish(_ data: Data, _ verdict: DNSQueryLogEntry.Verdict, rule: String? = nil, list: String? = nil,
                    upstream: String? = nil, error: String? = nil) {
            respond(Reply(data: data, query: query), udpLimit)
            let parsed = try? DNSMessage.parse(data)
            record(DNSQueryLogEntry(date: started, name: q.name, type: DNSType.name(q.type), verdict: verdict,
                                    rule: rule, listSource: list, upstream: upstream,
                                    answers: parsed?.answers.compactMap(\.value) ?? [],
                                    rcode: Int(parsed?.rcode ?? 0), client: client, transport: transport,
                                    milliseconds: Date().timeIntervalSince(started) * 1000, error: error))
        }

        // 1. Canaries.
        var canaries = config.canaryDomains.map(DNSWire.normalize)
        if config.blockPrivateRelay { canaries += ["mask.icloud.com", "mask-h2.icloud.com"] }
        if canaries.contains(q.name) {
            finish(DNSWire.buildError(for: query, rcode: DNSRCode.nxDomain), .canary, rule: q.name, list: "canary")
            return
        }
        // 2. Lists.
        let allowRule: String?
        switch blocklist.verdict(for: q.name) {
        case .blocked(let rule, let source):
            finish(DNSWire.buildBlockedResponse(for: query, mode: config.blockMode, ttl: config.blockedTTL),
                   .blocked, rule: rule, list: source)
            return
        case .allowlisted(let rule): allowRule = rule
        case .allowed: allowRule = nil
        }
        // 3. Cache.
        if let hit = cache.lookup(q, id: query.id) {
            finish(hit, allowRule == nil ? .cached : .allowlisted, rule: allowRule, list: allowRule == nil ? nil : "allowlist")
            return
        }
        // 4. DoH upstream.
        doh.resolve(packet) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let (data, url)):
                if allowRule == nil, self.config.inspectCNAMEs, let m = try? DNSMessage.parse(data) {
                    for rr in m.answers where rr.type == DNSType.cname {
                        if let target = rr.value, case .blocked(let rule, let src) = self.blocklist.verdict(for: target) {
                            finish(DNSWire.buildBlockedResponse(for: query, mode: self.config.blockMode, ttl: self.config.blockedTTL),
                                   .blocked, rule: "cname:" + rule, list: src)
                            return
                        }
                    }
                }
                self.cache.store(data, for: q)
                finish(data, allowRule == nil ? .forwarded : .allowlisted, rule: allowRule,
                       list: allowRule == nil ? nil : "allowlist", upstream: url.host)
            case .failure(let e):
                self.log.error("DoH failed for \(q.name, privacy: .public): \(e.description, privacy: .public)")
                finish(DNSWire.buildError(for: query, rcode: DNSRCode.servFail), .servfail, error: e.description)
            }
        }
    }

    private func record(_ e: DNSQueryLogEntry) {
        stateLock.lock(); statsStore[e.verdict, default: 0] += 1; stateLock.unlock()
        queryLog?(e)
    }
}

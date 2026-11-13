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
    /// Where learned DoH key pins persist (root-owned dir in the daemon). nil = in-memory for this run.
    public var pinStateURL: URL? = nil
    /// o4: when listening on 127.0.0.1, also claim [::1] on the same port. DNSSwitcher points the system at both
    /// 127.0.0.1 and ::1; macOS lets any user bind ports below 1024, so an unclaimed ::1:53 could be taken by local
    /// malware and answer the Mac's lookups past the filter.
    public var alsoListenIPv6Loopback: Bool = true
    /// o4: strip private/loopback/link-local answers for public names (DNS rebinding).
    public var blockRebinding: Bool = true

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
    case badAddress(String), notLoopback(String), socket(String, Int32)
    public var description: String {
        switch self {
        case .badAddress(let a): return "invalid listen address \(a)"
        case .notLoopback(let a): return "refusing to listen on non-loopback address \(a) (would be an open resolver)"
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
    private var udpFDs: [Int32] = []
    private var tcpFDs: [Int32] = []
    /// o4: true when the [::1] listener is up as well.
    public private(set) var ipv6LoopbackBound = false
    private var threads: [Thread] = []
    public private(set) var boundPort: UInt16 = 0
    private var statsStore: [DNSQueryLogEntry.Verdict: Int] = [:]

    // Resource limits (hx4): a local flood can't exhaust threads, sockets or DoH connections.
    /// Concurrent DoH lookups. o4: only upstream work is limited by this; blocked, canary and cached answers are
    /// served without an upstream slot, so a random-name flood cannot starve cached names (or the watchdog probe).
    public static let maxInFlight = 256
    /// o4: UDP datagrams queued for processing (bounds memory/threads under a flood; over the limit = drop).
    public static let maxQueued = 2048
    public static let maxTCPConnections = 32
    /// o4: TCP idle time between queries, and the deadline for a whole message once its length arrived.
    public static let tcpIdleSeconds: Double = 10
    public static let tcpMessageSeconds: Double = 5
    private var inFlight = 0
    private var queued = 0
    public private(set) var droppedOverload = 0
    private var tcpConnections = 0
    /// Upstream health for the DNS-restore watchdog (see `upstreamHealthy`).
    private var consecutiveUpstreamFailures = 0
    private var lastUpstreamSuccess: Date?
    public private(set) var droppedNonLocal = 0

    private var _policy: DNSPolicy?
    /// Content filter / SafeSearch / app-firewall hook (ContentFilter.swift). Changing it clears the cache.
    public var policy: DNSPolicy? {
        get { blocklistLock.lock(); defer { blocklistLock.unlock() }; return _policy }
        set { blocklistLock.lock(); _policy = newValue; blocklistLock.unlock(); cache.clear() }
    }

    /// `doh` injects a client (tests use a mock URLProtocol); production passes nil.
    public init(config: DNSFilterConfig = DNSFilterConfig(), blocklist: DomainBlocklist = DomainBlocklist(),
                doh: DoHClient? = nil) {
        self.config = config
        self._blocklist = blocklist
        self.cache = DNSResponseCache(capacity: config.cacheCapacity)
        self.doh = doh ?? DoHClient(upstreams: config.upstreams, timeout: config.upstreamTimeout,
                                    pins: DoHPinStore(stateURL: config.pinStateURL))
    }

    deinit { stop() }

    public var isRunning: Bool { stateLock.lock(); defer { stateLock.unlock() }; return running }

    /// False after 5+ consecutive DoH failures with no success in the last 60 s. The daemon watchdog should
    /// then restore the original DNS (`DNSSwitcher.restore()`) so the Mac is never left without DNS.
    public var upstreamHealthy: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        if consecutiveUpstreamFailures < 5 { return true }
        return lastUpstreamSuccess.map { Date().timeIntervalSince($0) < 60 } ?? false
    }

    /// Loopback only: 127.0.0.0/8 or ::1. Anything else would make this an open resolver.
    public static func isLoopbackAddress(_ address: String) -> Bool {
        guard let b = DNSWire.addressBytes(address) else { return false }
        if b.count == 4 { return b[0] == 127 }
        return b == [UInt8](repeating: 0, count: 15) + [1]
    }

    /// True when a datagram/connection source is loopback (127/8, ::1, or ::ffff:127.x).
    static func isLoopbackPeer(_ ss: sockaddr_storage) -> Bool {
        var s = ss
        switch Int32(ss.ss_family) {
        case AF_INET:
            return withUnsafePointer(to: &s) { $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                (UInt32(bigEndian: $0.pointee.sin_addr.s_addr) >> 24) == 127 } }
        case AF_INET6:
            let bytes: [UInt8] = withUnsafePointer(to: &s) { $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in
                var a = p.pointee.sin6_addr; return withUnsafeBytes(of: &a) { Array($0) } } }
            if bytes == [UInt8](repeating: 0, count: 15) + [1] { return true }
            return bytes.prefix(12) == [0,0,0,0,0,0,0,0,0,0,0xFF,0xFF] && bytes[12] == 127
        default: return false
        }
    }

    private func acquireSlot() -> Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        guard inFlight < Self.maxInFlight else { droppedOverload += 1; return false }
        inFlight += 1; return true
    }
    private func releaseSlot() { stateLock.lock(); inFlight = max(0, inFlight - 1); stateLock.unlock() }
    private func acquireQueue() -> Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        guard queued < Self.maxQueued else { droppedOverload += 1; return false }
        queued += 1; return true
    }
    private func releaseQueue() { stateLock.lock(); queued = max(0, queued - 1); stateLock.unlock() }
    private func noteUpstream(ok: Bool) {
        stateLock.lock()
        if ok { consecutiveUpstreamFailures = 0; lastUpstreamSuccess = Date() } else { consecutiveUpstreamFailures += 1 }
        stateLock.unlock()
    }
    private func noteDroppedNonLocal() { stateLock.lock(); droppedNonLocal += 1; stateLock.unlock() }

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
        guard Self.isLoopbackAddress(config.listenAddress) else { throw DNSFilterServerError.notLoopback(config.listenAddress) }
        let (addr, len, family) = try Self.makeSockaddr(config.listenAddress, port: config.port)
        let u = try Self.openSocket(family: family, type: SOCK_DGRAM, addr: addr, len: len)
        let port = Self.localPort(u)
        var tcp: [Int32] = [], udp: [Int32] = [u]
        if config.enableTCP {
            do { tcp.append(try Self.openListener(config.listenAddress, port: port)) } catch { close(u); throw error }
        }
        // o4: claim [::1] on the same port too (best effort: a Mac with IPv6 off on lo0 just skips it).
        ipv6LoopbackBound = false
        if config.alsoListenIPv6Loopback, family == AF_INET, port != 0 {
            do {
                let (a6, l6, _) = try Self.makeSockaddr("::1", port: port)
                let u6 = try Self.openSocket(family: AF_INET6, type: SOCK_DGRAM, addr: a6, len: l6)
                udp.append(u6)
                if config.enableTCP, let t6 = try? Self.openListener("::1", port: port) { tcp.append(t6) }
                ipv6LoopbackBound = true
            } catch {
                log.error("DNS filter: could not also listen on [::1]:\(port): \(String(describing: error), privacy: .public)")
            }
        }
        udpFDs = udp; tcpFDs = tcp; boundPort = port
        running = true
        for fd in udp {
            let ut = Thread { [weak self] in self?.udpLoop(fd: fd) }
            ut.name = "rampart-dns-udp"; ut.start(); threads.append(ut)
        }
        for fd in tcp {
            let tt = Thread { [weak self] in self?.tcpAcceptLoop(fd: fd) }
            tt.name = "rampart-dns-tcp"; tt.start(); threads.append(tt)
        }
        log.info("DNS filter listening on \(self.config.listenAddress, privacy: .public):\(port) (tcp: \(!tcp.isEmpty), ::1: \(self.ipv6LoopbackBound))")
    }

    public func stop() {
        stateLock.lock()
        guard running else { stateLock.unlock(); return }
        running = false
        let fds = udpFDs + tcpFDs
        udpFDs = []; tcpFDs = []; threads = []; ipv6LoopbackBound = false
        stateLock.unlock()
        // Loops poll with a short timeout and exit when `running` is false; close after they notice.
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.6) { for fd in fds { close(fd) } }
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

    static func openListener(_ address: String, port: UInt16) throws -> Int32 {
        let (a, l, f) = try makeSockaddr(address, port: port)
        let t = try openSocket(family: f, type: SOCK_STREAM, addr: a, len: l)
        guard listen(t, 64) == 0 else { let e = errno; close(t); throw DNSFilterServerError.socket("listen", e) }
        return t
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
            // Defence in depth: the socket is bound to loopback, but never answer an off-host source.
            guard Self.isLoopbackPeer(from) else { noteDroppedNonLocal(); continue }
            let packet = Data(buf[0..<n])
            let client = from, clientLen = fromLen
            guard acquireQueue() else { continue }   // overloaded: drop (client retries)
            work.async { [weak self] in
                guard let self else { return }
                self.handle(packet, client: Self.describe(client), transport: "udp") { reply, limit in
                    let out = limit.map { DNSWire.truncateIfNeeded(reply.data, limit: $0, query: reply.query) } ?? reply.data
                    var c = client
                    _ = out.withUnsafeBytes { raw in
                        withUnsafePointer(to: &c) { cp in
                            cp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, raw.baseAddress, out.count, 0, $0, clientLen) }
                        }
                    }
                    self.releaseQueue()
                } dropped: { self.releaseQueue() }
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
            guard Self.isLoopbackPeer(from) else { noteDroppedNonLocal(); close(c); continue }
            stateLock.lock()
            let full = tcpConnections >= Self.maxTCPConnections
            if !full { tcpConnections += 1 }
            stateLock.unlock()
            if full { close(c); continue }
            var tv = timeval(tv_sec: 10, tv_usec: 0)
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            var one: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            let clientName = Self.describe(from)
            DispatchQueue.global().async { [weak self] in
                self?.tcpConnection(c, client: clientName)
                close(c)
                if let self { self.stateLock.lock(); self.tcpConnections -= 1; self.stateLock.unlock() }
            }
        }
    }

    /// o4: reads exactly `n` bytes before an absolute deadline. SO_RCVTIMEO alone restarts on every byte, so a
    /// slow-loris client trickling one byte every few seconds could hold all 32 TCP slots forever.
    static func readExactly(_ fd: Int32, _ n: Int, deadline: Date) -> Data? {
        var buf = [UInt8](repeating: 0, count: n); var got = 0
        while got < n {
            let ms = Int32(max(0, min(60_000, deadline.timeIntervalSinceNow * 1000)))
            guard ms > 0 else { return nil }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let pr = poll(&p, 1, ms)
            if pr < 0 && errno == EINTR { continue }
            guard pr > 0 else { return nil }
            let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, n - got) }
            if r <= 0 { return nil }
            got += r
        }
        return Data(buf)
    }

    /// Test hook for the slow-loris deadline (selftest has no @testable import).
    public static func readExactlyForTest(_ fd: Int32, _ n: Int, deadline: Date) -> Data? { readExactly(fd, n, deadline: deadline) }

    private func tcpConnection(_ fd: Int32, client: String) {
        while isRunning, let head = Self.readExactly(fd, 2, deadline: Date().addingTimeInterval(Self.tcpIdleSeconds)) {
            let len = Int(head[0]) << 8 | Int(head[1])
            guard len >= 12, let msg = Self.readExactly(fd, len, deadline: Date().addingTimeInterval(Self.tcpMessageSeconds)) else { return }
            let sem = DispatchSemaphore(value: 0)
            let box = ReplyBox()
            handle(msg, client: client, transport: "tcp", respond: { reply, _ in box.data = reply.data; sem.signal() },
                   dropped: { sem.signal() })
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
    /// `dropped` runs instead of `respond` when no reply is sent (responses, oversize packets).
    func handle(_ packet: Data, client: String, transport: String, respond: @escaping @Sendable (Reply, Int?) -> Void,
                dropped: @escaping @Sendable () -> Void = {}) {
        let started = Date()
        // Never answer a message with QR set: replying to responses enables reflection loops between resolvers.
        if packet.count >= 3, packet[packet.startIndex + 2] & 0x80 != 0 { dropped(); return }
        guard packet.count <= 65_535 else { dropped(); return }
        guard let query = try? DNSMessage.parse(packet), !query.isResponse else {
            if let fe = DNSWire.buildFormErr(raw: packet), let fq = try? DNSMessage.parse(fe) {
                record(DNSQueryLogEntry(date: started, name: "", type: "", verdict: .formerr, answers: [],
                                        rcode: Int(DNSRCode.formErr), client: client, transport: transport,
                                        milliseconds: 0))
                respond(Reply(data: fe, query: fq), nil)
            } else { dropped() }
            return
        }
        let udpLimit: Int? = transport == "udp" ? (query.ednsPayloadSize ?? 512) : nil
        guard let q = query.questions.first, query.questions.count == 1, query.opcode == 0, query.isWellFormedQuery else {
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

        // 0. Bootstrap: the DoH upstream hostnames are answered from pinned addresses so resolving them never
        //    loops back through this resolver (which would leave the Mac without DNS).
        if q.qclass == 1, q.type == DNSType.a || q.type == DNSType.aaaa,
           let pinned = DoHClient.bootstrapAddresses[q.name] {
            var r = DNSMessage(id: query.id, flags: DNSWire.responseFlags(for: query, rcode: DNSRCode.noError))
            r.questions = [q]
            for a in pinned {
                guard let bytes = DNSWire.addressBytes(a), bytes.count == (q.type == DNSType.a ? 4 : 16) else { continue }
                r.answers.append(DNSResourceRecord(name: q.name, type: q.type, ttl: 300, rdata: Data(bytes), value: a))
            }
            finish(r.serialize(), .forwarded, rule: "bootstrap", list: "bootstrap")
            return
        }
        // 1. Canaries.
        var canaries = config.canaryDomains.map(DNSWire.normalize)
        if config.blockPrivateRelay { canaries += ["mask.icloud.com", "mask-h2.icloud.com"] }
        if canaries.contains(q.name) {
            finish(DNSWire.buildError(for: query, rcode: DNSRCode.nxDomain), .canary, rule: q.name, list: "canary")
            return
        }
        // 2. Lists (and the content-filter policy, which may override them).
        let allowRule: String?
        var listVerdict = blocklist.verdict(for: q.name)
        if let pol = policy {
            switch pol.decide(name: q.name, type: q.type, listVerdict: listVerdict, now: started) {
            case .useList: break
            case .pass: listVerdict = .allowed
            case .block(let rule, let source): listVerdict = .blocked(rule: rule, source: source)
            case .rewrite(let target, let rule):
                rewrite(query: query, q: q, target: target, rule: rule, finish: finish)
                return
            }
        }
        switch listVerdict {
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
        // 4. DoH upstream (o4: needs an upstream slot; the query sent is rebuilt from the question, see
        //    `DNSWire.upstreamQuery`, so client EDNS options, CD and stray records never reach the upstream).
        guard acquireSlot() else {
            if transport == "udp" { dropped() }   // the stub retries
            else { finish(DNSWire.buildError(for: query, rcode: DNSRCode.servFail), .servfail, error: "overloaded") }
            return
        }
        doh.resolve(DNSWire.upstreamQuery(for: query)) { [weak self] result in
            guard let self else { return }
            self.releaseSlot()
            switch result {
            case .success(let (rawData, url)):
                self.noteUpstream(ok: true)
                let data = rawData
                // o4: DNS rebinding. A public name answered with a private/loopback address is stripped.
                if allowRule == nil, self.config.blockRebinding, let (clean, gone) = DNSRebindGuard.strip(rawData, question: q) {
                    self.log.error("DNS rebinding blocked for \(q.name, privacy: .public): \(gone.joined(separator: ","), privacy: .public)")
                    self.cache.store(clean, for: q)
                    finish(clean, .blocked, rule: "rebind:" + (gone.first ?? "private"), list: "rebind-guard")
                    return
                }
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
                self.noteUpstream(ok: false)
                self.log.error("DoH failed for \(q.name, privacy: .public): \(e.description, privacy: .public)")
                finish(DNSWire.buildError(for: query, rcode: DNSRCode.servFail), .servfail, error: e.description)
            }
        }
    }

    /// SafeSearch: answers `q` with `q.name CNAME target` plus the target's own records. Only A/AAAA are rewritten;
    /// other types (HTTPS/SVCB hints could carry the unrestricted addresses) get an empty NOERROR answer.
    private func rewrite(query: DNSMessage, q: DNSQuestion, target: String, rule: String,
                         finish: @escaping @Sendable (Data, DNSQueryLogEntry.Verdict, String?, String?, String?, String?) -> Void) {
        var r = DNSMessage(id: query.id, flags: DNSWire.responseFlags(for: query, rcode: DNSRCode.noError))
        r.questions = [q]
        guard q.qclass == 1, q.type == DNSType.a || q.type == DNSType.aaaa else {
            finish(r.serialize(), .forwarded, rule, "safesearch", nil, nil); return   // not a block (no activity row)
        }
        r.answers.append(DNSResourceRecord(name: q.name, type: DNSType.cname, ttl: 300,
                                           rdata: Data(DNSWire.encodeName(target)), value: target))
        let base = r
        guard acquireSlot() else {
            finish(DNSWire.buildError(for: query, rcode: DNSRCode.servFail), .servfail, rule, "safesearch", nil, "overloaded"); return
        }
        doh.resolve(DNSWire.buildQuery(name: target, type: q.type)) { [weak self] result in
            guard let self else { return }
            self.releaseSlot()
            switch result {
            case .success(let (data, url)):
                self.noteUpstream(ok: true)
                var out = base
                if let m = try? DNSMessage.parse(data) {
                    for rr in m.answers where rr.type == q.type || rr.type == DNSType.cname {
                        // CNAME rdata may hold compression pointers into the upstream message: re-encode it.
                        let rdata = rr.type == DNSType.cname ? Data(DNSWire.encodeName(rr.value ?? "")) : rr.rdata
                        if rr.type == DNSType.cname && (rr.value ?? "").isEmpty { continue }
                        out.answers.append(DNSResourceRecord(name: rr.name, type: rr.type, ttl: min(rr.ttl, 300), rdata: rdata, value: rr.value))
                    }
                }
                finish(out.serialize(), .forwarded, rule, "safesearch", url.host, nil)
            case .failure(let e):
                self.noteUpstream(ok: false)
                finish(DNSWire.buildError(for: query, rcode: DNSRCode.servFail), .servfail, rule, "safesearch", nil, e.description)
            }
        }
    }

    private func record(_ e: DNSQueryLogEntry) {
        stateLock.lock(); statsStore[e.verdict, default: 0] += 1; stateLock.unlock()
        queryLog?(e)
    }
}

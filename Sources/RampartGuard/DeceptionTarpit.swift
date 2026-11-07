import Foundation
import Darwin
import RampartShared

/// The lure / tarpit listener. Off by default and opt-in. In production it runs inside the separate, unprivileged,
/// sandboxed helper described by `LureContainment` (layers 1-3, 7); this class is the in-helper server
/// (layers 4-6, 8) and is loopback-testable. It drips its fixed replies slowly (the tarpit) and records attempts.
public struct TarpitAttempt: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID = UUID()
    public var date: Date
    public var port: UInt16
    public var proto: LureProtocol = .nasLogin
    public var remote: String
    public var clientBanner: String    // first line the peer sent, sanitised, ≤ 120 chars
    public var bytesReceived: Int
    public var credentialAttempts: Int = 0
    public var seconds: Double
    public var refused: String? = nil  // set when dropped by scope / rate / concurrency caps
}

public final class TarpitServer: @unchecked Sendable {
    public let port: UInt16
    public let proto: LureProtocol
    public let scope: LureScope
    public let localSubnets: [String]
    public var lineDelay: TimeInterval
    public let limits: LureLimits
    private let rate: LureRateLimiter

    private let lock = NSLock()
    private var fd: Int32 = -1
    private var active = 0
    private var stopped = false
    private var attempts: [TarpitAttempt] = []
    public var onAttempt: (@Sendable (TarpitAttempt) -> Void)?
    public private(set) var boundPort: UInt16 = 0

    /// `.loopback` binds 127.0.0.1. `.localSubnet` binds all interfaces but drops any peer outside `localSubnets`
    /// (and the pf anchor enforces the same). `.anywhere` needs `confirmedAnywhere` (the user's explicit choice).
    public init(port: UInt16, proto: LureProtocol? = nil, scope: LureScope = .loopback, localSubnets: [String] = [],
                confirmedAnywhere: Bool = false, lineDelay: TimeInterval = 6, limits: LureLimits = LureLimits()) throws {
        if scope == .anywhere && !confirmedAnywhere { throw DeceptionError.bindRefused("exposing the lure to the internet needs explicit confirmation") }
        if scope == .localSubnet && localSubnets.isEmpty { throw DeceptionError.bindRefused("no local subnet known") }
        guard port == 0 || port >= 1024 else { throw DeceptionError.bindRefused("lure uses unprivileged high ports only") }
        self.port = port; self.proto = proto ?? LureProtocol.forPort(port); self.scope = scope; self.localSubnets = localSubnets
        self.lineDelay = max(0, lineDelay); self.limits = limits; self.rate = LureRateLimiter(perMinute: limits.maxPerPeerPerMinute)
    }

    public var recorded: [TarpitAttempt] { lock.lock(); defer { lock.unlock() }; return attempts }
    public var bindAddress: String { scope == .loopback ? "127.0.0.1" : "0.0.0.0" }

    public func start() throws {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { throw DeceptionError.io("socket") }
        var one: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, bindAddress, &addr.sin_addr) == 1 else { close(s); throw DeceptionError.bindRefused("bad address") }
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard rc == 0, listen(s, 16) == 0 else { close(s); throw DeceptionError.bindRefused("bind/listen errno \(errno)") }
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
        boundPort = UInt16(bigEndian: bound.sin_port)
        lock.lock(); fd = s; stopped = false; lock.unlock()
        let t = Thread { [weak self] in self?.acceptLoop(s) }
        t.name = "rampart.lure"; t.start()
    }

    /// Kill switch (layer 9): stops accepting and ends every session at its next step.
    public func stop() {
        lock.lock(); stopped = true; let s = fd; fd = -1; lock.unlock()
        if s >= 0 { shutdown(s, SHUT_RDWR); close(s) }
    }
    var isStopped: Bool { lock.lock(); defer { lock.unlock() }; return stopped }

    private func record(_ a: TarpitAttempt) {
        lock.lock(); attempts.append(a); if attempts.count > 500 { attempts.removeFirst(attempts.count - 500) }; lock.unlock()
        onAttempt?(a)
    }

    private func acceptLoop(_ s: Int32) {
        while true {
            var peer = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let c = withUnsafeMutablePointer(to: &peer) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(s, $0, &len) } }
            if c < 0 { if isStopped || errno == EBADF || errno == EINVAL { return }; continue }
            if isStopped { close(c); return }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var a = peer.sin_addr
            inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN))
            let ip = String(cString: buf)
            let remote = ip + ":" + String(UInt16(bigEndian: peer.sin_port))
            func refuse(_ why: String) {
                close(c)
                record(TarpitAttempt(date: Date(), port: boundPort, proto: proto, remote: remote, clientBanner: "", bytesReceived: 0, seconds: 0, refused: why))
            }
            guard LureAccessFilter.allows(peerIPv4: ip, scope: scope, localSubnets: localSubnets) else { refuse("outside allowed scope"); continue }
            guard rate.allow(ip) else { refuse("rate limit"); continue }
            lock.lock()
            guard active < limits.maxConcurrent else { lock.unlock(); refuse("too many sessions"); continue }
            active += 1; lock.unlock()
            Thread.detachNewThread { [weak self] in
                self?.session(c, remote: remote)
                close(c)
                self?.lock.lock(); self?.active -= 1; self?.lock.unlock()
            }
        }
    }

    private func session(_ c: Int32, remote: String) {
        let start = Date()
        var one: Int32 = 1
        setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: 0, tv_usec: 100_000)
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var sm = LureStateMachine(proto, limits: limits)
        var pending = Data()
        var total = 0
        var creds = 0
        var lastInput = Date()
        let deadline = start.addingTimeInterval(limits.maxSessionSeconds)

        func send(_ lines: [String]) -> Bool {
            for l in lines {
                if isStopped || Date() > deadline { return false }
                let b = Array((l + "\r\n").utf8)
                if Darwin.send(c, b, b.count, 0) < 0 { return false }
                if lineDelay > 0 { Thread.sleep(forTimeInterval: lineDelay) }   // the tarpit
            }
            return true
        }

        var alive = send(sm.greeting())
        while alive, !isStopped, Date() < deadline {
            if let nl = pending.firstIndex(of: 0x0A) {
                let lineData = pending[pending.startIndex..<nl]
                pending.removeSubrange(pending.startIndex...nl)
                let line = String(decoding: lineData.prefix(limits.maxLineBytes), as: UTF8.self).trimmingCharacters(in: .controlCharacters)
                let r = sm.input(line)
                if r.credentialAttempt { creds += 1 }
                alive = send(r.lines) && !r.close
                continue
            }
            if pending.count > limits.maxLineBytes * 4 { _ = sm.input(String(repeating: "x", count: limits.maxLineBytes * 5)); break }
            if Date().timeIntervalSince(lastInput) > limits.idleTimeout { break }
            var b = [UInt8](repeating: 0, count: 512)
            let n = recv(c, &b, b.count, 0)
            if n == 0 { break }
            if n < 0 { if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { continue }; break }
            total += n; lastInput = Date()
            if total > limits.maxTotalBytes { _ = send(["Too much typing. The cat got bored. Bye."]); break }
            pending.append(contentsOf: b[0..<n])
        }
        record(TarpitAttempt(date: start, port: boundPort == 0 ? port : boundPort, proto: proto, remote: remote,
                             clientBanner: SafeText.line(sm.firstLine, max: 120), bytesReceived: total,
                             credentialAttempts: creds, seconds: Date().timeIntervalSince(start)))
    }
}

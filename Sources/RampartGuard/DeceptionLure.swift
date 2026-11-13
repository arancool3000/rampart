import Foundation

// The network lure's brain: a FIXED, tiny protocol state machine. It never interprets commands, never touches a
// file, never runs anything, never echoes attacker bytes back (UI spoofing / reflection), and every reply comes
// from a static synthetic table. Containment layer 4 (synthetic data only) and layer 5 (fixed state machine).

public enum LureProtocol: String, Codable, Sendable, CaseIterable {
    case ssh        // slow pre-banner drip (RFC 4253 §4.2), then a version string; clients hang on kex
    case nasLogin   // telnet-style "BackupNAS login:" prompt, 3 tries, then a roast
    case nasHTTP    // "Backup NAS" admin login page; POSTs get a slow 401 and a joke
    public static func forPort(_ p: UInt16) -> LureProtocol {
        switch p { case 22, 2222, 22222: return .ssh; case 80, 8080, 5000, 5001, 8443: return .nasHTTP; default: return .nasLogin }
    }
}

/// Hard caps (containment layer 6). Shared by the state machine and the server.
public struct LureLimits: Sendable, Equatable {
    public var maxLineBytes = 256
    public var maxTotalBytes = 4096
    public var maxLines = 24
    public var maxSessionSeconds: TimeInterval = 120
    public var idleTimeout: TimeInterval = 20
    public var maxConcurrent = 8
    public var maxPerPeerPerMinute = 6
    public init() {}
}

public struct LureReply: Sendable, Equatable {
    public var lines: [String]
    public var close: Bool
    public var credentialAttempt: Bool = false
}

public struct LureStateMachine: Sendable {
    public enum State: String, Sendable { case greeting, awaitUser, awaitPass, awaitHTTP, awaitBanner, closed }
    public let proto: LureProtocol
    public private(set) var state: State = .greeting
    public private(set) var tries = 0
    public private(set) var bytesIn = 0
    public private(set) var linesIn = 0
    public private(set) var firstLine = ""
    public let limits: LureLimits
    var jokeIndex: Int

    public init(_ proto: LureProtocol, limits: LureLimits = LureLimits(), seed: Int = Int.random(in: 0..<1000)) {
        self.proto = proto; self.limits = limits; self.jokeIndex = abs(seed)
    }

    public static let jokes = [
        "Loading your loot... 1%... 1%... still 1%...",
        "Did you try 'hunter2'? Everyone tries hunter2.",
        "This NAS is guarded by one very bored cat. It has noticed you.",
        "Password rejected. Also your hoodie is unflattering.",
        "Fun fact: you are being logged. Have a nice day.",
        "Access denied. Have you tried turning your career off and on again?",
        "Wrong. The cat would like to know why you're still here.",
        "Your IP has been added to the cat's naughty list. It's a long list. You're on top.",
        "Error 418: I'm a teapot, and you're a mouse.",
        "Brute force detected. Brute charm not detected either.",
    ]
    mutating func joke() -> String { defer { jokeIndex += 1 }; return Self.jokes[jokeIndex % Self.jokes.count] }

    /// Lines to drip before the first input (slowly: one per `lineDelay`).
    public mutating func greeting() -> [String] {
        switch proto {
        case .ssh:
            state = .awaitBanner
            return ["# BackupNAS DS-4 firmware 7.2.1 - authorized users only",
                    "# last backup: today 03:00 (2.1 TB: Documents, Photos, Wallets, Keys)",
                    "# loading host keys, please wait...",
                    "# still loading. good things come to those who wait.",
                    "SSH-2.0-OpenSSH_8.2p1 BackupNAS"]
        case .nasLogin:
            state = .awaitUser
            return ["BackupNAS DS-4 (tty0) - nightly backups: Documents, Photos, Wallets", "", "BackupNAS login:"]
        case .nasHTTP:
            state = .awaitHTTP
            return []
        }
    }

    /// Feeds one input line (already capped by the server). Unknown input never changes the fixed transitions.
    public mutating func input(_ raw: String) -> LureReply {
        guard state != .closed else { return LureReply(lines: [], close: true) }
        let line = String(raw.prefix(limits.maxLineBytes))
        bytesIn += line.utf8.count + 1; linesIn += 1
        if firstLine.isEmpty { firstLine = line }
        if bytesIn > limits.maxTotalBytes || linesIn > limits.maxLines || raw.utf8.count > limits.maxLineBytes * 4 {
            state = .closed; return LureReply(lines: ["Too much typing. The cat got bored. Bye."], close: true)
        }
        switch state {
        case .awaitBanner:
            state = .closed; return LureReply(lines: [], close: true)   // client banner recorded; kex never happens
        case .awaitUser:
            state = .awaitPass; return LureReply(lines: ["Password:"], close: false)
        case .awaitPass:
            tries += 1
            if tries >= 3 {
                state = .closed
                return LureReply(lines: ["", "Login incorrect", joke(), "Three strikes. The cat is writing this down. Bye. 🐱"], close: true, credentialAttempt: true)
            }
            state = .awaitUser
            return LureReply(lines: ["", "Login incorrect", joke(), "BackupNAS login:"], close: false, credentialAttempt: true)
        case .awaitHTTP:
            // Only the request line is looked at, and only its method token; everything else is ignored.
            let method = line.split(separator: " ", maxSplits: 1).first.map(String.init) ?? ""
            state = .closed
            if method == "POST" {
                return LureReply(lines: Self.http(status: "401 Unauthorized", body: "<h1>Invalid password</h1><p>\(joke())</p>"), close: true, credentialAttempt: true)
            }
            if method == "GET" || method == "HEAD" { return LureReply(lines: Self.http(status: "200 OK", body: Self.loginPage), close: true) }
            return LureReply(lines: Self.http(status: "400 Bad Request", body: "<p>\(joke())</p>"), close: true)
        case .greeting, .closed:
            state = .closed; return LureReply(lines: [], close: true)
        }
    }

    static let loginPage = """
    <!doctype html><title>BackupNAS - Sign in</title><h2>BackupNAS DS-4</h2><p>Nightly backup: Documents, Photos, Wallets</p>\
    <form method=post action=/login><input name=user placeholder=admin><input name=pass type=password><button>Sign in</button></form>
    """
    static func http(status: String, body: String) -> [String] {
        ["HTTP/1.0 \(status)", "Server: BackupNAS-httpd/7.2", "Content-Type: text/html; charset=utf-8",
         "Content-Length: \(body.utf8.count)", "Connection: close", "", body]
    }
}

/// Containment layer 6 (rate caps): sliding one-minute window per peer address, bounded table.
/// The table is hard-capped: a LAN attacker cycling through thousands of source addresses inside one minute used to
/// grow it without bound (the prune only dropped expired peers). When it is full of live peers, new peers are
/// refused (fail closed) until entries expire.
public final class LureRateLimiter: @unchecked Sendable {
    private let lock = NSLock()
    private var hits: [String: [Date]] = [:]
    public let perMinute: Int
    public let maxPeers: Int
    public init(perMinute: Int, maxPeers: Int = 2048) { self.perMinute = max(1, perMinute); self.maxPeers = max(1, maxPeers) }
    public var trackedPeers: Int { lock.lock(); defer { lock.unlock() }; return hits.count }
    public func allow(_ peer: String, now: Date = Date()) -> Bool {
        lock.lock(); defer { lock.unlock() }
        var h = (hits[peer] ?? []).filter { now.timeIntervalSince($0) < 60 }
        guard h.count < perMinute else { hits[peer] = h; return false }
        if hits[peer] == nil && hits.count >= maxPeers {
            hits = hits.filter { $0.value.contains { now.timeIntervalSince($0) < 60 } }
            if hits.count >= maxPeers { return false }
        }
        h.append(now); hits[peer] = h
        return true
    }
}

/// Refused connections (scope / rate / concurrency) are recorded, logged and alerted; without a cap a connect flood
/// turned into a log line, a tarpit.json rewrite and an alert per SYN. At most one record per peer per minute and
/// `globalPerMinute` in total; the rest are counted and folded into the next record that gets through.
public final class LureRefusalThrottle: @unchecked Sendable {
    private let lock = NSLock()
    private var lastByPeer: [String: Date] = [:]
    private var window: (start: Date, count: Int) = (.distantPast, 0)
    private var suppressed = 0
    public let globalPerMinute: Int
    public let maxPeers: Int
    public init(globalPerMinute: Int = 20, maxPeers: Int = 1024) { self.globalPerMinute = max(1, globalPerMinute); self.maxPeers = max(1, maxPeers) }
    /// nil = drop silently (counted); otherwise the number of refusals suppressed since the last recorded one.
    public func admit(_ peer: String, now: Date = Date()) -> Int? {
        lock.lock(); defer { lock.unlock() }
        if now.timeIntervalSince(window.start) >= 60 { window = (now, 0) }
        if let last = lastByPeer[peer], now.timeIntervalSince(last) < 60 { suppressed += 1; return nil }
        guard window.count < globalPerMinute else { suppressed += 1; return nil }
        if lastByPeer.count >= maxPeers { lastByPeer = lastByPeer.filter { now.timeIntervalSince($0.value) < 60 } }
        if lastByPeer.count >= maxPeers { suppressed += 1; return nil }
        lastByPeer[peer] = now; window.count += 1
        defer { suppressed = 0 }
        return suppressed
    }
}

/// Containment layer 8: who may talk to the lure at all.
public enum LureScope: String, Codable, Sendable { case loopback, localSubnet, anywhere }

public enum LureAccessFilter {
    /// IPv4 CIDRs like "192.168.1.0/24".
    public static func allows(peerIPv4 peer: String, scope: LureScope, localSubnets: [String]) -> Bool {
        guard let p = ipv4(peer) else { return false }
        if peer.hasPrefix("127.") { return true }
        switch scope {
        case .loopback: return false
        case .anywhere: return true
        case .localSubnet:
            return localSubnets.contains { cidr in
                let parts = cidr.split(separator: "/")
                guard parts.count == 2, let net = ipv4(String(parts[0])), let bits = UInt32(parts[1]), (8...32).contains(bits) else { return false }
                let mask: UInt32 = bits == 32 ? .max : ~(UInt32.max >> bits)
                return (p & mask) == (net & mask)
            }
        }
    }
    /// Strict "a.b.c.d/nn" (nn 8...32) in canonical form (network bits only), or nil. Used for everything that ends
    /// up in the pf anchor or the helper's command line.
    public static func canonicalCIDR(_ s: String) -> String? {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let ip = ipv4(String(parts[0])), parts[1].count <= 2, parts[1].allSatisfy({ $0.isASCII && $0.isNumber }),
              let bits = UInt32(parts[1]), (8...32).contains(bits) else { return nil }
        let net = ip & (bits == 32 ? .max : ~(UInt32.max >> bits))
        return "\(net >> 24).\((net >> 16) & 255).\((net >> 8) & 255).\(net & 255)/\(bits)"
    }
    static func ipv4(_ s: String) -> UInt32? {
        let o = s.split(separator: ".", omittingEmptySubsequences: false)
        guard o.count == 4 else { return nil }
        var v: UInt32 = 0
        for x in o { guard (1...3).contains(x.count), x.allSatisfy({ $0.isASCII && $0.isNumber }), let b = UInt8(x) else { return nil }; v = v << 8 | UInt32(b) }
        return v
    }
}

/// Containment layer 9: watchdog. The daemon samples the helper (libproc CPU/RSS, sandbox deny lines from the
/// unified log for its pid) and calls this; any anomaly kills the lure and raises an alert.
public struct LureHealthSample: Sendable, Equatable {
    public var cpuPercent: Double
    public var residentMB: Double
    public var sandboxViolations: Int
    public var openFiles: Int
    public var childProcesses: Int
    public var outboundConnections: Int
    public init(cpuPercent: Double = 0, residentMB: Double = 10, sandboxViolations: Int = 0, openFiles: Int = 8, childProcesses: Int = 0, outboundConnections: Int = 0) {
        self.cpuPercent = cpuPercent; self.residentMB = residentMB; self.sandboxViolations = sandboxViolations
        self.openFiles = openFiles; self.childProcesses = childProcesses; self.outboundConnections = outboundConnections
    }
}

public enum LureWatchdog {
    public enum Verdict: Equatable, Sendable { case ok, kill(reason: String, emergency: Bool) }
    public static func evaluate(_ s: LureHealthSample) -> Verdict {
        // Things the lure can never legitimately do: these suggest an escape attempt → Emergency Lockdown hook.
        if s.childProcesses > 0 { return .kill(reason: "lure spawned a process", emergency: true) }
        if s.outboundConnections > 0 { return .kill(reason: "lure opened an outbound connection", emergency: true) }
        if s.sandboxViolations > 0 { return .kill(reason: "sandbox blocked \(s.sandboxViolations) action(s)", emergency: true) }
        // Resource anomalies: kill, alert, no lockdown.
        if s.cpuPercent > 50 { return .kill(reason: "CPU \(Int(s.cpuPercent))%", emergency: false) }
        if s.residentMB > 64 { return .kill(reason: "memory \(Int(s.residentMB)) MB", emergency: false) }
        if s.openFiles > 40 { return .kill(reason: "\(s.openFiles) open files", emergency: false) }
        return .ok
    }
}

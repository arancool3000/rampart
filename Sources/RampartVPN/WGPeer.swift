import Foundation

/// An IPv4 or IPv6 prefix (AllowedIPs, Address).
public struct IPPrefix: Hashable, Codable, CustomStringConvertible, Sendable {
    public let address: [UInt8]   // 4 or 16 bytes
    public let length: Int
    public var isIPv6: Bool { address.count == 16 }
    public var description: String { "\(IPPrefix.format(address))/\(length)" }
    public var addressString: String { IPPrefix.format(address) }

    public init?(_ s: String) {
        let parts = s.trimmingCharacters(in: .whitespaces).split(separator: "/", maxSplits: 1).map(String.init)
        guard let first = parts.first, let a = IPPrefix.parseAddress(first) else { return nil }
        let max = a.count * 8
        let len = parts.count == 2 ? Int(parts[1]) : max
        guard let len, len >= 0, len <= max else { return nil }
        address = IPPrefix.mask(a, len); length = len
    }
    public init(address: [UInt8], length: Int) { self.address = IPPrefix.mask(address, length); self.length = length }

    /// For an interface Address such as 10.8.0.2/24 the host part is kept (only for display / ifconfig).
    public static func hostAddress(_ s: String) -> (address: [UInt8], length: Int)? {
        let parts = s.trimmingCharacters(in: .whitespaces).split(separator: "/", maxSplits: 1).map(String.init)
        guard let first = parts.first, let a = parseAddress(first) else { return nil }
        let len = parts.count == 2 ? Int(parts[1]) ?? -1 : a.count * 8
        guard len >= 0, len <= a.count * 8 else { return nil }
        return (a, len)
    }

    public func contains(_ ip: [UInt8]) -> Bool {
        guard ip.count == address.count else { return false }
        return IPPrefix.mask(ip, length) == address
    }

    static func mask(_ a: [UInt8], _ len: Int) -> [UInt8] {
        var out = a
        for i in 0..<out.count {
            let bitsHere = max(0, min(8, len - 8 * i))
            out[i] &= bitsHere == 0 ? 0 : UInt8(truncatingIfNeeded: 0xff << (8 - bitsHere))
        }
        return out
    }

    public static func parseAddress(_ s: String) -> [UInt8]? {
        var t = s.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("[") && t.hasSuffix("]") { t = String(t.dropFirst().dropLast()) }
        if let i = t.firstIndex(of: "%") { t = String(t[..<i]) }
        var v4 = in_addr()
        if !t.contains(":"), inet_pton(AF_INET, t, &v4) == 1 { return withUnsafeBytes(of: &v4) { Array($0) } }
        var v6 = in6_addr()
        if t.contains(":"), inet_pton(AF_INET6, t, &v6) == 1 { return withUnsafeBytes(of: &v6) { Array($0) } }
        return nil
    }

    public static func format(_ a: [UInt8]) -> String {
        var buf = [CChar](repeating: 0, count: 64)
        var a = a
        if a.count == 4 { return a.withUnsafeMutableBytes { inet_ntop(AF_INET, $0.baseAddress, &buf, 64) }.map { _ in String(cString: buf) } ?? "?" }
        if a.count == 16 { return a.withUnsafeMutableBytes { inet_ntop(AF_INET6, $0.baseAddress, &buf, 64) }.map { _ in String(cString: buf) } ?? "?" }
        return "?"
    }

    /// Source / destination address of an IP packet.
    public static func addresses(of p: [UInt8]) -> (src: [UInt8], dst: [UInt8])? {
        guard let v = p.first.map({ $0 >> 4 }) else { return nil }
        if v == 4, p.count >= 20 { return (Array(p[12..<16]), Array(p[16..<20])) }
        if v == 6, p.count >= 40 { return (Array(p[8..<24]), Array(p[24..<40])) }
        return nil
    }
}

/// UDP endpoint (numeric host + port). Transport-agnostic so tests can route packets in memory.
public struct WGEndpoint: Hashable, Codable, CustomStringConvertible, Sendable {
    public var host: String
    public var port: UInt16
    public init(host: String, port: UInt16) { self.host = host; self.port = port }
    public var description: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }
    /// Bytes used for cookie MACs (address || port).
    var cookieBytes: [UInt8] { (IPPrefix.parseAddress(host) ?? Array(host.utf8)) + [UInt8(port >> 8), UInt8(port & 0xff)] }
}

public struct WGPeerConfig: Sendable {
    public var publicKey: [UInt8]
    public var presharedKey: [UInt8]
    public var endpoint: WGEndpoint?
    public var allowedIPs: [IPPrefix]
    public var persistentKeepalive: Int?
    public init(publicKey: [UInt8], presharedKey: [UInt8] = [], endpoint: WGEndpoint?, allowedIPs: [IPPrefix], persistentKeepalive: Int? = nil) {
        self.publicKey = publicKey; self.presharedKey = presharedKey; self.endpoint = endpoint
        self.allowedIPs = allowedIPs; self.persistentKeepalive = persistentKeepalive
    }
}

public struct WGStats: Codable, Equatable, Sendable {
    public var txBytes: UInt64 = 0, rxBytes: UInt64 = 0
    public var txPackets: UInt64 = 0, rxPackets: UInt64 = 0
    public var handshakes = 0
    public var handshakeAttempts = 0
    public var lastHandshake: Date?
    public var droppedPackets: UInt64 = 0
    public var cookieReplies = 0
    public init() {}
}

/// One WireGuard peer: handshake (both roles), keypair rotation, transport data, cookie replies and the timer
/// state machine. Not thread-safe: call everything on one serial queue. Time and randomness are injectable.
public final class WireGuardPeer {
    public enum Event: Equatable { case handshakeComplete, handshakeGaveUp, keysExpired, cookieReceived }

    final class Keypair {
        let send: [UInt8], receive: [UInt8]
        let localIndex: UInt32, remoteIndex: UInt32
        let created: Date
        let weInitiated: Bool
        var sendCounter: UInt64 = 0
        var replay = ReplayWindow()
        init(send: [UInt8], receive: [UInt8], localIndex: UInt32, remoteIndex: UInt32, created: Date, weInitiated: Bool) {
            self.send = send; self.receive = receive; self.localIndex = localIndex; self.remoteIndex = remoteIndex
            self.created = created; self.weInitiated = weInitiated
        }
    }

    public let privateKey: [UInt8]
    public let publicKey: [UInt8]
    public private(set) var config: WGPeerConfig
    public var sendUDP: (([UInt8], WGEndpoint) -> Void)?
    public var deliverPacket: (([UInt8]) -> Void)?
    public var onEvent: ((Event) -> Void)?
    /// Accept handshakes initiated by the peer (always true in WireGuard; a client may still be a responder).
    public var acceptsInitiations = true
    /// Responder under load: demand a valid mac2 (cookie) before doing any Diffie-Hellman.
    public var underLoad = false
    public private(set) var stats = WGStats()
    public var endpoint: WGEndpoint? { config.endpoint }

    let now: () -> Date
    let random: (Int) -> [UInt8]
    let jitter: () -> TimeInterval

    var current: Keypair?, previous: Keypair?, next: Keypair?
    var pending: WG.InitiatorState?
    var pendingLocalIndex: UInt32?
    var handshakeStarted: Date?           // first attempt of the current handshake
    var lastInitiationSent: Date?
    var retransmitDelay: TimeInterval = WG.rekeyTimeout
    var lastMac1Sent: [UInt8]?
    var cookie: (value: [UInt8], received: Date)?
    var greatestTimestamp = [UInt8](repeating: 0, count: 12)
    var lastSent: Date?, lastReceived: Date?
    var lastDataSent: Date?, lastDataReceived: Date?
    var lastNewKeys: Date?
    var queue: [[UInt8]] = []
    static let maxQueue = 1024
    // responder cookie secret (rotated every 2 minutes)
    var cookieSecret: (value: [UInt8], created: Date)?

    public init(privateKey: [UInt8], peer: WGPeerConfig, now: @escaping () -> Date = Date.init,
                random: @escaping (Int) -> [UInt8] = WGCrypto.randomBytes,
                jitter: @escaping () -> TimeInterval = { Double.random(in: 0...0.333) }) throws {
        self.privateKey = privateKey
        publicKey = try WGCrypto.publicKey(privateKey)
        config = peer
        self.now = now; self.random = random; self.jitter = jitter
    }

    public func setEndpoint(_ e: WGEndpoint?) { config.endpoint = e }

    public var hasUsableSession: Bool { usable(current) }
    public var lastHandshake: Date? { stats.lastHandshake }
    public var isHandshaking: Bool { pending != nil }

    func usable(_ k: Keypair?) -> Bool {
        guard let k else { return false }
        return now().timeIntervalSince(k.created) < WG.rejectAfterTime && k.sendCounter < WG.rejectAfterMessages
    }

    func newIndex() -> UInt32 {
        let b = random(4)
        return UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16 | UInt32(b[3]) << 24
    }

    func ephemeral() -> [UInt8] { WGCrypto.clamp(random(32)) }

    func emit(_ bytes: [UInt8]) {
        guard let ep = config.endpoint else { return }
        lastSent = now()
        sendUDP?(bytes, ep)
    }

    // MARK: handshake (initiator)

    /// Sends a new handshake initiation (fresh ephemeral each time). `retransmit` bypasses the rate limit.
    public func initiateHandshake(retransmit: Bool = false) {
        guard config.endpoint != nil else { return }
        let t = now()
        if !retransmit, let last = lastInitiationSent, t.timeIntervalSince(last) < WG.rekeyTimeout { return }
        if handshakeStarted == nil { handshakeStarted = t }
        let idx = newIndex()
        let ck = cookie.flatMap { t.timeIntervalSince($0.received) < WG.cookieRefreshTime ? $0.value : nil }
        do {
            let r = try WG.createInitiation(staticPrivate: privateKey, peerPublic: config.publicKey, psk: config.presharedKey,
                                            senderIndex: idx, ephemeralPrivate: ephemeral(), timestamp: TAI64N.encode(t), cookie: ck)
            pending = r.state; pendingLocalIndex = idx; lastMac1Sent = r.state.mac1
            lastInitiationSent = t
            retransmitDelay = WG.rekeyTimeout + jitter()
            stats.handshakeAttempts += 1
            emit(r.message)
        } catch {
            pending = nil
        }
    }

    // MARK: inbound

    public func receiveUDP(_ b: [UInt8], from src: WGEndpoint) {
        switch WG.messageType(b) {
        case WG.typeInitiation?: handleInitiation(b, from: src)
        case WG.typeResponse?: handleResponse(b, from: src)
        case WG.typeCookie?: handleCookie(b)
        case WG.typeData?: handleData(b, from: src)
        default: stats.droppedPackets += 1
        }
    }

    func currentCookie(for src: WGEndpoint) -> [UInt8] {
        let t = now()
        if cookieSecret == nil || t.timeIntervalSince(cookieSecret!.created) >= WG.cookieRefreshTime { cookieSecret = (random(32), t) }
        return WGHash.mac(key: cookieSecret!.value, src.cookieBytes)
    }

    func handleInitiation(_ b: [UInt8], from src: WGEndpoint) {
        guard acceptsInitiations, b.count == WG.initiationSize, WG.validMac1(b, ourPublic: publicKey) else { stats.droppedPackets += 1; return }
        if underLoad {
            let c = currentCookie(for: src)
            if !WG.validMac2(b, cookie: c) {
                if let reply = try? WG.createCookieReply(to: b, receiverIndex: WG.readU32(b, 4), cookie: c, ourPublic: publicKey, nonce: random(24)) {
                    lastSent = now(); sendUDP?(reply, src)
                }
                return
            }
        }
        do {
            let peerKey = config.publicKey, psk = config.presharedKey
            let c = try WG.consumeInitiation(b, staticPrivate: privateKey, psk: { WGCrypto.equal($0, peerKey) ? psk : nil })
            guard TAI64N.isAfter(c.timestamp, greatestTimestamp) else { stats.droppedPackets += 1; return }   // replayed initiation
            greatestTimestamp = c.timestamp
            let idx = newIndex()
            let r = try WG.createResponse(c, senderIndex: idx, ephemeralPrivate: ephemeral(), cookie: nil)
            config.endpoint = src
            next = Keypair(send: r.keys.send, receive: r.keys.receive, localIndex: idx, remoteIndex: c.peerIndex, created: now(), weInitiated: false)
            lastNewKeys = now()
            lastReceived = now()
            emit(r.message)
        } catch { stats.droppedPackets += 1 }
    }

    func handleResponse(_ b: [UInt8], from src: WGEndpoint) {
        guard let st = pending, let idx = WG.responseIndices(b), idx.receiver == st.senderIndex else { stats.droppedPackets += 1; return }
        do {
            let r = try WG.consumeResponse(b, state: st)
            let t = now()
            previous = current
            current = Keypair(send: r.keys.send, receive: r.keys.receive, localIndex: st.senderIndex, remoteIndex: r.peerIndex, created: t, weInitiated: true)
            next = nil
            pending = nil; pendingLocalIndex = nil; handshakeStarted = nil
            config.endpoint = src
            lastReceived = t; lastNewKeys = t
            stats.handshakes += 1; stats.lastHandshake = t
            onEvent?(.handshakeComplete)
            if queue.isEmpty { sendKeepalive() } else { flushQueue() }
        } catch { stats.droppedPackets += 1 }
    }

    func handleCookie(_ b: [UInt8]) {
        guard let mac1 = lastMac1Sent, b.count == WG.cookieSize, let idx = pendingLocalIndex, WG.readU32(b, 4) == idx,
              let r = try? WG.consumeCookieReply(b, peerPublic: config.publicKey, lastMac1: mac1) else { stats.droppedPackets += 1; return }
        cookie = (r.cookie, now())
        stats.cookieReplies += 1
        onEvent?(.cookieReceived)
    }

    func handleData(_ b: [UInt8], from src: WGEndpoint) {
        guard let h = WG.dataHeader(b) else { stats.droppedPackets += 1; return }
        let kp = [current, previous, next].compactMap { $0 }.first { $0.localIndex == h.receiver }
        guard let kp, now().timeIntervalSince(kp.created) < WG.rejectAfterTime, h.counter < WG.rejectAfterMessages,
              let plain = try? WG.openData(key: kp.receive, b) else { stats.droppedPackets += 1; return }
        guard kp.replay.accept(h.counter) else { stats.droppedPackets += 1; return }
        let t = now()
        if let n = next, n === kp {   // responder: the initiator confirmed the new session
            previous = current; current = n; next = nil
            stats.handshakes += 1; stats.lastHandshake = n.created
            onEvent?(.handshakeComplete)
            flushQueue()
        }
        config.endpoint = src
        lastReceived = t
        // Initiator receiving on an old session: rekey before the peer has to reject it.
        if kp === current, kp.weInitiated, t.timeIntervalSince(kp.created) >= WG.rejectAfterTime - WG.keepaliveTimeout - WG.rekeyTimeout, pending == nil {
            initiateHandshake()
        }
        if plain.isEmpty { return }   // keepalive
        guard let pkt = WG.trimPadding(plain), let addr = IPPrefix.addresses(of: pkt),
              config.allowedIPs.contains(where: { $0.contains(addr.src) }) else { stats.droppedPackets += 1; return }
        lastDataReceived = t
        stats.rxBytes += UInt64(pkt.count); stats.rxPackets += 1
        deliverPacket?(pkt)
    }

    // MARK: outbound

    /// An IP packet from the tunnel interface. Queued while a handshake is in flight.
    public func sendPacket(_ p: [UInt8]) {
        guard let addr = IPPrefix.addresses(of: p), config.allowedIPs.contains(where: { $0.contains(addr.dst) }) else { stats.droppedPackets += 1; return }
        if usable(current) { transmit(p) }
        else {
            queue.append(p); if queue.count > Self.maxQueue { queue.removeFirst(); stats.droppedPackets += 1 }
            if pending == nil { initiateHandshake() }
        }
    }

    public func sendKeepalive() {
        guard usable(current) else { return }
        transmit([])
    }

    func transmit(_ p: [UInt8]) {
        guard let kp = current else { return }
        guard let msg = try? WG.sealData(key: kp.send, receiverIndex: kp.remoteIndex, counter: kp.sendCounter, packet: p) else { return }
        kp.sendCounter += 1
        emit(msg)
        if !p.isEmpty {
            lastDataSent = now()
            stats.txBytes += UInt64(p.count); stats.txPackets += 1
        }
        let age = now().timeIntervalSince(kp.created)
        if pending == nil && ((kp.weInitiated && age >= WG.rekeyAfterTime) || kp.sendCounter >= WG.rekeyAfterMessages) { initiateHandshake() }
    }

    func flushQueue() {
        let q = queue; queue.removeAll()
        for p in q { transmit(p) }
    }

    // MARK: timers

    /// Drive every ~250 ms (tests call it with a fake clock).
    public func tick() {
        let t = now()
        // Handshake retransmission / give up after REKEY_ATTEMPT_TIME.
        if pending != nil, let sent = lastInitiationSent, t.timeIntervalSince(sent) >= retransmitDelay {
            if let start = handshakeStarted, t.timeIntervalSince(start) >= WG.rekeyAttemptTime {
                pending = nil; pendingLocalIndex = nil; handshakeStarted = nil
                stats.droppedPackets += UInt64(queue.count); queue.removeAll()
                onEvent?(.handshakeGaveUp)
            } else {
                initiateHandshake(retransmit: true)
            }
        }
        // Passive keepalive: data arrived and we have sent nothing back for KEEPALIVE_TIMEOUT.
        if let r = lastDataReceived, (lastSent ?? .distantPast) < r, t.timeIntervalSince(r) >= WG.keepaliveTimeout { sendKeepalive() }
        // We sent data and heard nothing for KEEPALIVE + REKEY_TIMEOUT: start a new handshake.
        if let s = lastDataSent, (lastReceived ?? .distantPast) < s, t.timeIntervalSince(s) >= WG.keepaliveTimeout + WG.rekeyTimeout, pending == nil {
            lastDataSent = nil
            initiateHandshake()
        }
        // Persistent keepalive.
        if let k = config.persistentKeepalive, k > 0, t.timeIntervalSince(lastSent ?? .distantPast) >= TimeInterval(k) {
            if usable(current) { sendKeepalive() } else if pending == nil { initiateHandshake() }
        }
        // Expire keys: nothing usable after REJECT_AFTER_TIME; wipe all after 3x without a new handshake.
        if let n = lastNewKeys, t.timeIntervalSince(n) >= 3 * WG.rejectAfterTime, current != nil || previous != nil || next != nil {
            current = nil; previous = nil; next = nil
            onEvent?(.keysExpired)
        }
    }

    /// Forget all sessions (disconnect).
    public func reset() {
        current = nil; previous = nil; next = nil; pending = nil; pendingLocalIndex = nil
        handshakeStarted = nil; queue.removeAll(); lastDataSent = nil; lastDataReceived = nil
    }
}

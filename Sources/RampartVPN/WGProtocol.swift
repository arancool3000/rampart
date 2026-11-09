import Foundation

/// WireGuard wire format and handshake (whitepaper section 5.4), on top of `NoiseIKpsk2`.
public enum WG {
    public static let construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    public static let identifier = Array("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8)
    public static let labelMac1 = Array("mac1----".utf8)
    public static let labelCookie = Array("cookie--".utf8)

    public static let typeInitiation: UInt8 = 1, typeResponse: UInt8 = 2, typeCookie: UInt8 = 3, typeData: UInt8 = 4
    public static let initiationSize = 148, responseSize = 92, cookieSize = 64, dataHeaderSize = 16, minDataSize = 32

    // Timers and limits (whitepaper section 6.1)
    public static let rekeyAfterMessages: UInt64 = 1 << 60
    public static let rejectAfterMessages: UInt64 = UInt64.max - (1 << 13)
    public static let rekeyAfterTime: TimeInterval = 120
    public static let rejectAfterTime: TimeInterval = 180
    public static let rekeyAttemptTime: TimeInterval = 90
    public static let rekeyTimeout: TimeInterval = 5
    public static let keepaliveTimeout: TimeInterval = 10
    public static let cookieRefreshTime: TimeInterval = 120

    static func u32le(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * UInt32($0))) } }
    static func u64le(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: v >> (8 * UInt64($0))) } }
    static func readU32(_ b: [UInt8], _ o: Int) -> UInt32 { (0..<4).reduce(UInt32(0)) { $0 | UInt32(b[o + $1]) << (8 * UInt32($1)) } }
    static func readU64(_ b: [UInt8], _ o: Int) -> UInt64 { (0..<8).reduce(UInt64(0)) { $0 | UInt64(b[o + $1]) << (8 * UInt64($1)) } }

    /// The key that authenticates mac1 on messages sent TO the owner of `publicKey`.
    public static func mac1Key(_ publicKey: [UInt8]) -> [UInt8] { WGHash.hash(labelMac1, publicKey) }
    public static func cookieKey(_ publicKey: [UInt8]) -> [UInt8] { WGHash.hash(labelCookie, publicKey) }

    public static func messageType(_ b: [UInt8]) -> UInt8? {
        guard b.count >= 4, b[1] == 0, b[2] == 0, b[3] == 0 else { return nil }
        return b[0]
    }

    /// Writes mac1 (and mac2 if a fresh cookie is known) into a handshake message whose last 32 bytes are the macs.
    static func addMacs(_ msg: inout [UInt8], peerPublic: [UInt8], cookie: [UInt8]?) -> [UInt8] {
        let n = msg.count
        let mac1 = WGHash.mac(key: mac1Key(peerPublic), Array(msg[0..<n - 32]))
        msg.replaceSubrange(n - 32..<n - 16, with: mac1)
        let mac2 = cookie.map { WGHash.mac(key: $0, Array(msg[0..<n - 16])) } ?? [UInt8](repeating: 0, count: 16)
        msg.replaceSubrange(n - 16..<n, with: mac2)
        return mac1
    }

    /// mac1 check on a received handshake message addressed to `ourPublic`.
    public static func validMac1(_ msg: [UInt8], ourPublic: [UInt8]) -> Bool {
        let n = msg.count; guard n >= 32 else { return false }
        return WGCrypto.equal(WGHash.mac(key: mac1Key(ourPublic), Array(msg[0..<n - 32])), Array(msg[n - 32..<n - 16]))
    }
    public static func validMac2(_ msg: [UInt8], cookie: [UInt8]) -> Bool {
        let n = msg.count; guard n >= 32 else { return false }
        return WGCrypto.equal(WGHash.mac(key: cookie, Array(msg[0..<n - 16])), Array(msg[n - 16..<n]))
    }

    // MARK: handshake initiation

    public struct InitiatorState {
        public var noise: NoiseIKpsk2
        public let senderIndex: UInt32
        public let mac1: [UInt8]
    }

    public static func createInitiation(staticPrivate: [UInt8], peerPublic: [UInt8], psk: [UInt8], senderIndex: UInt32,
                                        ephemeralPrivate: [UInt8], timestamp: [UInt8], cookie: [UInt8]?) throws -> (message: [UInt8], state: InitiatorState) {
        var noise = try NoiseIKpsk2(initiator: true, prologue: identifier, staticPrivate: staticPrivate, remoteStatic: peerPublic, psk: psk)
        let m = try noise.writeMessage1(ephemeralPrivate: ephemeralPrivate, payload: timestamp)
        var msg: [UInt8] = [typeInitiation, 0, 0, 0] + u32le(senderIndex) + m.ephemeral + m.encStatic + m.encPayload
        msg += [UInt8](repeating: 0, count: 32)
        let mac1 = addMacs(&msg, peerPublic: peerPublic, cookie: cookie)
        return (msg, InitiatorState(noise: noise, senderIndex: senderIndex, mac1: mac1))
    }

    public struct ConsumedInitiation {
        public var noise: NoiseIKpsk2
        public let peerPublic: [UInt8]
        public let peerIndex: UInt32
        public let timestamp: [UInt8]
    }

    /// Responder side. `psk(peerPublic)` returns the pre-shared key for a known peer, or nil to reject.
    public static func consumeInitiation(_ msg: [UInt8], staticPrivate: [UInt8], psk: ([UInt8]) -> [UInt8]?) throws -> ConsumedInitiation {
        guard msg.count == initiationSize, messageType(msg) == typeInitiation else { throw WGCryptoError.badLength }
        var noise = try NoiseIKpsk2(initiator: false, prologue: identifier, staticPrivate: staticPrivate, remoteStatic: nil, psk: [])
        guard validMac1(msg, ourPublic: noise.sPub) else { throw WGCryptoError.authenticationFailed }
        let ts = try noise.readMessage1(ephemeral: Array(msg[8..<40]), encStatic: Array(msg[40..<88]), encPayload: Array(msg[88..<116]))
        guard let peer = noise.rs, let key = psk(peer) else { throw WGCryptoError.badKey }
        // The psk only enters at message 2, so it can be chosen now that the initiator is known.
        noise = try noise.withPSK(key)
        return ConsumedInitiation(noise: noise, peerPublic: peer, peerIndex: readU32(msg, 4), timestamp: ts)
    }

    public static func createResponse(_ c: ConsumedInitiation, senderIndex: UInt32, ephemeralPrivate: [UInt8], cookie: [UInt8]?) throws -> (message: [UInt8], keys: (send: [UInt8], receive: [UInt8])) {
        var noise = c.noise
        let m = try noise.writeMessage2(ephemeralPrivate: ephemeralPrivate, payload: [])
        var msg: [UInt8] = [typeResponse, 0, 0, 0] + u32le(senderIndex) + u32le(c.peerIndex) + m.ephemeral + m.encPayload
        msg += [UInt8](repeating: 0, count: 32)
        _ = addMacs(&msg, peerPublic: c.peerPublic, cookie: cookie)
        return (msg, noise.transportKeys())
    }

    public static func responseIndices(_ msg: [UInt8]) -> (sender: UInt32, receiver: UInt32)? {
        guard msg.count == responseSize, messageType(msg) == typeResponse else { return nil }
        return (readU32(msg, 4), readU32(msg, 8))
    }

    /// Initiator side: returns the peer's index and the transport keys.
    public static func consumeResponse(_ msg: [UInt8], state: InitiatorState) throws -> (peerIndex: UInt32, keys: (send: [UInt8], receive: [UInt8])) {
        guard let idx = responseIndices(msg), idx.receiver == state.senderIndex else { throw WGCryptoError.badLength }
        guard validMac1(msg, ourPublic: state.noise.sPub) else { throw WGCryptoError.authenticationFailed }
        var noise = state.noise
        _ = try noise.readMessage2(ephemeral: Array(msg[12..<44]), encPayload: Array(msg[44..<60]))
        return (idx.sender, noise.transportKeys())
    }

    // MARK: cookie reply

    /// Responder under load: tells the initiator to retry with mac2 = MAC(cookie, ...).
    public static func createCookieReply(to msg: [UInt8], receiverIndex: UInt32, cookie: [UInt8], ourPublic: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        let n = msg.count
        let mac1 = Array(msg[n - 32..<n - 16])
        let enc = try WGCrypto.xseal(key: cookieKey(ourPublic), nonce: nonce, cookie, ad: mac1)
        return [typeCookie, 0, 0, 0] + u32le(receiverIndex) + nonce + enc
    }

    /// Initiator: decrypts a cookie reply. `peerPublic` is the key of the peer we sent the handshake to;
    /// `lastMac1` is the mac1 of that handshake message.
    public static func consumeCookieReply(_ msg: [UInt8], peerPublic: [UInt8], lastMac1: [UInt8]) throws -> (receiverIndex: UInt32, cookie: [UInt8]) {
        guard msg.count == cookieSize, messageType(msg) == typeCookie else { throw WGCryptoError.badLength }
        let cookie = try WGCrypto.xopen(key: cookieKey(peerPublic), nonce: Array(msg[8..<32]), Array(msg[32..<64]), ad: lastMac1)
        guard cookie.count == 16 else { throw WGCryptoError.badLength }
        return (readU32(msg, 4), cookie)
    }

    // MARK: transport data

    public static func sealData(key: [UInt8], receiverIndex: UInt32, counter: UInt64, packet: [UInt8]) throws -> [UInt8] {
        var p = packet
        let pad = (16 - p.count % 16) % 16
        p += [UInt8](repeating: 0, count: pad)
        return [typeData, 0, 0, 0] + u32le(receiverIndex) + u64le(counter) + (try WGCrypto.seal(key: key, counter: counter, p, ad: []))
    }

    public static func dataHeader(_ msg: [UInt8]) -> (receiver: UInt32, counter: UInt64)? {
        guard msg.count >= minDataSize, messageType(msg) == typeData else { return nil }
        return (readU32(msg, 4), readU64(msg, 8))
    }

    public static func openData(key: [UInt8], _ msg: [UInt8]) throws -> [UInt8] {
        guard let h = dataHeader(msg) else { throw WGCryptoError.badLength }
        return try WGCrypto.open(key: key, counter: h.counter, Array(msg[16...]), ad: [])
    }

    /// Strips transport padding using the IP header's length. nil = not an IP packet.
    public static func trimPadding(_ p: [UInt8]) -> [UInt8]? {
        guard let v = p.first.map({ $0 >> 4 }) else { return [] }   // keepalive
        if v == 4, p.count >= 20 {
            let len = Int(p[2]) << 8 | Int(p[3]); guard len >= 20, len <= p.count else { return nil }
            return Array(p[0..<len])
        }
        if v == 6, p.count >= 40 {
            let len = (Int(p[4]) << 8 | Int(p[5])) + 40; guard len <= p.count else { return nil }
            return Array(p[0..<len])
        }
        return nil
    }
}

extension NoiseIKpsk2 {
    /// Responder: the PSK is looked up once the initiator is identified (it is used only in message 2).
    func withPSK(_ key: [UInt8]) throws -> NoiseIKpsk2 {
        var copy = self
        copy.setPSK(key)
        return copy
    }
}

/// Sliding-window replay protection (RFC 6479 style, 2048 bits like the reference implementation).
public struct ReplayWindow {
    static let bits = 2048
    static let words = bits / 64
    private var bitmap = [UInt64](repeating: 0, count: words)
    public private(set) var greatest: UInt64 = 0
    private var any = false
    public init() {}

    /// Returns true (and records the counter) if it is new and inside the window.
    public mutating func accept(_ c: UInt64) -> Bool {
        if c >= WG.rejectAfterMessages { return false }
        if !any || c > greatest {
            let shift = any ? c - greatest : UInt64(Self.bits)
            if shift >= UInt64(Self.bits) {
                bitmap = [UInt64](repeating: 0, count: Self.words)
            } else {
                for i in (greatest + 1)...c { let b = Int(i % UInt64(Self.bits)); bitmap[b / 64] &= ~(1 << UInt64(b % 64)) }
            }
            greatest = c; any = true
        } else if greatest - c >= UInt64(Self.bits - 64) {
            return false
        }
        let b = Int(c % UInt64(Self.bits))
        let mask: UInt64 = 1 << UInt64(b % 64)
        if bitmap[b / 64] & mask != 0 { return false }
        bitmap[b / 64] |= mask
        return true
    }
}

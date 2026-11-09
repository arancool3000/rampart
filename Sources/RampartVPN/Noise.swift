import Foundation

/// Noise symmetric state with BLAKE2s + ChaChaPoly (Noise spec section 5.2), the core of WireGuard's handshake.
public struct NoiseSymmetricState {
    public private(set) var ck: [UInt8]
    public private(set) var h: [UInt8]
    private var k: [UInt8]?
    private var n: UInt64 = 0

    public init(protocolName: String, prologue: [UInt8]) {
        let name = Array(protocolName.utf8)
        h = name.count <= 32 ? name + [UInt8](repeating: 0, count: 32 - name.count) : WGHash.hash(name)
        ck = h
        mixHash(prologue)
    }

    public mutating func mixHash(_ data: [UInt8]) { h = WGHash.hash(h, data) }
    public mutating func mixKey(_ ikm: [UInt8]) {
        let o = WGHash.kdf(2, key: ck, input: ikm); ck = o[0]; k = o[1]; n = 0
    }
    public mutating func mixKeyAndHash(_ ikm: [UInt8]) {
        let o = WGHash.kdf(3, key: ck, input: ikm); ck = o[0]; mixHash(o[1]); k = o[2]; n = 0
    }
    public mutating func encryptAndHash(_ plain: [UInt8]) throws -> [UInt8] {
        guard let k else { mixHash(plain); return plain }
        let c = try WGCrypto.seal(key: k, counter: n, plain, ad: h)
        mixHash(c); n += 1
        return c
    }
    public mutating func decryptAndHash(_ cipher: [UInt8]) throws -> [UInt8] {
        guard let k else { mixHash(cipher); return cipher }
        let p = try WGCrypto.open(key: k, counter: n, cipher, ad: h)
        mixHash(cipher); n += 1
        return p
    }
    /// (initiator-to-responder key, responder-to-initiator key)
    public func split() -> (initiatorSend: [UInt8], responderSend: [UInt8]) {
        let o = WGHash.kdf(2, key: ck, input: [])
        return (o[0], o[1])
    }
}

/// The Noise_IKpsk2 pattern:  <- s  ...  -> e, es, s, ss   <- e, ee, se, psk
/// Ephemeral keys are passed in so the handshake is deterministic under test vectors.
public struct NoiseIKpsk2 {
    public var sym: NoiseSymmetricState
    public let isInitiator: Bool
    let s: [UInt8]
    public let sPub: [UInt8]
    public private(set) var rs: [UInt8]?
    private var e: [UInt8]?
    private var re: [UInt8]?
    private(set) var psk: [UInt8]
    mutating func setPSK(_ k: [UInt8]) { psk = k.isEmpty ? [UInt8](repeating: 0, count: 32) : k }

    public static let wireGuardProtocol = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

    public init(initiator: Bool, protocolName: String = wireGuardProtocol, prologue: [UInt8], staticPrivate: [UInt8],
                remoteStatic: [UInt8]?, psk: [UInt8]) throws {
        isInitiator = initiator
        s = staticPrivate
        sPub = try WGCrypto.publicKey(staticPrivate)
        rs = remoteStatic
        self.psk = psk.isEmpty ? [UInt8](repeating: 0, count: 32) : psk
        sym = NoiseSymmetricState(protocolName: protocolName, prologue: prologue)
        if initiator {
            guard let rs = remoteStatic, rs.count == 32 else { throw WGCryptoError.badKey }
            sym.mixHash(rs)
        } else {
            sym.mixHash(sPub)
        }
    }

    /// Initiator: returns e.pub, encrypted static (48 bytes) and the encrypted payload.
    public mutating func writeMessage1(ephemeralPrivate: [UInt8], payload: [UInt8]) throws -> (ephemeral: [UInt8], encStatic: [UInt8], encPayload: [UInt8]) {
        guard isInitiator, let rs else { throw WGCryptoError.badKey }
        e = ephemeralPrivate
        let ePub = try WGCrypto.publicKey(ephemeralPrivate)
        sym.mixHash(ePub); sym.mixKey(ePub)                      // e (psk mode also mixes e into the chaining key)
        sym.mixKey(try WGCrypto.dh(ephemeralPrivate, rs))         // es
        let encS = try sym.encryptAndHash(sPub)                  // s
        sym.mixKey(try WGCrypto.dh(s, rs))                        // ss
        let encP = try sym.encryptAndHash(payload)
        return (ePub, encS, encP)
    }

    /// Responder: consumes message 1, learns the initiator's static key, returns the payload.
    public mutating func readMessage1(ephemeral ePub: [UInt8], encStatic: [UInt8], encPayload: [UInt8]) throws -> [UInt8] {
        guard !isInitiator, ePub.count == 32 else { throw WGCryptoError.badLength }
        re = ePub
        sym.mixHash(ePub); sym.mixKey(ePub)
        sym.mixKey(try WGCrypto.dh(s, ePub))
        let rsPub = try sym.decryptAndHash(encStatic)
        guard rsPub.count == 32 else { throw WGCryptoError.badLength }
        rs = rsPub
        sym.mixKey(try WGCrypto.dh(s, rsPub))
        return try sym.decryptAndHash(encPayload)
    }

    public mutating func writeMessage2(ephemeralPrivate: [UInt8], payload: [UInt8]) throws -> (ephemeral: [UInt8], encPayload: [UInt8]) {
        guard !isInitiator, let re, let rs else { throw WGCryptoError.badKey }
        let ePub = try WGCrypto.publicKey(ephemeralPrivate)
        sym.mixHash(ePub); sym.mixKey(ePub)
        sym.mixKey(try WGCrypto.dh(ephemeralPrivate, re))         // ee
        sym.mixKey(try WGCrypto.dh(ephemeralPrivate, rs))         // se
        sym.mixKeyAndHash(psk)                                     // psk
        return (ePub, try sym.encryptAndHash(payload))
    }

    public mutating func readMessage2(ephemeral ePub: [UInt8], encPayload: [UInt8]) throws -> [UInt8] {
        guard isInitiator, let e, ePub.count == 32 else { throw WGCryptoError.badKey }
        re = ePub
        sym.mixHash(ePub); sym.mixKey(ePub)
        sym.mixKey(try WGCrypto.dh(e, ePub))
        sym.mixKey(try WGCrypto.dh(s, ePub))
        sym.mixKeyAndHash(psk)
        return try sym.decryptAndHash(encPayload)
    }

    /// Transport keys (send, receive) from this side's point of view.
    public func transportKeys() -> (send: [UInt8], receive: [UInt8]) {
        let k = sym.split()
        return isInitiator ? (k.initiatorSend, k.responderSend) : (k.responderSend, k.initiatorSend)
    }
}

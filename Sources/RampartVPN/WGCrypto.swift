import Foundation
import CryptoKit
import Security

public enum WGCryptoError: Error, CustomStringConvertible, Equatable {
    case badKey, zeroSharedSecret, authenticationFailed, badLength
    public var description: String {
        switch self {
        case .badKey: return "invalid key"
        case .zeroSharedSecret: return "the peer's key produced an all-zero shared secret"
        case .authenticationFailed: return "decryption failed (wrong key or tampered packet)"
        case .badLength: return "message has the wrong length"
        }
    }
}

/// Curve25519, ChaCha20-Poly1305 (CryptoKit) and XChaCha20-Poly1305 (HChaCha20 here + CryptoKit) for WireGuard.
public enum WGCrypto {
    public static let keyLength = 32

    public static func randomBytes(_ n: Int) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: n)
        if SecRandomCopyBytes(kSecRandomDefault, n, &b) != errSecSuccess {
            for i in 0..<n { b[i] = UInt8.random(in: 0...255) }   // SystemRandomNumberGenerator is also a CSPRNG
        }
        return b
    }

    /// A new Curve25519 private key (clamped form, like `wg genkey`).
    public static func generatePrivateKey() -> [UInt8] { clamp(Array(Curve25519.KeyAgreement.PrivateKey().rawRepresentation)) }

    public static func clamp(_ k: [UInt8]) -> [UInt8] {
        var k = k; guard k.count == 32 else { return k }
        k[0] &= 248; k[31] = (k[31] & 127) | 64; return k
    }

    public static func publicKey(_ priv: [UInt8]) throws -> [UInt8] {
        guard priv.count == 32, let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv) else { throw WGCryptoError.badKey }
        return Array(k.publicKey.rawRepresentation)
    }

    /// DH(private, public). Rejects an all-zero result (low-order public key).
    public static func dh(_ priv: [UInt8], _ pub: [UInt8]) throws -> [UInt8] {
        guard priv.count == 32, pub.count == 32,
              let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv),
              let p = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub) else { throw WGCryptoError.badKey }
        guard let s = try? k.sharedSecretFromKeyAgreement(with: p) else { throw WGCryptoError.zeroSharedSecret }
        let out = s.withUnsafeBytes { Array($0) }
        if out.allSatisfy({ $0 == 0 }) { throw WGCryptoError.zeroSharedSecret }
        return out
    }

    /// 96-bit nonce: 32 zero bits then the 64-bit little-endian counter.
    static func nonce(_ counter: UInt64) -> [UInt8] {
        [0, 0, 0, 0] + (0..<8).map { UInt8(truncatingIfNeeded: counter >> (8 * UInt64($0))) }
    }

    /// AEAD(key, counter, plain, authtext) -> ciphertext || 16-byte tag
    public static func seal(key: [UInt8], counter: UInt64, _ plain: [UInt8], ad: [UInt8]) throws -> [UInt8] {
        guard key.count == 32 else { throw WGCryptoError.badKey }
        let box = try ChaChaPoly.seal(plain, using: SymmetricKey(data: key),
                                      nonce: try ChaChaPoly.Nonce(data: nonce(counter)), authenticating: ad)
        return Array(box.ciphertext) + Array(box.tag)
    }

    public static func open(key: [UInt8], counter: UInt64, _ sealed: [UInt8], ad: [UInt8]) throws -> [UInt8] {
        guard key.count == 32 else { throw WGCryptoError.badKey }
        guard sealed.count >= 16 else { throw WGCryptoError.badLength }
        do {
            let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce(counter)),
                                               ciphertext: sealed.dropLast(16), tag: sealed.suffix(16))
            return Array(try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: ad))
        } catch { throw WGCryptoError.authenticationFailed }
    }

    // MARK: XChaCha20-Poly1305 (cookie replies)

    /// HChaCha20(key, 16-byte nonce) -> 32-byte subkey (draft-irtf-cfrg-xchacha section 2.2).
    public static func hchacha20(key: [UInt8], nonce: [UInt8]) -> [UInt8] {
        precondition(key.count == 32 && nonce.count == 16)
        func le(_ b: [UInt8], _ i: Int) -> UInt32 { UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24 }
        var s: [UInt32] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        for i in 0..<8 { s.append(le(key, 4 * i)) }
        for i in 0..<4 { s.append(le(nonce, 4 * i)) }
        @inline(__always) func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }
        func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            s[a] = s[a] &+ s[b]; s[d] = rotl(s[d] ^ s[a], 16)
            s[c] = s[c] &+ s[d]; s[b] = rotl(s[b] ^ s[c], 12)
            s[a] = s[a] &+ s[b]; s[d] = rotl(s[d] ^ s[a], 8)
            s[c] = s[c] &+ s[d]; s[b] = rotl(s[b] ^ s[c], 7)
        }
        for _ in 0..<10 {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        var out: [UInt8] = []
        for w in Array(s[0..<4]) + Array(s[12..<16]) { out += [UInt8(w & 0xff), UInt8(w >> 8 & 0xff), UInt8(w >> 16 & 0xff), UInt8(w >> 24)] }
        return out
    }

    static func xParts(key: [UInt8], nonce: [UInt8]) throws -> (SymmetricKey, ChaChaPoly.Nonce) {
        guard key.count == 32, nonce.count == 24 else { throw WGCryptoError.badLength }
        let sub = hchacha20(key: key, nonce: Array(nonce[0..<16]))
        return (SymmetricKey(data: sub), try ChaChaPoly.Nonce(data: [0, 0, 0, 0] + Array(nonce[16..<24])))
    }

    public static func xseal(key: [UInt8], nonce: [UInt8], _ plain: [UInt8], ad: [UInt8]) throws -> [UInt8] {
        let (k, n) = try xParts(key: key, nonce: nonce)
        let box = try ChaChaPoly.seal(plain, using: k, nonce: n, authenticating: ad)
        return Array(box.ciphertext) + Array(box.tag)
    }

    public static func xopen(key: [UInt8], nonce: [UInt8], _ sealed: [UInt8], ad: [UInt8]) throws -> [UInt8] {
        let (k, n) = try xParts(key: key, nonce: nonce)
        guard sealed.count >= 16 else { throw WGCryptoError.badLength }
        do {
            let box = try ChaChaPoly.SealedBox(nonce: n, ciphertext: sealed.dropLast(16), tag: sealed.suffix(16))
            return Array(try ChaChaPoly.open(box, using: k, authenticating: ad))
        } catch { throw WGCryptoError.authenticationFailed }
    }

    /// Constant-time comparison.
    public static func equal(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var d: UInt8 = 0; for i in 0..<a.count { d |= a[i] ^ b[i] }; return d == 0
    }
}

/// Base64 / hex helpers for 32-byte WireGuard keys.
public enum WGKey {
    public static func base64(_ k: [UInt8]) -> String { Data(k).base64EncodedString() }
    public static func decode(_ s: String) -> [UInt8]? {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard t.count == 44, t.hasSuffix("="), let d = Data(base64Encoded: t), d.count == 32 else { return nil }
        return Array(d)
    }
    public static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    public static func fromHex(_ s: String) -> [UInt8]? {
        let c = Array(s.utf8); guard c.count % 2 == 0 else { return nil }
        var out: [UInt8] = []; out.reserveCapacity(c.count / 2)
        var i = 0
        while i < c.count {
            guard let b = UInt8(String(decoding: c[i..<i + 2], as: UTF8.self), radix: 16) else { return nil }
            out.append(b); i += 2
        }
        return out
    }
}

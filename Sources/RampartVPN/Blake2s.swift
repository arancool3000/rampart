import Foundation

/// BLAKE2s (RFC 7693), pure Swift. Supports keyed hashing and 1...32 byte digests (WireGuard uses 32 and 16).
public struct BLAKE2s {
    static let iv: [UInt32] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    private var h: [UInt32]
    private var t: UInt64 = 0
    private var buffer: [UInt8] = []
    public let outputLength: Int

    public init(outputLength: Int = 32, key: [UInt8] = []) {
        precondition(outputLength >= 1 && outputLength <= 32 && key.count <= 32)
        self.outputLength = outputLength
        h = Self.iv
        h[0] ^= 0x0101_0000 ^ (UInt32(key.count) << 8) ^ UInt32(outputLength)
        if !key.isEmpty { buffer = key + [UInt8](repeating: 0, count: 64 - key.count) }
    }

    public mutating func update(_ data: [UInt8]) {
        var i = 0
        while i < data.count {
            if buffer.count == 64 {           // a full block is compressed only once more input follows
                t &+= 64
                compress(buffer, last: false)
                buffer.removeAll(keepingCapacity: true)
            }
            let n = min(64 - buffer.count, data.count - i)
            buffer.append(contentsOf: data[i..<i + n])
            i += n
        }
    }

    public mutating func finalize() -> [UInt8] {
        t &+= UInt64(buffer.count)
        let block = buffer + [UInt8](repeating: 0, count: 64 - buffer.count)
        compress(block, last: true)
        var out = [UInt8](); out.reserveCapacity(32)
        for w in h { out += [UInt8(w & 0xff), UInt8(w >> 8 & 0xff), UInt8(w >> 16 & 0xff), UInt8(w >> 24)] }
        return Array(out.prefix(outputLength))
    }

    private mutating func compress(_ block: [UInt8], last: Bool) {
        var m = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            m[i] = UInt32(block[4 * i]) | UInt32(block[4 * i + 1]) << 8 | UInt32(block[4 * i + 2]) << 16 | UInt32(block[4 * i + 3]) << 24
        }
        var v = h + Self.iv
        v[12] ^= UInt32(truncatingIfNeeded: t)
        v[13] ^= UInt32(truncatingIfNeeded: t >> 32)
        if last { v[14] = ~v[14] }
        @inline(__always) func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }
        @inline(__always) func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
            v[a] = v[a] &+ v[b] &+ x; v[d] = rotr(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d];      v[b] = rotr(v[b] ^ v[c], 12)
            v[a] = v[a] &+ v[b] &+ y; v[d] = rotr(v[d] ^ v[a], 8)
            v[c] = v[c] &+ v[d];      v[b] = rotr(v[b] ^ v[c], 7)
        }
        for r in 0..<10 {
            let s = Self.sigma[r]
            g(0, 4, 8, 12, m[s[0]], m[s[1]]); g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
    }

    public static func hash(_ data: [UInt8], outputLength: Int = 32, key: [UInt8] = []) -> [UInt8] {
        var b = BLAKE2s(outputLength: outputLength, key: key); b.update(data); return b.finalize()
    }
}

/// WireGuard's hash-based primitives (whitepaper section 5.4).
public enum WGHash {
    /// HASH(input) = BLAKE2s(input, 32)
    public static func hash(_ parts: [UInt8]...) -> [UInt8] {
        var b = BLAKE2s(); for p in parts { b.update(p) }; return b.finalize()
    }
    /// MAC(key, input) = Keyed-BLAKE2s(key, input, 16)
    public static func mac(key: [UInt8], _ input: [UInt8]) -> [UInt8] { BLAKE2s.hash(input, outputLength: 16, key: key) }

    /// HMAC(key, input) with BLAKE2s (block size 64).
    public static func hmac(key: [UInt8], _ input: [UInt8]) -> [UInt8] {
        var k = key.count > 64 ? BLAKE2s.hash(key) : key
        k += [UInt8](repeating: 0, count: 64 - k.count)
        var inner = BLAKE2s(); inner.update(k.map { $0 ^ 0x36 }); inner.update(input)
        var outer = BLAKE2s(); outer.update(k.map { $0 ^ 0x5c }); outer.update(inner.finalize())
        return outer.finalize()
    }

    /// HKDF as used by Noise / WireGuard: KDF_n(key, input) -> n 32-byte outputs.
    public static func kdf(_ n: Int, key: [UInt8], input: [UInt8]) -> [[UInt8]] {
        let prk = hmac(key: key, input)
        var out: [[UInt8]] = []
        var prev: [UInt8] = []
        for i in 1...n {
            prev = hmac(key: prk, prev + [UInt8(i)])
            out.append(prev)
        }
        return out
    }
}

/// TAI64N timestamp (12 bytes, big-endian): 2^62 + 10 + seconds, then nanoseconds.
public enum TAI64N {
    public static let base: UInt64 = 0x4000_0000_0000_000a
    public static func encode(_ date: Date) -> [UInt8] {
        let t = date.timeIntervalSince1970
        let secs = UInt64(max(0, floor(t)))
        let nanos = UInt32(min(999_999_999, max(0, (t - floor(t)) * 1e9)))
        return encode(seconds: secs, nanoseconds: nanos)
    }
    public static func encode(seconds: UInt64, nanoseconds: UInt32) -> [UInt8] {
        let s = base &+ seconds
        return (0..<8).map { UInt8(truncatingIfNeeded: s >> (56 - 8 * UInt64($0))) }
            + (0..<4).map { UInt8(truncatingIfNeeded: nanoseconds >> (24 - 8 * UInt32($0))) }
    }
    /// Lexicographic comparison of two encoded stamps (big-endian, so byte order == time order).
    public static func isAfter(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == 12, b.count == 12 else { return false }
        for i in 0..<12 where a[i] != b[i] { return a[i] > b[i] }
        return false
    }
    public static func decode(_ b: [UInt8]) -> (seconds: UInt64, nanoseconds: UInt32)? {
        guard b.count == 12 else { return nil }
        let s = b[0..<8].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let n = b[8..<12].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return (s &- base, n)
    }
}

import Foundation
import Security

/// Cryptographically secure randomness from `SecRandomCopyBytes`, with unbiased bounded integers.
public enum SecureRandom {
    public static func bytes(_ count: Int) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: count)
        guard count > 0 else { return b }
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &b)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return b
    }

    public static func data(_ count: Int) -> Data { Data(bytes(count)) }

    static func uint32() -> UInt32 {
        var v: UInt32 = 0
        let status = withUnsafeMutableBytes(of: &v) { SecRandomCopyBytes(kSecRandomDefault, 4, $0.baseAddress!) }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return v
    }

    /// Largest multiple of `n` that fits in 2^32. Raw values at or above it are rejected so that every
    /// residue `0..<n` is produced by exactly the same number of raw values (no modulo bias).
    public static func rejectionLimit(_ n: UInt32) -> UInt64 {
        precondition(n > 0)
        let range: UInt64 = 1 << 32
        return range - range % UInt64(n)
    }

    /// Uniform integer in `0..<n` via rejection sampling.
    public static func uniform(_ n: Int) -> Int {
        precondition(n > 0 && n <= Int(UInt32.max))
        if n == 1 { return 0 }
        let limit = rejectionLimit(UInt32(n))
        while true {
            let r = UInt64(uint32())
            if r < limit { return Int(r % UInt64(n)) }
        }
    }

    /// Fisher–Yates shuffle with unbiased indices.
    public static func shuffle<T>(_ a: inout [T]) {
        guard a.count > 1 else { return }
        for i in stride(from: a.count - 1, to: 0, by: -1) {
            a.swapAt(i, uniform(i + 1))
        }
    }
}

/// Overwrite a buffer in a way the optimiser may not elide.
@inline(never)
public func secureZero(_ data: inout Data) {
    let n = data.count
    guard n > 0 else { return }
    data.withUnsafeMutableBytes { p in _ = memset_s(p.baseAddress, n, 0, n) }
}

@inline(never)
public func secureZero(_ bytes: inout [UInt8]) {
    let n = bytes.count
    guard n > 0 else { return }
    bytes.withUnsafeMutableBytes { p in _ = memset_s(p.baseAddress, n, 0, n) }
}

/// Key material that is wiped when released. Swift may still make transient copies (for example when a
/// `SymmetricKey` is built from it); we keep those short-lived and scoped.
public final class SecretKeyBytes: @unchecked Sendable {
    private var storage: [UInt8]
    private let lock = NSLock()
    public init(_ bytes: [UInt8]) { storage = bytes }
    public convenience init(data: Data) { self.init([UInt8](data)) }
    public var count: Int { lock.withLock { storage.count } }
    public func withBytes<R>(_ body: ([UInt8]) throws -> R) rethrows -> R { try lock.withLock { try body(storage) } }
    public func wipe() { lock.withLock { secureZero(&storage); storage = [] } }
    deinit { secureZero(&storage) }
}

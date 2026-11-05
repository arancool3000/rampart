import Foundation
import CryptoKit
import RampartShared

/// Streamed SHA-256 using CryptoKit (hardware accelerated on Apple silicon).
public enum FileHasher {
    /// Default read chunk size.
    public static let chunkSize = 1 << 20

    /// Hashes a regular file without following symlinks. `bypassPageCache` sets `F_NOCACHE`
    /// so bulk scans do not evict the user's page cache.
    public static func sha256(path: String, bypassPageCache: Bool = true) throws -> (hex: String, bytes: UInt64) {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw EngineError.posix(op: "open", path: path, errno: errno) }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else { throw EngineError.posix(op: "fstat", path: path, errno: errno) }
        guard st.isRegular else { throw EngineError.notRegularFile(path) }
        return try sha256(fd: fd, sizeHint: UInt64(st.st_size), path: path, bypassPageCache: bypassPageCache)
    }

    /// Hashes from the start of an open file descriptor.
    public static func sha256(fd: Int32, sizeHint: UInt64, path: String = "", bypassPageCache: Bool = true) throws -> (hex: String, bytes: UInt64) {
        if bypassPageCache && sizeHint > UInt64(chunkSize) { _ = fcntl(fd, F_NOCACHE, 1) }
        let cap = Int(min(UInt64(chunkSize), max(sizeHint, 4096)))
        let buf = UnsafeMutableRawPointer.allocate(byteCount: cap, alignment: 16)
        defer { buf.deallocate() }
        var hasher = SHA256()
        var total: UInt64 = 0
        var offset: off_t = 0
        while true {
            let n = pread(fd, buf, cap, offset)
            if n < 0 {
                if errno == EINTR { continue }
                throw EngineError.posix(op: "read", path: path, errno: errno)
            }
            if n == 0 { break }
            hasher.update(bufferPointer: UnsafeRawBufferPointer(start: buf, count: n))
            total += UInt64(n); offset += off_t(n)
        }
        return (hex(hasher.finalize()), total)
    }

    /// SHA-256 of in-memory bytes, lowercase hex.
    public static func sha256(data: Data) -> String { hex(SHA256.hash(data: data)) }

    static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        let table = Array("0123456789abcdef".utf8)
        var out = [UInt8](); out.reserveCapacity(64)
        for b in digest { out.append(table[Int(b >> 4)]); out.append(table[Int(b & 0xF)]) }
        return String(decoding: out, as: UTF8.self)
    }

    /// True if `s` is 64 hex characters.
    public static func isSHA256Hex(_ s: Substring) -> Bool {
        s.utf8.count == 64 && s.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) || ($0 >= 65 && $0 <= 70) }
    }
    public static func isSHA256Hex(_ s: String) -> Bool { isSHA256Hex(Substring(s)) }
}

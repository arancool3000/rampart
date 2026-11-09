import Foundation
import RampartShared

/// Content-based file type detection (magic bytes, not extensions, except where the format has no header).
public enum FileSniffer {
    /// Number of header bytes `kind(header:)` looks at.
    public static let headerLength = 512

    /// Sniffs the file at `path`. Directories ending in `.app` report `.appBundle`; unreadable files `.other`.
    public static func kind(path: String) -> FileKind {
        var st = stat()
        guard lstat(path, &st) == 0 else { return .other }
        if st.isDirectory { return path.hasSuffix(".app") || path.hasSuffix(".app/") ? .appBundle : .other }
        guard st.isRegular else { return .other }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return .other }
        defer { close(fd) }
        return kind(fd: fd, size: UInt64(st.st_size), path: path)
    }

    /// Sniffs an already-open regular file.
    public static func kind(fd: Int32, size: UInt64, path: String) -> FileKind { sniff(fd: fd, size: size, path: path).kind }

    /// Sniffs an already-open regular file and also returns the header bytes read (for triage).
    public static func sniff(fd: Int32, size: UInt64, path: String) -> (kind: FileKind, header: [UInt8]) {
        var header = [UInt8](repeating: 0, count: headerLength)
        let n = header.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
        guard n > 0 else { return (.other, []) }
        header.removeSubrange(n...)
        let k = kind(header: header, path: path)
        // A compressed UDIF image (UDZO/ULFO) starts with a zlib/lzfse chunk, so its header sniffs as
        // `.archive` (zlib stream); the "koly" trailer is authoritative and must win over that weak magic.
        if k == .other || k == .archive || k == .dmg {
            if trailerKind(fd: fd, size: size) == .dmg { return (.dmg, header) }
        }
        if k != .other { return (k, header) }
        return (.other, header)
    }

    private static func trailerKind(fd: Int32, size: UInt64) -> FileKind {
        // UDIF disk images have no header magic; the 512-byte "koly" trailer identifies them.
        if size >= 512 {
            var trailer = [UInt8](repeating: 0, count: 4)
            let t = trailer.withUnsafeMutableBytes { pread(fd, $0.baseAddress, 4, off_t(size - 512)) }
            if t == 4 && trailer == Array("koly".utf8) { return .dmg }
        }
        return .other
    }

    /// Classifies a header buffer. `path` is only used for formats without magic (e.g. raw `.dmg`).
    public static func kind(header h: [UInt8], path: String = "") -> FileKind {
        func be32(_ o: Int) -> UInt32? {
            guard h.count >= o + 4 else { return nil }
            return UInt32(h[o]) << 24 | UInt32(h[o+1]) << 16 | UInt32(h[o+2]) << 8 | UInt32(h[o+3])
        }
        func starts(_ s: [UInt8], at o: Int = 0) -> Bool {
            h.count >= o + s.count && Array(h[o..<o + s.count]) == s
        }
        if let m = be32(0) {
            switch m {
            case 0xCFFAEDFE, 0xCEFAEDFE, 0xFEEDFACF, 0xFEEDFACE: return .machO
            case 0xCAFEBABE, 0xCAFEBABF:
                // Java .class shares 0xCAFEBABE; its next word is a version (>= 45), never a small arch count.
                if let n = be32(4), n > 0, n < 20 { return .fatMachO }
            case 0x504B0304, 0x504B0506, 0x504B0708: return .zip
            case 0x78617221: return .pkg                    // "xar!" (flat pkg)
            default: break
            }
        }
        if starts([0x23, 0x21]) { return .script }          // "#!"
        if starts(Array("bplist0".utf8)) { return .plist }
        if starts(Array("<?xml".utf8)) || starts([0xEF, 0xBB, 0xBF] + Array("<?xml".utf8)) {
            let text = String(decoding: h, as: UTF8.self)
            return text.contains("<plist") || text.contains("PropertyList") ? .plist : .document
        }
        if starts([0x1F, 0x8B]) || starts(Array("BZh".utf8)) || starts([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])
            || starts([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) || starts(Array("Rar!".utf8))
            || starts([0x28, 0xB5, 0x2F, 0xFD]) || starts(Array("ustar".utf8), at: 257) {
            return .archive
        }
        // .Z, lz4, cpio, Apple Archive (.aar/.yaa), zlib-wrapped blobs (trial-inflated), legacy .lzma.
        switch ArchiveFormat.detect(header: h, path: path) {
        case .compressZ, .lz4, .cpio, .appleArchive, .zlib, .lzma: return .archive
        default: break
        }
        if starts(Array("%PDF".utf8)) || starts([0xD0, 0xCF, 0x11, 0xE0]) || starts(Array("{\\rtf".utf8)) {
            return .document
        }
        if path.lowercased().hasSuffix(".dmg") { return .dmg }
        return .other
    }
}

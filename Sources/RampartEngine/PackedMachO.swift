import Foundation
import RampartShared

/// Recognises packed / self-decompressing Mach-O programs (UPX and look-alikes): packer marker strings or
/// segment names, a near-random (compressed or encrypted) `__TEXT`, and an almost empty import table.
/// A packed program only becomes readable once it decompresses itself in memory, so a file scan can't see
/// what it really does. On its own that is a weak signal (score ≤ 40); unsigned / ad-hoc packed programs in
/// user-writable folders score 60. Notarised and Apple-signed programs lose this evidence through the trust prior.
public struct PackedMachODetector: FileDetector {
    public init() {}
    public var name: String { "packed-macho" }
    public static let title = "Packed (self-decompressing) program"

    public struct Analysis: Equatable, Sendable {
        public var packerMarker: String?
        public var textEntropy: Double = 0
        public var textBytes: Int = 0
        public var dylibCount = 0
        public var symbolCount = 0
        public var hasCodeSignature = false
        public var isPacked: Bool {
            packerMarker != nil || (textEntropy >= 7.4 && textBytes >= 4096 && dylibCount <= 2 && symbolCount <= 16)
        }
    }

    /// Segment / section names packers use.
    static let markers = ["UPX0", "UPX1", "UPX2", "UPX_DATA", "__XHDR", "MPRESS1", "MPRESS2", "__upx"]

    public func inspect(_ facts: FileFacts) -> [Evidence] {
        guard facts.kind == .machO || facts.kind == .fatMachO, facts.size >= 64 else { return [] }
        if let s = facts.signing, Scoring.isTrusted(s) { return [] }
        guard let a = Self.analyze(path: facts.path), a.isPacked else { return [] }
        let unsigned: Bool = {
            if let s = facts.signing { return [.unsigned, .adHoc, .invalid, .unknown].contains(s.status) }
            return !a.hasCodeSignature
        }()
        let userFolder = Self.isUserWritable(facts.path)
        var score = 40
        var why: [String] = []
        if let m = a.packerMarker { why.append("it contains the packer marker \"\(m)\"") }
        if a.textEntropy >= 7.4 { why.append(String(format: "its code section looks compressed or encrypted (entropy %.2f of 8)", a.textEntropy)) }
        if a.dylibCount <= 2 && a.symbolCount <= 16 { why.append("it links almost nothing (\(a.dylibCount) libraries)") }
        if unsigned && userFolder { score = 60; why.append("it is unsigned or ad-hoc signed and sits in a user-writable folder") }
        else if unsigned { score = 45; why.append("it is unsigned or ad-hoc signed") }
        return [Evidence(source: .heuristic, title: Self.title,
                         detail: "This program is packed: it decompresses its real code only when it runs, so its contents can't be checked on disk ("
                            + why.joined(separator: "; ") + "). Legitimate Mac software is almost never packed this way; RamPart watches what it does when it runs.",
                         score: score)]
    }

    static func isUserWritable(_ p: String) -> Bool {
        p.hasPrefix("/Users/") || p.hasPrefix("/private/tmp/") || p.hasPrefix("/tmp/") || p.hasPrefix("/private/var/folders/")
            || p.hasPrefix("/var/folders/") || p.hasPrefix("/private/var/tmp/") || p.hasPrefix("/Library/Application Support/")
    }

    /// Parses the first (or arm64) slice of a Mach-O file.
    public static func analyze(path: String) -> Analysis? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        guard let head = try? h.read(upToCount: 64 << 10), head.count >= 32 else { return nil }
        let b = [UInt8](head)
        var sliceOff = 0
        let magicBE = be32(b, 0)
        if magicBE == 0xCAFEBABE || magicBE == 0xCAFEBABF {
            let n = Int(be32(b, 4)), is64 = magicBE == 0xCAFEBABF
            guard n > 0, n < 20 else { return nil }
            let stride = is64 ? 32 : 20
            var chosen: Int?
            for i in 0..<n {
                let o = 8 + i * stride
                guard o + stride <= b.count else { break }
                let cpu = be32(b, o)
                let off = is64 ? Int(be64(b, o + 8)) : Int(be32(b, o + 8))
                if chosen == nil || cpu == 0x0100000C { chosen = off }
            }
            guard let c = chosen else { return nil }
            sliceOff = c
        }
        let slice: [UInt8]
        if sliceOff == 0 { slice = b }
        else {
            guard (try? h.seek(toOffset: UInt64(sliceOff))) != nil, let d = try? h.read(upToCount: 64 << 10), d.count >= 32 else { return nil }
            slice = [UInt8](d)
        }
        return analyzeSlice(slice, sliceOffset: UInt64(sliceOff)) { off, len in
            guard (try? h.seek(toOffset: off)) != nil else { return nil }
            return try? h.read(upToCount: len)
        }
    }

    /// Analyses one thin Mach-O slice whose first bytes are `s`. `read` fetches file ranges (absolute offsets).
    public static func analyzeSlice(_ s: [UInt8], sliceOffset: UInt64, read: (UInt64, Int) -> Data?) -> Analysis? {
        let magic = le32(s, 0)
        guard magic == 0xFEEDFACF || magic == 0xFEEDFACE else { return nil }
        let is64 = magic == 0xFEEDFACF
        let ncmds = Int(le32(s, 16)), sizeofcmds = Int(le32(s, 20))
        var a = Analysis()
        var off = is64 ? 32 : 28
        let end = min(s.count, off + sizeofcmds)
        // UPX puts its "UPX!" info block right after the load commands; look only there (not at string tables).
        if end < s.count {
            let window = String(decoding: s[end..<min(s.count, end + 1024)], as: UTF8.self)
            a.packerMarker = ["UPX!", "MPRESS"].first { window.contains($0) }
        }
        var textRange: (UInt64, UInt64)?
        for _ in 0..<min(ncmds, 512) {
            guard off + 8 <= end else { break }
            let cmd = le32(s, off), size = Int(le32(s, off + 4))
            guard size >= 8, off + size <= end else { break }
            switch cmd {
            case 0x19, 0x1:   // LC_SEGMENT_64 / LC_SEGMENT
                let seg = cstr(s, off + 8, 16)
                if a.packerMarker == nil, let m = markers.first(where: { seg.hasPrefix($0) }) { a.packerMarker = m }
                let fileoff = cmd == 0x19 ? le64(s, off + 40) : UInt64(le32(s, off + 32))
                let filesize = cmd == 0x19 ? le64(s, off + 48) : UInt64(le32(s, off + 36))
                let nsects = Int(cmd == 0x19 ? le32(s, off + 64) : le32(s, off + 48))
                let secStart = off + (cmd == 0x19 ? 72 : 56), secSize = cmd == 0x19 ? 80 : 68
                for k in 0..<min(nsects, 64) {
                    let so = secStart + k * secSize
                    guard so + 32 <= off + size else { break }
                    let sect = cstr(s, so, 16)
                    if a.packerMarker == nil, let m = markers.first(where: { sect.hasPrefix($0) }) { a.packerMarker = m }
                    if seg == "__TEXT" && sect == "__text" {
                        let sOff = UInt64(le32(s, so + (cmd == 0x19 ? 48 : 40)))
                        let sSize = cmd == 0x19 ? le64(s, so + 40) : UInt64(le32(s, so + 36))
                        if sSize > 0 { textRange = (sOff, sSize) }
                    }
                }
                if seg == "__TEXT" && textRange == nil && filesize > 0 { textRange = (fileoff, filesize) }
            case 0xC, 0x80000018, 0x1F, 0x80000023:   // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB
                a.dylibCount += 1
            case 0x2:    // LC_SYMTAB
                a.symbolCount = Int(le32(s, off + 12))
            case 0x1D:   // LC_CODE_SIGNATURE
                a.hasCodeSignature = true
            default: break
            }
            off += size
        }
        if let (o, n) = textRange, n > 0 {
            let len = Int(min(n, 4 << 20))
            if let d = read(sliceOffset + o, len), !d.isEmpty {
                a.textBytes = d.count
                a.textEntropy = entropy(d)
            }
        }
        return a
    }

    public static func entropy(_ d: Data) -> Double {
        var counts = [Int](repeating: 0, count: 256)
        for b in d { counts[Int(b)] += 1 }
        let n = Double(d.count)
        var h = 0.0
        for c in counts where c > 0 { let p = Double(c) / n; h -= p * log2(p) }
        return h
    }

    static func le32(_ b: [UInt8], _ o: Int) -> UInt32 {
        guard o + 4 <= b.count else { return 0 }
        return UInt32(b[o]) | UInt32(b[o+1]) << 8 | UInt32(b[o+2]) << 16 | UInt32(b[o+3]) << 24
    }
    static func le64(_ b: [UInt8], _ o: Int) -> UInt64 { UInt64(le32(b, o)) | UInt64(le32(b, o + 4)) << 32 }
    static func be32(_ b: [UInt8], _ o: Int) -> UInt32 {
        guard o + 4 <= b.count else { return 0 }
        return UInt32(b[o]) << 24 | UInt32(b[o+1]) << 16 | UInt32(b[o+2]) << 8 | UInt32(b[o+3])
    }
    static func be64(_ b: [UInt8], _ o: Int) -> UInt64 { UInt64(be32(b, o)) << 32 | UInt64(be32(b, o + 4)) }
    static func cstr(_ b: [UInt8], _ o: Int, _ n: Int) -> String {
        guard o + n <= b.count else { return "" }
        let raw = b[o..<(o + n)].prefix { $0 != 0 }
        return String(decoding: raw, as: UTF8.self)
    }
}

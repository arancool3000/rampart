import Foundation

/// Read-only, bounds-checked Mach-O parser (thin and fat, 32/64-bit, both endiannesses).
/// Never trusts `ncmds` / `sizeofcmds` / fat offsets: every read is validated against the file length.
public struct MachOFile: Sendable {
    public enum ParseError: Error, Equatable, Sendable {
        case unreadable, notMachO, truncated, malformed(String)
    }

    /// One architecture slice.
    public struct Slice: Sendable {
        public var cpuType: Int32
        public var cpuSubtype: Int32
        public var fileType: UInt32
        public var flags: UInt32
        public var is64Bit: Bool
        public var offset: UInt64        // slice start in the file
        public var size: UInt64
        public var loadCommandCount: UInt32
        public var loadCommands: [UInt32]        // raw cmd values in order
        public var segments: [String]
        public var dylibs: [Dylib]
        public var rpaths: [String]
        public var installName: String?          // LC_ID_DYLIB
        public var dylinker: String?             // LC_LOAD_DYLINKER
        public var dyldEnvironment: [String]     // LC_DYLD_ENVIRONMENT (suspicious)
        public var uuid: UUID?
        public var hasMain: Bool                 // LC_MAIN
        public var isEncrypted: Bool             // LC_ENCRYPTION_INFO(_64) cryptid != 0
        public var minOS: String?                // LC_BUILD_VERSION / LC_VERSION_MIN_MACOSX
        public var codeSignatureRange: (offset: UInt32, size: UInt32)?
        public var codeSignature: CodeSignatureBlob?
        public var warnings: [String]            // malformed bits we tolerated

        public var hasCodeSignature: Bool { codeSignatureRange != nil }
        public var cpuName: String { MachOFile.cpuName(cpuType, cpuSubtype) }
        public var fileTypeName: String { MachOFile.fileTypeName(fileType) }
    }

    public struct Dylib: Sendable, Hashable {
        public enum Kind: String, Sendable { case load, weak, reexport, lazy, upward }
        public var path: String
        public var kind: Kind
    }

    /// Parsed embedded code signature (SuperBlob at LC_CODE_SIGNATURE).
    public struct CodeSignatureBlob: Sendable {
        public var codeDirectoryFlags: UInt32
        public var codeDirectoryVersion: UInt32
        public var identifier: String?
        public var teamID: String?
        public var hashType: UInt8
        public var platform: UInt8
        public var hasCMSSignature: Bool          // non-empty 0xfade0b01 blob
        public var entitlementKeys: [String]      // from the XML entitlements blob (0xfade7171)
        public var isAdHoc: Bool { codeDirectoryFlags & 0x2 != 0 }
        public var isLinkerSigned: Bool { codeDirectoryFlags & 0x20000 != 0 }
        public var hardenedRuntime: Bool { codeDirectoryFlags & 0x10000 != 0 }
    }

    public var path: String?
    public var isFat: Bool
    public var slices: [Slice]

    // MARK: Convenience

    public var allDylibs: [Dylib] { var seen = Set<Dylib>(); return slices.flatMap(\.dylibs).filter { seen.insert($0).inserted } }
    public var allRpaths: [String] { var seen = Set<String>(); return slices.flatMap(\.rpaths).filter { seen.insert($0).inserted } }
    public var hasCodeSignature: Bool { !slices.isEmpty && slices.allSatisfy(\.hasCodeSignature) }
    public var anySliceUnsigned: Bool { slices.contains { !$0.hasCodeSignature } }
    public var cpuNames: [String] { slices.map(\.cpuName) }
    public var primaryFileType: UInt32? { slices.first?.fileType }

    /// Dylibs (absolute) loaded from user-writable or temp locations.
    public var userWritableDylibs: [String] {
        allDylibs.map(\.path).filter { PathClass.isUserWritable($0) }
    }
    /// Absolute LC_RPATH entries that point into user-writable or temp locations.
    public var userWritableRpaths: [String] {
        allRpaths.filter { $0.hasPrefix("/") && PathClass.isUserWritable($0) }
    }

    // MARK: Entry points

    /// Quick magic sniff (first 4 bytes). Does not validate the whole file.
    public static func looksLikeMachO(path: String) -> Bool {
        guard let fh = FileHandle(forReadingAtPath: path) else { return false }
        defer { try? fh.close() }
        guard let d = try? fh.read(upToCount: 8), d.count >= 8 else { return false }
        return looksLikeMachO(d)
    }

    public static func looksLikeMachO(_ head: Data) -> Bool {
        guard head.count >= 4 else { return false }
        let b = [UInt8](head.prefix(8))
        let be = UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
        switch be {
        case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe: return true
        case 0xcafebabe, 0xcafebabf:
            guard b.count >= 8 else { return false }
            let n = UInt32(b[4]) << 24 | UInt32(b[5]) << 16 | UInt32(b[6]) << 8 | UInt32(b[7])
            return n > 0 && n < 20   // Java class files share 0xcafebabe; their "count" is a version >= 45
        default: return false
        }
    }

    public init(path: String) throws {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .alwaysMapped) else {
            throw ParseError.unreadable
        }
        try self.init(data: data)
        self.path = path
    }

    public init(data: Data) throws {
        self.path = nil
        let r = Reader(data: data)
        guard let magicBE = r.u32(0, bigEndian: true) else { throw ParseError.notMachO }
        switch magicBE {
        case 0xcafebabe, 0xcafebabf:
            let is64 = magicBE == 0xcafebabf
            guard let n = r.u32(4, bigEndian: true), n > 0, n < 20 else { throw ParseError.notMachO }
            var slices: [Slice] = []
            let entry = is64 ? 32 : 20
            for i in 0..<Int(n) {
                let base = 8 + i * entry
                guard let cpu = r.u32(base, bigEndian: true), let sub = r.u32(base + 4, bigEndian: true) else { throw ParseError.truncated }
                let off: UInt64, size: UInt64
                if is64 {
                    guard let o = r.u64(base + 8, bigEndian: true), let s = r.u64(base + 16, bigEndian: true) else { throw ParseError.truncated }
                    off = o; size = s
                } else {
                    guard let o = r.u32(base + 8, bigEndian: true), let s = r.u32(base + 12, bigEndian: true) else { throw ParseError.truncated }
                    off = UInt64(o); size = UInt64(s)
                }
                guard off < UInt64(data.count), size <= UInt64(data.count) - off, size >= 28 else {
                    throw ParseError.malformed("fat arch \(i) out of bounds")
                }
                var s = try MachOFile.parseThin(r, at: Int(off), size: Int(size))
                if s.cpuType != Int32(bitPattern: cpu) { s.warnings.append("fat cputype mismatch") }
                _ = sub
                slices.append(s)
            }
            self.isFat = true; self.slices = slices
        default:
            let s = try MachOFile.parseThin(r, at: 0, size: data.count)
            self.isFat = false; self.slices = [s]
        }
    }

    // MARK: Thin parsing

    private static func parseThin(_ r: Reader, at base: Int, size: Int) throws -> Slice {
        guard let rawMagic = r.u32(base, bigEndian: false) else { throw ParseError.truncated }
        let le: Bool, is64: Bool
        switch rawMagic {
        case 0xfeedface: le = true; is64 = false
        case 0xfeedfacf: le = true; is64 = true
        case 0xcefaedfe: le = false; is64 = false
        case 0xcffaedfe: le = false; is64 = true
        default: throw ParseError.notMachO
        }
        let be = !le
        let headerSize = is64 ? 32 : 28
        guard size >= headerSize,
              let cpu = r.u32(base + 4, bigEndian: be), let sub = r.u32(base + 8, bigEndian: be),
              let ftype = r.u32(base + 12, bigEndian: be), let ncmds = r.u32(base + 16, bigEndian: be),
              let sizeofcmds = r.u32(base + 20, bigEndian: be), let flags = r.u32(base + 24, bigEndian: be)
        else { throw ParseError.truncated }

        var s = Slice(cpuType: Int32(bitPattern: cpu), cpuSubtype: Int32(bitPattern: sub & 0x00ff_ffff), fileType: ftype,
                      flags: flags, is64Bit: is64, offset: UInt64(base), size: UInt64(size), loadCommandCount: ncmds,
                      loadCommands: [], segments: [], dylibs: [], rpaths: [], installName: nil, dylinker: nil,
                      dyldEnvironment: [], uuid: nil, hasMain: false, isEncrypted: false, minOS: nil,
                      codeSignatureRange: nil, codeSignature: nil, warnings: [])

        let cmdsEnd = min(headerSize + Int(sizeofcmds), size)
        if headerSize + Int(sizeofcmds) > size { s.warnings.append("sizeofcmds exceeds slice") }
        var off = headerSize
        var count = 0
        while count < Int(ncmds) && count < 4096 {
            guard off + 8 <= cmdsEnd, let cmd = r.u32(base + off, bigEndian: be),
                  let cmdsize = r.u32(base + off + 4, bigEndian: be) else {
                s.warnings.append("load commands truncated at #\(count)"); break
            }
            guard cmdsize >= 8, off + Int(cmdsize) <= cmdsEnd else {
                s.warnings.append("bad cmdsize at #\(count)"); break
            }
            s.loadCommands.append(cmd)
            let c = base + off
            let lcEnd = c + Int(cmdsize)
            func str(_ fieldOffset: Int) -> String? {
                guard let o = r.u32(c + fieldOffset, bigEndian: be), Int(o) < Int(cmdsize) else { return nil }
                return r.cString(c + Int(o), limit: lcEnd)
            }
            switch cmd {
            case 0x1, 0x19: // LC_SEGMENT, LC_SEGMENT_64
                if let n = r.fixedString(c + 8, length: 16) { s.segments.append(n) }
            case 0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023:
                let kind: Dylib.Kind = cmd == 0xc ? .load : cmd == 0x80000018 ? .weak : cmd == 0x8000001f ? .reexport : cmd == 0x20 ? .lazy : .upward
                if let p = str(8) { s.dylibs.append(Dylib(path: p, kind: kind)) }
            case 0xd: s.installName = str(8)
            case 0xe: s.dylinker = str(8)
            case 0x27: if let p = str(8) { s.dyldEnvironment.append(p) }
            case 0x8000001c: if let p = str(8) { s.rpaths.append(p) }
            case 0x1b: // LC_UUID
                if cmdsize >= 24, let b = r.bytes(c + 8, 16) {
                    s.uuid = UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
                }
            case 0x80000028: s.hasMain = true
            case 0x21, 0x2c: // LC_ENCRYPTION_INFO(_64)
                if let id = r.u32(c + 16, bigEndian: be), id != 0 { s.isEncrypted = true }
            case 0x32: // LC_BUILD_VERSION: platform, minos
                if let v = r.u32(c + 12, bigEndian: be) { s.minOS = versionString(v) }
            case 0x24: if let v = r.u32(c + 8, bigEndian: be) { s.minOS = versionString(v) }
            case 0x1d: // LC_CODE_SIGNATURE
                if let dOff = r.u32(c + 8, bigEndian: be), let dSize = r.u32(c + 12, bigEndian: be) {
                    s.codeSignatureRange = (dOff, dSize)
                    if Int(dOff) < size, Int(dSize) <= size - Int(dOff) {
                        s.codeSignature = parseSuperBlob(r, at: base + Int(dOff), length: Int(dSize))
                    } else { s.warnings.append("code signature out of bounds") }
                }
            default: break
            }
            off += Int(cmdsize); count += 1
        }
        return s
    }

    // MARK: Code signature blobs (always big-endian)

    private static func parseSuperBlob(_ r: Reader, at base: Int, length: Int) -> CodeSignatureBlob? {
        guard let magic = r.u32(base, bigEndian: true), magic == 0xfade0cc0,
              let count = r.u32(base + 8, bigEndian: true), count < 64 else { return nil }
        var blob = CodeSignatureBlob(codeDirectoryFlags: 0, codeDirectoryVersion: 0, identifier: nil, teamID: nil,
                                     hashType: 0, platform: 0, hasCMSSignature: false, entitlementKeys: [])
        var sawCD = false
        for i in 0..<Int(count) {
            guard let type = r.u32(base + 12 + i * 8, bigEndian: true),
                  let off = r.u32(base + 16 + i * 8, bigEndian: true), Int(off) + 8 <= length else { continue }
            let b = base + Int(off)
            guard let m = r.u32(b, bigEndian: true), let len = r.u32(b + 4, bigEndian: true),
                  len >= 8, Int(off) + Int(len) <= length else { continue }
            let end = b + Int(len)
            switch m {
            case 0xfade0c02 where !sawCD || type == 0: // CodeDirectory (primary at slot 0)
                sawCD = true
                blob.codeDirectoryVersion = r.u32(b + 8, bigEndian: true) ?? 0
                blob.codeDirectoryFlags = r.u32(b + 12, bigEndian: true) ?? 0
                if let io = r.u32(b + 20, bigEndian: true), io > 0, Int(io) < Int(len) { blob.identifier = r.cString(b + Int(io), limit: end) }
                blob.hashType = r.u8(b + 37) ?? 0
                blob.platform = r.u8(b + 38) ?? 0
                if blob.codeDirectoryVersion >= 0x20200, let to = r.u32(b + 48, bigEndian: true), to > 0, Int(to) < Int(len) {
                    blob.teamID = r.cString(b + Int(to), limit: end)
                }
            case 0xfade0b01: blob.hasCMSSignature = len > 8
            case 0xfade7171:
                if let bytes = r.bytes(b + 8, Int(len) - 8),
                   let plist = try? PropertyListSerialization.propertyList(from: Data(bytes), format: nil) as? [String: Any] {
                    blob.entitlementKeys = plist.keys.sorted()
                }
            default: break
            }
        }
        return sawCD ? blob : nil
    }

    private static func versionString(_ v: UInt32) -> String { "\(v >> 16).\((v >> 8) & 0xff).\(v & 0xff)" }

    // MARK: Names

    public static func cpuName(_ type: Int32, _ subtype: Int32) -> String {
        switch type {
        case 0x0100000c: return subtype == 2 ? "arm64e" : "arm64"
        case 0x0200000c: return "arm64_32"
        case 12: return "arm"
        case 0x01000007: return subtype == 8 ? "x86_64h" : "x86_64"
        case 7: return "i386"
        case 0x01000012: return "ppc64"
        case 18: return "ppc"
        default: return "cpu(\(type))"
        }
    }

    public static func fileTypeName(_ t: UInt32) -> String {
        switch t {
        case 1: return "object"; case 2: return "execute"; case 3: return "fvmlib"; case 4: return "core"
        case 5: return "preload"; case 6: return "dylib"; case 7: return "dylinker"; case 8: return "bundle"
        case 9: return "dylib_stub"; case 10: return "dsym"; case 11: return "kext_bundle"; case 12: return "fileset"
        default: return "type(\(t))"
        }
    }

    public static let MH_EXECUTE: UInt32 = 2, MH_DYLIB: UInt32 = 6, MH_BUNDLE: UInt32 = 8, MH_KEXT_BUNDLE: UInt32 = 11
}

// MARK: - Bounds-checked byte reader

struct Reader {
    let data: Data
    let count: Int
    init(data: Data) { self.data = data; self.count = data.count }

    func bytes(_ off: Int, _ n: Int) -> [UInt8]? {
        guard off >= 0, n >= 0, off <= count, n <= count - off else { return nil }
        let start = data.startIndex + off
        return [UInt8](data[start..<start + n])
    }
    func u8(_ off: Int) -> UInt8? {
        guard off >= 0, off < count else { return nil }
        return data[data.startIndex + off]
    }
    func u32(_ off: Int, bigEndian: Bool) -> UInt32? {
        guard off >= 0, off + 4 <= count else { return nil }
        let s = data.startIndex + off
        let b0 = UInt32(data[s]), b1 = UInt32(data[s + 1]), b2 = UInt32(data[s + 2]), b3 = UInt32(data[s + 3])
        return bigEndian ? (b0 << 24 | b1 << 16 | b2 << 8 | b3) : (b3 << 24 | b2 << 16 | b1 << 8 | b0)
    }
    func u64(_ off: Int, bigEndian: Bool) -> UInt64? {
        guard let a = u32(off, bigEndian: bigEndian), let b = u32(off + 4, bigEndian: bigEndian) else { return nil }
        return bigEndian ? (UInt64(a) << 32 | UInt64(b)) : (UInt64(b) << 32 | UInt64(a))
    }
    /// NUL-terminated string starting at `off`, not reading past `limit` (exclusive) or 4096 bytes.
    func cString(_ off: Int, limit: Int) -> String? {
        let end = min(limit, count, off + 4096)
        guard off >= 0, off < end else { return nil }
        var i = off
        while i < end && data[data.startIndex + i] != 0 { i += 1 }
        let s = data.startIndex
        return String(decoding: data[(s + off)..<(s + i)], as: UTF8.self)
    }
    func fixedString(_ off: Int, length: Int) -> String? {
        guard let b = bytes(off, length) else { return nil }
        return String(decoding: b.prefix { $0 != 0 }, as: UTF8.self)
    }
}

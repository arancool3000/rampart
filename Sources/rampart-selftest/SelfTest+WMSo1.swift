import Foundation
import Compression
import RampartShared
import RampartEngine
import RampartSigning
import RampartYara

// WMS agent o1: in-process mutation fuzzing of RamPart's untrusted-input parsers (Mach-O / code signature,
// FileSniffer / ArchiveFormat, EmbeddedPayload, PackedMachO, ArchiveUnpacker streams, plists, the YARA rule
// parser and scanner). Deterministic seeds; each target runs for a bounded time.
//   RAMPART_FUZZ_SECONDS=N   seconds per target (default: short budget, whole suite stays under 60 s)
//   RAMPART_FUZZ_SEED=N      base seed (default fixed)
//   RAMPART_FUZZ_TRACE=1     write each input to <tmp>/o1-current-<target>.bin before running it (crash triage)
// A crash or trap kills the selftest process (a scan-evasion DoS); a slow input is reported as FAIL with its seed.
// All fixtures are generated in a private temp dir and deleted; the only "malware" is harmless markers.

struct O1Rng {
    var s: UInt64
    mutating func next() -> UInt64 {
        s &+= 0x9E37_79B9_7F4A_7C15
        var z = s
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
    mutating func int(_ n: Int) -> Int { n <= 0 ? 0 : Int(next() % UInt64(n)) }
    mutating func byte() -> UInt8 { UInt8(truncatingIfNeeded: next()) }
}

enum O1Mutator {
    static let interesting32: [UInt32] = [0, 1, 2, 7, 8, 0x10, 0x1f, 0x20, 0x7f, 0x80, 0xff, 0x100, 0x1000, 0x7fff, 0x8000, 0xffff,
                                          0x10000, 0x00ff_ffff, 0x7fff_ffff, 0x8000_0000, 0xffff_fff0, 0xffff_fffe, 0xffff_ffff]

    static func mutate(_ input: [UInt8], rng: inout O1Rng, hot: [Range<Int>], dict: [[UInt8]], maxSize: Int = 1 << 22) -> [UInt8] {
        var d = input
        let rounds = 1 + rng.int(6)
        for _ in 0..<rounds {
            func pos() -> Int {
                if d.isEmpty { return 0 }
                if !hot.isEmpty && rng.int(3) > 0 {
                    let r = hot[rng.int(hot.count)].clamped(to: 0..<d.count)
                    if !r.isEmpty { return r.lowerBound + rng.int(r.count) }
                }
                return rng.int(d.count)
            }
            switch rng.int(11) {
            case 0: if !d.isEmpty { let p = pos(); d[p] ^= UInt8(1) << UInt8(rng.int(8)) }
            case 1: if !d.isEmpty { d[pos()] = rng.byte() }
            case 2, 3:
                guard d.count >= 4 else { break }
                let p = min(pos(), d.count - 4)
                var v = interesting32[rng.int(interesting32.count)]
                if rng.int(4) == 0 { v = v &+ UInt32(truncatingIfNeeded: rng.int(64)) &- 32 }
                let be = rng.int(2) == 0
                for k in 0..<4 { d[p + k] = UInt8(truncatingIfNeeded: be ? v >> (24 - 8 * k) : v >> (8 * k)) }
            case 4:
                guard d.count >= 8 else { break }
                let p = min(pos(), d.count - 8)
                let v: UInt64 = [UInt64.max, UInt64(Int64.max), 0x8000_0000_0000_0000, 0x0000_0001_0000_0000, 0xffff_ffff_0000_0000][rng.int(5)]
                let be = rng.int(2) == 0
                for k in 0..<8 { d[p + k] = UInt8(truncatingIfNeeded: be ? v >> (56 - 8 * k) : v >> (8 * k)) }
            case 5:
                guard !d.isEmpty else { break }
                let p = pos(); let n = min(d.count - p, 1 + rng.int(rng.int(4) == 0 ? 4096 : 64))
                d.removeSubrange(p..<(p + n))
            case 6:
                guard !d.isEmpty else { break }
                let a = rng.int(d.count); let n = min(d.count - a, 1 + rng.int(256))
                let chunk = Array(d[a..<(a + n)])
                let reps = rng.int(8) == 0 ? 1 + rng.int(64) : 1
                var ins: [UInt8] = []
                for _ in 0..<reps { ins += chunk }
                d.insert(contentsOf: ins, at: pos())
            case 7:
                if d.count > 1 { d.removeSubrange(rng.int(d.count)...) }
            case 8, 9:
                guard !dict.isEmpty else { break }
                let tok = dict[rng.int(dict.count)]
                let p = pos()
                if rng.int(2) == 0 || d.count < p + tok.count { d.insert(contentsOf: tok, at: min(p, d.count)) }
                else { d.replaceSubrange(p..<(p + tok.count), with: tok) }
            default:
                if !d.isEmpty { let p = pos(); d[p] = d[p] &+ UInt8(truncatingIfNeeded: rng.int(33) - 16) }
            }
        }
        if d.count > maxSize { d.removeSubrange(maxSize...) }
        return d
    }
}

extension SelfTest {
    static var o1FuzzSeconds: Double? { ProcessInfo.processInfo.environment["RAMPART_FUZZ_SECONDS"].flatMap(Double.init) }
    static var o1Seed: UInt64 { ProcessInfo.processInfo.environment["RAMPART_FUZZ_SEED"].flatMap { UInt64($0) } ?? 0x0_1F00_2026 }

    /// Runs one fuzz target. Returns the iteration count. Any single input slower than `slow` seconds is a FAIL.
    @discardableResult
    static func o1Fuzz(_ name: String, seconds: Double, maxIters: Int = Int.max, corpus: [[UInt8]], hot: [[Range<Int>]] = [],
                       dict: [[UInt8]] = [], slow: Double = 2.0, work: String, maxSize: Int = 1 << 22, wallClock: Bool = false,
                       body: ([UInt8]) -> Void) -> Int {
        let budget = o1FuzzSeconds ?? seconds
        var rng = O1Rng(s: o1Seed ^ name.utf8.reduce(UInt64(5381)) { ($0 &* 33) &+ UInt64($1) })
        let trace = ProcessInfo.processInfo.environment["RAMPART_FUZZ_TRACE"] == "1"
        let start = Date()
        var iters = 0, worst = 0.0, slowFails = 0
        while iters < maxIters && Date().timeIntervalSince(start) < budget {
            let ci = rng.int(corpus.count)
            let input = iters < corpus.count ? corpus[iters] : O1Mutator.mutate(corpus[ci], rng: &rng, hot: ci < hot.count ? hot[ci] : [], dict: dict, maxSize: maxSize)
            if trace { FileManager.default.createFile(atPath: work + "/o1-current-\(name).bin", contents: Data(input)) }
            // Thread CPU time, not wall time: a hang is CPU spent in our parser, and other processes' load (or
            // being descheduled) must not look like one. Subprocess-driven targets use wall time.
            let t0 = wallClock ? Date().timeIntervalSince1970 : o1CPU()
            autoreleasepool { body(input) }
            let dt = (wallClock ? Date().timeIntervalSince1970 : o1CPU()) - t0
            worst = max(worst, dt)
            if dt > slow && slowFails < 3 {
                slowFails += 1
                let keep = (o1KeepDir ?? work) + "/o1-slow-\(name)-\(iters).bin"
                FileManager.default.createFile(atPath: keep, contents: Data(input))
                print("FUZZ SLOW \(name) iter \(iters) \(String(format: "%.2f", dt))s input \(input.count) B saved \(keep)")
            }
            iters += 1
        }
        print(String(format: "  fuzz %@: %d inputs in %.1fs, slowest %.3fs", name, iters, Date().timeIntervalSince(start), worst))
        check(slowFails == 0, "o1 fuzz \(name): no input slower than \(slow)s")
        check(iters > 0, "o1 fuzz \(name): ran")
        return iters
    }

    static var o1KeepDir: String? { ProcessInfo.processInfo.environment["RAMPART_FUZZ_KEEP"] }

    static func o1CPU() -> Double {
        var ts = timespec(); clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts)
        return Double(ts.tv_sec) + Double(ts.tv_nsec) / 1e9
    }
    /// CPU seconds spent by this thread in `body`.
    static func o1Time(_ body: () -> Void) -> Double { let t = o1CPU(); body(); return o1CPU() - t }

    // MARK: fixtures

    static func o1Run(_ tool: String, _ args: [String]) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: tool); p.arguments = args
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try? p.run(); p.waitUntilExit()
    }

    static func o1Read(_ path: String) -> [UInt8] { (FileManager.default.contents(atPath: path)).map { [UInt8]($0) } ?? [] }

    static func o1BE32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
    static func o1LE32(_ v: UInt32) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff), UInt8((v >> 16) & 0xff), UInt8(v >> 24)] }
    static func o1LE64(_ v: UInt64) -> [UInt8] { o1LE32(UInt32(v & 0xffff_ffff)) + o1LE32(UInt32(v >> 32)) }
    static func o1Pad(_ b: [UInt8], to n: Int) -> [UInt8] { b + [UInt8](repeating: 0, count: max(0, n - b.count)) }

    /// Small synthetic thin arm64 Mach-O: segments with sections, dylibs, rpath, uuid, symtab, and an embedded
    /// code signature SuperBlob (CodeDirectory + entitlements plist + empty CMS). Returns the bytes and hot ranges.
    static func o1SyntheticMachO(packed: Bool = false) -> (bytes: [UInt8], hot: [Range<Int>]) {
        var cmds: [UInt8] = []
        var ncmds: UInt32 = 0
        func lc(_ cmd: UInt32, _ body: [UInt8]) {
            var b = body; while (b.count + 8) % 8 != 0 { b.append(0) }
            cmds += o1LE32(cmd) + o1LE32(UInt32(b.count + 8)) + b; ncmds += 1
        }
        func name16(_ s: String) -> [UInt8] { o1Pad(Array(s.utf8), to: 16) }
        // __TEXT with one __text section pointing at file offset 0x1000, size 0x1000
        var seg = name16("__TEXT") + o1LE64(0x1_0000_0000) + o1LE64(0x2000) + o1LE64(0) + o1LE64(0x2000) + o1LE32(5) + o1LE32(5) + o1LE32(1) + o1LE32(0)
        seg += name16("__text") + name16("__TEXT") + o1LE64(0x1_0000_1000) + o1LE64(0x1000) + o1LE32(0x1000) + o1LE32(4) + o1LE32(0) + o1LE32(0) + o1LE32(0) + o1LE32(0) + o1LE32(0) + o1LE32(0)
        lc(0x19, seg)
        lc(0x19, name16(packed ? "UPX0" : "__LINKEDIT") + o1LE64(0) + o1LE64(0) + o1LE64(0x2000) + o1LE64(0x800) + o1LE32(1) + o1LE32(1) + o1LE32(0) + o1LE32(0))
        lc(0xc, o1LE32(24) + o1LE32(2) + o1LE32(0x10000) + o1LE32(0x10000) + Array("/usr/lib/libSystem.B.dylib\0".utf8))
        lc(0x80000018, o1LE32(24) + o1LE32(2) + o1LE32(0) + o1LE32(0) + Array("@rpath/libFoo.dylib\0".utf8))
        lc(0x8000001c, o1LE32(12) + Array("/tmp/rpath\0".utf8))
        lc(0x1b, [UInt8](repeating: 0xab, count: 16))
        lc(0x2, o1LE32(0x2400) + o1LE32(3) + o1LE32(0x2500) + o1LE32(16))
        lc(0x32, o1LE32(1) + o1LE32(0x000e_0000) + o1LE32(0x000e_0000) + o1LE32(0))
        lc(0x80000028, o1LE64(0x1000) + o1LE64(0))
        lc(0x21, o1LE32(0x1000) + o1LE32(0x100) + o1LE32(0))
        let csOff = 0x2000
        lc(0x1d, o1LE32(UInt32(csOff)) + o1LE32(0x600))
        var head = o1LE32(0xfeedfacf) + o1LE32(0x0100000c) + o1LE32(2) + o1LE32(2) + o1LE32(ncmds) + o1LE32(UInt32(cmds.count)) + o1LE32(0x00200085) + o1LE32(0)
        head += cmds
        if packed { head += Array("UPX!".utf8) }
        var file = o1Pad(head, to: 0x1000)
        var rng = O1Rng(s: 7)
        for _ in 0..<0x1000 { file.append(packed ? rng.byte() : UInt8(0x1f)) }
        // Code signature SuperBlob (big-endian).
        let ent = Array("""
        <?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
        """.utf8)
        var cd = o1BE32(0xfade0c02) + o1BE32(0) + o1BE32(0x20400) + o1BE32(0x2) + o1BE32(0) + o1BE32(88) + o1BE32(0) + o1BE32(0) + o1BE32(0) + o1BE32(0)
        cd = o1Pad(cd, to: 37) + [2, 0] ; cd = o1Pad(cd, to: 48) + o1BE32(104); cd = o1Pad(cd, to: 88) + Array("com.rampart.test.o1\0".utf8)
        cd = o1Pad(cd, to: 104) + Array("O1TEAMID00\0".utf8)
        cd.replaceSubrange(4..<8, with: o1BE32(UInt32(cd.count)))
        let entBlob = o1BE32(0xfade7171) + o1BE32(UInt32(ent.count + 8)) + ent
        let cms = o1BE32(0xfade0b01) + o1BE32(8)
        let idx0 = 12 + 3 * 8
        var sb = o1BE32(0xfade0cc0) + o1BE32(0) + o1BE32(3)
        sb += o1BE32(0) + o1BE32(UInt32(idx0))
        sb += o1BE32(5) + o1BE32(UInt32(idx0 + cd.count))
        sb += o1BE32(0x10000) + o1BE32(UInt32(idx0 + cd.count + entBlob.count))
        sb += cd + entBlob + cms
        sb.replaceSubrange(4..<8, with: o1BE32(UInt32(sb.count)))
        file = o1Pad(file, to: csOff) + sb
        file = o1Pad(file, to: csOff + 0x600)
        return (file, [0..<(32 + cmds.count), csOff..<(csOff + sb.count)])
    }

    static func o1Fat(_ thin: [UInt8], is64: Bool) -> [UInt8] {
        var h = o1BE32(is64 ? 0xcafebabf : 0xcafebabe) + o1BE32(2)
        let off1 = 0x4000, off2 = 0x4000 + ((thin.count + 0x3fff) & ~0x3fff)
        for (cpu, off) in [(UInt32(0x01000007), off1), (UInt32(0x0100000c), off2)] {
            h += o1BE32(cpu) + o1BE32(3)
            if is64 { h += o1BE32(0) + o1BE32(UInt32(off)) + o1BE32(0) + o1BE32(UInt32(thin.count)) + o1BE32(14) + o1BE32(0) }
            else { h += o1BE32(UInt32(off)) + o1BE32(UInt32(thin.count)) + o1BE32(14) }
        }
        var f = o1Pad(h, to: off1) + thin
        f = o1Pad(f, to: off2) + thin
        return f
    }

    static func o1Zlib(_ payload: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: payload.count + 1024)
        let n = compression_encode_buffer(&out, out.count, payload, payload.count, nil, COMPRESSION_ZLIB)
        return [0x78, 0x9c] + Array(out.prefix(n)) + [0, 0, 0, 0]
    }

    static let o1YaraFixtures: [String] = [
        #"private rule Hdr { condition: uint32be(0) == 0x41424344 }"#,
        #"rule Text { strings: $a = "hello" nocase $b = "World" wide $c = "word" fullword condition: $a and $b and $c }"#,
        #"rule Hex { strings: $h = { 41 ?? 43 [1-3] 46 ( 47 | 48 49 ) 4? } condition: $h }"#,
        #"rule HexJ { strings: $h = { 6A 40 [-] 68 00 30 [2-] 00 ( 6A | 63 [0-8] 64 ) } condition: $h at 0 or #h > 2 }"#,
        #"rule Re { strings: $r = /ab[0-9]{2,3}c/ $w = /x.z/ wide $n = /(a|b)*c+?[^\x00-\x1f]{1,40}\bq/is condition: $r or $w or $n }"#,
        #"rule Counts { strings: $a = "ab" condition: #a == 3 and @a[2] == 4 and !a[1] == 2 and #a in (0..5) == 2 }"#,
        #"rule Of { strings: $x1 = "q1" $x2 = "q2" $y = "zz" condition: 2 of ($x*) and none of ($y) and any of them }"#,
        #"rule ForIn { condition: for all i in (0..3) : ( uint8(i) == 0x41 + i ) }"#,
        #"rule ForOf { strings: $a = "ABCD" $b = "q1" condition: for any of ($a, $b) : ( $ at 0 ) }"#,
        #"rule Arith { condition: (uint16(0) | 0x0100) == 0x4341 and 7 \ 2 == 3 and 7 % 4 == 3 and -1 < 0 and 1 << 4 == 16 and int32be(filesize - 4) != 5 }"#,
        #"rule MachO { condition: macho.magic == macho.MH_MAGIC_64 and macho.ncmds > 3 and macho.number_of_segments >= 1 and macho.filetype == macho.MH_EXECUTE }"#,
        #"rule Fat { condition: macho.fat_magic == macho.FAT_MAGIC and macho.nfat_arch == 2 and macho.cputype == macho.CPU_TYPE_X86_64 }"#,
        #"rule HashRule { condition: filesize < 10MB and hash.sha256(0, filesize) != "" and hash.md5(0, 16) != "x" }"#,
        #"rule Meta : tag1 tag2 { meta: description = "o1" score = 5 ok = true strings: $s = "UPX!" condition: $s in (0..filesize) }"#,
        #"import "macho" global rule G { condition: filesize > 0 } rule Dep { condition: G and not Hdr }"#,
    ]

    static let o1YaraDict: [[UInt8]] = ["(", ")", "{", "}", "[", "]", "[-]", "[0-99999999]", "??", "~", "|", "/", "\\", "\"", "$", "#", "@", "!",
        "*", "+", "?", "{999}", "{0,1000}", "((((((((", "))))", "and ", "or ", "not ", "of ", "them", "for all i in (0..99999999) : (", "at ", "in (",
        "..", "uint32(", "int8(-1)", "filesize", "0x7fffffffffffffff", "9223372036854775807", "-9223372036854775808", " \\ 0", " % 0", " << 64",
        " >> -1", "macho.", "hash.sha256(", "wide ", "nocase ", "xor ", "base64 ", "fullword ", "private ", "global ", "rule ", "strings:",
        "condition:", "meta:", "/(a*)*b/", "/(a|aa)+$/", "\u{0}", "\u{ff}", "€", "//", "/*", "*/", "\n"].map { Array($0.utf8) }

    // MARK: suite

    static func wmsO1Checks() {
        let fm = FileManager.default
        let work = fixtureTempDir + "com.rampart.test.o1-\(getpid())-\(UUID().uuidString.prefix(8))"
        try? fm.createDirectory(atPath: work, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(atPath: work) }

        o1RegressionChecks(work: work)

        // ---- Mach-O + code signature (RampartSigning.MachOFile) ----
        let syn = o1SyntheticMachO()
        let packed = o1SyntheticMachO(packed: true)
        let fat32 = o1Fat(syn.bytes, is64: false), fat64 = o1Fat(syn.bytes, is64: true)
        var machoCorpus = [syn.bytes, packed.bytes, fat32, fat64]
        var machoHot: [[Range<Int>]] = [syn.hot, packed.hot, [0..<64] + syn.hot.map { ($0.lowerBound + 0x4000)..<($0.upperBound + 0x4000) },
                                         [0..<80] + syn.hot.map { ($0.lowerBound + 0x4000)..<($0.upperBound + 0x4000) }]
        let realTrue = o1Read("/usr/bin/true")
        if !realTrue.isEmpty, let m = try? MachOFile(data: Data(realTrue)) {
            var hot: [Range<Int>] = [0..<256]
            for s in m.slices {
                let o = Int(s.offset); hot.append(o..<(o + 4096))
                if let cs = s.codeSignatureRange { hot.append((o + Int(cs.offset))..<(o + Int(cs.offset) + min(Int(cs.size), 8192))) }
            }
            machoCorpus.append(realTrue); machoHot.append(hot)
        }
        let machoDict: [[UInt8]] = [o1BE32(0xfade0cc0), o1BE32(0xfade0c02), o1BE32(0xfade7171), o1BE32(0xcafebabe), o1LE32(0xfeedfacf),
                                     o1LE32(0x1d), o1LE32(0x19), o1LE32(0xc), Array("<plist><dict><key>a</key><array><array><array>".utf8)]
        o1Fuzz("macho", seconds: 6, corpus: machoCorpus, hot: machoHot, dict: machoDict, work: work) { b in
            if let m = try? MachOFile(data: Data(b)) {
                _ = m.allDylibs; _ = m.userWritableRpaths; _ = m.hasCodeSignature; _ = m.cpuNames
                for s in m.slices { _ = s.codeSignature?.entitlementKeys.count; _ = s.cpuName; _ = s.fileTypeName }
            }
            _ = MachOFile.looksLikeMachO(Data(b.prefix(8)))
        }

        // ---- PackedMachO (file-based, fat offsets) ----
        let packedPath = work + "/packed.bin"
        o1Fuzz("packedmacho", seconds: 4, corpus: machoCorpus, hot: machoHot, dict: machoDict, work: work) { b in
            _ = PackedMachODetector.analyzeSlice(b, sliceOffset: 0) { off, len in
                guard off < UInt64(b.count) else { return nil }
                let s = Int(off); return Data(b[s..<min(b.count, s + len)])
            }
            fm.createFile(atPath: packedPath, contents: Data(b))
            _ = PackedMachODetector.analyze(path: packedPath)
        }

        // ---- FileSniffer / ArchiveFormat (incl. zlib trial inflate and the dmg koly trailer) ----
        var kolyDMG = [UInt8](repeating: 0x11, count: 2048)
        kolyDMG += Array("koly".utf8) + [UInt8](repeating: 0, count: 508)
        let gz = o1Gzip(work: work, Array("hello o1 harmless marker\n".utf8))
        let zl = o1Zlib(Array(String(repeating: "o1 harmless zlib payload ", count: 20).utf8))
        let tarFix = o1Tar(work: work)
        let zipFix = o1Zip(work: work)
        var sniffCorpus: [[UInt8]] = []
        sniffCorpus.append(Array(syn.bytes.prefix(4096)))
        sniffCorpus.append(Array(fat32.prefix(4096)))
        sniffCorpus.append(kolyDMG)
        sniffCorpus.append(gz)
        sniffCorpus.append(zl)
        sniffCorpus.append(Array(tarFix.prefix(4096)))
        sniffCorpus.append(Array(zipFix.prefix(4096)))
        for t in ["#!/bin/sh\necho hi\n", "bplist00", "<?xml version=\"1.0\"?><plist>", "BZh9", "070701"] { sniffCorpus.append(Array(t.utf8)) }
        sniffCorpus.append([0x78, 0x9c])
        sniffCorpus.append([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])
        let sniffPath = work + "/sniff.dmg"
        o1Fuzz("sniffer", seconds: 3, corpus: sniffCorpus, work: work) { b in
            _ = FileSniffer.kind(header: Array(b.prefix(512)), path: "x.dmg")
            _ = ArchiveFormat.detect(header: Array(b.prefix(512)), path: "x.lzma")
            fm.createFile(atPath: sniffPath, contents: Data(b))
            let fd = open(sniffPath, O_RDONLY)
            if fd >= 0 {
                // Lie about the size (a file that changed between stat and read) as well as tell the truth.
                _ = FileSniffer.sniff(fd: fd, size: UInt64(b.count), path: sniffPath)
                _ = FileSniffer.sniff(fd: fd, size: UInt64(b.count) &+ 4096, path: sniffPath)
                _ = FileSniffer.sniff(fd: fd, size: 600, path: sniffPath)
                close(fd)
            }
        }

        // ---- EmbeddedPayload (regex-heavy script analysis) ----
        let scripts: [String] = [
            "#!/bin/sh\ntail -n +4 \"$0\" | base64 -D | gunzip | sh\nexit 0\n" + String(repeating: "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", count: 4) + "\n",
            "#!/bin/bash\nsed '1,/^__PAYLOAD__$/d' \"$0\" | tar xz\nexit 0\n__PAYLOAD__\n\u{1}\u{2}\u{0}\u{0}binary\u{0}\u{3}",
            "#!/usr/bin/env python3\nimport zlib,base64\nexec(zlib.decompress(base64.b64decode('eJwLycgsVgCi4pLMvHQFAD5cBjg=')))\n",
            "#!/usr/bin/env node\nconst x = Buffer.from('aGVsbG8=', 'base64').toString()\neval(x)\n",
            "#!/bin/sh\neval \"$(echo ZWNobyBoaQ== | base64 -d)\"\nbegin 644 x\n#86)C\n`\nend\n",
            "#!/bin/sh\ntail -c 2048 \"$0\" | xxd -r | perl -e 'print unpack(\"m\", <>)'\n",
        ]
        let scriptDict: [[UInt8]] = ["| sh", "| bash ", "base64 -d ", "gunzip ", "eval(", "exec(", "zlib.decompress(", "$0", "tail -n +", "tail -c ",
                                      "__PAYLOAD__\n", "exit 0\n", "begin 644 x\n", "\u{0}", String(repeating: "A", count: 200), "\n", "x = ",
                                      String(repeating: "gunzip ", count: 200), String(repeating: "zlib.decompress ", count: 100)].map { Array($0.utf8) }
        o1Fuzz("embedded", seconds: 6, corpus: scripts.map { Array($0.utf8) }, dict: scriptDict, slow: 2.5, work: work, maxSize: 1 << 20) { b in
            let d = Data(b)
            // Also claim a total size smaller than what was read (file grew between stat and read).
            for total in [UInt64(b.count), UInt64(b.count) + 100_000, UInt64(b.count / 2)] {
                _ = EmbeddedPayload.analyze(data: d, totalSize: total, cap: 1 << 20) { off, len in
                    guard off < UInt64(b.count) else { return nil }
                    let s = Int(off); return Data(b[s..<min(b.count, s + len)])
                }
            }
        }

        // ---- plists (WhereFroms xattr parser) ----
        let plistCorpus: [[UInt8]] = [
            (try? PropertyListSerialization.data(fromPropertyList: ["https://example.invalid/a", "https://example.invalid/"], format: .binary, options: 0)).map { [UInt8]($0) } ?? [],
            (try? PropertyListSerialization.data(fromPropertyList: ["https://example.invalid/a"], format: .xml, options: 0)).map { [UInt8]($0) } ?? [],
        ].filter { !$0.isEmpty }
        o1Fuzz("plist", seconds: 2, corpus: plistCorpus, dict: [Array("<array>".utf8), Array("<dict>".utf8), [0xaf], [0xdf], [0x6f]], work: work) { b in
            _ = Provenance.parseWhereFroms(Data(b))
        }

        // ---- YARA rule parser + compiler ----
        var ruleCorpus = o1YaraFixtures.map { Array($0.utf8) }
        if let g = try? String(contentsOfFile: "Rules/rampart-generic.yar", encoding: .utf8) { ruleCorpus.append(Array(g.utf8.prefix(16 << 10))) }
        let scanData = Array("ABCDhello W\0o\0r\0l\0d\0 word ab12c xyz q1 q2 UPX!".utf8) + syn.bytes.prefix(512)
        o1Fuzz("yararules", seconds: 8, corpus: ruleCorpus, dict: o1YaraDict, slow: 3.0, work: work, maxSize: 64 << 10) { b in
            let rules = YaraRules.compile([YaraSource(namespace: "fz", text: String(decoding: b, as: UTF8.self))])
            _ = rules.scan(scanData, options: YaraScanOptions(timeout: 1))
        }

        // ---- YARA scanner over mutated inputs (incl. the macho module) ----
        let fixedRules = YaraRules.compile([YaraSource(namespace: "fx", text: o1YaraFixtures.joined(separator: "\n"))])
        check(fixedRules.stats.compiled >= 10, "o1: fixture YARA rules compile (\(fixedRules.stats.compiled))")
        o1Fuzz("yarascan", seconds: 5, corpus: machoCorpus + [zipFix, tarFix, Array(scripts[0].utf8)], hot: machoHot, dict: machoDict, slow: 2.5, work: work) { b in
            _ = fixedRules.scan(b, options: YaraScanOptions(timeout: 2))
        }

        // ---- ArchiveUnpacker over mutated zip / tar / gz / zlib / xz (subprocess tools, bounded count) ----
        let xz = o1Xz(work: work)
        let unpackCorpus: [(String, [UInt8], FileKind)] = [("z.zip", zipFix, .zip), ("t.tar", tarFix, .archive), ("g.gz", gz, .archive),
                                                           ("c.zlib", zl, .archive), ("x.xz", xz, .archive)].filter { !$0.1.isEmpty }
        var lim = ArchiveLimits(); lim.timeout = 10
        let unpacker = ArchiveUnpacker(limits: lim, tempRoot: work + "/unpack")
        var ui = 0
        o1Fuzz("unpack", seconds: 8, maxIters: 400, corpus: unpackCorpus.map(\.1), slow: 20, work: work, wallClock: true) { b in
            let (name, _, kind) = unpackCorpus[ui % unpackCorpus.count]; ui += 1
            let p = work + "/in-" + name
            fm.createFile(atPath: p, contents: Data(b))
            if let c = try? unpacker.unpack(path: p, kind: kind, size: UInt64(b.count)) { c.cleanup() }
        }
    }

    static func o1Gzip(work: String, _ payload: [UInt8]) -> [UInt8] {
        let p = work + "/fx.txt"; FileManager.default.createFile(atPath: p, contents: Data(payload))
        o1Run("/usr/bin/gzip", ["-k", "-f", p]); defer { try? FileManager.default.removeItem(atPath: p + ".gz") }
        return o1Read(p + ".gz")
    }
    static func o1Tar(work: String) -> [UInt8] {
        let d = work + "/tarsrc"; try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: d + "/a.txt", contents: Data("o1 harmless\n".utf8))
        FileManager.default.createFile(atPath: d + "/b.sh", contents: Data("#!/bin/sh\necho o1\n".utf8))
        o1Run("/usr/bin/tar", ["-cf", work + "/fx.tar", "-C", d, "."])
        return o1Read(work + "/fx.tar")
    }
    static func o1Xz(work: String) -> [UInt8] {
        _ = o1Tar(work: work)
        o1Run("/usr/bin/tar", ["-cJf", work + "/fx.tar.xz", "-C", work + "/tarsrc", "."])
        return o1Read(work + "/fx.tar.xz")
    }
    static func o1Zip(work: String) -> [UInt8] {
        _ = o1Tar(work: work)
        o1Run("/usr/bin/ditto", ["-c", "-k", "--norsrc", work + "/tarsrc", work + "/fx.zip"])
        return o1Read(work + "/fx.zip")
    }

    // MARK: regressions for the findings

    static func o1RegressionChecks(work: String) {
        let fm = FileManager.default
        // F1: fat64 arch offset > Int.max trapped in PackedMachODetector (Int(UInt64)).
        var fat = o1BE32(0xcafebabf) + o1BE32(1) + o1BE32(0x0100000c) + o1BE32(0)
        let hugeOff: [UInt8] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0]
        fat += hugeOff; fat += o1BE32(0); fat += o1BE32(0x1000); fat += o1BE32(14); fat += o1BE32(0)
        fat = o1Pad(fat, to: 256)
        let p1 = work + "/f1.bin"; fm.createFile(atPath: p1, contents: Data(fat))
        check(PackedMachODetector.analyze(path: p1) == nil, "o1 F1: fat64 huge slice offset rejected without trapping")
        // F1b: __TEXT section offset near UInt64.max added to the slice offset must not trap.
        var thin = o1SyntheticMachO().bytes
        let seg = 32 // first LC_SEGMENT_64
        thin.replaceSubrange((seg + 40)..<(seg + 48), with: o1LE64(UInt64.max - 4))   // fileoff
        thin.replaceSubrange((seg + 72 + 48)..<(seg + 72 + 52), with: o1LE32(0))      // section offset 0 -> use segment
        thin.replaceSubrange((seg + 72 + 40)..<(seg + 72 + 48), with: o1LE64(0))      // section size 0
        _ = PackedMachODetector.analyzeSlice(thin, sliceOffset: UInt64.max - 2) { _, _ in nil }
        check(true, "o1 F1b: slice + segment offset overflow does not trap")

        // F2: EmbeddedPayload with totalSize smaller than the bytes read (file grew after stat) must not trap.
        let grown = Data(("#!/bin/sh\nsed '1,/^__PAYLOAD__$/d' \"$0\" | sh\nexit 0\n__PAYLOAD__\n" + String(repeating: "\u{1}\u{0}", count: 400)).utf8)
        let r2 = EmbeddedPayload.analyze(data: grown, totalSize: 20, cap: 1 << 20) { _, _ in nil }
        check(r2.payloads.allSatisfy { !$0.data.isEmpty }, "o1 F2: payload extraction with a stale (smaller) size does not trap")

        // F3: catastrophic regex backtracking on one long line of decoder words must finish quickly.
        let longLine = "#!/bin/sh\n" + String(repeating: "gunzip ", count: 140_000) + "\n"
        let t3 = o1Time { _ = EmbeddedPayload.analyze(data: Data(longLine.utf8), totalSize: UInt64(longLine.utf8.count), cap: 1 << 20) { _, _ in nil } }
        check(t3 < 3, "o1 F3: long decoder line analysed in \(String(format: "%.2f", t3))s (< 3s)")
        let twoStep = "#!/usr/bin/env python3\n" + (0..<20_000).map { _ in "x = zlib.decompress zlib.decompress zlib.decompress b64decode\n" }.joined()
        let t3b = o1Time { _ = EmbeddedPayload.analyze(data: Data(twoStep.utf8), totalSize: UInt64(twoStep.utf8.count), cap: 1 << 20) { _, _ in nil } }
        check(t3b < 3, "o1 F3b: many decode/assign lines analysed in \(String(format: "%.2f", t3b))s (< 3s)")
        // Detection still works after the bound.
        let real = "#!/bin/sh\ntail -n +3 \"$0\" | base64 -D | gunzip | sh\n"
        let r3 = EmbeddedPayload.analyze(data: Data(real.utf8), totalSize: UInt64(real.utf8.count), cap: 1 << 20) { _, _ in nil }
        check(r3.evidence.contains { $0.title == EmbeddedPayload.decodeRunTitle }, "o1 F3: decode|run pattern still detected")

        // F4: deeply nested YARA conditions / hex / regex must not overflow the stack (run on a 512 KB thread).
        var ok4 = false
        let th = Thread {
            let deep = String(repeating: "(", count: 50_000) + "true" + String(repeating: ")", count: 50_000)
            let nots = String(repeating: "not ", count: 50_000) + "true"
            let neg = String(repeating: "-", count: 50_000) + "1 == 1"
            let hex = "{ " + String(repeating: "( 41 | ", count: 20_000) + "42" + String(repeating: " )", count: 20_000) + " }"
            let rx = "/" + String(repeating: "(", count: 50_000) + "a" + String(repeating: ")", count: 50_000) + "/"
            let src = """
            rule D1 { condition: \(deep) }
            rule D2 { condition: \(nots) }
            rule D5 { condition: \(neg) }
            rule D3 { strings: $h = \(hex) condition: $h }
            rule D4 { strings: $r = \(rx) condition: $r }
            rule Ok { condition: true }
            """
            let rules = YaraRules.compile([YaraSource(namespace: "deep", text: src)])
            ok4 = rules.scan(Array("ab".utf8)).matches.contains { $0.rule == "Ok" }
        }
        th.stackSize = 512 << 10
        let done = DispatchSemaphore(value: 0)
        let th2 = Thread { th.start(); while !th.isFinished { usleep(10_000) }; done.signal() }
        th2.start()
        check(done.wait(timeout: .now() + 20) == .success && ok4, "o1 F4: deeply nested YARA rules rejected without stack overflow")

        // F5: a file truncated while the YARA scanner reads it must not SIGBUS (mmap) the scanner.
        let p5 = work + "/f5.bin"
        fm.createFile(atPath: p5, contents: Data([UInt8](repeating: 0x41, count: 8 << 20)))
        let rules5 = YaraRules.compile([YaraSource(namespace: "t", text: #"rule T { strings: $a = "ZZZZ" condition: $a or uint8(filesize - 1) == 0x41 }"#)])
        let stop = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            for i in 0..<40 { truncate(p5, i % 2 == 0 ? 4096 : off_t(8 << 20)); usleep(1000) }
            stop.signal()
        }
        for _ in 0..<40 { _ = rules5.scanFile(atPath: p5) }
        stop.wait()
        check(true, "o1 F5: YARA scan of a file being truncated did not crash")
        // MachOFile(path:) on a file truncated after open must not SIGBUS either.
        let p5b = work + "/f5.macho"
        let big = o1Fat(o1SyntheticMachO().bytes, is64: false) + [UInt8](repeating: 0, count: 4 << 20)
        fm.createFile(atPath: p5b, contents: Data(big))
        let stop2 = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            for i in 0..<60 { truncate(p5b, i % 2 == 0 ? 0x5000 : off_t(big.count)); usleep(500) }
            stop2.signal()
        }
        for _ in 0..<60 { _ = try? MachOFile(path: p5b) }
        stop2.wait()
        check(true, "o1 F5b: MachOFile(path:) on a file being truncated did not crash")

        // F6: in-process xz/zlib inflate streams to disk under the cap (no multi-GB in-memory buffer).
        let zeros = [UInt8](repeating: 0, count: 8 << 20)
        let bomb = o1Zlib(zeros)
        let p6 = work + "/f6.zlib"; fm.createFile(atPath: p6, contents: Data(bomb))
        var lim = ArchiveLimits(); lim.maxExpandedBytes = 1 << 20; lim.maxRatio = 2
        do {
            let c = try ArchiveUnpacker(limits: lim, tempRoot: work + "/u6").unpack(path: p6, kind: .archive, size: UInt64(bomb.count))
            c.cleanup(); check(false, "o1 F6: zlib bomb refused")
        } catch let e as ContainerUnreadable { check(e.reason == .bomb, "o1 F6: zlib bomb refused as bomb (\(e.reason))") }
        catch { check(false, "o1 F6: zlib bomb refused (\(error))") }
        let okZ = o1Zlib(Array(String(repeating: "o1 zlib ok ", count: 500).utf8))
        let p6b = work + "/f6ok.zlib"; fm.createFile(atPath: p6b, contents: Data(okZ))
        if let c = try? ArchiveUnpacker(tempRoot: work + "/u6").unpack(path: p6b, kind: .archive, size: UInt64(okZ.count)) {
            let files = (try? fm.subpathsOfDirectory(atPath: c.root)) ?? []
            let sz = files.compactMap { try? fm.attributesOfItem(atPath: c.root + "/" + $0)[.size] as? UInt64 }.reduce(0, +)
            check(sz == 5500, "o1 F6: zlib stream still inflates fully (\(sz) B)")
            c.cleanup()
        } else { check(false, "o1 F6: zlib stream still inflates") }
        // Truncated / stalled stream must terminate.
        let p6c = work + "/f6bad.zlib"; fm.createFile(atPath: p6c, contents: Data(okZ.prefix(40)))
        let t6 = o1Time { _ = try? ArchiveUnpacker(tempRoot: work + "/u6").unpack(path: p6c, kind: .archive, size: 40) }
        check(t6 < 5, "o1 F6: truncated zlib stream terminates")

        // F8: deeply nested plists (Mach-O entitlements blob, kMDItemWhereFroms xattr) parsed on a 512 KB-stack
        // worker thread must not overflow the stack.
        var ok8 = false
        let t8 = Thread {
            let depth = 30_000
            let xml = Array(("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>k</key>" + String(repeating: "<array>", count: depth)
                             + String(repeating: "</array>", count: depth) + "</dict></plist>").utf8)
            _ = Provenance.parseWhereFroms(Data(xml))
            // Binary plist: object i is a one-element array holding object i+1.
            let n = 20_000
            var objs: [UInt8] = [], offsets: [Int] = []
            for i in 0..<n {
                offsets.append(8 + objs.count)
                if i == n - 1 { objs.append(0x09) } else { objs.append(0xA1); objs += o1BE32(UInt32(i + 1)) }
            }
            // Use 4-byte object refs.
            var bp = Array("bplist00".utf8) + objs
            let offTable = bp.count
            for o in offsets { bp += o1BE32(UInt32(o)) }
            let trailerHead: [UInt8] = [0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 0, 0]
            let zero8: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0], zero4: [UInt8] = [0, 0, 0, 0]
            bp += trailerHead; bp += o1BE32(UInt32(n)); bp += zero8; bp += zero4; bp += o1BE32(UInt32(offTable))
            _ = Provenance.parseWhereFroms(Data(bp))
            // Same XML inside a Mach-O entitlements blob.
            var m = o1SyntheticMachO()
            let ent = Array(String(repeating: "<array>", count: 20_000).utf8)
            if let r = m.bytes.indices.first(where: { m.bytes[$0] == 0xfa && m.bytes[$0 + 1] == 0xde && m.bytes[$0 + 2] == 0x71 && m.bytes[$0 + 3] == 0x71 }) {
                let len = Int(m.bytes[r + 6]) << 8 | Int(m.bytes[r + 7])
                var blob = o1BE32(0xfade7171) + o1BE32(UInt32(ent.count + 8)) + ent
                blob = Array(blob.prefix(max(len, 8)))   // keep the layout: overwrite in place, same length
                blob.replaceSubrange(4..<8, with: o1BE32(UInt32(blob.count)))
                m.bytes.replaceSubrange(r..<(r + blob.count), with: blob)
                _ = try? MachOFile(data: Data(m.bytes))
            }
            ok8 = true
        }
        t8.stackSize = 512 << 10
        t8.start()
        let wait8 = Date()
        while !t8.isFinished && Date().timeIntervalSince(wait8) < 20 { usleep(20_000) }
        check(ok8, "o1 F8: deeply nested plists parsed on a 512 KB stack without overflow")

        // F10: integer-overflow traps in the YARA rule compiler and evaluator (found by the long fuzz run).
        let trapRules = """
        rule T1 { strings: $h = { 6A 40 [-9223372036854775808( 6A | 63 [0-8] 64 ) } condition: $h }
        rule T2 { strings: $h = { 41 [99999999999999999999999-] 42 } condition: $h or true }
        rule T3 { condition: (-9223372036854775807 - 1) \\ -1 == 0 or true }
        rule T4 { condition: (-9223372036854775807 - 1) % -1 == 0 or true }
        rule T5 { condition: for any i in (-9223372036854775807 .. 9223372036854775807) : ( i == 1 ) or true }
        rule T6 { strings: $a = "ab" condition: 9223372036854775807% of them or true }
        rule T7 { condition: hash.md5(9223372036854775807, 9223372036854775807) == "" or true }
        rule TOk { condition: true }
        """
        let tr = YaraRules.compile([YaraSource(namespace: "trap", text: trapRules)])
        let tm = tr.scan(Array("ab ab ab".utf8)).matches.map(\.rule)
        // Reaching here is the real check (each case used to trap). Out-of-range hash() is undefined, so T7 is false.
        check(tm.contains("TOk") && ["T3", "T4", "T5", "T6"].allSatisfy(tm.contains), "o1 F10: overflowing YARA numbers/arithmetic evaluate without trapping (\(tm))")

        // F4 coverage: the depth limits must not skip any real rule (XProtect, read-only, and the bundled rules).
        var realSources: [YaraSource] = []
        if let x = try? String(contentsOfFile: "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara", encoding: .utf8) {
            realSources.append(YaraSource(namespace: "xprotect", text: x))
        }
        if let g = try? String(contentsOfFile: "Rules/rampart-generic.yar", encoding: .utf8) { realSources.append(YaraSource(namespace: "generic", text: g)) }
        if !realSources.isEmpty {
            let real = YaraRules.compile(realSources)
            let deep = real.stats.sources.flatMap { $0.skippedReasons.values }.filter { $0.contains("too deeply") }
            check(deep.isEmpty, "o1 F4: no real rule skipped by the nesting limits (\(deep.count))")
            print("  real rules: \(real.stats.compiled) compiled, \(real.stats.skipped) skipped")
        }

        // F7: zip listing output is bounded (a zip with many members can't make `unzip -Z` output exhaust memory).
        check(ArchiveUnpacker.zipListingCap(maxFiles: 50_000) <= 64 << 20, "o1 F7: zip listing output capped")
    }
}

import Foundation

/// Minimal native Mach-O header reader backing the supported subset of YARA's `macho` module.
/// Fields: magic, cputype, cpusubtype, filetype, ncmds (number_of_load_commands), sizeofcmds, flags,
/// number_of_segments, fat_magic, nfat_arch. For fat files the first slice is described.
struct MachOInfo {
    var values: [String: Int64] = [:]

    static let fields: Set<String> = ["magic", "cputype", "cpusubtype", "filetype", "ncmds", "number_of_load_commands",
                                      "sizeofcmds", "flags", "number_of_segments", "fat_magic", "nfat_arch"]

    static let constants: [String: Int64] = [
        "MH_MAGIC": 0xfeedface, "MH_CIGAM": 0xcefaedfe, "MH_MAGIC_64": 0xfeedfacf, "MH_CIGAM_64": 0xcffaedfe,
        "FAT_MAGIC": 0xcafebabe, "FAT_CIGAM": 0xbebafeca, "FAT_MAGIC_64": 0xcafebabf, "FAT_CIGAM_64": 0xbfbafeca,
        "CPU_TYPE_X86": 7, "CPU_TYPE_I386": 7, "CPU_TYPE_X86_64": 0x01000007, "CPU_TYPE_ARM": 12,
        "CPU_TYPE_ARM64": 0x0100000c, "CPU_TYPE_POWERPC": 18, "CPU_TYPE_POWERPC64": 0x01000012,
        "MH_OBJECT": 1, "MH_EXECUTE": 2, "MH_FVMLIB": 3, "MH_CORE": 4, "MH_PRELOAD": 5, "MH_DYLIB": 6,
        "MH_DYLINKER": 7, "MH_BUNDLE": 8, "MH_DYLIB_STUB": 9, "MH_DSYM": 10, "MH_KEXT_BUNDLE": 11,
        "MH_NOUNDEFS": 0x1, "MH_DYLDLINK": 0x4, "MH_TWOLEVEL": 0x80, "MH_PIE": 0x200000,
        "MH_ALLOW_STACK_EXECUTION": 0x20000, "MH_NO_HEAP_EXECUTION": 0x1000000,
    ]

    static func parse(_ d: UnsafeBufferPointer<UInt8>) -> MachOInfo? {
        func u32(_ o: Int, big: Bool) -> UInt32? {
            guard o >= 0, o + 4 <= d.count else { return nil }
            let v = UInt32(d[o]) | UInt32(d[o + 1]) << 8 | UInt32(d[o + 2]) << 16 | UInt32(d[o + 3]) << 24
            return big ? v.byteSwapped : v
        }
        guard let be = u32(0, big: true) else { return nil }
        var info = MachOInfo()
        var base = 0
        if be == 0xcafebabe || be == 0xcafebabf {
            guard let n = u32(4, big: true), n > 0, n < 64 else { return nil }
            info.values["fat_magic"] = Int64(be)
            info.values["nfat_arch"] = Int64(n)
            let is64 = be == 0xcafebabf
            let off: UInt32?
            if is64 { off = u32(8 + 12, big: true) } else { off = u32(8 + 8, big: true) }
            guard let o = off else { return info }
            base = Int(o)
        }
        guard let magic = u32(base, big: false) else { return info.values.isEmpty ? nil : info }
        let swapped: Bool
        let is64: Bool
        switch magic {
        case 0xfeedface: swapped = false; is64 = false
        case 0xfeedfacf: swapped = false; is64 = true
        case 0xcefaedfe: swapped = true; is64 = false
        case 0xcffaedfe: swapped = true; is64 = true
        default: return info.values.isEmpty ? nil : info
        }
        func f(_ o: Int) -> Int64? { u32(base + o, big: swapped).map { Int64($0) } }
        info.values["magic"] = Int64(magic)
        info.values["cputype"] = f(4)
        info.values["cpusubtype"] = f(8)
        info.values["filetype"] = f(12)
        let ncmds = f(16) ?? 0
        info.values["ncmds"] = ncmds
        info.values["number_of_load_commands"] = ncmds
        info.values["sizeofcmds"] = f(20)
        info.values["flags"] = f(24)
        var p = base + (is64 ? 32 : 28)
        var segs: Int64 = 0
        for _ in 0..<min(ncmds, 4096) {
            guard let cmd = u32(p, big: swapped), let size = u32(p + 4, big: swapped), size >= 8 else { break }
            if cmd == 0x1 || cmd == 0x19 { segs += 1 }   // LC_SEGMENT / LC_SEGMENT_64
            p += Int(size)
        }
        info.values["number_of_segments"] = segs
        return info
    }
}

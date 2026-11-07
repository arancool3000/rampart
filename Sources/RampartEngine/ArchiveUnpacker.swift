import Foundation
import Compression
import RampartShared

/// Resource limits for archive/disk-image/package expansion.
public struct ArchiveLimits: Sendable {
    /// Maximum nesting depth (archive inside archive ...). 0 disables unpacking.
    public var maxDepth: Int = 3
    /// Skip containers larger than this on disk.
    public var maxContainerSize: UInt64 = 2 << 30
    /// Maximum declared/observed expanded size per container.
    public var maxExpandedBytes: UInt64 = 4 << 30
    /// Maximum number of member files per container.
    public var maxFiles: Int = 50_000
    /// Maximum expansion ratio (expanded / compressed) for zips, to stop zip bombs before extraction.
    public var maxRatio: Double = 250
    /// Wall-clock limit for each helper tool invocation.
    public var timeout: TimeInterval = 120
    public init() {}
}

/// An expanded container. Call `cleanup()` (idempotent) to delete temp files / detach images.
public final class UnpackedContainer: @unchecked Sendable {
    /// Directory to walk.
    public let root: String
    /// Detected container format.
    public internal(set) var format: ArchiveFormat = .unknown
    private let tempDir: String?
    private let mountPoint: String?
    private var done = false
    private let lock = NSLock()

    init(root: String, tempDir: String?, mountPoint: String?) {
        self.root = root; self.tempDir = tempDir; self.mountPoint = mountPoint
    }

    public func cleanup() {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        if let mountPoint {
            if (try? Subprocess.run("/usr/bin/hdiutil", ["detach", mountPoint, "-quiet"], timeout: 30))?.status != 0 {
                _ = try? Subprocess.run("/usr/bin/hdiutil", ["detach", mountPoint, "-force", "-quiet"], timeout: 30)
            }
        }
        if let tempDir { try? FileManager.default.removeItem(atPath: tempDir) }
    }

    deinit { cleanup() }
}

/// Container formats recognised by magic bytes (never by extension, except raw `.dmg`/`.lzma` that have no reliable magic).
public enum ArchiveFormat: String, Sendable, CaseIterable {
    case zip, tar, gzip, bzip2, xz, zstd, lzma, lz4, sevenZip = "7z", rar, cpio, xar, compressZ = "Z", zlib,
         appleArchive = "aa", dmg, pkg, unknown

    /// Single compressed streams (one payload, no member list).
    public var isStream: Bool { [.gzip, .bzip2, .xz, .zstd, .lzma, .lz4, .compressZ, .zlib].contains(self) }

    public var displayName: String {
        switch self {
        case .zip: return "zip archive"
        case .tar: return "tar archive"
        case .gzip: return "gzip stream"
        case .bzip2: return "bzip2 stream"
        case .xz: return "xz stream"
        case .zstd: return "zstd stream"
        case .lzma: return "lzma stream"
        case .lz4: return "lz4 stream"
        case .sevenZip: return "7-Zip archive"
        case .rar: return "RAR archive"
        case .cpio: return "cpio archive"
        case .xar: return "xar archive"
        case .compressZ: return "Unix compress (.Z) stream"
        case .zlib: return "zlib stream"
        case .appleArchive: return "Apple Archive"
        case .dmg: return "disk image"
        case .pkg: return "installer package"
        case .unknown: return "container"
        }
    }

    /// Classifies a header (first ≥ 512 bytes).
    public static func detect(header h: [UInt8], path: String = "") -> ArchiveFormat {
        func starts(_ s: [UInt8], at o: Int = 0) -> Bool { h.count >= o + s.count && Array(h[o..<o + s.count]) == s }
        func ascii(_ s: String, at o: Int = 0) -> Bool { starts(Array(s.utf8), at: o) }
        if starts([0x50, 0x4B, 0x03, 0x04]) || starts([0x50, 0x4B, 0x05, 0x06]) || starts([0x50, 0x4B, 0x07, 0x08]) { return .zip }
        if ascii("xar!") { return path.lowercased().hasSuffix(".pkg") || path.lowercased().hasSuffix(".mpkg") ? .pkg : .xar }
        if ascii("ustar", at: 257) { return .tar }
        if starts([0x1F, 0x8B]) { return .gzip }
        if starts([0x1F, 0x9D]) { return .compressZ }
        if ascii("BZh") && h.count > 3 && (0x31...0x39).contains(h[3]) { return .bzip2 }
        if starts([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) { return .xz }
        if starts([0x28, 0xB5, 0x2F, 0xFD]) { return .zstd }
        if starts([0x04, 0x22, 0x4D, 0x18]) { return .lz4 }
        if starts([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) { return .sevenZip }
        if ascii("Rar!\u{1A}\u{07}") { return .rar }
        if ascii("070707") || ascii("070701") || ascii("070702") || starts([0xC7, 0x71]) || starts([0x71, 0xC7]) { return .cpio }
        if ascii("AA01") || ascii("YAA1") { return .appleArchive }
        if h.count >= 4 && ascii("pbz") && [UInt8(ascii: "e"), UInt8(ascii: "x"), UInt8(ascii: "4"), UInt8(ascii: "z"), UInt8(ascii: "b")].contains(h[3]) {
            return .appleArchive
        }
        if isZlibHeader(h) { return .zlib }
        let lower = path.lowercased()
        if h.count >= 13 && h[0] == 0x5D && h[1] == 0x00 && h[2] == 0x00 && lower.hasSuffix(".lzma") { return .lzma }
        if lower.hasSuffix(".dmg") { return .dmg }
        return .unknown
    }

    /// zlib (RFC 1950) header: CM=8, valid FCHECK, no preset dictionary, and the start of the stream inflates.
    /// The 2-byte magic is weak, so a trial inflate of the header bytes is required.
    static func isZlibHeader(_ h: [UInt8]) -> Bool {
        guard h.count >= 16, h[0] == 0x78, [0x01, 0x5E, 0x9C, 0xDA].contains(h[1]),
              (UInt16(h[0]) << 8 | UInt16(h[1])) % 31 == 0, h[1] & 0x20 == 0 else { return false }
        let out = StreamInflater.inflate(Array(h[2...]), algorithm: COMPRESSION_ZLIB, limit: 4096, allowTruncated: true)
        return (out?.count ?? 0) >= 8
    }
}

/// Why a container could not be (fully) looked into.
public struct ContainerUnreadable: Error, CustomStringConvertible, Sendable {
    public enum Reason: String, Sendable {
        case encrypted, tooLarge, bomb, tooManyFiles, tooDeep, corrupt, unsupported, timedOut
    }
    public var reason: Reason
    public var format: ArchiveFormat
    public var detail: String
    /// Member names we could still list (e.g. an encrypted zip's central directory). Capped.
    public var memberNames: [String] = []
    public var description: String { "\(format.displayName) \(reason.rawValue): \(detail)" }
    public init(reason: Reason, format: ArchiveFormat, detail: String, memberNames: [String] = []) {
        self.reason = reason; self.format = format; self.detail = detail; self.memberNames = memberNames
    }
}

/// Expands archives, compressed streams, DMGs and flat PKGs into a private temp directory using only
/// Apple-shipped tools (`ditto`, `bsdtar`, `gzip`, `bzip2`, `aa`, `pkgutil`, `hdiutil`) and Apple's
/// Compression framework (xz, zlib). Every path is bounded by `ArchiveLimits`; nothing touches the network.
public struct ArchiveUnpacker: Sendable {
    public var limits: ArchiveLimits
    /// Parent for temp extraction directories.
    public var tempRoot: String

    public init(limits: ArchiveLimits = ArchiveLimits(),
                tempRoot: String = ArchiveUnpacker.defaultTempRoot) {
        self.limits = limits; self.tempRoot = tempRoot
    }

    /// Per-user Darwin temp dir (`/private/var/folders/…/T/`, from confstr, ignoring `$TMPDIR`) + "rampart-unpack".
    /// Unpacked members never land in watched or shared folders such as /private/tmp, so real-time protection
    /// (which skips /private/var/folders) doesn't re-detect what a scan is in the middle of checking.
    public static var defaultTempRoot: String { darwinUserTempDir + "rampart-unpack" }

    public static var darwinUserTempDir: String {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        let n = confstr(_CS_DARWIN_USER_TEMP_DIR, &buf, buf.count)
        if n > 0 && n <= buf.count {
            let s = String(cString: buf)
            if s.hasPrefix("/") { return s.hasSuffix("/") ? s : s + "/" }
        }
        let t = NSTemporaryDirectory()
        return t.hasSuffix("/") ? t : t + "/"
    }

    /// File kinds this unpacker can expand.
    public static func canUnpack(_ kind: FileKind) -> Bool {
        [.zip, .archive, .dmg, .pkg].contains(kind)
    }

    /// Passphrase handed to bsdtar so it never prompts on a tty for encrypted 7z/rar/zip members.
    static let noPassphrase = "rampart-no-passphrase"

    /// Expands `path`. Throws `ContainerUnreadable` when the content can't be looked into (encrypted, over a
    /// limit, corrupt, unsupported compression), or `EngineError` for an unsupported kind.
    public func unpack(path: String, kind: FileKind, size: UInt64) throws -> UnpackedContainer {
        guard Self.canUnpack(kind) else { throw EngineError.unpackFailed("unsupported kind \(kind.rawValue)") }
        let header = Self.readHeader(path)
        var format = ArchiveFormat.detect(header: header, path: path)
        if kind == .dmg { format = .dmg }
        if kind == .pkg && format == .xar && path.lowercased().hasSuffix(".pkg") { format = .pkg }
        if kind == .pkg && format == .unknown { format = .pkg }
        guard size <= limits.maxContainerSize else {
            throw ContainerUnreadable(reason: .tooLarge, format: format,
                                      detail: "\(Self.mb(size)) on disk, over the \(Self.mb(limits.maxContainerSize)) unpack limit")
        }
        try FileManager.default.createDirectory(atPath: tempRoot, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let dir = (tempRoot as NSString).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        let out = (dir as NSString).appendingPathComponent("x")
        do {
            let c: UnpackedContainer
            // A compressed tar (.tar.gz, .tbz, .txz, .tar.Z): bsdtar reads it in one step (one nesting level, not two).
            let compressedTar = [ArchiveFormat.gzip, .bzip2, .xz, .compressZ, .lzma].contains(format) && (try? tarListing(path))?.isTar == true
            switch format {
            case _ where compressedTar:
                try bsdtarExtract(path, format: format, size: size, to: out)
                c = UnpackedContainer(root: out, tempDir: dir, mountPoint: nil)
            case .zip:
                try unzip(path, size: size, to: out)
                c = UnpackedContainer(root: out, tempDir: dir, mountPoint: nil)
            case .tar, .sevenZip, .rar, .cpio, .xar:
                try bsdtarExtract(path, format: format, size: size, to: out)
                c = UnpackedContainer(root: out, tempDir: dir, mountPoint: nil)
            case .gzip, .bzip2, .xz, .compressZ, .zlib, .lzma:
                try FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: false)
                try decompressStream(path, format: format, size: size, to: (out as NSString).appendingPathComponent(Self.streamMemberName(path)))
                c = UnpackedContainer(root: out, tempDir: dir, mountPoint: nil)
            case .zstd, .lz4:
                throw ContainerUnreadable(reason: .unsupported, format: format,
                                          detail: "macOS ships no \(format.rawValue) decompressor RamPart may use")
            case .appleArchive:
                try appleArchiveExtract(path, size: size, to: out)
                c = UnpackedContainer(root: out, tempDir: dir, mountPoint: nil)
            case .pkg:
                do {
                    try runChecked("/usr/sbin/pkgutil", ["--expand-full", path, out], format: .pkg)
                } catch {
                    // Not a flat installer package (e.g. a .xip or a plain xar): fall back to bsdtar.
                    try? FileManager.default.removeItem(atPath: out)
                    try bsdtarExtract(path, format: .xar, size: size, to: out)
                }
                c = UnpackedContainer(root: out, tempDir: dir, mountPoint: nil)
            case .dmg:
                // An encrypted image would make hdiutil ask for a password (a dialog). Never attach those.
                if let r = try? Subprocess.run("/usr/bin/hdiutil", ["isencrypted", path], timeout: 30),
                   String(decoding: r.stdout + r.stderr, as: UTF8.self).contains("encrypted: YES") {
                    throw ContainerUnreadable(reason: .encrypted, format: .dmg, detail: "password-protected disk image")
                }
                let mnt = (dir as NSString).appendingPathComponent("mnt")
                try FileManager.default.createDirectory(atPath: mnt, withIntermediateDirectories: false)
                let r = try Subprocess.run("/usr/bin/hdiutil",
                    ["attach", "-nobrowse", "-readonly", "-noautoopen", "-noverify", "-noautofsck",
                     "-mountpoint", mnt, "-plist", path], timeout: limits.timeout)
                guard r.status == 0 else {
                    throw ContainerUnreadable(reason: .corrupt, format: .dmg,
                                              detail: "hdiutil: \(String(decoding: r.stderr, as: UTF8.self).prefix(160))")
                }
                c = UnpackedContainer(root: mnt, tempDir: dir, mountPoint: mnt)
            case .unknown:
                // The sniffer said "archive" but no format matched (truncated header, unknown compression).
                throw ContainerUnreadable(reason: .unsupported, format: .unknown, detail: "unrecognised compression or archive format")
            }
            c.format = format
            return c
        } catch let e as EngineError {
            try? FileManager.default.removeItem(atPath: dir)
            if case .subprocessTimeout = e { throw ContainerUnreadable(reason: .timedOut, format: format, detail: "unpacking took too long") }
            throw ContainerUnreadable(reason: .corrupt, format: format, detail: e.description)
        } catch {
            try? FileManager.default.removeItem(atPath: dir)
            throw error
        }
    }

    // MARK: zip

    private func unzip(_ path: String, size: UInt64, to out: String) throws {
        let listing = zipListing(path)
        if let totals = listing.totals {
            if totals.files > limits.maxFiles {
                throw ContainerUnreadable(reason: .tooManyFiles, format: .zip, detail: "\(totals.files) members", memberNames: listing.names)
            }
            if totals.bytes > limits.maxExpandedBytes {
                throw ContainerUnreadable(reason: .bomb, format: .zip, detail: "declares \(Self.mb(totals.bytes)) expanded", memberNames: listing.names)
            }
            if size > 0 && Double(totals.bytes) / Double(size) > limits.maxRatio && totals.bytes > 64 << 20 {
                throw ContainerUnreadable(reason: .bomb, format: .zip,
                                          detail: "compression ratio \(Int(Double(totals.bytes) / Double(size))):1", memberNames: listing.names)
            }
        }
        if listing.encrypted {
            throw ContainerUnreadable(reason: .encrypted, format: .zip, detail: "password-protected members", memberNames: listing.names)
        }
        do {
            try runChecked("/usr/bin/ditto", ["-x", "-k", "--noqtn", path, out], format: .zip)
        } catch var e as ContainerUnreadable {
            if e.detail.lowercased().contains("password") || e.detail.contains("encryption") { e.reason = .encrypted }
            e.memberNames = listing.names
            throw e
        }
    }

    struct ZipListing { var totals: (files: Int, bytes: UInt64)?; var encrypted = false; var names: [String] = [] }

    /// `unzip -Z` (zipinfo) listing: totals, encryption (uppercase T/B in the 5th column) and member names.
    func zipListing(_ path: String) -> ZipListing {
        guard let r = try? Subprocess.run("/usr/bin/unzip", ["-Z", path], timeout: 30) else { return ZipListing() }
        return Self.parseZipInfo(String(decoding: r.stdout.prefix(4 << 20), as: UTF8.self))
    }

    static func parseZipInfo(_ s: String) -> ZipListing {
        var l = ZipListing()
        for line in s.split(separator: "\n") {
            let f = line.split(separator: " ", maxSplits: 8, omittingEmptySubsequences: true)
            if f.count >= 9, f[0].count == 10, f[4].count == 2, let c = f[4].first {
                if c == "T" || c == "B" { l.encrypted = true }
                if l.names.count < 500 { l.names.append(String(f[8])) }
            } else if let t = parseZipTotals(String(line)) { l.totals = t }
        }
        return l
    }

    /// Reads the zip central directory totals via `unzip -Zt` ("N files, B bytes uncompressed, ...").
    func zipDeclaredSize(_ path: String) -> (files: Int, bytes: UInt64)? {
        guard let r = try? Subprocess.run("/usr/bin/unzip", ["-Zt", path], timeout: 30), r.status == 0 else { return nil }
        return Self.parseZipTotals(String(decoding: r.stdout, as: UTF8.self))
    }

    static func parseZipTotals(_ s: String) -> (files: Int, bytes: UInt64)? {
        let parts = s.split(whereSeparator: { $0 == " " || $0 == "," || $0 == "\n" })
        guard parts.count >= 4, let files = Int(parts[0]), parts[1].hasPrefix("file"),
              let bytes = UInt64(parts[2]), parts[3] == "bytes" else { return nil }
        return (files, bytes)
    }

    // MARK: bsdtar (tar, 7z, rar, cpio, xar)

    struct TarListing { var result: BoundedProcess.Result; var parsed: (files: Int, bytes: UInt64, names: [String])
        /// bsdtar recognised an archive (not just a compressed blob of something else).
        var isTar: Bool { (result.status == 0 && parsed.files > 0) || result.truncated } }

    /// `tar -tv` with bounded output (bsdtar auto-detects compression and format).
    func tarListing(_ path: String) throws -> TarListing {
        let maxListing = min(64 << 20, max(1 << 20, limits.maxFiles * 400))
        let list = try BoundedProcess.run("/usr/bin/tar", ["-t", "-v", "--passphrase", Self.noPassphrase, "-f", path],
                                          maxStdout: maxListing, timeout: limits.timeout)
        return TarListing(result: list, parsed: Self.parseTarListing(String(decoding: list.stdout, as: UTF8.self)))
    }

    private func bsdtarExtract(_ path: String, format: ArchiveFormat, size: UInt64, to out: String) throws {
        // List first (bounded output) so bombs and member counts are refused before anything is written.
        let l = try tarListing(path)
        let list = l.result, parsed = l.parsed
        let err = String(decoding: list.stderr.prefix(400), as: UTF8.self)
        if list.truncated || parsed.files > limits.maxFiles {
            throw ContainerUnreadable(reason: .tooManyFiles, format: format, detail: "more than \(limits.maxFiles) members", memberNames: parsed.names)
        }
        if parsed.bytes > limits.maxExpandedBytes || (size > 0 && parsed.bytes > 64 << 20 && Double(parsed.bytes) / Double(size) > limits.maxRatio) {
            throw ContainerUnreadable(reason: .bomb, format: format, detail: "declares \(Self.mb(parsed.bytes)) expanded", memberNames: parsed.names)
        }
        if list.status != 0 {
            let reason: ContainerUnreadable.Reason = Self.mentionsEncryption(err) ? .encrypted : .corrupt
            throw ContainerUnreadable(reason: reason, format: format, detail: "tar: \(err.prefix(160))", memberNames: parsed.names)
        }
        try FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: false)
        // bsdtar refuses absolute paths and ".." by default; -o / --no-same-permissions keep it unprivileged.
        let r = try Subprocess.run("/usr/bin/tar", ["-x", "-o", "--no-same-permissions", "--passphrase", Self.noPassphrase,
                                                    "-f", path, "-C", out], timeout: limits.timeout)
        if r.status != 0 {
            let e = String(decoding: r.stderr.prefix(400), as: UTF8.self)
            throw ContainerUnreadable(reason: Self.mentionsEncryption(e) ? .encrypted : .corrupt, format: format,
                                      detail: "tar: \(e.prefix(160))", memberNames: parsed.names)
        }
    }

    static func mentionsEncryption(_ s: String) -> Bool {
        let l = s.lowercased()
        return l.contains("encrypt") || l.contains("passphrase") || l.contains("password")
    }

    /// Parses `tar -tv` (ls -l style) output: member count, summed sizes, names.
    static func parseTarListing(_ s: String) -> (files: Int, bytes: UInt64, names: [String]) {
        var files = 0, bytes: UInt64 = 0, names: [String] = []
        for line in s.split(separator: "\n") {
            let f = line.split(separator: " ", maxSplits: 8, omittingEmptySubsequences: true)
            guard f.count >= 9 else { continue }
            files += 1
            if let n = UInt64(f[4]) { bytes &+= n }
            if names.count < 500 { names.append(String(f[8])) }
        }
        return (files, bytes, names)
    }

    // MARK: Apple Archive

    private func appleArchiveExtract(_ path: String, size: UInt64, to out: String) throws {
        let aa = "/usr/bin/aa"
        guard FileManager.default.isExecutableFile(atPath: aa) else {
            throw ContainerUnreadable(reason: .unsupported, format: .appleArchive, detail: "aa tool not available")
        }
        let list = try BoundedProcess.run(aa, ["list", "-i", path], maxStdout: min(64 << 20, limits.maxFiles * 400), timeout: limits.timeout)
        let names = String(decoding: list.stdout, as: UTF8.self).split(separator: "\n").prefix(500).map(String.init)
        let count = String(decoding: list.stdout, as: UTF8.self).split(separator: "\n").count
        if list.truncated || count > limits.maxFiles {
            throw ContainerUnreadable(reason: .tooManyFiles, format: .appleArchive, detail: "more than \(limits.maxFiles) members", memberNames: names)
        }
        if list.status != 0 {
            throw ContainerUnreadable(reason: .corrupt, format: .appleArchive,
                                      detail: "aa: \(String(decoding: list.stderr.prefix(160), as: UTF8.self))", memberNames: names)
        }
        try FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: false)
        let r = try Subprocess.run(aa, ["extract", "-i", path, "-d", out], timeout: limits.timeout)
        guard r.status == 0 else {
            throw ContainerUnreadable(reason: .corrupt, format: .appleArchive,
                                      detail: "aa: \(String(decoding: r.stderr.prefix(160), as: UTF8.self))", memberNames: names)
        }
        if Self.treeBytes(out, cap: limits.maxExpandedBytes) > limits.maxExpandedBytes {
            throw ContainerUnreadable(reason: .bomb, format: .appleArchive, detail: "expands past \(Self.mb(limits.maxExpandedBytes))", memberNames: names)
        }
    }

    // MARK: single streams

    /// Decompresses a single stream into `dest`, never writing more than `maxExpandedBytes` (or `maxRatio`× input).
    func decompressStream(_ path: String, format: ArchiveFormat, size: UInt64, to dest: String) throws {
        let cap = Self.streamCap(size: size, limits: limits)
        switch format {
        case .gzip, .compressZ, .bzip2:
            let tool = format == .bzip2 ? "/usr/bin/bzip2" : "/usr/bin/gzip"
            let r = try BoundedProcess.run(tool, ["-d", "-c", path], maxStdout: Int(clamping: cap) + 1, timeout: limits.timeout, writeTo: dest)
            if r.truncated {
                throw ContainerUnreadable(reason: .bomb, format: format, detail: "expands past \(Self.mb(cap)) (\(Int(limits.maxRatio)):1 limit)")
            }
            if r.status != 0 {
                let e = String(decoding: r.stderr.prefix(160), as: UTF8.self)
                // gzip exits non-zero on trailing garbage but still produced the payload; keep what we got.
                let produced = (try? FileManager.default.attributesOfItem(atPath: dest)[.size] as? UInt64) ?? 0
                if produced == 0 { throw ContainerUnreadable(reason: .corrupt, format: format, detail: "\((tool as NSString).lastPathComponent): \(e)") }
            }
        case .xz, .zlib:
            guard let data = FileManager.default.contents(atPath: path) else {
                throw ContainerUnreadable(reason: .corrupt, format: format, detail: "unreadable")
            }
            let body = format == .zlib ? Array(data.dropFirst(2)) : Array(data)
            guard let outBytes = StreamInflater.inflate(body, algorithm: format == .xz ? COMPRESSION_LZMA : COMPRESSION_ZLIB,
                                                        limit: Int(clamping: cap) + 1, allowTruncated: false) else {
                throw ContainerUnreadable(reason: .corrupt, format: format, detail: "stream does not decompress (corrupt or truncated)")
            }
            if UInt64(outBytes.count) > cap {
                throw ContainerUnreadable(reason: .bomb, format: format, detail: "expands past \(Self.mb(cap))")
            }
            guard FileManager.default.createFile(atPath: dest, contents: Data(outBytes), attributes: [.posixPermissions: 0o600]) else {
                throw ContainerUnreadable(reason: .corrupt, format: format, detail: "could not write payload")
            }
        case .lzma:
            // Legacy .lzma: only bsdtar's liblzma reads it, and only when a tar is inside.
            let r = try BoundedProcess.run("/usr/bin/tar", ["-x", "-O", "--passphrase", Self.noPassphrase, "-f", path],
                                           maxStdout: Int(clamping: cap) + 1, timeout: limits.timeout, writeTo: dest)
            if r.truncated { throw ContainerUnreadable(reason: .bomb, format: format, detail: "expands past \(Self.mb(cap))") }
            if r.status != 0 { throw ContainerUnreadable(reason: .unsupported, format: format, detail: "raw lzma stream (no tar inside)") }
        default:
            throw ContainerUnreadable(reason: .unsupported, format: format, detail: "no decompressor")
        }
    }

    static func streamCap(size: UInt64, limits: ArchiveLimits) -> UInt64 {
        // A small file may legitimately expand a lot (text); allow at least 64 MB, else the ratio limit.
        let byRatio = UInt64(Double(max(size, 1)) * limits.maxRatio)
        return min(limits.maxExpandedBytes, max(64 << 20, byRatio))
    }

    /// Name of the decompressed member: "x.tar.gz" -> "x.tar", "x.gz" -> "x", otherwise "payload".
    static func streamMemberName(_ path: String) -> String {
        let name = (path as NSString).lastPathComponent
        let lower = name.lowercased()
        for (ext, repl) in [(".tgz", ".tar"), (".tbz2", ".tar"), (".tbz", ".tar"), (".txz", ".tar"), (".taz", ".tar"), (".tz", ".tar")]
            where lower.hasSuffix(ext) { return String(name.dropLast(ext.count)) + repl }
        for ext in [".gz", ".gzip", ".bz2", ".bzip2", ".xz", ".z", ".zz", ".zlib", ".lzma", ".deflate"] where lower.hasSuffix(ext) && lower.count > ext.count {
            return String(name.dropLast(ext.count))
        }
        let base = name.isEmpty ? "payload" : name
        return base + ".decompressed"
    }

    // MARK: helpers

    static func readHeader(_ path: String) -> [UInt8] {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return [] }
        defer { close(fd) }
        var h = [UInt8](repeating: 0, count: 512)
        let n = h.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
        return n > 0 ? Array(h[0..<n]) : []
    }

    static func treeBytes(_ root: String, cap: UInt64) -> UInt64 {
        var total: UInt64 = 0
        let e = FileManager.default.enumerator(atPath: root)
        while let rel = e?.nextObject() as? String {
            var st = stat()
            if lstat((root as NSString).appendingPathComponent(rel), &st) == 0, st.isRegular { total &+= UInt64(st.st_size) }
            if total > cap { break }
        }
        return total
    }

    static func mb(_ b: UInt64) -> String {
        b >= 1 << 30 ? String(format: "%.1f GB", Double(b) / Double(1 << 30)) : "\(b >> 20) MB"
    }

    private func runChecked(_ tool: String, _ args: [String], format: ArchiveFormat) throws {
        let r = try Subprocess.run(tool, args, timeout: limits.timeout)
        guard r.status == 0 else {
            throw ContainerUnreadable(reason: .corrupt, format: format,
                                      detail: "\((tool as NSString).lastPathComponent) exit \(r.status): \(String(decoding: r.stderr, as: UTF8.self).prefix(200))")
        }
    }
}

/// In-process streaming decompression (Apple Compression framework) with a hard output cap.
enum StreamInflater {
    /// Returns nil on a decode error (or, unless `allowTruncated`, an unterminated stream). Stops at `limit` bytes.
    static func inflate(_ input: [UInt8], algorithm: compression_algorithm, limit: Int, allowTruncated: Bool) -> [UInt8]? {
        guard !input.isEmpty, limit > 0 else { return nil }
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: 64 << 10)
        defer { dst.deallocate() }
        var stream = compression_stream(dst_ptr: dst, dst_size: 0, src_ptr: UnsafePointer(dst), src_size: 0, state: nil)
        guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, algorithm) == COMPRESSION_STATUS_OK else { return nil }
        defer { compression_stream_destroy(&stream) }
        var out: [UInt8] = []
        return input.withUnsafeBufferPointer { src -> [UInt8]? in
            stream.src_ptr = src.baseAddress!
            stream.src_size = src.count
            while true {
                stream.dst_ptr = dst; stream.dst_size = 64 << 10
                let st = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                let produced = (64 << 10) - stream.dst_size
                if produced > 0 { out.append(contentsOf: UnsafeBufferPointer(start: dst, count: produced)) }
                if out.count >= limit { return Array(out.prefix(limit)) }
                switch st {
                case COMPRESSION_STATUS_END: return out
                case COMPRESSION_STATUS_OK:
                    if produced == 0 && stream.src_size == 0 { return allowTruncated ? out : nil }
                default: return allowTruncated && !out.isEmpty ? out : nil
                }
            }
        }
    }
}

/// Runs a tool and streams stdout to memory or a file, killing it once `maxStdout` bytes have arrived.
enum BoundedProcess {
    struct Result { var status: Int32; var stdout: Data; var stderr: Data; var truncated: Bool }

    static func run(_ executable: String, _ arguments: [String], maxStdout: Int, timeout: TimeInterval,
                    writeTo file: String? = nil) throws -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = arguments
        let out = Pipe(), err = Pipe()
        p.standardOutput = out; p.standardError = err
        p.standardInput = FileHandle.nullDevice
        var env = ProcessInfo.processInfo.environment
        env["LC_ALL"] = "C"
        p.environment = env
        var sink: FileHandle?
        if let file {
            guard FileManager.default.createFile(atPath: file, contents: nil, attributes: [.posixPermissions: 0o600]),
                  let h = FileHandle(forWritingAtPath: file) else { throw EngineError.unpackFailed("cannot create \(file)") }
            sink = h
        }
        defer { try? sink?.close() }
        try p.run()
        let lock = NSLock()
        var outData = Data(), errData = Data(), total = 0, truncated = false
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            let h = out.fileHandleForReading
            while true {
                let chunk = h.availableData
                if chunk.isEmpty { break }
                lock.lock()
                let room = maxStdout - total
                if room <= 0 { truncated = true; lock.unlock(); break }
                let piece = chunk.count > room ? chunk.prefix(room) : chunk
                total += piece.count
                if chunk.count > room { truncated = true }
                lock.unlock()
                if let sink { sink.write(piece) } else { outData.append(piece) }
                if truncated { break }
            }
            if truncated { kill(p.processIdentifier, SIGKILL) }
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async { errData = err.fileHandleForReading.readDataToEndOfFile().prefix(64 << 10); group.leave() }
        group.enter()
        DispatchQueue.global().async { p.waitUntilExit(); group.leave() }
        if group.wait(timeout: .now() + timeout) == .timedOut {
            kill(p.processIdentifier, SIGKILL)
            _ = group.wait(timeout: .now() + 3)
            throw EngineError.subprocessTimeout("\(executable) \(arguments.joined(separator: " "))")
        }
        return Result(status: p.terminationStatus, stdout: outData, stderr: errData, truncated: truncated)
    }
}

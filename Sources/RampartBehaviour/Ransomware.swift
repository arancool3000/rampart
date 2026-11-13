import Foundation
import RampartShared

public struct RansomwareConfig: Sendable {
    /// User-data roots watched for entropy / velocity (default: Documents, Desktop, Downloads, Pictures, Movies, Music).
    public var protectedRoots: [String]
    public var encryptedBurstCount = 10
    public var encryptedBurstWindow: TimeInterval = 30
    public var renameCount = 20
    public var renameWindow: TimeInterval = 60
    public var noteDirCount = 5
    public var noteWindow: TimeInterval = 120
    public var velocityCount = 20
    public var velocityWindow: TimeInterval = 10
    public var velocityMinDirs = 3
    public var minSampleSize = 1024
    public var sampleBytes = 64 * 1024
    public var entropyThreshold = 7.5
    public var chiSquareMax = 400.0
    /// wms-o6 slow-and-low: one actor writing this many distinct random-looking user files within `slowWindow`
    /// (however slowly) is still an encryption run. Catches "one file every few minutes" ransomware.
    public var slowEncryptedCount = 25
    public var slowWindow: TimeInterval = 4 * 3600
    /// Across all actors that aren't the user's own signed GUI apps (one worker process per file, relaunched by a
    /// launch item, defeats per-actor counting).
    public var slowGlobalCount = 40
    /// Renames that append an unfamiliar extension to the whole original name ("report.pdf.x7k2q"), counted even
    /// when each file gets a different extension (per-file random extensions defeat R04's same-extension count).
    public var appendRenameCount = 20
    /// User files moved out of the protected folders into a hidden or temp folder (data held hostage without
    /// rewriting a byte, or staged for off-machine encryption).
    public var relocateCount = 20
    /// Bound on every per-key table (memory under event floods).
    public var maxKeys = 10_000

    public init(protectedRoots: [String]? = nil) {
        let h = PathUtil.home
        self.protectedRoots = protectedRoots ?? ["Documents", "Desktop", "Downloads", "Pictures", "Movies", "Music"].map { h + "/" + $0 }
    }
}

/// A raw finding from the ransomware detector; the engine turns it into scored evidence.
public struct RansomHit: Sendable {
    public var ruleID: String
    public var path: String
    public var detail: String
}

/// RansomWhere-style detector: canary files, encrypted-output bursts (Shannon entropy + chi-square),
/// header-to-random transitions, mass renames, ransom notes and modification velocity.
public final class RansomwareDetector: @unchecked Sendable {
    public var config: RansomwareConfig
    private var canaries: [String: Data] = [:]
    private var headerCache: [String: String] = [:]     // path -> magic type last seen
    private var encrypted: [String: [(Date, String)]] = [:]
    private var renames: [String: [(Date, String, String)]] = [:]  // key -> (date, newExt, path)
    private var notes: [String: [(Date, String)]] = [:]           // filename -> (date, dir)
    private var writes: [String: [(Date, String)]] = [:]
    private var slow: [String: [(Date, String)]] = [:]          // actorKey (or "*") -> distinct random outputs
    private var appended: [String: [(Date, String)]] = [:]
    private var relocated: [String: [(Date, String)]] = [:]
    private let lock = NSLock()

    public init(config: RansomwareConfig = RansomwareConfig()) { self.config = config }

    public var canaryPaths: [String] { lock.lock(); defer { lock.unlock() }; return Array(canaries.keys) }

    // MARK: canaries

    // Canary files are planted by RampartGuard.RansomCanaryRegistry (keyed, per-install names and bodies);
    // this detector only watches the paths it is given.

    /// Legacy recogniser: the fixed sentence older builds wrote into every canary. Used only to migrate them.
    public static let legacyCanaryMarker = "Rampart ransomware protection file"
    public static func isLegacyCanary(_ d: Data) -> Bool {
        String(decoding: d.prefix(4096), as: UTF8.self).contains(legacyCanaryMarker)
    }

    /// Registers an existing file as a canary (its current content is the reference).
    public func registerCanary(_ path: String) {
        guard let d = FileManager.default.contents(atPath: path) else { return }
        lock.lock(); canaries[PathUtil.canonical(path)] = d; lock.unlock()
    }

    // MARK: event intake

    /// Atomic-save temp names: `.sb-xxxxxxxx-yyyyyy` (NSDocument/AppKit safe-save), "(A Document Being Saved By X)"
    /// folders and `~` backup copies.
    public static func isAtomicSaveTemp(_ p: String) -> Bool {
        let b = PathUtil.basename(p)
        return b.contains(".sb-") || p.contains("/(A Document Being Saved By ") || p.contains("/.TemporaryItems/")
            || b.hasSuffix("~") || p.contains("/NSIRD_")
    }

    /// Stops watching these canary paths. Never touches the files (RampartGuard.RansomCanaryRegistry removes them).
    public func removeCanaries(_ paths: [String]) {
        lock.lock(); for p in paths { canaries[PathUtil.canonical(p)] = nil }; lock.unlock()
    }

    public func observe(_ e: SecurityEvent, actorKey: String, trustedGUIActor: Bool = false) -> [RansomHit] {
        guard let raw = e.path else { return [] }
        let path = PathUtil.canonical(raw)
        let dest = e.destPath.map(PathUtil.canonical)
        var hits: [RansomHit] = []
        lock.lock(); defer { lock.unlock() }

        // R01 canaries (any kind of touch that changed content, moved or deleted it).
        for p in [path, dest].compactMap({ $0 }) {
            guard let ref = canaries[p] else { continue }
            let now = FileManager.default.contents(atPath: p)
            let moved = e.kind == .fileRename && p == path
            // An editor's atomic save (temp file renamed over the canary, or the canary renamed to a backup)
            // by the user's own GUI app is not ransomware: adopt the new content as the reference.
            if e.kind == .fileRename, let dest, Self.isAtomicSaveTemp(p == path ? dest : path) {
                let notRandom = now.map { !Self.looksEncrypted($0, entropyThreshold: config.entropyThreshold, chiMax: config.chiSquareMax) } ?? true
                if trustedGUIActor || (e.process == nil && notRandom) {
                    if let now { canaries[p] = now }
                    continue
                }
            }
            if moved || e.kind == .fileDelete || now == nil || now != ref {
                hits.append(RansomHit(ruleID: "R01", path: p,
                    detail: "Canary \(PathUtil.basename(p)) was \(moved ? "renamed" : (now == nil ? "deleted" : "modified")) (event \(e.kind.rawValue))."))
            }
        }
        if !hits.isEmpty { return hits }

        // R04 (wms-o6): user files moved out of the protected folders into hiding (before the in-scope guard below,
        // which only looks at destinations inside the protected folders).
        if e.kind == .fileRename, let dest, inScope(path), !inScope(dest), !trustedGUIActor,
           PathClass.classify(dest).isSuspiciousLocation, !dest.contains("/.Trash/") {
            var r = (relocated[actorKey] ?? []).filter { e.date.timeIntervalSince($0.0) <= config.renameWindow }
            if !r.contains(where: { $0.1 == path }) { r.append((e.date, path)) }
            relocated[actorKey] = r
            if r.count >= config.relocateCount {
                hits.append(RansomHit(ruleID: "R04", path: dest,
                    detail: "\(r.count) user files were moved out of your folders into the hidden or temporary folder \(PathUtil.dirname(dest)) within \(Int(config.renameWindow)) s."))
                relocated[actorKey] = []
            }
        }

        let written: String?
        switch e.kind {
        case .fileWrite, .fileCreate: written = path
        case .fileClose: written = e.detail["modified"] == "0" ? nil : path
        case .fileRename: written = dest
        default: written = nil
        }
        guard let target = written, inScope(target), e.detail["is_dir"] != "1" else { return hits }
        let now = e.date

        // RW1 velocity
        var w = (writes[actorKey] ?? []).filter { now.timeIntervalSince($0.0) <= config.velocityWindow }
        if !w.contains(where: { $0.1 == target }) { w.append((now, target)) }
        writes[actorKey] = w
        let dirs = Set(w.map { PathUtil.dirname($0.1) })
        if w.count >= config.velocityCount && dirs.count >= config.velocityMinDirs {
            hits.append(RansomHit(ruleID: "RW1", path: target,
                detail: "\(w.count) user files modified in \(Int(config.velocityWindow)) s across \(dirs.count) folders."))
            writes[actorKey] = []
        }

        // R04 mass rename to one new extension
        if e.kind == .fileRename, let dest, PathUtil.ext(dest) != PathUtil.ext(path) {
            let ne = PathUtil.ext(dest)
            if !ne.isEmpty && !Self.commonExtensions.contains(ne) {
                var r = (renames[actorKey] ?? []).filter { now.timeIntervalSince($0.0) <= config.renameWindow }
                r.append((now, ne, dest)); renames[actorKey] = r
                let same = r.filter { $0.1 == ne }
                if same.count >= config.renameCount {
                    hits.append(RansomHit(ruleID: "R04", path: dest,
                        detail: "\(same.count) files renamed to the unfamiliar extension .\(ne) within \(Int(config.renameWindow)) s."))
                    renames[actorKey] = r.filter { $0.1 != ne }
                }
            }
        }

        // R04 (wms-o6): appended unfamiliar extensions, whatever they are, and mass relocation into hiding.
        if e.kind == .fileRename, let dest {
            let srcName = PathUtil.basename(path), dstName = PathUtil.basename(dest)
            let ne = PathUtil.ext(dest)
            if dstName.count > srcName.count + 1, dstName.hasPrefix(srcName + "."), !PathUtil.ext(path).isEmpty,
               !ne.isEmpty, !Self.commonExtensions.contains(ne.lowercased()), !Self.isAtomicSaveTemp(dest) {
                var a = (appended[actorKey] ?? []).filter { now.timeIntervalSince($0.0) <= config.renameWindow * 5 }
                if !a.contains(where: { $0.1 == dest }) { a.append((now, dest)) }
                appended[actorKey] = a
                if a.count >= config.appendRenameCount {
                    hits.append(RansomHit(ruleID: "R04", path: dest,
                        detail: "\(a.count) files had an unfamiliar extension appended to their full names (last: .\(ne)) within \(Int(config.renameWindow * 5)) s; ransomware often uses a different extension per file."))
                    appended[actorKey] = []
                }
            }
        }
        // R05 ransom-note pattern
        if e.kind == .fileCreate || (e.kind == .fileRename && dest != nil) {
            let name = PathUtil.basename(target)
            if ["txt", "html", "htm", "rtf", "hta", "url"].contains(PathUtil.ext(name)) {
                var n = (notes[name] ?? []).filter { now.timeIntervalSince($0.0) <= config.noteWindow }
                n.append((now, PathUtil.dirname(target))); notes[name] = n
                let nd = Set(n.map { $0.1 })
                if nd.count >= config.noteDirCount {
                    hits.append(RansomHit(ruleID: "R05", path: target,
                        detail: "The file name \"\(name)\" appeared in \(nd.count) folders within \(Int(config.noteWindow)) s."))
                    notes[name] = []
                }
            }
        }

        // R02 / R03 content analysis
        if e.kind != .fileDelete, let sample = readSample(target) {
            let magic = Self.magicType(sample)
            let prior = headerCache[target]
            let random = Self.looksEncrypted(sample, entropyThreshold: config.entropyThreshold, chiMax: config.chiSquareMax)
            if random {
                let ent = Self.shannonEntropy(sample)
                if let prior, Self.documentTypes.contains(prior) {
                    hits.append(RansomHit(ruleID: "R03", path: target,
                        detail: "\(PathUtil.basename(target)) was a valid \(prior.uppercased()) and now holds random data (entropy \(String(format: "%.2f", ent)) bits/byte)."))
                }
                var enc = (encrypted[actorKey] ?? []).filter { now.timeIntervalSince($0.0) <= config.encryptedBurstWindow }
                if !enc.contains(where: { $0.1 == target }) { enc.append((now, target)) }
                encrypted[actorKey] = enc
                if enc.count >= config.encryptedBurstCount {
                    hits.append(RansomHit(ruleID: "R02", path: target,
                        detail: "\(enc.count) user files were written with random-looking content within \(Int(config.encryptedBurstWindow)) s (last entropy \(String(format: "%.2f", ent)) bits/byte)."))
                    encrypted[actorKey] = []
                } else {
                    // Slow-and-low (wms-o6): same signal over hours instead of seconds, per actor and machine-wide.
                    for (key, need) in [(actorKey, config.slowEncryptedCount), ("*", trustedGUIActor ? Int.max : config.slowGlobalCount)] where need != Int.max {
                        var sl = (slow[key] ?? []).filter { now.timeIntervalSince($0.0) <= config.slowWindow }
                        if !sl.contains(where: { $0.1 == target }) { sl.append((now, target)) }
                        if sl.count > need * 4 { sl.removeFirst(sl.count - need * 4) }
                        slow[key] = sl
                        if sl.count >= need {
                            let span = max(1, Int(now.timeIntervalSince(sl.first!.0) / 60))
                            hits.append(RansomHit(ruleID: "R02", path: target,
                                detail: "\(sl.count) user files were rewritten with random-looking content over \(span) min\(key == "*" ? " by several processes" : ""): a slow encryption run that stays under burst limits."))
                            slow[key] = []; slow["*"] = []; slow[actorKey] = []
                            break
                        }
                    }
                }
            }
            if let magic { headerCache[target] = magic } else if !random { headerCache[target] = nil }
            if headerCache.count > 100_000 { headerCache.removeAll(keepingCapacity: true) }
        }
        capTables()
        return hits
    }

    private func capTables() {
        let m = config.maxKeys
        if writes.count > m { writes.removeAll(keepingCapacity: true) }
        if encrypted.count > m { encrypted.removeAll(keepingCapacity: true) }
        if renames.count > m { renames.removeAll(keepingCapacity: true) }
        if notes.count > m { notes.removeAll(keepingCapacity: true) }
        if appended.count > m { appended.removeAll(keepingCapacity: true) }
        if relocated.count > m { relocated.removeAll(keepingCapacity: true) }
        if slow.count > m { let g = slow["*"]; slow.removeAll(keepingCapacity: true); slow["*"] = g }
    }

    /// Number of keys across the per-actor tables (tests).
    public var tableKeyCount: Int {
        lock.lock(); defer { lock.unlock() }
        return writes.count + encrypted.count + renames.count + notes.count + appended.count + relocated.count + slow.count
    }

    /// Records the current header type of existing files (so a later rewrite can be compared).
    public func primeHeader(_ path: String) {
        guard let s = readSample(path), let m = Self.magicType(s) else { return }
        lock.lock(); headerCache[PathUtil.canonical(path)] = m; lock.unlock()
    }

    func inScope(_ p: String) -> Bool {
        guard config.protectedRoots.contains(where: { p.hasPrefix(PathUtil.canonical($0) + "/") }) else { return false }
        for bad in ["/Library/", "/.git/", "/node_modules/", "/.build/", "/DerivedData/", "/.Trash/"] where p.contains(bad) { return false }
        return true
    }

    private func readSample(_ p: String) -> Data? {
        guard let fh = FileHandle(forReadingAtPath: p) else { return nil }
        defer { try? fh.close() }
        let d = (try? fh.read(upToCount: config.sampleBytes)) ?? nil
        guard let d, d.count >= config.minSampleSize else { return nil }
        return d
    }

    // MARK: statistics

    static let commonExtensions: Set<String> = ["txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png",
        "gif", "heic", "mov", "mp4", "mp3", "m4a", "zip", "tar", "gz", "dmg", "pkg", "app", "pages", "numbers", "key", "rtf",
        "csv", "json", "md", "html", "swift", "py", "js", "ts", "tmp", "bak", "log", "plist", "sqlite", "db", "part",
        "crdownload", "download", "webp", "svg", "psd", "ai", "sketch", "fig", "tiff", "tif", "wav", "aac", "flac", "epub"]
    static let documentTypes: Set<String> = ["pdf", "zip-office", "ole2", "png", "jpeg", "gif", "rtf", "text", "tiff", "heic", "mp4", "psd", "sqlite", "plist"]

    public static func shannonEntropy(_ d: Data) -> Double {
        guard !d.isEmpty else { return 0 }
        var counts = [Int](repeating: 0, count: 256)
        d.withUnsafeBytes { for b in $0 { counts[Int(b)] += 1 } }
        let n = Double(d.count)
        var h = 0.0
        for c in counts where c > 0 { let p = Double(c) / n; h -= p * log2(p) }
        return h
    }

    /// Pearson chi-square statistic against a uniform byte distribution (≈255 for random data).
    public static func chiSquare(_ d: Data) -> Double {
        guard !d.isEmpty else { return .infinity }
        var counts = [Int](repeating: 0, count: 256)
        d.withUnsafeBytes { for b in $0 { counts[Int(b)] += 1 } }
        let e = Double(d.count) / 256
        return counts.reduce(0.0) { $0 + pow(Double($1) - e, 2) / e }
    }

    public static func looksEncrypted(_ d: Data, entropyThreshold: Double = 7.5, chiMax: Double = 400) -> Bool {
        guard d.count >= 512, magicType(d) == nil else { return false }
        return shannonEntropy(d) >= entropyThreshold && chiSquare(d) <= chiMax * max(1, Double(d.count) / 65536)
    }

    /// Identifies common formats by magic bytes. Compressed/media formats are legitimately high entropy.
    public static func magicType(_ d: Data) -> String? {
        let b = [UInt8](d.prefix(16))
        func starts(_ m: [UInt8], at o: Int = 0) -> Bool { b.count >= o + m.count && Array(b[o..<o + m.count]) == m }
        if starts([0x25, 0x50, 0x44, 0x46]) { return "pdf" }
        if starts([0x50, 0x4B, 0x03, 0x04]) || starts([0x50, 0x4B, 0x05, 0x06]) { return "zip-office" }
        if starts([0xD0, 0xCF, 0x11, 0xE0]) { return "ole2" }
        if starts([0x89, 0x50, 0x4E, 0x47]) { return "png" }
        if starts([0xFF, 0xD8, 0xFF]) { return "jpeg" }
        if starts([0x47, 0x49, 0x46, 0x38]) { return "gif" }
        if starts([0x7B, 0x5C, 0x72, 0x74, 0x66]) { return "rtf" }
        if starts([0x49, 0x49, 0x2A, 0x00]) || starts([0x4D, 0x4D, 0x00, 0x2A]) { return "tiff" }
        if starts([0x66, 0x74, 0x79, 0x70], at: 4) { return "mp4" }       // ftyp: mp4/mov/heic
        if starts([0x38, 0x42, 0x50, 0x53]) { return "psd" }
        if starts(Array("SQLite format 3".utf8)) { return "sqlite" }
        if starts(Array("bplist0".utf8)) { return "plist" }
        if starts([0x1F, 0x8B]) { return "gzip" }
        if starts([0x42, 0x5A, 0x68]) { return "bzip2" }
        if starts([0xFD, 0x37, 0x7A, 0x58, 0x5A]) { return "xz" }
        if starts([0x37, 0x7A, 0xBC, 0xAF]) { return "7z" }
        if starts([0x52, 0x61, 0x72, 0x21]) { return "rar" }
        if starts([0x28, 0xB5, 0x2F, 0xFD]) { return "zstd" }
        if starts([0x78, 0x01]) || starts([0x78, 0x9C]) || starts([0x78, 0xDA]) { return "zlib" }
        if starts([0x4F, 0x67, 0x67, 0x53]) { return "ogg" }
        if starts([0x49, 0x44, 0x33]) || starts([0xFF, 0xFB]) { return "mp3" }
        if starts([0x66, 0x4C, 0x61, 0x43]) { return "flac" }
        if starts([0x52, 0x49, 0x46, 0x46]) { return "riff" }
        if starts([0x1A, 0x45, 0xDF, 0xA3]) { return "mkv" }
        if starts([0x78, 0x61, 0x72, 0x21]) { return "xar" }
        if starts([0x6B, 0x6F, 0x6C, 0x79]) || starts([0x45, 0x52, 0x02, 0x00]) { return "dmg" }
        if starts([0x41, 0x45, 0x41, 0x31]) { return "aea" }   // Apple encrypted archive (legit)
        if starts([0x77, 0x4F, 0x46, 0x46]) || starts([0x77, 0x4F, 0x46, 0x32]) { return "woff" }
        if starts([0xCF, 0xFA, 0xED, 0xFE]) || starts([0xCA, 0xFE, 0xBA, 0xBE]) { return "macho" }
        // Mostly-printable first 16 bytes: text-like
        if b.count >= 8 && b.allSatisfy({ ($0 >= 0x20 && $0 < 0x7F) || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }) { return "text" }
        return nil
    }
}

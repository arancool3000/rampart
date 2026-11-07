import Foundation
import RampartShared

/// Covers "runs only once it's been unpacked": remembers archive extractions (Archive Utility, ditto, unzip,
/// tar/bsdtar, gunzip, aa, cpio, 7z, The Unarchiver, pkgutil, xar) and the files they write, and when one of
/// those files is executed within `window` (directly, or as the script of an interpreter), asks for it to be
/// scanned and supplies the lineage for the explanation.
///
/// Feed it every `SecurityEvent` (exec + file events). Thread-safe; memory is bounded (`maxEntries`).
/// Without exec/file events (no eslogger, no FSEvents) it can't see anything — that limit is honest in the UI.
public final class ExtractionLineage: @unchecked Sendable {
    public struct Extraction: Sendable, Equatable {
        public var tool: String
        public var pid: Int32
        public var archive: String?
        public var destination: String?
        public var date: Date
        /// The archive carried a download quarantine flag.
        public var archiveDownloaded: Bool
        /// The tool is known not to copy the quarantine flag to what it extracts (or was told not to).
        public var dropsQuarantine: Bool
    }

    /// What to scan on exec, and why.
    public struct ExecScanRequest: Sendable {
        public var path: String
        public var extraction: Extraction
        public var runner: String
        public var runnerPid: Int32
        public var secondsAfterExtraction: Double
        public var lineage: String
    }

    public var window: TimeInterval
    public var maxEntries: Int
    private let lock = NSLock()
    private var byPid: [Int32: Extraction] = [:]
    private var created: [String: Extraction] = [:]
    private var recent: [Extraction] = []
    private var lastScan: [String: Date] = [:]
    private let quarantineCheck: (String) -> Bool

    public init(window: TimeInterval = 600, maxEntries: Int = 20_000,
                quarantineCheck: @escaping (String) -> Bool = { ContainerRisk.origin(of: $0).quarantined }) {
        self.window = window; self.maxEntries = maxEntries; self.quarantineCheck = quarantineCheck
    }

    static let extractorNames: Set<String> = [
        "ditto", "unzip", "tar", "bsdtar", "gunzip", "gzip", "zcat", "bunzip2", "bzip2", "xz", "unxz", "aa", "cpio", "pax",
        "7z", "7za", "7zz", "unar", "unrar", "Archive Utility", "The Unarchiver", "Keka", "pkgutil", "xar", "compression_tool",
        "uncompress", "Bom", "BetterZip 5",
    ]
    static let interpreters: Set<String> = [
        "sh", "bash", "zsh", "ksh", "dash", "fish", "csh", "tcsh", "python", "python3", "perl", "ruby", "osascript", "node", "php",
        "Python", "lua", "tclsh", "pwsh",
    ]
    /// Tools that extract without copying the archive's quarantine flag (Archive Utility and The Unarchiver propagate it).
    static let quarantineDroppers: Set<String> = ["unzip", "tar", "bsdtar", "gunzip", "gzip", "zcat", "bunzip2", "bzip2", "xz", "unxz",
                                                   "cpio", "pax", "7z", "7za", "7zz", "unrar", "aa", "xar", "compression_tool", "uncompress"]

    static func toolName(_ p: ProcessInfoLite) -> String {
        if let r = p.path.range(of: ".app/Contents/MacOS/") { return String(p.path[r.upperBound...]) }
        return (p.path as NSString).lastPathComponent
    }

    /// Feeds one event. Returns a scan request when an extracted file is being executed.
    @discardableResult
    public func observe(_ ev: SecurityEvent) -> ExecScanRequest? {
        guard let proc = ev.process else { return nil }
        let tool = Self.toolName(proc)
        switch ev.kind {
        case .exec:
            if Self.extractorNames.contains(tool), let x = parseExtraction(tool: tool, proc: proc, date: ev.date) {
                lock.lock(); byPid[proc.pid] = x; recent.append(x); prune(now: ev.date); lock.unlock()
                return nil
            }
            return execRequest(proc: proc, tool: tool, date: ev.date)
        case .fileCreate, .fileWrite, .fileClose, .fileRename:
            guard let p = ev.destPath ?? ev.path else { return nil }
            lock.lock(); defer { lock.unlock() }
            if let x = byPid[proc.pid] ?? (Self.extractorNames.contains(tool) ? recent.last(where: { $0.tool == tool }) : nil) {
                if created.count < maxEntries { created[p] = x }
            }
            return nil
        default:
            return nil
        }
    }

    private func parseExtraction(tool: String, proc: ProcessInfoLite, date: Date) -> Extraction? {
        let args = Array(proc.args.dropFirst())
        let lowerArgs = args.map { $0.lowercased() }
        func value(after flags: [String]) -> String? {
            for (i, a) in args.enumerated() where flags.contains(a) && i + 1 < args.count { return args[i + 1] }
            return nil
        }
        let archiveLike = args.first { a in
            let e = ScanTriage.pathExtension(a)
            return ["zip", "tar", "tgz", "gz", "bz2", "xz", "txz", "7z", "rar", "cpio", "xar", "aar", "yaa", "pkg", "z", "lzma", "zst", "cpgz", "sit", "dmg", "xip"].contains(e)
                || a.hasSuffix(".tar.gz")
        }
        var archive: String? = archiveLike
        var dest: String?
        var drops = Self.quarantineDroppers.contains(tool)
        switch tool {
        case "ditto":
            guard lowerArgs.contains("-x") || lowerArgs.contains("-xk") else { return nil }
            let paths = args.filter { !$0.hasPrefix("-") }
            if paths.count >= 2 { archive = paths[paths.count - 2]; dest = paths.last }
            drops = lowerArgs.contains("--noqtn")
        case "tar", "bsdtar":
            guard args.contains(where: { $0.hasPrefix("-x") || $0 == "x" || ($0.hasPrefix("-") && !$0.hasPrefix("--") && $0.contains("x")) || $0.hasPrefix("x") }) else { return nil }
            archive = value(after: ["-f", "--file"]) ?? archive
            dest = value(after: ["-C", "--directory", "--cd"])
        case "unzip":
            dest = value(after: ["-d"])
        case "aa":
            guard args.first == "extract" else { return nil }
            archive = value(after: ["-i"]); dest = value(after: ["-d"])
        case "pkgutil":
            guard args.contains("--expand") || args.contains("--expand-full") else { return nil }
            let paths = args.filter { !$0.hasPrefix("-") }
            if paths.count >= 2 { archive = paths[paths.count - 2]; dest = paths.last }
        case "gzip", "bzip2", "xz":
            guard args.contains(where: { $0.hasPrefix("-") && $0.contains("d") }) else { return nil }
        default: break
        }
        if dest == nil, let a = archive, a.hasPrefix("/") { dest = (a as NSString).deletingLastPathComponent }
        let downloaded = archive.map { $0.hasPrefix("/") && quarantineCheck($0) } ?? false
        return Extraction(tool: tool, pid: proc.pid, archive: archive, destination: dest, date: date,
                          archiveDownloaded: downloaded, dropsQuarantine: drops)
    }

    private func execRequest(proc: ProcessInfoLite, tool: String, date: Date) -> ExecScanRequest? {
        // The executed file itself, or the script handed to an interpreter.
        var candidates = [proc.path]
        if Self.interpreters.contains(tool) || tool.hasPrefix("python") {
            if let script = proc.args.dropFirst().first(where: { !$0.hasPrefix("-") && $0.hasPrefix("/") }) { candidates.append(script) }
        }
        lock.lock(); defer { lock.unlock() }
        prune(now: date)
        for c in candidates.reversed() {
            let path = (c as NSString).standardizingPath
            var x = created[path]
            if x == nil {
                // No file events: fall back to "inside the folder an extraction wrote to, and modified after it began".
                x = recent.last { e in
                    guard let d = e.destination, d.count > 1, path.hasPrefix(d.hasSuffix("/") ? d : d + "/"),
                          date.timeIntervalSince(e.date) <= window else { return false }
                    var st = stat()
                    guard stat(path, &st) == 0 else { return false }
                    let m = Double(st.st_mtimespec.tv_sec), cTime = Double(st.st_ctimespec.tv_sec)
                    return max(m, cTime) >= e.date.timeIntervalSince1970 - 2
                }
            }
            guard let found = x, date.timeIntervalSince(found.date) <= window else { continue }
            if let last = lastScan[path], date.timeIntervalSince(last) < 30 { return nil }
            lastScan[path] = date
            let secs = max(0, date.timeIntervalSince(found.date))
            return ExecScanRequest(path: path, extraction: found, runner: tool, runnerPid: proc.pid,
                                   secondsAfterExtraction: secs, lineage: Self.describe(found, path: path, runner: tool, pid: proc.pid, secs: secs))
        }
        return nil
    }

    static func describe(_ x: Extraction, path: String, runner: String, pid: Int32, secs: Double) -> String {
        let name = (path as NSString).lastPathComponent
        let from = x.archive.map { "\"\(($0 as NSString).lastPathComponent)\"" } ?? "an archive"
        var s = "\(name) was unpacked from \(from) by \(x.tool) (pid \(x.pid))"
        if x.archiveDownloaded { s += ", a downloaded archive," }
        s += " and run \(Int(secs.rounded())) s later by \(runner) (pid \(pid))."
        return s
    }

    /// Evidence describing the lineage, to attach to the exec-time scan result.
    /// Score 0 (context only) normally; 45 when a downloaded archive was unpacked with a tool that drops the
    /// quarantine flag and the program now runs without it (Gatekeeper never saw it).
    public func evidence(for r: ExecScanRequest) -> Evidence {
        let bypass = r.extraction.archiveDownloaded && r.extraction.dropsQuarantine && !quarantineCheck(r.path)
        if bypass {
            return Evidence(source: .behaviour, title: "Ran straight out of a downloaded archive without Gatekeeper",
                            detail: r.lineage + " The unpacking tool did not copy the download flag, so Gatekeeper never checked this program before it ran.",
                            score: 45)
        }
        return Evidence(source: .behaviour, title: "Unpacked, then run", detail: r.lineage, score: 0)
    }

    /// Scans the extracted file on exec with `coordinator` and attaches the lineage. Returns nil when clean.
    public func scanOnExec(_ r: ExecScanRequest, coordinator: ScanCoordinator, options: ScanOptions? = nil) -> Detection? {
        let out = coordinator.scanFile(at: r.path, options: options)
        let lineageEv = evidence(for: r)
        var ev = out.detection?.evidence ?? []
        // A signed + notarised program that ran out of an archive is normal; keep only real findings.
        if let s = out.facts?.signing, Scoring.isTrusted(s), out.detection == nil { return nil }
        if ev.isEmpty && lineageEv.score == 0 { return nil }
        ev.append(lineageEv)
        guard var d = Scoring.makeDetection(path: r.path, sha256: out.detection?.sha256 ?? out.facts?.sha256, evidence: ev, pid: r.runnerPid) else { return nil }
        if let old = out.detection { d.id = old.id }
        return d
    }

    private func prune(now: Date) {
        let cutoff = now.addingTimeInterval(-window)
        if recent.count > 256 || recent.first.map({ $0.date < cutoff }) == true { recent.removeAll { $0.date < cutoff }; if recent.count > 256 { recent.removeFirst(recent.count - 256) } }
        if created.count >= maxEntries { created = created.filter { $0.value.date >= cutoff } }
        if byPid.count > 512 { byPid = byPid.filter { $0.value.date >= cutoff } }
        if lastScan.count > 4096 { lastScan = lastScan.filter { now.timeIntervalSince($0.value) < 60 } }
    }
}

import Foundation
import RampartShared

/// Fills extra `FileFacts` fields before detectors run (e.g. RampartSigning sets `signing`,
/// provenance code sets `quarantineOrigin`). Must be thread-safe.
public protocol FileFactsEnricher: Sendable {
    func enrich(_ facts: inout FileFacts)
}

/// Options for one scan.
public struct ScanOptions: Sendable {
    public var walk = WalkOptions()
    public var archiveLimits = ArchiveLimits()
    /// Expand zip/tar/dmg/pkg and scan members.
    public var unpackArchives = true
    /// Mount DMGs (slower, touches DiskArbitration). Off by default for real-time scans.
    public var unpackDiskImages = true
    /// Use and update the inode/mtime scan cache.
    public var useCache = true
    /// Worker threads. Defaults to the active core count.
    public var concurrency = max(2, ProcessInfo.processInfo.activeProcessorCount)
    /// Minimum seconds between progress callbacks.
    public var progressInterval: TimeInterval = 0.1
    public init() {}

    /// Locations a quick scan covers for the current user (existing ones only).
    public static func quickScanRoots(home: String = NSHomeDirectory()) -> [String] {
        let candidates = [
            home + "/Downloads", home + "/Desktop", home + "/Library/LaunchAgents",
            home + "/Library/Application Support", "/Applications", "/Library/LaunchAgents",
            "/Library/LaunchDaemons", "/Library/Application Support", "/Users/Shared", "/private/tmp", "/private/var/tmp",
        ]
        return candidates.filter { FileManager.default.fileExists(atPath: $0) }
    }
}

/// Progress snapshot, delivered on a worker thread.
public struct ScanProgress: Sendable {
    public var scanned: Int
    /// Files discovered so far (grows while the walker is still running).
    public var discovered: Int
    public var current: String
    public var detections: Int
    public var walkFinished: Bool
}

/// Outcome of scanning one file.
public struct FileScanOutcome: Sendable {
    public var path: String
    public var detection: Detection?
    public var facts: FileFacts?
    public var cacheHit: Bool
    public var hashedBytes: UInt64
    /// Set when the file was not scanned (allowlisted, dataless, unreadable, too big).
    public var skippedReason: String?
    public var verdict: Scoring.Verdict { detection.map { Scoring.verdict(confidence: $0.confidence) } ?? .clean }
}

/// Summary of a multi-file scan.
public struct ScanReport: Sendable {
    public var scanned = 0
    public var cacheHits = 0
    public var skipped = 0
    public var errors = 0
    public var bytesHashed: UInt64 = 0
    public var archivesExpanded = 0
    public var detections: [Detection] = []
    public var seconds: Double = 0
    public var cancelled = false
}

/// Runs registered `FileDetector`s over files concurrently: walk -> stat -> cache -> sniff -> hash ->
/// allowlist -> enrich -> detectors -> trust prior -> score -> archive members -> cache write.
///
/// Thread-safe; one coordinator can serve concurrent scans and real-time `scanFile` calls.
public final class ScanCoordinator: @unchecked Sendable {
    public let database: HashDatabase?
    public var options: ScanOptions
    private let lock = NSLock()
    private var detectors: [FileDetector]
    private var enrichers: [FileFactsEnricher] = []
    private var pendingCache: [ScanCacheEntry] = []
    private let log = RLog.logger("engine")

    /// Creates a coordinator. With a database it registers `HashDetector` automatically; `EICARDetector` is
    /// always registered. Pass `extraDetectors` (YARA, signing heuristics, ...) or call `register(_:)` later.
    public init(database: HashDatabase?, extraDetectors: [FileDetector] = [], options: ScanOptions = ScanOptions()) {
        self.database = database
        self.options = options
        var d: [FileDetector] = [EICARDetector()]
        if let database { d.append(HashDetector(database: database)) }
        self.detectors = d + extraDetectors
    }

    public func register(_ detector: FileDetector) { lock.lock(); detectors.append(detector); lock.unlock() }
    public func register(_ enricher: FileFactsEnricher) { lock.lock(); enrichers.append(enricher); lock.unlock() }
    public var detectorNames: [String] { lock.lock(); defer { lock.unlock() }; return detectors.map(\.name) }

    /// Cache key component: engine + signature generation + detector set. Changing any re-evaluates cached files.
    public var cacheVersion: String {
        "\(EngineInfo.version)|sig\(database?.signatureGeneration ?? 0)|\(detectorNames.sorted().joined(separator: ","))"
    }

    // MARK: Multi-file scans

    /// Scans files and directories (recursively) with a worker pool. Blocks until done or cancelled.
    public func scan(paths: [String], options: ScanOptions? = nil, cancel: ScanCancellation? = nil,
                     progress: ((ScanProgress) -> Void)? = nil) -> ScanReport {
        let opts = options ?? self.options
        let start = Date()
        let version = cacheVersion
        let snapshot = currentPipeline()
        let queue = BoundedQueue<WalkedFile>(capacity: 4096)
        let state = ScanState()
        let workers = max(1, opts.concurrency)
        let group = DispatchGroup()

        for _ in 0..<workers {
            group.enter()
            let t = Thread { [self] in
                defer { group.leave() }
                while let f = queue.pop() {
                    if cancel?.isCancelled == true { continue }
                    let out = self.scanWalked(f, opts: opts, version: version, pipeline: snapshot, depth: 0, displayPath: nil)
                    let p = state.record(out, interval: opts.progressInterval)
                    if let p, let progress { progress(p) }
                }
            }
            t.stackSize = 1 << 20
            t.qualityOfService = .utility
            t.start()
        }

        var seen = Set<HardLinkKey>()
        let walkStats = FileWalker.walk(roots: paths, options: opts.walk, cancel: cancel) { f in
            if f.linkCount > 1 {
                if !seen.insert(HardLinkKey(dev: f.device, ino: f.inode)).inserted { return true }
            }
            state.discovered()
            return queue.push(f)
        }
        state.walkDone()
        queue.close()
        group.wait()
        flushCache()

        var report = state.report()
        report.skipped += walkStats.skipped
        report.errors += walkStats.errors
        report.cancelled = cancel?.isCancelled == true
        report.seconds = Date().timeIntervalSince(start)
        if let progress { progress(state.progress(current: "", force: true)!) }
        log.info("scan finished: \(report.scanned) files, \(report.detections.count) detections, \(report.seconds, format: .fixed(precision: 2))s")
        return report
    }

    /// Async wrapper over `scan(paths:)`; runs on a background thread.
    public func scan(paths: [String], options: ScanOptions? = nil, cancel: ScanCancellation? = nil,
                     progress: (@Sendable (ScanProgress) -> Void)? = nil) async -> ScanReport {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                cont.resume(returning: self.scan(paths: paths, options: options, cancel: cancel, progress: progress))
            }
        }
    }

    // MARK: Single-file scans (real-time / on-write)

    /// Scans one file synchronously (no cache skip for files written moments ago is needed: the
    /// cache key includes mtime/ctime). Directories are scanned recursively and the strongest detection returned.
    public func scanFile(at path: String, options: ScanOptions? = nil) -> FileScanOutcome {
        let opts = options ?? self.options
        var st = stat()
        guard lstat(path, &st) == 0 else {
            return FileScanOutcome(path: path, cacheHit: false, hashedBytes: 0, skippedReason: "not found")
        }
        if st.isDirectory {
            let r = scan(paths: [path], options: opts)
            return FileScanOutcome(path: path, detection: r.detections.max { $0.confidence < $1.confidence },
                                   cacheHit: false, hashedBytes: r.bytesHashed, skippedReason: nil)
        }
        guard let f = WalkedFile.stat(path: path) else {
            return FileScanOutcome(path: path, cacheHit: false, hashedBytes: 0, skippedReason: "not a regular file")
        }
        let out = scanWalked(f, opts: opts, version: cacheVersion, pipeline: currentPipeline(), depth: 0, displayPath: nil)
        flushCache()
        return out
    }

    /// Persists buffered scan-cache rows.
    public func flushCache() {
        lock.lock(); let rows = pendingCache; pendingCache.removeAll(); lock.unlock()
        guard let database, !rows.isEmpty else { return }
        do { try database.storeCache(rows) } catch { log.error("cache write failed: \(String(describing: error), privacy: .public)") }
    }

    // MARK: Pipeline

    private struct Pipeline { var detectors: [FileDetector]; var enrichers: [FileFactsEnricher] }
    private func currentPipeline() -> Pipeline {
        lock.lock(); defer { lock.unlock() }
        return Pipeline(detectors: detectors, enrichers: enrichers)
    }

    private func scanWalked(_ f: WalkedFile, opts: ScanOptions, version: String, pipeline: Pipeline,
                            depth: Int, displayPath: String?) -> FileScanOutcome {
        let shownPath = displayPath ?? f.path
        if f.isDataless && opts.walk.skipDataless {
            return FileScanOutcome(path: shownPath, cacheHit: false, hashedBytes: 0, skippedReason: "dataless")
        }
        if f.size > opts.walk.maxFileSize {
            return FileScanOutcome(path: shownPath, cacheHit: false, hashedBytes: 0, skippedReason: "too large")
        }

        // Cache: identical (dev, ino, size, mtime, ctime). Same version + clean => skip; otherwise reuse the hash.
        let cacheable = depth == 0 && opts.useCache && database != nil
        var knownHash: String?
        if cacheable, let e = database!.cacheEntry(device: f.device, inode: f.inode),
           e.size == f.size, e.mtimeNanos == f.mtimeNanos, e.ctimeNanos == f.ctimeNanos {
            if e.clean && e.version == version {
                return FileScanOutcome(path: shownPath, facts: nil, cacheHit: true, hashedBytes: 0, skippedReason: nil)
            }
            knownHash = e.sha256
        }

        let fd = open(f.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            return FileScanOutcome(path: shownPath, cacheHit: false, hashedBytes: 0, skippedReason: "unreadable (errno \(errno))")
        }
        let kind = FileSniffer.kind(fd: fd, size: f.size, path: f.path)
        var hashed: UInt64 = 0
        let sha: String
        if let knownHash { sha = knownHash } else {
            guard let h = try? FileHasher.sha256(fd: fd, sizeHint: f.size, path: f.path) else {
                close(fd)
                return FileScanOutcome(path: shownPath, cacheHit: false, hashedBytes: 0, skippedReason: "read error")
            }
            sha = h.hex; hashed = h.bytes
        }
        close(fd)

        var facts = FileFacts(path: f.path, size: f.size, sha256: sha, kind: kind,
                              isExecutable: f.isExecutable || kind == .machO || kind == .fatMachO)
        func remember(clean: Bool) {
            guard cacheable else { return }
            let row = ScanCacheEntry(device: f.device, inode: f.inode, size: f.size, mtimeNanos: f.mtimeNanos,
                                     ctimeNanos: f.ctimeNanos, sha256: sha, version: version, clean: clean)
            lock.lock(); pendingCache.append(row); let n = pendingCache.count; lock.unlock()
            if n >= 512 { flushCache() }
        }

        if database?.isAllowed(sha256: sha) == true {
            remember(clean: true)
            return FileScanOutcome(path: shownPath, facts: facts, cacheHit: false, hashedBytes: hashed, skippedReason: "allowlisted")
        }

        for e in pipeline.enrichers { e.enrich(&facts) }
        var evidence: [Evidence] = []
        for d in pipeline.detectors { evidence += d.inspect(facts) }
        evidence = Scoring.applyTrustPrior(Scoring.normalize(evidence, signing: facts.signing), signing: facts.signing)

        // Containers: scan members and attribute their evidence to the container.
        if opts.unpackArchives, depth < opts.archiveLimits.maxDepth, ArchiveUnpacker.canUnpack(kind),
           kind != .dmg || opts.unpackDiskImages {
            evidence += scanContainer(f, kind: kind, opts: opts, version: version, pipeline: pipeline,
                                      depth: depth, shownPath: shownPath, hashed: &hashed)
        }

        let detection = Scoring.makeDetection(path: shownPath, sha256: depth == 0 ? sha : nil, evidence: evidence)
        remember(clean: detection == nil)
        return FileScanOutcome(path: shownPath, detection: detection, facts: facts, cacheHit: false,
                               hashedBytes: hashed, skippedReason: nil)
    }

    private func scanContainer(_ f: WalkedFile, kind: FileKind, opts: ScanOptions, version: String,
                               pipeline: Pipeline, depth: Int, shownPath: String, hashed: inout UInt64) -> [Evidence] {
        let unpacker = ArchiveUnpacker(limits: opts.archiveLimits)
        let container: UnpackedContainer
        do { container = try unpacker.unpack(path: f.path, kind: kind, size: f.size) } catch {
            log.debug("not expanded \(f.path, privacy: .public): \(String(describing: error), privacy: .public)")
            return []
        }
        defer { container.cleanup() }
        var memberWalk = opts.walk
        memberWalk.excludedPrefixes = []
        memberWalk.stayOnDevice = true
        var files = 0
        var bytes: UInt64 = 0
        var found: [Evidence] = []
        let rootLen = container.root.count
        FileWalker.walk(roots: [container.root], options: memberWalk) { m in
            files += 1; bytes += m.size
            if files > opts.archiveLimits.maxFiles || bytes > opts.archiveLimits.maxExpandedBytes { return false }
            let rel = String(m.path.dropFirst(rootLen)).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            let shown = shownPath + "!/" + rel
            let out = scanWalked(m, opts: opts, version: version, pipeline: pipeline, depth: depth + 1, displayPath: shown)
            hashed += out.hashedBytes
            if let d = out.detection {
                for e in d.evidence where e.score >= Scoring.logThreshold {
                    var e2 = e
                    if !e2.detail.hasPrefix("Inside ") { e2.detail = "Inside \(kind.rawValue) member \(rel): " + e2.detail }
                    found.append(e2)
                }
            }
            return found.count < 32
        }
        return found
    }
}

private struct HardLinkKey: Hashable { var dev: Int64; var ino: UInt64 }

/// Aggregates worker results; all access under one lock.
private final class ScanState: @unchecked Sendable {
    private let lock = NSLock()
    private var r = ScanReport()
    private var discoveredCount = 0
    private var walkFinished = false
    private var lastProgress = Date.distantPast
    private var current = ""

    func discovered() { lock.lock(); discoveredCount += 1; lock.unlock() }
    func walkDone() { lock.lock(); walkFinished = true; lock.unlock() }

    func record(_ o: FileScanOutcome, interval: TimeInterval) -> ScanProgress? {
        lock.lock()
        if o.skippedReason != nil && o.facts == nil { r.skipped += 1 } else { r.scanned += 1 }
        if o.cacheHit { r.cacheHits += 1 }
        r.bytesHashed += o.hashedBytes
        if let d = o.detection { r.detections.append(d) }
        current = o.path
        lock.unlock()
        return progress(current: o.path, force: false, interval: interval)
    }

    func progress(current: String, force: Bool, interval: TimeInterval = 0) -> ScanProgress? {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        guard force || now.timeIntervalSince(lastProgress) >= interval else { return nil }
        lastProgress = now
        return ScanProgress(scanned: r.scanned + r.skipped, discovered: discoveredCount, current: current,
                            detections: r.detections.count, walkFinished: walkFinished)
    }

    func report() -> ScanReport { lock.lock(); defer { lock.unlock() }; return r }
}

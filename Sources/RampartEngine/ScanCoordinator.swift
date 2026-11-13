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
    /// Directory walks triage files (`ScanTriage`): only executable / payload-capable files get hashing + YARA.
    /// Explicitly named files and `scanFile` always get the full pipeline.
    public var triage = true
    /// Hard wall-time limit per walked file (0 = none). A file that exceeds it is abandoned and counted
    /// as "couldn't be scanned (timed out)" so a scan always finishes.
    public var perFileDeadline: TimeInterval = 20
    public init() {}

    /// Locations a quick scan covers for the current user (existing ones only).
    public static func quickScanRoots(home: String = NSHomeDirectory()) -> [String] {
        let candidates = [
            home + "/Downloads", home + "/Desktop", home + "/Library/LaunchAgents",
            home + "/Library/Application Support", "/Applications", "/Library/LaunchAgents",
            "/Library/LaunchDaemons", "/Library/Application Support", "/Users/Shared", "/private/tmp", "/private/var/tmp",
        ] + persistenceRoots(home: home)
        return candidates.filter { FileManager.default.fileExists(atPath: $0) }
    }

    /// wms-o10: places persistence and plug-ins live that a quick scan used to miss: privileged helpers, startup
    /// items, authorization plug-ins, plug-in folders system processes load from, kernel extensions, user scripts,
    /// and unfamiliar hidden folders at the top of the home folder (a favourite hiding place). Known large
    /// tool caches are left to full scans. Existing paths only.
    public static func persistenceRoots(home: String) -> [String] {
        var out = ["/Library/PrivilegedHelperTools", "/Library/StartupItems", "/Library/Security/SecurityAgentPlugins",
                   "/Library/DirectoryServices/PlugIns", "/Library/Extensions", "/Library/Audio/Plug-Ins", "/Library/Internet Plug-Ins",
                   "/Library/Scripts", "/private/var/root/.ssh"]
        for base in ["/Library", home + "/Library"] {
            out += ["Spotlight", "QuickLook", "Screen Savers", "ColorPickers", "Input Methods", "PreferencePanes"].map { base + "/" + $0 }
        }
        out += [home + "/Library/Scripts", home + "/Library/Internet Plug-Ins", home + "/.config/fish"]
        out += hiddenHomeFolders(home: home)
        return out.filter { FileManager.default.fileExists(atPath: $0) }
    }

    /// Big, well-known tool caches skipped by the quick scan's hidden-folder sweep (a full scan still covers them).
    public static let quickSkipDotDirs: Set<String> = [
        ".Trash", ".cache", ".npm", ".cargo", ".rustup", ".gradle", ".m2", ".nvm", ".pyenv", ".rbenv", ".docker", ".vscode",
        ".vscode-server", ".cursor", ".swiftpm", ".bun", ".deno", ".conda", ".pnpm-store", ".yarn", ".volta", ".sdkman", ".android",
        ".lima", ".colima", ".gem", ".git", ".oh-my-zsh", ".nix-profile", ".ollama", ".minikube", ".vagrant.d", ".terraform.d",
        ".rye", ".julia", ".ghcup", ".stack", ".opam", ".platformio", ".espressif", ".arduino15", ".claude", ".codex", ".Spotlight-V100",
        ".fseventsd", ".DocumentRevisions-V100", ".TemporaryItems", ".Trashes", ".local", ".gnupg", ".zsh_sessions", ".dartServer", ".pub-cache",
        ".kube", ".aws", ".azure", ".config", ".expo", ".gemini", ".ipython", ".jupyter", ".keras", ".matplotlib", ".mozbuild", ".node-gyp",
        ".nuget", ".dotnet", ".sonarlint", ".vscode-insiders", ".windsurf", ".zed",
    ]

    public static func hiddenHomeFolders(home: String) -> [String] {
        let fm = FileManager.default
        return ((try? fm.contentsOfDirectory(atPath: home)) ?? []).sorted().compactMap { n in
            guard n.hasPrefix("."), n.count > 1, !quickSkipDotDirs.contains(n) else { return nil }
            var st = stat()
            let p = home + "/" + n
            guard lstat(p, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { return nil }
            return p
        }
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
    /// Files abandoned at the per-file deadline so far.
    public var timedOut: Int = 0
    /// Seconds since a file last finished (large while one big or stuck file is being checked).
    public var secondsSinceLastCompletion: Double = 0
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
    /// True if the file took the cheap triage path.
    public var triaged: Bool = false
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
    /// Files that got the cheap triage path (no YARA; hashed only when small).
    public var triaged = 0
    /// Files abandoned at the per-file deadline ("couldn't be scanned (timed out)").
    public var timedOut = 0
    public var timedOutPaths: [String] = []
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
        var d: [FileDetector] = [EICARDetector(), PackedMachODetector()]
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
        // Explicitly named files always get the full pipeline; only walked directory contents are triaged.
        let explicitFiles = Set(paths.filter { p in var st = stat(); return lstat(p, &st) == 0 && st.isRegular })
        let pool = WorkerPool()

        func startWorker() {
            group.enter()
            let slot = pool.newSlot()
            let t = Thread { [self] in
                while let f = queue.pop() {
                    if cancel?.isCancelled == true { continue }
                    guard pool.begin(slot, f) else { return }   // abandoned (cannot happen before begin)
                    let triage = opts.triage && !explicitFiles.contains(f.path)
                    let out = self.scanWalked(f, opts: opts, version: version, pipeline: snapshot, depth: 0,
                                              displayPath: nil, triage: triage)
                    // If the watchdog abandoned this file, it already recorded the timeout, left the group
                    // and started a replacement worker: drop the late result and let this thread end.
                    guard pool.end(slot) else { return }
                    let p = state.record(out, interval: opts.progressInterval)
                    if let p, let progress { progress(p) }
                }
                if pool.retire(slot) { group.leave() }
            }
            t.stackSize = 1 << 20
            t.qualityOfService = .utility
            t.start()
        }
        for _ in 0..<workers { startWorker() }

        // Watchdog: enforce the per-file wall-time deadline so one stuck file can't hang the scan.
        let watchdogDone = DispatchSemaphore(value: 0)
        let finished = ScanCancellation()
        let wake = DispatchSemaphore(value: 0)      // ends the watchdog's sleep as soon as the scan is done
        if opts.perFileDeadline > 0 {
            let deadline = opts.perFileDeadline
            let tick = min(1.0, max(0.05, deadline / 4))
            let w = Thread {
                while !finished.isCancelled {
                    _ = wake.wait(timeout: .now() + tick)
                    for f in pool.abandonOverdue(deadline: deadline) {
                        self.log.error("scan: gave up on \(f.path, privacy: .public) after \(deadline, format: .fixed(precision: 0))s")
                        let out = FileScanOutcome(path: f.path, cacheHit: false, hashedBytes: 0, skippedReason: "timed out")
                        if let p = state.record(out, interval: opts.progressInterval), let progress { progress(p) }
                        startWorker()          // keep the pool at full strength
                        group.leave()          // on behalf of the stuck worker
                    }
                }
                watchdogDone.signal()
            }
            w.qualityOfService = .utility
            w.start()
        } else { watchdogDone.signal() }

        var seen = Set<HardLinkKey>()
        let walkStats = FileWalker.walk(roots: paths, options: opts.walk, cancel: cancel) { f in
            if f.linkCount > 1 {
                if !seen.insert(HardLinkKey(dev: f.device, ino: f.inode)).inserted { return true }
            }
            state.discovered()
            return queue.push(f)
        }
        state.walkDone()
        // Tell the UI right away that the total is final ("Finding files…" -> real percentage).
        if let progress, let p = state.progress(current: "", force: true) { progress(p) }
        queue.close()
        group.wait()
        finished.cancel()
        wake.signal()
        watchdogDone.wait()
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
        // RamPart's own data (quarantine vault, state) is never scanned, whoever asks.
        if OwnData.contains(path) {
            return FileScanOutcome(path: path, cacheHit: false, hashedBytes: 0, skippedReason: "RamPart data folder")
        }
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
        let out = scanWalked(f, opts: opts, version: cacheVersion, pipeline: currentPipeline(), depth: 0, displayPath: nil, triage: false)
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
                            depth: Int, displayPath: String?, triage: Bool) -> FileScanOutcome {
        let shownPath = displayPath ?? f.path
        if depth == 0, OwnData.contains(f.path) {
            return FileScanOutcome(path: shownPath, cacheHit: false, hashedBytes: 0, skippedReason: "RamPart data folder")
        }
        if f.isDataless && opts.walk.skipDataless {
            return FileScanOutcome(path: shownPath, cacheHit: false, hashedBytes: 0, skippedReason: "dataless")
        }
        if f.size > opts.walk.maxFileSize {
            return FileScanOutcome(path: shownPath, cacheHit: false, hashedBytes: 0, skippedReason: "too large")
        }

        // Cache: identical (dev, ino, size, mtime, ctime). Same version + clean => skip; otherwise reuse the hash.
        // Rows written by the triage (light) path carry a "|light" version and only satisfy triaged walks:
        // real-time / explicit scans never trust them. Any change to content, mode bits or xattrs (e.g. an exec
        // bit or quarantine flag that would upgrade the file to the full path) changes ctime and misses the cache.
        let cacheable = depth == 0 && opts.useCache && database != nil
        let lightVersion = version + "|light"
        var knownHash: String?
        if cacheable, let e = database!.cacheEntry(device: f.device, inode: f.inode),
           e.size == f.size, e.mtimeNanos == f.mtimeNanos, e.ctimeNanos == f.ctimeNanos {
            if e.clean && (e.version == version || (triage && e.version == lightVersion)) {
                return FileScanOutcome(path: shownPath, facts: nil, cacheHit: true, hashedBytes: 0, skippedReason: nil)
            }
            if !e.sha256.isEmpty { knownHash = e.sha256 }
        }

        // O_NONBLOCK: a FIFO/device swapped in after the walk can't block open(); fstat below rejects it before any read.
        let fd = open(f.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            return FileScanOutcome(path: shownPath, cacheHit: false, hashedBytes: 0, skippedReason: "unreadable (errno \(errno))")
        }
        var fst = stat()
        guard fstat(fd, &fst) == 0, fst.isRegular, !(opts.walk.skipDataless && fst.st_flags & kSFDataless != 0) else {
            close(fd)
            return FileScanOutcome(path: shownPath, cacheHit: false, hashedBytes: 0, skippedReason: "not a regular local file")
        }
        let (kind, header) = FileSniffer.sniff(fd: fd, size: f.size, path: f.path)
        let plan = triage
            ? ScanTriage.plan(path: f.path, kind: kind, header: header, size: f.size, executable: f.isExecutable,
                              quarantined: { ScanTriage.hasQuarantine(fd: fd) })
            : .full
        var hashed: UInt64 = 0
        var sha: String?
        if let knownHash { sha = knownHash } else if plan.hash {
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
                                     ctimeNanos: f.ctimeNanos, sha256: sha ?? "", version: plan.full ? version : lightVersion,
                                     clean: clean)
            lock.lock(); pendingCache.append(row); let n = pendingCache.count; lock.unlock()
            if n >= 512 { flushCache() }
        }

        if let sha, database?.isAllowed(sha256: sha) == true {
            remember(clean: true)
            return FileScanOutcome(path: shownPath, facts: facts, cacheHit: false, hashedBytes: hashed, skippedReason: "allowlisted")
        }

        for e in pipeline.enrichers { e.enrich(&facts) }
        var evidence: [Evidence] = []
        for d in pipeline.detectors where plan.yara || d.name != "yara" { evidence += d.inspect(facts) }
        evidence = Scoring.applyTrustPrior(Scoring.normalize(evidence, signing: facts.signing), signing: facts.signing)

        // Containers: scan members and attribute their evidence to the container. A container we can't open
        // (encrypted, over a limit, corrupt, unknown compression, nested too deep) is never silently clean.
        if plan.full, opts.unpackArchives, opts.archiveLimits.maxDepth > 0, ArchiveUnpacker.canUnpack(kind),
           kind != .dmg || opts.unpackDiskImages {
            if depth < opts.archiveLimits.maxDepth {
                evidence += scanContainer(f, kind: kind, opts: opts, version: version, pipeline: pipeline,
                                          depth: depth, shownPath: shownPath, hashed: &hashed)
            } else {
                let e = ContainerUnreadable(reason: .tooDeep, format: ArchiveFormat.detect(header: header, path: f.path),
                                            detail: "more than \(opts.archiveLimits.maxDepth) levels")
                if let n = ContainerRisk.evidence(for: e, displayPath: shownPath, origin: ContainerRisk.origin(of: ContainerRisk.outerPath(shownPath))) {
                    evidence.append(n)
                }
            }
        }
        // Scripts that unpack and run hidden code ("runs only when decompressed"): flag the pattern and scan the payload.
        if plan.full, EmbeddedPayload.applies(kind: kind, path: f.path, executable: f.isExecutable, header: header, nested: depth > 0) {
            evidence += scanEmbedded(f, opts: opts, version: version, pipeline: pipeline, depth: depth, shownPath: shownPath, hashed: &hashed)
        }

        let detection = Scoring.makeDetection(path: shownPath, sha256: depth == 0 ? sha : nil, evidence: evidence)
        remember(clean: detection == nil)
        return FileScanOutcome(path: shownPath, detection: detection, facts: facts, cacheHit: false,
                               hashedBytes: hashed, skippedReason: nil, triaged: !plan.full)
    }

    private func scanContainer(_ f: WalkedFile, kind: FileKind, opts: ScanOptions, version: String,
                               pipeline: Pipeline, depth: Int, shownPath: String, hashed: inout UInt64) -> [Evidence] {
        let unpacker = ArchiveUnpacker(limits: opts.archiveLimits)
        let container: UnpackedContainer
        do { container = try unpacker.unpack(path: f.path, kind: kind, size: f.size) } catch let e as ContainerUnreadable {
            log.debug("not expanded \(f.path, privacy: .public): \(e.description, privacy: .public)")
            let origin = ContainerRisk.origin(of: ContainerRisk.outerPath(shownPath))
            return ContainerRisk.evidence(for: e, displayPath: shownPath, origin: origin).map { [$0] } ?? []
        } catch {
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
        var names: [String] = []
        var stopped: ContainerUnreadable.Reason?
        let rootLen = container.root.count
        FileWalker.walk(roots: [container.root], options: memberWalk) { m in
            files += 1; bytes += m.size
            if files > opts.archiveLimits.maxFiles { stopped = .tooManyFiles; return false }
            if bytes > opts.archiveLimits.maxExpandedBytes { stopped = .bomb; return false }
            let rel = String(m.path.dropFirst(rootLen)).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            let shown = shownPath + "!/" + rel
            if names.count < 500 { names.append(rel) }
            let out = scanWalked(m, opts: opts, version: version, pipeline: pipeline, depth: depth + 1, displayPath: shown, triage: false)
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
        if let stopped {
            let e = ContainerUnreadable(reason: stopped, format: container.format,
                                        detail: stopped == .bomb ? "expanded past \(ArchiveUnpacker.mb(opts.archiveLimits.maxExpandedBytes))"
                                                                 : "more than \(opts.archiveLimits.maxFiles) members", memberNames: names)
            if let n = ContainerRisk.evidence(for: e, displayPath: shownPath, origin: ContainerRisk.origin(of: ContainerRisk.outerPath(shownPath))) {
                found.append(n)
            }
        }
        return found
    }

    /// Analyses a script for run-time unpacking, extracts embedded payloads into a private temp dir and scans them.
    private func scanEmbedded(_ f: WalkedFile, opts: ScanOptions, version: String, pipeline: Pipeline, depth: Int,
                              shownPath: String, hashed: inout UInt64) -> [Evidence] {
        let cap = min(ArchiveUnpacker.streamCap(size: f.size, limits: opts.archiveLimits), 256 << 20)
        let r = EmbeddedPayload.analyze(path: f.path, size: f.size, cap: cap)
        var found = r.evidence
        guard !r.payloads.isEmpty, opts.unpackArchives else { return found }
        guard depth < opts.archiveLimits.maxDepth else {
            if !found.isEmpty, let n = ContainerRisk.evidence(
                for: ContainerUnreadable(reason: .tooDeep, format: .unknown, detail: "payload nested more than \(opts.archiveLimits.maxDepth) levels"),
                displayPath: shownPath, origin: ContainerRisk.origin(of: ContainerRisk.outerPath(shownPath))) { found.append(n) }
            return found
        }
        let root = ArchiveUnpacker(limits: opts.archiveLimits).tempRoot
        let dir = (root as NSString).appendingPathComponent(UUID().uuidString)
        let fm = FileManager.default
        guard (try? fm.createDirectory(atPath: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])) != nil,
              (try? fm.createDirectory(atPath: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])) != nil else { return found }
        defer { try? fm.removeItem(atPath: dir) }
        for (i, p) in r.payloads.enumerated() {
            let file = (dir as NSString).appendingPathComponent("embedded-\(i + 1)")
            guard fm.createFile(atPath: file, contents: p.data, attributes: [.posixPermissions: 0o600]),
                  let m = WalkedFile.stat(path: file) else { continue }
            let out = scanWalked(m, opts: opts, version: version, pipeline: pipeline, depth: depth + 1,
                                 displayPath: shownPath + "!/" + p.label, triage: false)
            hashed += out.hashedBytes
            for e in out.detection?.evidence ?? [] where e.score >= Scoring.logThreshold {
                var e2 = e
                if !e2.detail.hasPrefix("Inside ") { e2.detail = "Inside the \(p.label) of this script: " + e2.detail }
                found.append(e2)
            }
            try? fm.removeItem(atPath: file)
            if found.count >= 32 { break }
        }
        return found
    }
}

private struct HardLinkKey: Hashable { var dev: Int64; var ino: UInt64 }

/// Tracks what each scan worker is doing so the watchdog can abandon files past the per-file deadline.
private final class WorkerPool: @unchecked Sendable {
    final class Slot { var file: WalkedFile?; var started = Date(); var abandoned = false }
    private let lock = NSLock()
    private var slots: [ObjectIdentifier: Slot] = [:]

    func newSlot() -> Slot { let s = Slot(); lock.lock(); slots[ObjectIdentifier(s)] = s; lock.unlock(); return s }
    /// Marks `f` as in progress. False if the slot was abandoned.
    func begin(_ s: Slot, _ f: WalkedFile) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if s.abandoned { return false }
        s.file = f; s.started = Date(); return true
    }
    /// Marks the current file done. False if the watchdog abandoned it meanwhile (the thread must exit).
    func end(_ s: Slot) -> Bool {
        lock.lock(); defer { lock.unlock() }
        s.file = nil
        if s.abandoned { slots[ObjectIdentifier(s)] = nil; return false }
        return true
    }
    /// Worker is exiting normally. True if it still owns its group membership.
    func retire(_ s: Slot) -> Bool {
        lock.lock(); defer { lock.unlock() }
        slots[ObjectIdentifier(s)] = nil
        return !s.abandoned
    }
    /// Abandons every slot whose file has run past `deadline`; returns those files.
    func abandonOverdue(deadline: TimeInterval) -> [WalkedFile] {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        var out: [WalkedFile] = []
        for s in slots.values where !s.abandoned {
            if let f = s.file, now.timeIntervalSince(s.started) > deadline { s.abandoned = true; out.append(f) }
        }
        return out
    }
}

/// Aggregates worker results; all access under one lock.
private final class ScanState: @unchecked Sendable {
    private let lock = NSLock()
    private var r = ScanReport()
    private var discoveredCount = 0
    private var walkFinished = false
    private var lastProgress = Date.distantPast
    private var lastCompletion = Date()
    private var current = ""

    func discovered() { lock.lock(); discoveredCount += 1; lock.unlock() }
    func walkDone() { lock.lock(); walkFinished = true; lock.unlock() }

    func record(_ o: FileScanOutcome, interval: TimeInterval) -> ScanProgress? {
        lock.lock()
        if o.skippedReason == "timed out" {
            r.timedOut += 1; if r.timedOutPaths.count < 100 { r.timedOutPaths.append(o.path) }
        }
        if o.skippedReason != nil && o.facts == nil { r.skipped += 1 } else { r.scanned += 1 }
        if o.cacheHit { r.cacheHits += 1 }
        if o.triaged { r.triaged += 1 }
        lastCompletion = Date()
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
                            detections: r.detections.count, walkFinished: walkFinished, timedOut: r.timedOut,
                            secondsSinceLastCompletion: now.timeIntervalSince(lastCompletion))
    }

    func report() -> ScanReport { lock.lock(); defer { lock.unlock() }; return r }
}

import Foundation
import RampartShared

/// Snapshot for IPC (`IPCResponse.deception(Data)` = JSON of this) and the app's Cat & Mouse screen.
public struct DeceptionStatus: Codable, Hashable, Sendable {
    public var config: DeceptionConfig
    public var decoys: [DecoyRecord]
    public var catches: [DeceptionCatch]
    public var tarpitAttempts: [TarpitAttempt]
    public var tarpitListening: Bool
    public var readDetectionAvailable: Bool   // reads are seen (eslogger, or decoy access times in user mode)
    public var notes: [String]
    /// Paths RamPart's own walkers and cleaners must skip (decoys + maze roots). Optional: older helpers omit it.
    public var exclusions: [String]? = nil
    /// Why the lure isn't listening although it is switched on (e.g. "port 2222 is already in use"). nil = fine.
    public var tarpitError: String? = nil
    /// Decoys and maze folders currently watched (kqueue + access-time polling).
    public var watching: Int? = nil
    /// True when the RamPart system service (eslogger) can tell which program touched a decoy.
    public var attributionAvailable: Bool? = nil
    /// Notifications for the app to post (latest 50): one per catch story / lure knock, newest last.
    public var alerts: [CatMouseAlert]? = nil
}

/// The daemon-side orchestrator. Wiring (see report): feed every SecurityEvent to `handle`, route returned
/// detections into the normal pipeline (≥90 = auto-quarantine per policy), call `markContained` after remediation.
public final class DeceptionService: @unchecked Sendable {
    public let directory: URL
    public let registry: DecoyRegistry
    public let detector: DeceptionDetector
    public let log = DeceptionEventLog()
    let tagger: DecoyTagger
    public let home: String
    private let lock = NSLock()
    private(set) public var config: DeceptionConfig
    private var catches: [DeceptionCatch] = []
    private var decoySizes: [String: Int64] = [:]
    private var tarpit: TarpitServer?
    private var tarpitError: String?
    private var tarpitHistory: [TarpitAttempt] = []
    private var tarpitRetry: DispatchSourceTimer?
    /// Reads are detected: in user mode from decoy access times (DecoyWatcher), as root also via eslogger.
    public var readDetectionAvailable = true
    /// The system service reports the actor (eslogger here, or forwarded by the root daemon).
    public var attributionAvailable = false
    /// Watches decoys without eslogger: kqueue for writes/renames/deletes, access times for reads.
    public let watcher: DecoyWatcher
    /// Paths of RamPart itself (never a catch when found holding a decoy open).
    public let ownPaths: [String]
    private var pendingMessages: [DeceptionMessage] = []
    private var planner = CatMouseAlertPlanner()
    private var alerts: [CatMouseAlert] = []
    private var pendingAlerts: [CatMouseAlert] = []
    /// Every catch and every lure attempt that wasn't refused produces one alert (the app posts it as a macOS
    /// notification). Alerts raised before this is set are delivered when it is.
    public var onAlert: (@Sendable (CatMouseAlert) -> Void)? {
        didSet { lock.lock(); let p = pendingAlerts; pendingAlerts = []; let n = onAlert; lock.unlock(); if let n { p.forEach(n) } }
    }
    private var pendingDetections: [Detection] = []
    private var unattributedMaze: [String: Date] = [:]
    /// Catches are posted here (Activity in the daemon). Messages raised before it is set are delivered when it is.
    public var notify: (@Sendable (DeceptionMessage) -> Void)? {
        didSet { lock.lock(); let p = pendingMessages; pendingMessages = []; let n = notify; lock.unlock(); if let n { p.forEach(n) } }
    }
    /// Detections from catches the watcher attributed (a program found holding the decoy, still running).
    public var onDetection: (@Sendable (Detection) -> Void)? {
        didSet { lock.lock(); let p = pendingDetections; pendingDetections = []; let n = onDetection; lock.unlock(); if let n { p.forEach(n) } }
    }
    /// Layer 10: lure attempts as normal detections; watchdog escapes as Emergency Lockdown requests.
    public var onLureDetection: (@Sendable (Detection) -> Void)?
    public var onEmergency: (@Sendable (String) -> Void)?

    /// `directory`: e.g. ~/Library/Application Support/RamPart/deception (user mode) or /Library/... (root).
    /// `home`: the user whose folders get decoys. Tests pass scratch folders for both.
    /// Applies the persisted settings at once (`applyPersisted`): watchers start when decoys or the maze are on,
    /// and the lure starts listening when it is on. A failed bind is kept as `tarpitError` (status shows it) and
    /// retried every 30 s; it never stops the daemon.
    public init(directory: URL, home: String, ownPaths: [String] = [], pollInterval: TimeInterval = 2, applyPersisted: Bool = true) throws {
        self.directory = directory; self.home = home; self.ownPaths = ownPaths
        tagger = try DecoyTagger.loadOrCreateKey(at: directory.appendingPathComponent("decoy.key"))
        registry = DecoyRegistry(url: directory.appendingPathComponent("decoys.json"))
        detector = DeceptionDetector(registry: registry, ownPaths: ownPaths)
        watcher = DecoyWatcher(registry: registry, interval: pollInterval, armedURL: directory.appendingPathComponent("armed.json"))
        config = (try? Data(contentsOf: directory.appendingPathComponent("config.json")))
            .flatMap { try? JSONDecoder.deception.decode(DeceptionConfig.self, from: $0) } ?? DeceptionConfig()
        catches = (try? Data(contentsOf: directory.appendingPathComponent("catches.json")))
            .flatMap { try? JSONDecoder.deception.decode([DeceptionCatch].self, from: $0) } ?? []
        tarpitHistory = (try? Data(contentsOf: directory.appendingPathComponent("tarpit.json")))
            .flatMap { try? JSONDecoder.deception.decode([TarpitAttempt].self, from: $0) } ?? []
        watcher.onTouch = { [weak self] t in self?.ingest(t) }
        if applyPersisted { applyPersistedConfig() }
    }

    deinit { tarpitRetry?.cancel(); tarpit?.stop(); watcher.stop() }

    /// Stops the lure and the watchers (daemon exit, tests simulating a restart). Settings are kept.
    public func shutdown() { stopTarpit(); watcher.stop() }

    /// Starts what the saved config says is on (called by init; safe to call again).
    public func applyPersistedConfig() {
        lock.lock(); let c = config; let listening = tarpit != nil; lock.unlock()
        // "Decoys on" with nothing planted (fresh state, or decoys.json lost): plant them now, never overwriting.
        if c.decoysEnabled, !registry.all.contains(where: { $0.kind.isFile && $0.kind != .mazeNote }) {
            var pl = planter; pl.hideFromFinder = !c.decoysVisible; pl.plantDefaults(home: home)
        }
        if c.mazeEnabled, c.decoysEnabled, registry.record(at: mazeRoot) == nil {
            var pl = planter; pl.hideFromFinder = !c.decoysVisible; try? DeceptionMaze.build(at: mazeRoot, planter: pl)
        }
        if c.decoysEnabled || c.mazeEnabled { watcher.start(); watcher.reload() } else { watcher.stop() }
        if c.tarpitEnabled && !listening { startTarpit(c) }
    }

    var planter: DecoyPlanter { DecoyPlanter(registry: registry, tagger: tagger) }
    public var mazeRoot: String { home + "/Documents/Private" }

    func save() {
        lock.lock(); let c = config; let k = catches; lock.unlock()
        try? JSONEncoder.deception.encode(c).write(to: directory.appendingPathComponent("config.json"), options: .atomic)
        try? JSONEncoder.deception.encode(k).write(to: directory.appendingPathComponent("catches.json"), options: .atomic)
    }

    private func emit(_ m: DeceptionMessage) {
        lock.lock(); let n = notify; if n == nil { pendingMessages.append(m); if pendingMessages.count > 50 { pendingMessages.removeFirst() } }; lock.unlock()
        n?(m)
    }
    /// Activity line + notification alert for one catch.
    private func announce(_ c: DeceptionCatch) {
        lock.lock(); let tone = config.tone; lock.unlock()
        emit(c.userOpened ? DeceptionVoice.userOpened(c, tone: tone) : DeceptionVoice.caught(c, tone: tone))
        lock.lock(); let a = planner.alert(for: c, tone: tone); lock.unlock()
        pushAlert(a)
    }
    private func pushAlert(_ a: CatMouseAlert) {
        lock.lock()
        alerts.append(a); if alerts.count > 50 { alerts.removeFirst(alerts.count - 50) }
        let n = onAlert; if n == nil { pendingAlerts.append(a); if pendingAlerts.count > 50 { pendingAlerts.removeFirst() } }
        lock.unlock()
        n?(a)
    }
    private func emitDetection(_ d: Detection) {
        lock.lock(); let n = onDetection; if n == nil { pendingDetections.append(d); if pendingDetections.count > 50 { pendingDetections.removeFirst() } }; lock.unlock()
        n?(d)
    }

    public func status() -> DeceptionStatus {
        lock.lock(); defer { lock.unlock() }
        var notes = ["Decoys are a tripwire: RamPart sees a touch right after it happens and then responds; it cannot block the read itself."]
        if attributionAvailable {
            notes.append("The RamPart system service (with Full Disk Access) reports which program touched a decoy.")
        } else {
            notes.append("Reads, copies, moves and deletes are noticed within about 2 seconds (from the file's access time and file-system events). Without Full Disk Access / the system service RamPart often can't tell which program it was, and says so.")
        }
        let listening = tarpit != nil
        return DeceptionStatus(config: config, decoys: registry.all, catches: Array(catches.suffix(200)),
                               tarpitAttempts: Array(tarpitHistory.suffix(100)), tarpitListening: listening,
                               readDetectionAvailable: readDetectionAvailable, notes: notes,
                               exclusions: DeceptionExclusions.paths(registry: registry),
                               tarpitError: config.tarpitEnabled && !listening ? (tarpitError ?? "The network lure isn't listening yet.") : nil,
                               watching: watcher.watchedCount, attributionAvailable: attributionAvailable, alerts: alerts)
    }

    // MARK: Settings

    public func setDecoys(_ on: Bool) -> DeceptionChangeReport {
        lock.lock(); config.decoysEnabled = on; lock.unlock()
        var rep = DeceptionChangeReport()
        if on { var pl = planter; pl.hideFromFinder = !config.decoysVisible; let o = pl.plantDefaults(home: home); rep.planted = o.planted.count; rep.skipped = o.skipped }
        else { watcher.stop(); let o = planter.removeAll(); rep.removed = o.removed; rep.kept = o.keptBecauseChanged; lock.lock(); config.mazeEnabled = false; lock.unlock() }
        save(); applyPersistedConfig(); return rep
    }

    public func setMaze(_ on: Bool) throws {
        if on {
            guard config.decoysEnabled else { throw DeceptionError.disabled }
            if registry.record(at: mazeRoot) == nil {
                var pl = planter; pl.hideFromFinder = !config.decoysVisible
                try DeceptionMaze.build(at: mazeRoot, planter: pl)
            }
        } else {
            watcher.stop()
            // Remove only maze entries (keep the file decoys).
            let mazeRecords = registry.all.filter { $0.path == mazeRoot || $0.path.hasPrefix(mazeRoot + "/") }
            let other = registry.all.filter { !mazeRecords.contains($0) }
            for r in other { registry.remove(r.path) }
            _ = planter.removeAll()
            for r in other { registry.add(r) }
            try? registry.save()
        }
        lock.lock(); config.mazeEnabled = on; lock.unlock(); save(); applyPersistedConfig()
    }

    /// "Remove all decoys" (also turns decoys and maze off).
    public func removeAll() -> DeceptionChangeReport {
        watcher.stop()
        let o = planter.removeAll()
        lock.lock(); config.decoysEnabled = false; config.mazeEnabled = false; lock.unlock(); save()
        return DeceptionChangeReport(removed: o.removed, kept: o.keptBecauseChanged)
    }

    /// Shows or hides the decoys in Finder (UF_HIDDEN). Applies to decoys already planted, but only to files that
    /// still verify as ours (registry tag + unchanged content); anything else is left exactly as it is.
    /// Returns how many files were changed.
    @discardableResult
    public func setDecoysVisible(_ visible: Bool) -> Int {
        lock.lock(); config.decoysVisible = visible; lock.unlock()
        var changed = 0
        watcher.selfChange {
        for r in registry.all where r.kind != .mazeDir && r.kind != .mazeLink && tagger.verify(r) {
            var st = stat()
            guard lstat(r.path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size < 1 << 20,
                  let d = DecoyPlanter.readNoFollow(r.path), deceptionSHA256(d) == r.contentSHA256 else { continue }
            let flags = visible ? st.st_flags & ~UInt32(UF_HIDDEN) : st.st_flags | UInt32(UF_HIDDEN)
            if flags != st.st_flags, lchflags(r.path, flags) == 0 { changed += 1 }
        }
        }
        save(); return changed
    }

    public func setTone(_ t: DeceptionTone) { lock.lock(); config.tone = t; lock.unlock(); save() }

    /// In-process lure (dev / user mode, loopback). In the root daemon, prefer `lurePlan` (separate sandboxed helper).
    /// Policy refusals (internet exposure without confirmation, low ports) throw. A failed bind does not: the
    /// setting stays on, `status().tarpitError` says why, and the bind is retried every 30 s.
    public func setTarpit(_ on: Bool, port: UInt16? = nil, scope: LureScope = .loopback, localSubnets: [String] = [], confirmedAnywhere: Bool = false) throws {
        if on && scope == .anywhere && !confirmedAnywhere { throw DeceptionError.bindRefused("exposing the lure to the internet needs explicit confirmation") }
        if on, let p = port, p != 0, p < 1024 { throw DeceptionError.bindRefused("lure uses unprivileged high ports only") }
        stopTarpit()
        lock.lock(); config.tarpitEnabled = on; if let p = port { config.tarpitPort = p }; config.lureScope = scope; tarpitError = nil; let c = config; lock.unlock()
        save()
        guard on else { return }
        startTarpit(c, localSubnets: localSubnets, confirmedAnywhere: confirmedAnywhere)
    }

    /// Port the lure is actually bound to (differs from the config only for port 0 in tests).
    public var tarpitBoundPort: UInt16? { lock.lock(); defer { lock.unlock() }; return tarpit?.boundPort }

    private func stopTarpit() {
        lock.lock(); let old = tarpit; tarpit = nil; let r = tarpitRetry; tarpitRetry = nil; lock.unlock()
        r?.cancel(); old?.stop()
    }

    private func startTarpit(_ c: DeceptionConfig, localSubnets: [String] = [], confirmedAnywhere: Bool = false) {
        do {
            let server = try TarpitServer(port: c.tarpitPort, scope: c.lureScope, localSubnets: localSubnets, confirmedAnywhere: confirmedAnywhere,
                                          lineDelay: Self.tarpitLineDelay)
            server.onAttempt = { [weak self] a in self?.recordAttempt(a) }
            try server.start()
            lock.lock(); tarpit = server; tarpitError = nil; let r = tarpitRetry; tarpitRetry = nil; lock.unlock()
            r?.cancel()
        } catch {
            let why = Self.describeBindError(error, port: c.tarpitPort)
            lock.lock(); tarpitError = why; let needRetry = tarpitRetry == nil; lock.unlock()
            if needRetry {
                let t = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
                t.schedule(deadline: .now() + 30, repeating: 30)
                t.setEventHandler { [weak self] in
                    guard let self else { return }
                    self.lock.lock(); let c = self.config; let up = self.tarpit != nil; self.lock.unlock()
                    if !c.tarpitEnabled || up { self.lock.lock(); self.tarpitRetry?.cancel(); self.tarpitRetry = nil; self.lock.unlock(); return }
                    self.startTarpit(c)
                }
                lock.lock(); tarpitRetry = t; lock.unlock()
                t.resume()
            }
        }
    }

    static func describeBindError(_ e: Error, port: UInt16) -> String {
        let text = "\(e)"
        if text.contains("errno \(EADDRINUSE)") { return "Port \(port) is already in use by another program, so the lure can't listen there. Pick another port or close that program; RamPart retries every 30 seconds." }
        if text.contains("errno \(EACCES)") { return "macOS refused port \(port) to the lure." }
        return "The network lure couldn't start: \(text)"
    }

    private func recordAttempt(_ a: TarpitAttempt) {
        lock.lock(); tarpitHistory.append(a); if tarpitHistory.count > 500 { tarpitHistory.removeFirst(tarpitHistory.count - 500) }
        let h = tarpitHistory; let tone = config.tone; lock.unlock()
        try? JSONEncoder.deception.encode(h).write(to: directory.appendingPathComponent("tarpit.json"), options: .atomic)
        if a.refused == nil {
            emit(DeceptionVoice.tarpit(a, tone: tone))
            lock.lock(); let al = planner.alert(for: a, tone: tone); lock.unlock()
            pushAlert(al)
        }
        onLureDetection?(LureContainment.detection(for: a))
    }

    /// Dry-run plan for the production lure (separate sandboxed helper + pf + launchd). Never executed here.
    public func lurePlan(localSubnets: [String]) throws -> LurePlan {
        try LureContainment.plan(port: config.tarpitPort, scope: config.lureScope, localSubnets: localSubnets)
    }

    /// Watchdog tick (layer 9): call with a sample of the helper; kills the lure on any anomaly.
    @discardableResult
    public func watchdog(_ s: LureHealthSample) -> LureWatchdog.Verdict {
        let v = LureWatchdog.evaluate(s)
        if case .kill(let reason, let emergency) = v {
            stopTarpit()
            lock.lock(); config.tarpitEnabled = false; lock.unlock(); save()
            emit(DeceptionMessage(title: config.tone == .playful ? "🐱 The cat closed the trap door" : "Network lure stopped",
                                     body: "The lure was shut down: \(reason).\(emergency ? " Treating this as a possible break-out attempt. Severity: Critical." : " Severity: Medium.")",
                                     severity: emergency ? .critical : .medium))
            if emergency { onEmergency?("Network lure anomaly: \(reason)") }
        }
        return v
    }

    // MARK: Events

    /// Feed every telemetry event. Returns serious detections for the normal pipeline.
    /// Events with an actor (eslogger, or forwarded by the system service) become attributed catches. Actor-less
    /// file events are covered by `watcher` instead (so FSEvents and kqueue never double-report); FSEvents
    /// creates/writes are still checked for a decoy's content landing somewhere else (a copy).
    public func handle(_ e: SecurityEvent) -> [Detection] {
        log.add(e)
        guard config.decoysEnabled || config.mazeEnabled else { return [] }
        if e.process == nil { checkCopyLanding(e); return [] }
        guard let c = detector.evaluate(e) else { return [] }
        lock.lock()
        // The watcher may already have reported this touch without an actor: upgrade that catch in place
        // (same id, so the app doesn't notify twice) instead of adding a second one.
        if let i = catches.lastIndex(where: { ($0.attribution == .unknown || $0.attribution == .commandLine) && $0.decoyPath == c.decoyPath
            && abs($0.date.timeIntervalSince(c.date)) < Self.mergeWindow && Self.sameIncident(existing: $0.access, new: c.access) }) {
            let old = catches[i]
            var up = c; up.id = old.id; up.destPath = c.destPath ?? old.destPath
            if old.access == .copy { up.access = .copy }
            catches[i] = up
            lock.unlock(); save()
            return up.userOpened ? [] : [DeceptionDetector.detection(for: up)]
        }
        catches.append(c); if catches.count > 1000 { catches.removeFirst(catches.count - 1000) }; lock.unlock()
        save()
        announce(c)
        return c.userOpened ? [] : [DeceptionDetector.detection(for: c)]
    }

    /// Seconds within which an actor-less touch and an attributed one of the same decoy are the same incident.
    static let mergeWindow: TimeInterval = 30

    /// Same kind of touch (a copy or a move starts with a read, so a read is part of it).
    static func sameIncident(existing: DeceptionAccess, new: DeceptionAccess) -> Bool {
        existing == new || (new == .read && (existing == .copy || existing == .rename)) || (existing == .read && new == .copy)
    }

    /// Seconds between the lure's reply lines (the tarpit). Tests set 0.
    nonisolated(unsafe) public static var tarpitLineDelay: TimeInterval = 6

    /// A watcher touch (no actor). Attribution: a process holding the decoy open (certain), else a just-started
    /// program whose command line named it (likely), else honestly unknown. RamPart itself and Apple's
    /// indexers are dropped.
    func ingest(_ t: DecoyTouch) {
        lock.lock(); let on = config.decoysEnabled || config.mazeEnabled; lock.unlock()
        guard on else { return }
        var proc: ProcessInfoLite?
        var attribution = DeceptionAttribution.unknown
        if let h = DecoyAttribution.holders(of: [t.path]).first {
            proc = h.process; attribution = .openFile
        } else if !t.whileOffline, let p = DecoyAttribution.commandLine(naming: t.path, before: t.date, log: log) {
            proc = p; attribution = .commandLine
        }
        if let p = proc, DeceptionBenign.isBenign(p, ownPaths: ownPaths) { return }
        let inMaze = registry.mazeRoots.contains { t.path == $0 || t.path.hasPrefix($0 + "/") }
        var access = t.access
        var dead = 0
        // A folder listing with no known program proves nothing: Finder showing ~/Documents, backup tools and
        // `find`/`grep` all walk folders. Maze walks count only when the system service names the program.
        if inMaze, t.kind == .mazeDir, proc == nil { return }
        if inMaze, t.kind == .mazeDir, access == .mazeWalk {
            lock.lock()
            let cutoff = t.date.addingTimeInterval(-600)
            unattributedMaze = unattributedMaze.filter { $0.value > cutoff }
            unattributedMaze[t.path] = t.date; dead = unattributedMaze.count
            lock.unlock()
            if dead % 5 != 1 { return }   // first folder, then every 5th: the timeline isn't flooded
        } else if inMaze, t.kind == .mazeDir, access == .read { access = .mazeWalk }
        let name = proc.map { SafeText.line(($0.path as NSString).lastPathComponent, max: 60) } ?? "unknown program"
        var c = DeceptionCatch(date: t.date, decoyPath: t.path, decoyKind: t.kind, access: access, pid: proc?.pid ?? 0,
                               processPath: proc.map { SafeText.path($0.path) } ?? "", processName: name.isEmpty ? "unknown" : name,
                               signingID: proc?.signingID.map { SafeText.line($0, max: 120) }, teamID: proc?.teamID,
                               destPath: t.destPath, mazeDeadEnds: dead)
        c.attribution = attribution
        if t.whileOffline { c.note = "it happened while RamPart wasn't running" }
        if let p = proc, attribution == .openFile, !inMaze, DeceptionUserOpen.isCalm(p, access: access, destPath: t.destPath, distinctDecoysByPid: 1) { c.userOpened = true }
        lock.lock()
        // An attributed catch (eslogger) of the same decoy already covers this touch: don't report it twice.
        // Same for a repeat of the same unattributed touch within a minute.
        let dup = c.access != .mazeWalk && catches.contains { k in
            k.decoyPath == c.decoyPath && abs(k.date.timeIntervalSince(c.date)) < (k.attribution == .unknown ? 60 : Self.mergeWindow)
                && Self.sameIncident(existing: k.access, new: c.access)
        }
        if dup { lock.unlock(); return }
        catches.append(c); if catches.count > 1000 { catches.removeFirst(catches.count - 1000) }
        lock.unlock()
        save()
        announce(c)
        if c.userOpened { return }
        // Only a program seen holding the decoy open (and still running) goes to the detection pipeline:
        // containment needs a real, certain actor. Everything else is a catch + notification + Activity entry.
        if attribution == .openFile, let p = proc, kill(p.pid, 0) == 0 { emitDetection(DeceptionDetector.detection(for: c)) }
    }

    /// FSEvents create/write/rename-into-place with no actor: if the new file holds exactly a decoy's content (a
    /// copy), record it. The recent read catch of that decoy is upgraded to a copy with the destination.
    func checkCopyLanding(_ e: SecurityEvent) {
        guard e.kind == .fileCreate || e.kind == .fileWrite || e.kind == .fileRename else { return }
        guard let p = e.kind == .fileRename ? e.destPath : e.path, registry.record(at: p) == nil,
              !registry.mazeRoots.contains(where: { p == $0 || p.hasPrefix($0 + "/") }) else { return }
        var st = stat()
        guard lstat(p, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size > 0, st.st_size <= 64 * 1024 else { return }
        let files = registry.all.filter { $0.kind.isFile }
        guard !files.isEmpty else { return }
        lock.lock(); var sizes = decoySizes; lock.unlock()
        if sizes.isEmpty || sizes.count != files.count {
            sizes = [:]
            for r in files { var s2 = stat(); if lstat(r.path, &s2) == 0 { sizes[r.path] = s2.st_size } }
            lock.lock(); decoySizes = sizes; lock.unlock()
        }
        let candidates = files.filter { sizes[$0.path] == st.st_size }
        guard !candidates.isEmpty, let data = DecoyPlanter.readNoFollow(p) else { return }
        let hash = deceptionSHA256(data)
        guard let r = candidates.first(where: { $0.contentSHA256 == hash }) else { return }
        lock.lock()
        if let i = catches.lastIndex(where: { $0.decoyPath == r.path && e.date.timeIntervalSince($0.date) < 120 && ($0.access == .read || $0.access == .copy) && $0.destPath == nil }) {
            catches[i].access = .copy; catches[i].destPath = SafeText.path(p)
            lock.unlock(); save(); return
        }
        if catches.contains(where: { $0.decoyPath == r.path && $0.destPath == SafeText.path(p) && e.date.timeIntervalSince($0.date) < 120 }) { lock.unlock(); return }
        var c = DeceptionCatch(date: e.date, decoyPath: r.path, decoyKind: r.kind, access: .copy, pid: 0, processPath: "", processName: "unknown program",
                               signingID: nil, teamID: nil, destPath: SafeText.path(p))
        c.attribution = .unknown
        if let pr = DecoyAttribution.commandLine(naming: r.path, before: e.date, window: 30, log: log), !DeceptionBenign.isBenign(pr, ownPaths: ownPaths) {
            c.pid = pr.pid; c.processPath = SafeText.path(pr.path); c.processName = SafeText.line((pr.path as NSString).lastPathComponent, max: 60)
            c.attribution = .commandLine
        }
        catches.append(c)
        lock.unlock()
        save()
        announce(c)
    }

    /// "Contain it" (notification action / Cat & Mouse screen): stops the program a catch names, only if it is
    /// still the same running program, isn't RamPart or an Apple indexer, and isn't pid 0/1.
    public func contain(catchID: UUID) throws -> DeceptionCatch {
        lock.lock(); let c = catches.first { $0.id == catchID }; lock.unlock()
        guard let c else { throw DeceptionError.io("no such catch") }
        guard c.pid > 1, c.pid != getpid(), !c.isUnattributed else { throw DeceptionError.io("RamPart doesn't know which program it was, so there is nothing to stop") }
        guard let now = DecoyAttribution.processInfo(c.pid), SafeText.path(now.path) == c.processPath else {
            throw DeceptionError.io("\(c.processName) is no longer running")
        }
        guard !DeceptionBenign.isBenign(now, ownPaths: ownPaths) else { throw DeceptionError.io("refusing to stop a system indexer or RamPart itself") }
        guard kill(c.pid, SIGKILL) == 0 else { throw DeceptionError.io("couldn't stop \(c.processName) (errno \(errno))") }
        markContained(pid: c.pid, quarantineID: nil)
        lock.lock(); let out = catches.first { $0.id == catchID } ?? c; lock.unlock()
        return out
    }

    public func markContained(pid: Int32, quarantineID: UUID?) {
        lock.lock()
        var last: DeceptionCatch?
        for i in catches.indices where catches[i].pid == pid && !catches[i].contained {
            catches[i].contained = true; catches[i].quarantineID = quarantineID; last = catches[i]
        }
        let tone = config.tone
        lock.unlock()
        save()
        if let c = last { emit(DeceptionVoice.contained(c, tone: tone)) }
    }

    public func evidence(catchID: UUID, process: ProcessInfoLite? = nil, ancestors: [ProcessInfoLite] = []) -> DeceptionEvidence? {
        lock.lock(); let c = catches.first { $0.id == catchID }; lock.unlock()
        return c.map { DeceptionStudy.gather($0, process: process, ancestors: ancestors, log: log, registry: registry) }
    }

    /// Keyed, per-install ransomware canaries (replaces RampartBehaviour's fixed canary body/names).
    public func ransomCanaries() -> RansomCanaryRegistry {
        RansomCanaryRegistry(tagger: tagger, url: directory.appendingPathComponent("canaries.json"))
    }
    public var installSeed: UInt64 { tagger.installSeed() }

    /// Paths RamPart's own walkers must skip.
    public var exclusions: [String] { DeceptionExclusions.paths(registry: registry) }
}

public struct DeceptionChangeReport: Codable, Hashable, Sendable {
    public var planted = 0
    public var removed = 0
    public var skipped: [String: String] = [:]
    public var kept: [String] = []
    public init(planted: Int = 0, removed: Int = 0, skipped: [String: String] = [:], kept: [String] = []) {
        self.planted = planted; self.removed = removed; self.skipped = skipped; self.kept = kept
    }
}

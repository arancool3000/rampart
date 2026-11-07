import Foundation
import RampartShared

/// Snapshot for IPC (`IPCResponse.deception(Data)` = JSON of this) and the app's Cat & Mouse screen.
public struct DeceptionStatus: Codable, Hashable, Sendable {
    public var config: DeceptionConfig
    public var decoys: [DecoyRecord]
    public var catches: [DeceptionCatch]
    public var tarpitAttempts: [TarpitAttempt]
    public var tarpitListening: Bool
    public var readDetectionAvailable: Bool   // false without eslogger (FSEvents cannot see reads)
    public var notes: [String]
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
    private var tarpit: TarpitServer?
    public var readDetectionAvailable = false
    public var notify: (@Sendable (DeceptionMessage) -> Void)?
    /// Layer 10: lure attempts as normal detections; watchdog escapes as Emergency Lockdown requests.
    public var onLureDetection: (@Sendable (Detection) -> Void)?
    public var onEmergency: (@Sendable (String) -> Void)?

    /// `directory`: e.g. ~/Library/Application Support/RamPart/deception (user mode) or /Library/... (root).
    /// `home`: the user whose folders get decoys. Tests pass scratch folders for both.
    public init(directory: URL, home: String, ownPaths: [String] = []) throws {
        self.directory = directory; self.home = home
        tagger = try DecoyTagger.loadOrCreateKey(at: directory.appendingPathComponent("decoy.key"))
        registry = DecoyRegistry(url: directory.appendingPathComponent("decoys.json"))
        detector = DeceptionDetector(registry: registry, ownPaths: ownPaths)
        config = (try? Data(contentsOf: directory.appendingPathComponent("config.json")))
            .flatMap { try? JSONDecoder.deception.decode(DeceptionConfig.self, from: $0) } ?? DeceptionConfig()
        catches = (try? Data(contentsOf: directory.appendingPathComponent("catches.json")))
            .flatMap { try? JSONDecoder.deception.decode([DeceptionCatch].self, from: $0) } ?? []
    }

    var planter: DecoyPlanter { DecoyPlanter(registry: registry, tagger: tagger) }
    public var mazeRoot: String { home + "/Documents/Private" }

    func save() {
        lock.lock(); let c = config; let k = catches; lock.unlock()
        try? JSONEncoder.deception.encode(c).write(to: directory.appendingPathComponent("config.json"), options: .atomic)
        try? JSONEncoder.deception.encode(k).write(to: directory.appendingPathComponent("catches.json"), options: .atomic)
    }

    public func status() -> DeceptionStatus {
        lock.lock(); defer { lock.unlock() }
        var notes = ["Decoys are a tripwire: RamPart sees a touch right after it happens and then responds; it cannot block the read itself."]
        if !readDetectionAvailable { notes.append("Read detection needs Full Disk Access for the RamPart helper (eslogger). Without it only copies, renames and deletes are seen.") }
        return DeceptionStatus(config: config, decoys: registry.all, catches: Array(catches.suffix(200)),
                               tarpitAttempts: tarpit?.recorded ?? [], tarpitListening: tarpit != nil,
                               readDetectionAvailable: readDetectionAvailable, notes: notes)
    }

    // MARK: Settings

    public func setDecoys(_ on: Bool) -> DeceptionChangeReport {
        lock.lock(); config.decoysEnabled = on; lock.unlock()
        var rep = DeceptionChangeReport()
        if on { var pl = planter; pl.hideFromFinder = !config.decoysVisible; let o = pl.plantDefaults(home: home); rep.planted = o.planted.count; rep.skipped = o.skipped }
        else { let o = planter.removeAll(); rep.removed = o.removed; rep.kept = o.keptBecauseChanged; lock.lock(); config.mazeEnabled = false; lock.unlock() }
        save(); return rep
    }

    public func setMaze(_ on: Bool) throws {
        if on {
            guard config.decoysEnabled else { throw DeceptionError.disabled }
            if registry.record(at: mazeRoot) == nil { try DeceptionMaze.build(at: mazeRoot, planter: planter) }
        } else {
            // Remove only maze entries (keep the file decoys).
            let mazeRecords = registry.all.filter { $0.path == mazeRoot || $0.path.hasPrefix(mazeRoot + "/") }
            let other = registry.all.filter { !mazeRecords.contains($0) }
            for r in other { registry.remove(r.path) }
            _ = planter.removeAll()
            for r in other { registry.add(r) }
            try? registry.save()
        }
        lock.lock(); config.mazeEnabled = on; lock.unlock(); save()
    }

    /// "Remove all decoys" (also turns decoys and maze off).
    public func removeAll() -> DeceptionChangeReport {
        let o = planter.removeAll()
        lock.lock(); config.decoysEnabled = false; config.mazeEnabled = false; lock.unlock(); save()
        return DeceptionChangeReport(removed: o.removed, kept: o.keptBecauseChanged)
    }

    public func setTone(_ t: DeceptionTone) { lock.lock(); config.tone = t; lock.unlock(); save() }

    /// In-process lure (dev / user mode, loopback). In the root daemon, prefer `lurePlan` (separate sandboxed helper).
    public func setTarpit(_ on: Bool, port: UInt16? = nil, scope: LureScope = .loopback, localSubnets: [String] = [], confirmedAnywhere: Bool = false) throws {
        lock.lock(); let old = tarpit; tarpit = nil; lock.unlock(); old?.stop()
        if on && scope == .anywhere && !confirmedAnywhere { throw DeceptionError.bindRefused("exposing the lure to the internet needs explicit confirmation") }
        lock.lock(); config.tarpitEnabled = on; if let p = port { config.tarpitPort = p }; config.lureScope = scope; let c = config; lock.unlock()
        save()
        guard on else { return }
        let server = try TarpitServer(port: c.tarpitPort, scope: c.lureScope, localSubnets: localSubnets, confirmedAnywhere: confirmedAnywhere)
        server.onAttempt = { [weak self] a in
            guard let self else { return }
            if a.refused == nil { self.notify?(DeceptionVoice.tarpit(a, tone: self.config.tone)) }
            self.onLureDetection?(LureContainment.detection(for: a))
        }
        try server.start()
        lock.lock(); tarpit = server; lock.unlock()
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
            lock.lock(); let t = tarpit; tarpit = nil; config.tarpitEnabled = false; lock.unlock(); t?.stop(); save()
            notify?(DeceptionMessage(title: config.tone == .playful ? "🐱 The cat closed the trap door" : "Network lure stopped",
                                     body: "The lure was shut down: \(reason).\(emergency ? " Treating this as a possible break-out attempt. Severity: Critical." : " Severity: Medium.")",
                                     severity: emergency ? .critical : .medium))
            if emergency { onEmergency?("Network lure anomaly: \(reason)") }
        }
        return v
    }

    // MARK: Events

    /// Feed every telemetry event. Returns serious detections for the normal pipeline.
    public func handle(_ e: SecurityEvent) -> [Detection] {
        log.add(e)
        guard config.decoysEnabled || config.mazeEnabled, let c = detector.evaluate(e) else { return [] }
        lock.lock(); catches.append(c); if catches.count > 1000 { catches.removeFirst(catches.count - 1000) }; let tone = config.tone; lock.unlock()
        save()
        if c.userOpened { notify?(DeceptionVoice.userOpened(c, tone: tone)); return [] }
        notify?(DeceptionVoice.caught(c, tone: tone))
        return [DeceptionDetector.detection(for: c)]
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
        if let c = last { notify?(DeceptionVoice.contained(c, tone: tone)) }
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

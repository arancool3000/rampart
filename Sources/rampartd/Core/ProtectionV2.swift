import Foundation
import Darwin
import RampartShared
import RampartEngine
import RampartGuard

/// Pause/cancel for running scans. Pausing blocks scan workers at the next file (see `ScanGate`).
final class ScanControl {
    private let cond = NSCondition()
    private var active: Set<UUID> = []
    private var cancelled: Set<UUID> = []
    private(set) var paused = false

    func begin() -> UUID { cond.lock(); let t = UUID(); active.insert(t); cond.unlock(); return t }
    func end(_ t: UUID) {
        cond.lock(); active.remove(t); cancelled.remove(t)
        if active.isEmpty { paused = false; cond.broadcast() }
        cond.unlock()
    }
    var running: Int { cond.lock(); defer { cond.unlock() }; return active.count }
    func isCancelled(_ t: UUID) -> Bool { cond.lock(); defer { cond.unlock() }; return cancelled.contains(t) }
    func cancelAll() -> Int {
        cond.lock(); defer { cond.unlock() }
        cancelled.formUnion(active); paused = false; cond.broadcast()
        return active.count
    }
    func setPaused(_ p: Bool) -> Int {
        cond.lock(); defer { cond.unlock() }
        guard !active.isEmpty else { return 0 }
        paused = p; if !p { cond.broadcast() }
        return active.count
    }
    /// Called by scan workers before each file. Real-time (on-write) scans are never paused.
    func waitIfPaused() {
        if Thread.current.threadDictionary["rampart.onwrite"] != nil { return }
        cond.lock()
        while paused { cond.wait(until: Date().addingTimeInterval(1)) }
        cond.unlock()
    }
    static let shared = ScanControl()
}

extension Protection {
    // MARK: allow rules

    func isAllowedByRule(_ d: Detection) -> Bool {
        let rules = allowRules.all()
        guard !rules.isEmpty else { return false }
        if let h = d.sha256?.lowercased(), rules.contains(where: { $0.scope == .fileHash && $0.value == h }) { return true }
        guard let raw = d.path else { return false }
        let path = Util.realPath(raw)
        if rules.contains(where: { $0.scope == .folder && (path == $0.value || path.hasPrefix($0.value + "/")) }) { return true }
        let needsSigning = rules.contains { $0.scope == .developer || $0.scope == .signingID }
        if needsSigning {
            // The file itself, then its enclosing app bundle (helpers and dylibs of a trusted app).
            var targets = [path]
            if let app = FindingTriage.outermostApp(path), app != path { targets.append(app) }
            for t in targets {
                guard let info = services.signingLookup?(t), info.status != .revoked else { continue }
                if let team = info.teamID, rules.contains(where: { $0.scope == .developer && $0.value == team }) { return true }
                if info.status != .adHoc && info.status != .unsigned,
                   let s = info.signingID, rules.contains(where: { $0.scope == .signingID && $0.value == s }) { return true }
            }
        }
        return false
    }

    /// Pushes allow rules into every consumer: hash DB allowlist, behaviour engine, walker exclusions.
    func applyAllowRules() {
        let rules = allowRules.all()
        for r in rules where r.scope == .fileHash {
            store.resolveAll(sha256: r.value)
            for hook in services.allowHooks { hook(r.value) }
        }
        runtime.allowFolders = rules.filter { $0.scope == .folder }.map(\.value)
        services.behaviour?.setAllowRules(rules)
        resolveAllowedDetections()
    }

    /// Resolves every open detection that an allow rule now covers. Returns how many.
    @discardableResult
    func resolveAllowedDetections() -> Int {
        var n = 0
        for d in store.all() where !d.resolved && isAllowedByRule(d) {
            _ = store.update(d.id) { $0.resolved = true }; n += 1
        }
        if n > 0 { logInfo("allow rules resolved \(n) open detection(s)") }
        return n
    }

    /// Context for `FindingTriage` (signing via the cached inspector).
    func triageContext() -> FindingTriage.Context {
        let lookup = services.signingLookup
        return FindingTriage.Context(signing: { lookup?($0) })
    }

    /// The app may send a developer / signing-ID rule whose value is a file path ("teach from this file"):
    /// resolve it to the Team ID (or signing ID) of the file's enclosing app, never guessing.
    func resolveRuleTarget(_ r: AllowRuleSpec) throws -> AllowRuleSpec {
        guard r.scope == .developer || r.scope == .signingID, r.value.hasPrefix("/") else { return r }
        let path = Util.realPath(r.value)
        let target = FindingTriage.outermostApp(path) ?? path
        guard let info = services.signingLookup?(target) ?? services.signingLookup?(path) else {
            throw ServiceError.failed("could not read the code signature of \(path)")
        }
        var out = r
        if r.scope == .developer {
            guard let t = info.teamID, !t.isEmpty else { throw ServiceError.failed("\((target as NSString).lastPathComponent) has no Team ID (not signed by a registered developer); trust the file or its folder instead") }
            out.value = t
        } else {
            guard let s = info.signingID, !s.isEmpty, info.status != .adHoc, info.status != .unsigned else {
                throw ServiceError.failed("\((target as NSString).lastPathComponent) has no stable signing identity; trust the file or its folder instead")
            }
            out.value = s
        }
        if out.name.isEmpty || out.name.hasPrefix("/") { out.name = (target as NSString).lastPathComponent }
        return out
    }

    func addAllowRule(_ rule: AllowRuleSpec) throws -> AllowRuleSpec {
        let r = try resolveRuleTarget(rule)
        if let why = AllowRuleStore.validate(r) { throw ServiceError.failed(why) }
        let saved = allowRules.add(r)
        applyAllowRules()
        activity.add(.settings, "Allowed \(r.name.isEmpty ? r.value : r.name)", detail: "\(r.scope.rawValue): \(saved.value)", outcome: "allow rule added",
                     event: .allowRuleAdded, actor: .user, target: r.scope == .folder ? saved.value : nil,
                     sha256: r.scope == .fileHash ? saved.value : nil, refID: saved.id.uuidString,
                     facts: ["name": r.name.isEmpty ? saved.value : r.name, "scope": r.scope.rawValue])
        return saved
    }

    func removeAllowRule(_ id: UUID) throws {
        let old = allowRules.all().first { $0.id == id }
        guard allowRules.remove(id) else { throw ServiceError.notFound("allow rule \(id)") }
        applyAllowRules()
        activity.add(.settings, old.map { "Removed rule for \($0.name.isEmpty ? $0.value : $0.name)" } ?? "Removed an allow rule", outcome: "allow rule removed",
                     event: .allowRuleRemoved, actor: .user, refID: id.uuidString,
                     facts: old.map { ["name": $0.name.isEmpty ? $0.value : $0.name, "scope": $0.scope.rawValue] })
    }

    // MARK: settings

    func settings() -> RampartSettings {
        var s = runtime.config.settings
        if runtime.userMode { s.webProtection = false }
        return s
    }

    /// Persists and applies settings live. Returns the effective settings.
    func setSettings(_ new: RampartSettings) -> RampartSettings {
        let old = runtime.config
        var s = new
        if let g = services.guardian {
            let bad = Set(g.exclusionsCoveringSelf(s.exclusions))
            if !bad.isEmpty {
                handle(g.detector.exclusionDetection(Array(bad), peerUID: getuid(), peerPID: getpid()))
                s.exclusions.removeAll { bad.contains($0) }
                logWarn("settings: refused exclusions covering \(Product.name) itself: \(bad.sorted())")
            }
        }
        if runtime.userMode && s.webProtection {
            s.webProtection = false
            logWarn("settings: web protection needs the system daemon; ignored in user mode")
        }
        runtime.updateConfig { $0.apply(s) }
        let cfg = runtime.config
        var changes: [String] = []
        if old.realtime != cfg.realtime { setRealtime(cfg.realtime, record: false); changes.append("real-time \(cfg.realtime ? "on" : "off")") }
        if old.learningMode != cfg.learningMode || old.developerMode != cfg.developerMode {
            services.behaviour?.apply(learningMode: cfg.learningMode, developerMode: cfg.developerMode)
            changes.append("learning \(cfg.learningMode ? "on" : "off"), developer mode \(cfg.developerMode ? "on" : "off")")
        }
        if old.ransomwareCanaries != cfg.ransomwareCanaries {
            state.update { $0.canariesOptIn = cfg.ransomwareCanaries ? true : nil }
            applyCanaries(); changes.append("ransomware canaries \(cfg.ransomwareCanaries ? "on" : "off")") }
        if old.webProtection != cfg.webProtection, let w = services.web {
            do { try w.setOn(cfg.webProtection) } catch { logWarn("web protection: \(error.localizedDescription)") }
            changes.append("web protection \(cfg.webProtection ? "on" : "off")")
        }
        if old.autoQuarantine != cfg.autoQuarantine { changes.append("auto-quarantine \(cfg.autoQuarantine ? "on" : "off")") }
        if old.exclusions != cfg.exclusions { changes.append("\(cfg.exclusions.count) exclusion(s)") }
        if old.scheduledQuickScan != cfg.scheduledQuickScan || old.scheduledScanHour != cfg.scheduledScanHour {
            changes.append(cfg.scheduledQuickScan ? "daily scan at \(cfg.scheduledScanHour):00" : "daily scan off")
        }
        if old.scanArchives != cfg.scanArchives { changes.append("archive scanning \(cfg.scanArchives ? "on" : "off")") }
        if old.autoUpdate != cfg.autoUpdate { changes.append("automatic updates \(cfg.autoUpdate ? "on" : "off")") }
        if old.notifyThreats != cfg.notifyThreats || old.notifyInfo != cfg.notifyInfo { changes.append("notifications changed") }
        if old.blockTrackers != cfg.blockTrackers { changes.append("tracker blocking \(cfg.blockTrackers ? "on" : "off")") }
        activity.add(.settings, "Settings changed", detail: changes.isEmpty ? "no effective change" : changes.joined(separator: "; "), outcome: "saved",
                     event: .settingsChanged, actor: .user, facts: ["changes": changes.joined(separator: "; ")])
        return settings()
    }

    /// Plants or removes ransomware canary files according to the setting (explicit opt-in only).
    /// A config value of `true` without a recorded opt-in (written by an older build) counts as off.
    func applyCanaries() {
        if runtime.config.ransomwareCanaries && state.value.canariesOptIn != true {
            runtime.updateConfig { $0.ransomwareCanaries = false }
            logInfo("ransomware canaries were on without an explicit opt-in; turned off")
        }
        let on = runtime.config.ransomwareCanaries
        let existing = state.value.canaries ?? []
        guard on || !existing.isEmpty else { return }
        guard let (reg, seed) = canaryRegistry() else { logWarn("ransomware canaries: no canary key available; nothing changed"); return }
        if on {
            guard let b = services.behaviour else { return }
            let dirs = Util.homeDirectories().flatMap { h in ["Documents", "Desktop", "Pictures"].map { h + "/" + $0 } }
                .filter { FileManager.default.fileExists(atPath: $0) }
            // Keyed per-install canaries. Plants missing ones, keeps ours, and replaces legacy fixed-sentence canaries
            // (old paths that are no longer active are dropped from the watch list).
            let planted = reg.plant(in: dirs, seed: seed)
            let stale = existing.filter { !planted.contains($0) }
            b.ransomware.removeCanaries(stale)
            _ = reg.remove(stale)   // only files byte-for-byte ours or holding the legacy sentence
            for p in planted { b.ransomware.registerCanary(p) }
            state.update { $0.canaries = planted.sorted() }
            logInfo("ransomware canaries active: \(planted.count) file(s)")
        } else {
            services.behaviour?.ransomware.removeCanaries(existing)
            let removed = reg.remove(existing)
            state.update { $0.canaries = nil }
            logInfo("removed \(removed.count) ransomware canary file(s)")
        }
    }

    /// Cat & Mouse: after remediation killed or quarantined the process behind a detection, mark its decoy catches
    /// contained (the user sees "caught and contained", with the quarantine item for "study it in the sandbox").
    func markDecoyCatchContained(_ d: Detection, quarantineID: UUID?) {
        guard let pid = d.pid, pid > 1, let dec = services.deception else { return }
        dec.markContained(pid: pid, quarantineID: quarantineID)
    }

    /// Cat & Mouse's registry in the user daemon; elsewhere (root daemon, where that service doesn't run) a registry
    /// keyed from this daemon's own deception state folder. Same files either way, so one daemon never sees two keys.
    func canaryRegistry() -> (RansomCanaryRegistry, UInt64)? {
        if let d = services.deception { return (d.ransomCanaries(), d.installSeed) }
        guard let o = try? RansomCanaryRegistry.load(directory: runtime.root.appendingPathComponent("deception")) else { return nil }
        return (o.registry, o.seed)
    }

    // MARK: real-time

    func startRealtime() {
        guard let rt = services.realtime, !rt.isRunning else { return }
        rt.start(onEvent: { _ in }, onDetection: { [weak self] in self?.handle($0) })
    }

    func setRealtime(_ on: Bool, record: Bool = true) {
        if record { runtime.updateConfig { $0.realtime = on } }
        guard let rt = services.realtime else { return }
        if on { startRealtime() } else { rt.stop() }
        if record { activity.add(.settings, "Real-time protection \(on ? "on" : "off")", outcome: on ? "on" : "off", severity: on ? .info : .medium,
                                event: .protectionToggled, actor: .user, facts: ["setting": "Real-time protection", "value": on ? "on" : "off"]) }
        logInfo("real-time protection \(on ? "on" : "off")")
    }

    // MARK: persistence remediation

    func lookupPersistence(_ id: String) throws -> PersistenceLookup {
        guard let p = services.persistence else { throw ServiceError.unavailable("persistence scanner") }
        if let r = p.lookup(id: id) { return r }
        throw ServiceError.notFound("persistence item \(id) (run `rampart persistence` to refresh)")
    }

    func previewRemediation(_ id: String) throws -> RemediationPreview {
        guard let r = services.persistenceRemediation else { throw ServiceError.unavailable("persistence remediation") }
        return try r.preview(try lookupPersistence(id))
    }

    func remediatePersistence(_ id: String) throws -> String {
        guard let r = services.persistenceRemediation else { throw ServiceError.unavailable("persistence remediation") }
        let item = try lookupPersistence(id)
        do {
            let summary = try r.remediate(item)
            activity.add(.persistence, "Removed \(item.item.kind.rawValue): \(item.item.label)", detail: summary, outcome: "removed", severity: .medium,
                         event: .startupItemRemoved, actor: .user, target: item.item.location, action: summary, facts: ["label": item.item.label])
            _ = try? persistence()
            return summary
        } catch {
            activity.add(.persistence, "Could not remove \(item.item.label)", detail: error.localizedDescription, outcome: "failed", severity: .medium,
                         event: .startupItemRemoveFailed, actor: .user, target: item.item.location, reason: error.localizedDescription, facts: ["label": item.item.label])
            throw error
        }
    }

    // MARK: health

    func health() -> HealthReport {
        var usage = rusage(); getrusage(RUSAGE_SELF, &usage)
        let cpu = Double(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) + Double(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6
        let now = Date()
        var pct: Double
        if let s = cpuSample, now.timeIntervalSince(s.wall) >= 0.5 {
            pct = (cpu - s.cpu) / now.timeIntervalSince(s.wall) * 100
        } else {
            pct = cpu / max(1, now.timeIntervalSince(started)) * 100
        }
        if cpuSample == nil || now.timeIntervalSince(cpuSample!.wall) >= 0.5 { cpuSample = (now, cpu) }
        pct = (pct * 10).rounded() / 10
        var h = HealthReport(mode: runtime.userMode ? "user" : "root", version: Product.version,
                            uptimeSeconds: now.timeIntervalSince(started), cpuPercent: pct,
                            residentMB: (Util.residentMB * 10).rounded() / 10,
                            sources: services.realtime?.sources ?? [:], lastErrors: DLog.shared.recentProblems,
                            sourceCPUSeconds: services.sourceCPU?() ?? [:])
        h.ipcVersion = IPC.version
        return h
    }
}

/// Daemon-only hooks set by rampartd's wiring.
enum DaemonHooks {
    /// Forwarded clipboard events go into the EventHub (its ClipboardMemory), not straight to the engine.
    static var ingestClipboard: ((SecurityEvent) -> Void)?
}

extension Protection {
    /// Admin-authenticated pause: real-time off for `minutes`, then back on automatically.
    func pauseProtection(minutes: Int) {
        let m = max(1, min(minutes, 24 * 60))
        setRealtime(false, record: false)
        activity.add(.settings, "Protection paused for \(m) min", outcome: "paused", severity: .medium, event: .protectionPaused, actor: .user, count: m)
        DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(m * 60)) { [weak self] in
            guard let self, self.runtime.config.realtime else { return }
            self.setRealtime(true, record: false)
            self.activity.add(.settings, "Protection resumed", outcome: "on", event: .protectionResumed, actor: .system)
        }
    }

    /// Authenticated uninstall: the root daemon runs the bundled setup script (which also stops this daemon).
    func beginUninstall() throws {
        guard !runtime.userMode, getuid() == 0, !Privileged.noPrivilegedTools else {
            throw ServiceError.failed("uninstall runs from the \(Product.name) system service; in user mode just quit the app and delete it")
        }
        let script = ["/Applications/Rampart.app/Contents/Resources/rampart-setup.sh"].first { FileManager.default.fileExists(atPath: $0) }
        guard let script else { throw ServiceError.notFound("rampart-setup.sh") }
        activity.add(.system, "Uninstall requested", outcome: "uninstalling", severity: .medium, event: .uninstall, actor: .user)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash"); p.arguments = [script, "uninstall"]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()   // detached: the script boots this daemon out
    }
}

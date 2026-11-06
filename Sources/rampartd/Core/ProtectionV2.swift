import Foundation
import Darwin
import RampartShared

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
        if needsSigning, let info = services.signingLookup?(path) {
            if let t = info.teamID, rules.contains(where: { $0.scope == .developer && $0.value == t }) { return true }
            if let s = info.signingID, rules.contains(where: { $0.scope == .signingID && $0.value == s }) { return true }
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
    }

    func addAllowRule(_ r: AllowRuleSpec) throws -> AllowRuleSpec {
        if let why = AllowRuleStore.validate(r) { throw ServiceError.failed(why) }
        let saved = allowRules.add(r)
        applyAllowRules()
        activity.add(.settings, "Allowed \(r.name.isEmpty ? r.value : r.name)", detail: "\(r.scope.rawValue): \(saved.value)", outcome: "allow rule added")
        return saved
    }

    func removeAllowRule(_ id: UUID) throws {
        guard allowRules.remove(id) else { throw ServiceError.notFound("allow rule \(id)") }
        applyAllowRules()
        activity.add(.settings, "Removed an allow rule", outcome: "allow rule removed")
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
        if old.ransomwareCanaries != cfg.ransomwareCanaries { applyCanaries(); changes.append("ransomware canaries \(cfg.ransomwareCanaries ? "on" : "off")") }
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
        activity.add(.settings, "Settings changed", detail: changes.isEmpty ? "no effective change" : changes.joined(separator: "; "), outcome: "saved")
        return settings()
    }

    /// Plants or removes ransomware canary files according to the setting (opt-in only).
    func applyCanaries() {
        let on = runtime.config.ransomwareCanaries
        let existing = state.value.canaries ?? []
        if on {
            guard existing.isEmpty, let b = services.behaviour else {
                if !existing.isEmpty { _ = services.behaviour?.plantCanaries(in: []) }
                return
            }
            let dirs = Util.homeDirectories().flatMap { h in ["Documents", "Desktop", "Pictures"].map { h + "/" + $0 } }
                .filter { FileManager.default.fileExists(atPath: $0) }
            let planted = b.plantCanaries(in: dirs)
            state.update { $0.canaries = planted }
            logInfo("planted \(planted.count) ransomware canary file(s)")
        } else if !existing.isEmpty {
            for p in existing { try? FileManager.default.removeItem(atPath: p) }
            state.update { $0.canaries = nil }
            logInfo("removed \(existing.count) ransomware canary file(s)")
        }
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
        if record { activity.add(.settings, "Real-time protection \(on ? "on" : "off")", outcome: on ? "on" : "off", severity: on ? .info : .medium) }
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
            activity.add(.persistence, "Removed \(item.item.kind.rawValue): \(item.item.label)", detail: summary, outcome: "removed", severity: .medium)
            _ = try? persistence()
            return summary
        } catch {
            activity.add(.persistence, "Could not remove \(item.item.label)", detail: error.localizedDescription, outcome: "failed", severity: .medium)
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
        return HealthReport(mode: runtime.userMode ? "user" : "root", version: Product.version,
                            uptimeSeconds: now.timeIntervalSince(started), cpuPercent: pct,
                            residentMB: (Util.residentMB * 10).rounded() / 10,
                            sources: services.realtime?.sources ?? [:], lastErrors: DLog.shared.recentProblems)
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
        activity.add(.settings, "Protection paused for \(m) min", outcome: "paused", severity: .medium)
        DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(m * 60)) { [weak self] in
            guard let self, self.runtime.config.realtime else { return }
            self.setRealtime(true, record: false)
            self.activity.add(.settings, "Protection resumed", outcome: "on")
        }
    }

    /// Authenticated uninstall: the root daemon runs the bundled setup script (which also stops this daemon).
    func beginUninstall() throws {
        guard !runtime.userMode, getuid() == 0, !Privileged.noPrivilegedTools else {
            throw ServiceError.failed("uninstall runs from the \(Product.name) system service; in user mode just quit the app and delete it")
        }
        let script = ["/Applications/Rampart.app/Contents/Resources/rampart-setup.sh"].first { FileManager.default.fileExists(atPath: $0) }
        guard let script else { throw ServiceError.notFound("rampart-setup.sh") }
        activity.add(.system, "Uninstall requested", outcome: "uninstalling", severity: .medium)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash"); p.arguments = [script, "uninstall"]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()   // detached: the script boots this daemon out
    }
}

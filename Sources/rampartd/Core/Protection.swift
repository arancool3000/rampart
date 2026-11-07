import Foundation
import RampartShared
import RampartEngine

/// Central coordinator: owns the store and services, applies remediation policy, fans detections out to subscribers.
final class Protection {
    let runtime: Runtime
    let services: Services
    let store: DetectionStore
    let state: StateStore
    /// When false (CLI --report-only) detections are recorded but never remediated.
    var remediate = true

    private let subLock = NSLock()
    private var subscribers: [UUID: (IPCResponse) -> Bool] = [:]
    private let scanLock = NSLock()
    private var activeScans = 0
    let activity: ActivityLog
    let allowRules: AllowRuleStore
    let started = Date()
    /// Controls of scans currently running (pause/cancel).
    let scanControl = ScanControl.shared
    private let persistLock = NSLock()
    private var _lastPersistence: [PersistenceItem] = []
    var lastPersistence: [PersistenceItem] {
        get { persistLock.lock(); defer { persistLock.unlock() }; return _lastPersistence }
        set { persistLock.lock(); _lastPersistence = newValue; persistLock.unlock() }
    }
    var cpuSample: (wall: Date, cpu: Double)?

    init(runtime: Runtime, services: Services) {
        self.runtime = runtime; self.services = services
        store = DetectionStore(url: runtime.detectionsURL)
        state = StateStore(url: runtime.stateURL)
        activity = ActivityLog(url: runtime.root.appendingPathComponent("activity.jsonl"))
        allowRules = AllowRuleStore(url: runtime.root.appendingPathComponent("allowrules.json"))
        applyAllowRules()
        services.onWebBlock = { [weak self] domain, list in
            self?.activity.add(.webBlock, "Blocked \(domain)", detail: list.map { "Listed in \($0)" } ?? "", outcome: "blocked", severity: .low)
        }
    }

    // MARK: events

    func subscribe(_ send: @escaping (IPCResponse) -> Bool) -> UUID {
        let id = UUID(); subLock.lock(); subscribers[id] = send; subLock.unlock(); return id
    }
    func unsubscribe(_ id: UUID) { subLock.lock(); subscribers[id] = nil; subLock.unlock() }
    private func broadcast(_ r: IPCResponse) {
        subLock.lock(); let subs = subscribers; subLock.unlock()
        for (id, send) in subs where !send(r) { unsubscribe(id) }
    }

    // MARK: policy

    /// Records a detection, applies the remediation policy, broadcasts it. Returns the stored version (or nil if allowlisted).
    @discardableResult
    func handle(_ detection: Detection) -> Detection? {
        if let h = detection.sha256, runtime.config.allowlist.contains(h) { return nil }
        if isAllowedByRule(detection) { return nil }
        if Self.isOwnDataFinding(detection, runtime: runtime) {
            logInfo("ignored \(detection.name) inside \(Product.name)'s own data folder: \(detection.path ?? "-")")
            return nil
        }
        if let path = detection.path, let h = detection.sha256, state.value.restored?[path] == h { return nil }
        let (triaged, outcome) = FindingTriage.apply(detection, triageContext())
        guard let triaged else {
            if case .notAFinding(let why) = outcome { logInfo("not a finding: \(detection.name) at \(detection.path ?? "-"): \(why)") }
            return nil
        }
        var d = store.add(triaged)
        let cfg = runtime.config
        if remediate && d.confidence >= 90 && !d.resolved {
            var actions: [String] = []
            if cfg.killMaliciousProcesses, let pid = d.pid, pid > 1, let killer = services.processes {
                actions.append(killer.terminate(pid: pid, expectedPath: d.path))
            }
            // Files are quarantined only on file-engine evidence. Behaviour/persistence findings point at
            // plists, scripts or apps that need a reviewed, journaled remediation instead.
            let fileEvidence = d.evidence.contains { [.hash, .yara, .xprotect].contains($0.source) || ($0.source == .heuristic && $0.score >= 90) }
            if cfg.autoQuarantine, fileEvidence, let path = d.path, isRegularFile(path) {
                do {
                    let rec = try services.quarantine.quarantine(path: path, detection: d)
                    actions.append("quarantined as \(rec.id.uuidString)")
                    d = store.update(d.id) { $0.resolved = true } ?? d
                } catch { actions.append("quarantine failed: \(error.localizedDescription)") }
            }
            if !actions.isEmpty {
                logInfo("remediation for \(d.name) at \(d.path ?? "pid \(d.pid ?? 0)"): \(actions.joined(separator: "; "))")
                if d.resolved {
                    activity.add(.quarantine, "Quarantined \(d.name)", detail: d.path ?? "", outcome: "quarantined", severity: d.severity, detectionID: d.id)
                }
            }
        }
        if d.confidence >= 30 {
            activity.add(.detection, d.name, detail: d.path ?? d.pid.map { "process \($0)" } ?? "",
                         outcome: d.resolved ? "contained" : (d.confidence >= 60 ? "needs review" : "logged"),
                         severity: d.severity, detectionID: d.id)
        }
        logInfo("detection \(d.name) conf=\(d.confidence) path=\(d.path ?? "-") resolved=\(d.resolved)")
        if d.confidence >= 60 || d.category == .test { broadcast(.event(d)) }
        return d
    }

    /// A file-engine finding (hash / YARA / XProtect / heuristic incl. EICAR / signing) on a path inside our own
    /// data folders: the vault and state, never a threat to report. Tamper / behaviour findings are kept.
    static func isOwnDataFinding(_ d: Detection, runtime: Runtime) -> Bool {
        guard let p = d.path, !d.evidence.isEmpty, runtime.isOwnData(p) else { return false }
        return d.evidence.allSatisfy { [.hash, .yara, .xprotect, .heuristic, .signing].contains($0.source) }
    }

    private func isRegularFile(_ p: String) -> Bool {
        var st = stat(); return lstat(p, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG
    }

    // MARK: operations

    func scan(paths: [String], quick: Bool, progress: @escaping ScanProgress, cancelled: @escaping () -> Bool = { false }) -> ScanOutcome {
        let targets = paths.isEmpty ? (quick ? runtime.quickScanPaths : Self.fullScanRoots) : (paths == ["/"] ? Self.fullScanRoots : paths)
        scanLock.lock(); activeScans += 1; scanLock.unlock()
        defer { scanLock.lock(); activeScans -= 1; scanLock.unlock() }
        logInfo("scan start (\(quick ? "quick" : "custom/full")) \(targets.count) roots")
        let token = scanControl.begin()
        defer { scanControl.end(token) }
        activity.add(.scan, quick ? "Quick scan started" : "Scan started", detail: targets.prefix(5).joined(separator: ", ") + (targets.count > 5 ? " …" : ""))
        var out = services.scanner.scan(paths: targets, progress: progress, cancelled: { cancelled() || self.scanControl.isCancelled(token) })
        out.detections = out.detections.compactMap { handle($0) }
        DetectionReevaluator.resolveStale(self)
        let wasCancelled = scanControl.isCancelled(token)
        activity.add(.scan, wasCancelled ? "Scan cancelled" : (quick ? "Quick scan finished" : "Scan finished"),
                     detail: "\(out.scanned) files in \(String(format: "%.1f", out.seconds)) s",
                     outcome: out.detections.isEmpty ? "no threats" : "\(out.detections.count) found",
                     severity: out.detections.isEmpty ? .info : .medium)
        state.update { s in s.lastScan = Date(); if quick || paths.isEmpty { s.lastQuickScan = Date() } }
        logInfo("scan done: \(out.scanned) files, \(out.detections.count) detections, \(String(format: "%.1f", out.seconds)) s")
        return out
    }

    var isScanning: Bool { scanLock.lock(); defer { scanLock.unlock() }; return activeScans > 0 }

    func status() -> ProtectionStatus {
        let rt = services.realtime
        let st = state.value
        var status = ProtectionStatus(realtimeOn: rt?.isRunning ?? false, sources: rt?.sources ?? [:],
                                webProtectionOn: services.web?.isOn ?? false,
                                fullDiskAccess: Util.hasFullDiskAccess, lastScan: st.lastScan,
                                signatureVersion: services.scanner.signatureVersion,
                                xprotectVersion: Util.xprotectVersion, securityScore: st.securityScore,
                                openDetections: store.openCount)
        status.definitionsUpdated = st.lastUpdate
        return status
    }

    func posture() throws -> [PostureCheck] {
        guard let p = services.posture else { throw ServiceError.unavailable("posture scanner") }
        let checks = p.checks()
        let score = p.score(checks)
        state.update { $0.securityScore = score; $0.lastPostureCheck = Date() }
        return checks
    }

    /// Lists persistence items; risky new/changed items become detections.
    func persistence(updateBaseline: Bool = true) throws -> [PersistenceItem] {
        guard let p = services.persistence else { throw ServiceError.unavailable("persistence scanner") }
        let (items, findings) = p.scan()
        let ids = Set(items.map(\.id))
        if let base = state.value.persistenceBaseline.map(Set.init) {
            for item in items where !base.contains(item.id) {
                logInfo("new persistence item: \(item.kind.rawValue) \(item.label) -> \(item.target ?? "?")")
            }
        }
        if let base = state.value.persistenceBaseline.map(Set.init) {
            let added = items.filter { !base.contains($0.id) }
            let removed = base.subtracting(ids)
            for item in added.prefix(20) {
                activity.add(.persistence, "New \(item.kind.rawValue): \(item.label)", detail: item.target ?? item.location, outcome: "recorded")
            }
            if !removed.isEmpty { activity.add(.persistence, "\(removed.count) persistence item(s) removed", outcome: "recorded") }
        }
        for d in findings { handle(d) }
        lastPersistence = items
        if updateBaseline { state.update { $0.persistenceBaseline = Array(ids).sorted() } }
        return items
    }

    func updateSignatures() -> String {
        guard let u = services.updater else { return "no updatable engines in this build" }
        let summary = u.update()
        let failed: Bool = {
            let s = summary.lowercased()
            return s.contains("failed") || s.contains("offline") || s.contains("could not connect") || s.contains("timed out")
        }()
        // Only record a successful update time, so "updated never" stays accurate after offline attempts.
        state.update { if !failed { $0.lastUpdate = Date() }; $0.lastUpdateSummary = summary }
        activity.add(.update, failed ? "Protection partly updated" : "Protection updated", detail: summary,
                     outcome: failed ? "will retry" : "ok", severity: .info)
        logInfo("update: \(summary)")
        return summary
    }

    /// Restores a quarantined item; the restored file isn't re-quarantined while its content is unchanged.
    func restore(id: UUID, allow: Bool) throws -> String {
        let rec = services.quarantine.list().first { $0.id == id }
        let path = try services.quarantine.restore(id: id)
        if let h = rec?.sha256, !h.isEmpty {
            state.update { s in var r = s.restored ?? [:]; r[path] = h; if r.count > 500 { r.removeAll() ; r[path] = h }; s.restored = r }
            if allow { self.allow(sha256: h) }
        }
        logInfo("restored \(id.uuidString) to \(path)\(allow ? " (trusted)" : "")")
        activity.add(.restore, "Restored \(rec?.detectionName ?? "item")", detail: path, outcome: allow ? "restored and trusted" : "restored")
        return path
    }

    func allow(sha256: String) {
        let h = sha256.lowercased()
        allowRules.add(AllowRuleSpec(scope: .fileHash, value: h, name: "File \(h.prefix(12))…"))
        applyAllowRules()
    }

    /// Full-scan roots: every top-level folder except the sealed system volume and mounts.
    static var fullScanRoots: [String] {
        let skip: Set<String> = ["System", "Volumes", "dev", "cores", ".vol", ".Spotlight-V100", ".fseventsd", ".nofollow", ".resolve"]
        let top = (try? FileManager.default.contentsOfDirectory(atPath: "/")) ?? []
        return top.filter { !skip.contains($0) }.map { "/" + $0 }.filter {
            (try? FileManager.default.attributesOfItem(atPath: $0))?[.type] as? FileAttributeType == .typeDirectory
        }.sorted()
    }
}

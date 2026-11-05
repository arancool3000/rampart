import Foundation
import RampartShared

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

    init(runtime: Runtime, services: Services) {
        self.runtime = runtime; self.services = services
        store = DetectionStore(url: runtime.detectionsURL)
        state = StateStore(url: runtime.stateURL)
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
        if let path = detection.path, let h = detection.sha256, state.value.restored?[path] == h { return nil }
        var d = store.add(detection)
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
            if !actions.isEmpty { logInfo("remediation for \(d.name) at \(d.path ?? "pid \(d.pid ?? 0)"): \(actions.joined(separator: "; "))") }
        }
        logInfo("detection \(d.name) conf=\(d.confidence) path=\(d.path ?? "-") resolved=\(d.resolved)")
        if d.confidence >= 60 || d.category == .test { broadcast(.event(d)) }
        return d
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
        var out = services.scanner.scan(paths: targets, progress: progress, cancelled: cancelled)
        out.detections = out.detections.compactMap { handle($0) }
        state.update { s in s.lastScan = Date(); if quick || paths.isEmpty { s.lastQuickScan = Date() } }
        logInfo("scan done: \(out.scanned) files, \(out.detections.count) detections, \(String(format: "%.1f", out.seconds)) s")
        return out
    }

    var isScanning: Bool { scanLock.lock(); defer { scanLock.unlock() }; return activeScans > 0 }

    func status() -> ProtectionStatus {
        let rt = services.realtime
        let st = state.value
        return ProtectionStatus(realtimeOn: rt?.isRunning ?? false, sources: rt?.sources ?? [:],
                                webProtectionOn: services.web?.isOn ?? false,
                                fullDiskAccess: Util.hasFullDiskAccess, lastScan: st.lastScan,
                                signatureVersion: services.scanner.signatureVersion,
                                xprotectVersion: Util.xprotectVersion, securityScore: st.securityScore,
                                openDetections: store.openCount)
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
        for d in findings { handle(d) }
        if updateBaseline { state.update { $0.persistenceBaseline = Array(ids).sorted() } }
        return items
    }

    func updateSignatures() -> String {
        guard let u = services.updater else { return "no updatable engines in this build" }
        let summary = u.update()
        state.update { $0.lastUpdate = Date(); $0.lastUpdateSummary = summary }
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
        return path
    }

    func allow(sha256: String) {
        let h = sha256.lowercased()
        runtime.updateConfig { if !$0.allowlist.contains(h) { $0.allowlist.append(h) } }
        store.resolveAll(sha256: h)
        for hook in services.allowHooks { hook(h) }
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

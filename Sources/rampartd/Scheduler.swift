import Foundation
import RampartShared

/// Periodic work: quick scans, signature updates, persistence diffing, posture refresh, vault purge.
/// Ticks once a minute and runs whatever is due; long jobs run off the tick queue and never overlap.
final class Scheduler {
    let p: Protection
    let allowNetworkUpdates: Bool
    private let q = DispatchQueue(label: "app.rampart.scheduler", qos: .utility)
    private let work = DispatchQueue(label: "app.rampart.scheduler.work", qos: .background)
    private var timer: DispatchSourceTimer?
    private var busy: Set<String> = []
    private var lastRun: [String: Date] = [:]
    private let started = Date()

    init(_ p: Protection, allowNetworkUpdates: Bool) { self.p = p; self.allowNetworkUpdates = allowNetworkUpdates }

    func start() {
        let t = DispatchSource.makeTimerSource(queue: q)
        t.schedule(deadline: .now() + 30, repeating: 60, leeway: .seconds(10))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume(); timer = t
    }
    func stop() { timer?.cancel(); timer = nil }

    private func due(_ key: String, every interval: TimeInterval, last persisted: Date?, initialDelay: TimeInterval) -> Bool {
        guard interval > 0, !busy.contains(key) else { return false }
        if Date().timeIntervalSince(started) < initialDelay { return false }
        let last = lastRun[key] ?? persisted ?? .distantPast
        return Date().timeIntervalSince(last) >= interval
    }

    private func run(_ key: String, _ job: @escaping () -> Void) {
        busy.insert(key); lastRun[key] = Date()
        work.async { [weak self] in
            job()
            self?.q.async { self?.busy.remove(key) }
        }
    }

    private func tick() {
        let cfg = p.runtime.config, st = p.state.value
        if due("quickScan", every: cfg.scheduledQuickScanHours * 3600, last: st.lastQuickScan, initialDelay: 600), !p.isScanning {
            run("quickScan") { [p] in _ = p.scan(paths: [], quick: true, progress: { _, _, _ in }) }
        }
        if allowNetworkUpdates, due("update", every: cfg.signatureUpdateHours * 3600, last: st.lastUpdate, initialDelay: 120) {
            run("update") { [p] in _ = p.updateSignatures() }
        }
        if due("persistence", every: cfg.persistenceCheckMinutes * 60, last: nil, initialDelay: 60) {
            run("persistence") { [p] in _ = try? p.persistence() }
        }
        if p.services.posture != nil, due("posture", every: cfg.postureCheckHours * 3600, last: st.lastPostureCheck, initialDelay: 90) {
            run("posture") { [p] in _ = try? p.posture() }
        }
        if due("purge", every: 86400, last: nil, initialDelay: 300) {
            run("purge") { [p] in p.services.quarantine.purgeExpired() }
        }
    }

    /// Triggered by a real-time persistence event: re-diff soon (coalesced).
    func persistenceChanged() {
        q.asyncAfter(deadline: .now() + 5) { [weak self] in
            guard let self, !self.busy.contains("persistence") else { return }
            self.run("persistence") { [p = self.p] in _ = try? p.persistence() }
        }
    }
}

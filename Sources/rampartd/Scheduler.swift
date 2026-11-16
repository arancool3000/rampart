import Foundation
import Darwin
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
        // Hand freed heap pages back to macOS. Scans and blocklist builds allocate big transient buffers; without
        // this the daemon kept ~160 MB of already-freed (fragmented) memory resident.
        malloc_zone_pressure_relief(nil, 0)
        let cfg = p.runtime.config, st = p.state.value
        // Scheduled scans wait for the charger (unless one hasn't finished in 3 days).
        let onBattery = PowerThrottle.shared.factor > 1
        let overdue = st.lastQuickScan.map { Date().timeIntervalSince($0) > 3 * 86_400 } ?? true
        if cfg.scheduledQuickScan, !busy.contains("quickScan"), !p.isScanning, !onBattery || overdue,
           Date().timeIntervalSince(started) > 600, Self.dailyDue(hour: cfg.scheduledScanHour, last: st.lastQuickScan),
           !Self.unfinishedAttemptBackoff(lastAttempt: st.lastQuickScanAttempt, lastFinished: st.lastQuickScan) {
            run("quickScan") { [p] in
                p.state.update { $0.lastQuickScanAttempt = Date() }
                _ = p.scan(paths: [], quick: true, actor: .schedule, progress: { _, _, _, _ in })
            }
        }
        // Definitions: soon after the first start (never updated yet), then at least daily. Network
        // failures are quiet: logged, retried within the hour, never shown as an alert.
        let updateEvery = Self.updateInterval(hours: cfg.signatureUpdateHours)
        if allowNetworkUpdates, cfg.autoUpdate, updateEvery > 0,
           due("update", every: updateEvery, last: st.lastUpdate, initialDelay: st.lastUpdate == nil ? 45 : 120) {
            run("update") { [weak self, p] in
                let summary = p.updateSignatures(actor: .schedule)
                if Self.updateFailed(summary) {
                    logInfo("definitions update incomplete (network?); retrying within the hour")
                    self?.q.async { self?.lastRun["update"] = Date().addingTimeInterval(min(3600, updateEvery) - updateEvery) }
                }
            }
        }
        if due("persistence", every: cfg.persistenceCheckMinutes * 60, last: nil, initialDelay: 60) {
            run("persistence") { [p] in _ = try? p.persistence() }
        }
        // Posture checks shell out to system tools; as non-root they run only when the user asks.
        if getuid() == 0, !p.runtime.userMode, p.services.posture != nil, due("posture", every: cfg.postureCheckHours * 3600, last: st.lastPostureCheck, initialDelay: 90) {
            run("posture") { [p] in _ = try? p.posture() }
        }
        if due("purge", every: 86400, last: nil, initialDelay: 300) {
            run("purge") { [p] in p.services.quarantine.purgeExpired() }
        }
    }

    /// Update cadence in seconds: the configured hours, capped at daily; 0 disables.
    static func updateInterval(hours: Double) -> TimeInterval {
        guard hours > 0 else { return 0 }
        return min(hours, 24) * 3600
    }

    static func updateFailed(_ summary: String) -> Bool {
        let s = summary.lowercased()
        return s.contains("failed") || s.contains("offline") || s.contains("could not connect") || s.contains("timed out")
    }

    /// True while a scheduled quick scan that started but never finished (crash, stop) is recent: without this
    /// a scan that kills the daemon re-ran 10 minutes after every launchd restart, all day.
    static func unfinishedAttemptBackoff(lastAttempt: Date?, lastFinished: Date?, now: Date = Date(),
                                         backoff: TimeInterval = 6 * 3600) -> Bool {
        guard let a = lastAttempt, (lastFinished ?? .distantPast) < a else { return false }
        return now.timeIntervalSince(a) < backoff
    }

    /// True when the most recent occurrence of `hour`:00 is after `last` (missed runs catch up once).
    static func dailyDue(hour: Int, last: Date?, now: Date = Date()) -> Bool {
        let cal = Calendar.current
        var mark = cal.date(bySettingHour: hour, minute: 0, second: 0, of: now)!
        if mark > now { mark = cal.date(byAdding: .day, value: -1, to: mark)! }
        return (last ?? .distantPast) < mark
    }

    /// Triggered by a real-time persistence event: re-diff soon (coalesced).
    func persistenceChanged() {
        q.asyncAfter(deadline: .now() + 5) { [weak self] in
            guard let self, !self.busy.contains("persistence") else { return }
            self.run("persistence") { [p = self.p] in _ = try? p.persistence() }
        }
    }
}

import Foundation
import RampartShared

/// Thread-safe detection history persisted as JSON (atomic writes, capped size).
final class DetectionStore {
    private let url: URL
    private let lock = NSLock()
    private var items: [Detection] = []
    private let cap: Int

    init(url: URL, cap: Int = 5000) {
        self.url = url; self.cap = cap
        if let data = try? Data(contentsOf: url) {
            if let list = try? JSONDecoder.rampart.decode([Detection].self, from: data) { items = list }
            else {
                logWarn("detections.json corrupt; moving aside")
                try? FileManager.default.moveItem(at: url, to: url.appendingPathExtension("corrupt-\(Int(Date().timeIntervalSince1970))"))
            }
        }
    }

    /// Adds a detection. If an unresolved detection with the same path+name (or pid+name) exists,
    /// it is updated in place and the existing id is returned (so repeated scans don't pile up duplicates).
    @discardableResult
    func add(_ d: Detection) -> Detection {
        lock.lock(); defer { lock.unlock() }
        if let i = items.firstIndex(where: { !$0.resolved && $0.name == d.name &&
            ((d.path != nil && $0.path == d.path && $0.sha256 == d.sha256) || (d.path == nil && d.pid != nil && $0.pid == d.pid)) }) {
            var merged = d; merged.id = items[i].id
            items[i] = merged
            saveLocked()
            return merged
        }
        items.append(d)
        if items.count > cap {
            // Drop oldest resolved first, then oldest.
            if let r = items.firstIndex(where: { $0.resolved }) { items.remove(at: r) } else { items.removeFirst() }
        }
        saveLocked()
        return d
    }

    func update(_ id: UUID, _ change: (inout Detection) -> Void) -> Detection? {
        lock.lock(); defer { lock.unlock() }
        guard let i = items.firstIndex(where: { $0.id == id }) else { return nil }
        change(&items[i]); saveLocked()
        return items[i]
    }

    func get(_ id: UUID) -> Detection? { lock.lock(); defer { lock.unlock() }; return items.first { $0.id == id } }
    func all() -> [Detection] { lock.lock(); defer { lock.unlock() }; return items.sorted { $0.date > $1.date } }
    var openCount: Int { lock.lock(); defer { lock.unlock() }; return items.filter { !$0.resolved && $0.confidence >= 60 }.count }

    func resolveAll(sha256: String) {
        lock.lock(); defer { lock.unlock() }
        for i in items.indices where items[i].sha256 == sha256 { items[i].resolved = true }
        saveLocked()
    }

    private func saveLocked() {
        do { try Util.writeJSON(items, to: url) } catch { logError("detection store save failed: \(error)") }
    }
}

/// Small persistent daemon state (last scan, last update, persistence baseline, posture score).
struct DaemonState: Codable {
    var lastScan: Date?
    var lastQuickScan: Date?
    var lastUpdate: Date?
    var lastUpdateSummary: String?
    var lastPostureCheck: Date?
    var securityScore: Int?
    var persistenceBaseline: [String]?   // PersistenceItem ids
    var signatureVersion: String?
    /// Files the user restored from quarantine (path -> sha256); not re-remediated while unchanged.
    var restored: [String: String]?
    /// Ransomware canary files we planted (removed when the setting is turned off).
    var canaries: [String]?
    /// DNS blocks per day (yyyy-MM-dd) and the most recent blocked domains.
    var dnsBlocksByDay: [String: Int]?
    var recentBlocks: [String]?
}

final class StateStore {
    private let url: URL
    private let lock = NSLock()
    private var state: DaemonState
    init(url: URL) {
        self.url = url
        state = (try? Data(contentsOf: url)).flatMap { try? JSONDecoder.rampart.decode(DaemonState.self, from: $0) } ?? DaemonState()
    }
    var value: DaemonState { lock.lock(); defer { lock.unlock() }; return state }
    func update(_ change: (inout DaemonState) -> Void) {
        lock.lock(); change(&state); let s = state; lock.unlock()
        try? Util.writeJSON(s, to: url)
    }
}

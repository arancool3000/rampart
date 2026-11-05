import Foundation
import RampartShared

/// Something that delivers SecurityEvents (RampartTelemetry.EventHub, or the built-in fan-in below).
protocol EventFeed: AnyObject {
    var status: [String: Bool] { get }
    func start(handler: @escaping (SecurityEvent) -> Void)
    func stop()
}

/// Built-in fan-in over EventSources (no dedupe / rate limiting).
final class SourcesFeed: EventFeed {
    let list: [EventSource]
    private let lock = NSLock()
    private var running: [String: Bool] = [:]
    init(_ list: [EventSource]) { self.list = list }
    var status: [String: Bool] { lock.lock(); defer { lock.unlock() }; return running }
    func start(handler: @escaping (SecurityEvent) -> Void) {
        for s in list {
            var ok = false
            if s.isAvailable {
                do { try s.start { ev in handler(ev) }; ok = true } catch { logWarn("event source \(s.name) failed: \(error)") }
            }
            lock.lock(); running[s.name] = ok; lock.unlock()
        }
    }
    func stop() { for s in list { s.stop() }; lock.lock(); for k in running.keys { running[k] = false }; lock.unlock() }
}

/// Real-time pipeline: takes events from a feed, gives every event to an optional behaviour sink,
/// and debounces file write/create/rename events into on-write scans.
final class RealtimePipeline: RealtimeService {
    let runtime: Runtime
    let feed: EventFeed
    let scanner: ScanService
    /// Behaviour engine hook: receives every event and returns zero or more detections.
    var behaviour: ((SecurityEvent) -> [Detection])?
    /// Called when a new persistence-related event arrives (e.g. BTM item added).
    var onPersistenceEvent: (() -> Void)?

    private let q = DispatchQueue(label: "app.rampart.realtime", qos: .utility)
    private let scanQ = DispatchQueue(label: "app.rampart.onwrite", qos: .utility, attributes: .concurrent)
    private var pending: [String: Date] = [:]
    private var started = false
    private var timer: DispatchSourceTimer?
    private var onDetection: ((Detection) -> Void)?
    private var onEvent: ((SecurityEvent) -> Void)?
    private(set) var eventsSeen = 0

    init(runtime: Runtime, feed: EventFeed, scanner: ScanService) {
        self.runtime = runtime; self.feed = feed; self.scanner = scanner
    }

    var sources: [String: Bool] { feed.status }
    var isRunning: Bool { q.sync { started } && feed.status.values.contains(true) }

    func start(onEvent: @escaping (SecurityEvent) -> Void, onDetection: @escaping (Detection) -> Void) {
        self.onDetection = onDetection; self.onEvent = onEvent
        feed.start { [weak self] ev in self?.q.async { self?.ingest(ev) } }
        for (k, v) in feed.status.sorted(by: { $0.key < $1.key }) { logInfo("event source \(k): \(v ? "running" : "unavailable")") }
        q.sync { started = true }
        let t = DispatchSource.makeTimerSource(queue: q)
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.flush() }
        t.resume(); timer = t
    }

    func stop() {
        timer?.cancel(); timer = nil
        feed.stop()
        q.sync { started = false }
    }

    private func ingest(_ ev: SecurityEvent) {
        eventsSeen += 1
        onEvent?(ev)
        if let b = behaviour {
            for d in b(ev) { onDetection?(d) }
        }
        switch ev.kind {
        case .fileCreate, .fileWrite, .fileClose, .fileRename:
            if let p = ev.destPath ?? ev.path, shouldScan(p) {
                if pending.count < 20000 { pending[p] = Date() }
            }
        case .persistenceAdded:
            onPersistenceEvent?()
        default: break
        }
    }

    private func shouldScan(_ p: String) -> Bool {
        let vault = runtime.quarantineDir.path
        if p.hasPrefix(vault) || p.hasPrefix(runtime.root.path) { return false }
        for e in ["/System/", "/dev/", "/private/var/db/", "/private/var/folders/", "/Library/Caches/"] where p.hasPrefix(e) { return false }
        if p.contains("/Library/Caches/") || p.contains("/.git/") || p.hasSuffix(".sb-") { return false }
        return true
    }

    /// Scan files whose last change is ≥1 s old (lets writers finish).
    private func flush() {
        let now = Date()
        let ready = pending.filter { now.timeIntervalSince($0.value) >= 1 }.map(\.key)
        for p in ready { pending[p] = nil }
        guard !ready.isEmpty else { return }
        let scanner = self.scanner, cb = onDetection
        for p in ready {
            scanQ.async {
                var isDir: ObjCBool = false
                guard FileManager.default.fileExists(atPath: p, isDirectory: &isDir), !isDir.boolValue else { return }
                if let d = scanner.scanFile(p) { cb?(d) }
            }
        }
    }
}

import Foundation
import RampartShared
import RampartTelemetry
import RampartSigning

// hx9: hardening regression tests for RampartTelemetry + RampartSigning.
// Covers: rate limiting must never drop high-priority / critical security events (event-flood evasion),
// hostile-string sanitisation of eslogger JSON fields (log injection / UI spoofing), Mach-O parser
// fuzzing, and signing-cache poisoning by swapping a file during inspection (TOCTOU).
extension SelfTest {

    private final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [SecurityEvent] = []
        func add(_ e: SecurityEvent) { lock.lock(); items.append(e); lock.unlock() }
        var all: [SecurityEvent] { lock.lock(); defer { lock.unlock() }; return items }
    }

    private static func hx9WaitUntil(_ timeout: TimeInterval, _ cond: () -> Bool) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end { if cond() { return true }; Thread.sleep(forTimeInterval: 0.02) }
        return cond()
    }

    // Flippable source used to simulate a primary feed (eslogger) that loses Full Disk Access mid-run.
    private final class StubSource: EventSource, SourceHealthReporting, @unchecked Sendable {
        let name: String
        private let lock = NSLock()
        private var available = true
        private var running = false
        private var blind = false
        private var _lastError: String?
        init(name: String) { self.name = name }
        var isAvailable: Bool { lock.withLock { available } }
        var isRunning: Bool { lock.withLock { running } }
        var lastError: String? { lock.withLock { _lastError } }
        func start(handler: @escaping @Sendable (SecurityEvent) -> Void) throws {
            lock.withLock {
                if blind { running = false; _lastError = "eslogger not permitted (grant Full Disk Access)" }
                else { running = available; _lastError = nil }
            }
            if !isRunning { throw POSIXError(.EPERM) }
        }
        func stop() { lock.withLock { running = false } }
        func goBlind() { lock.withLock { running = false; blind = true; _lastError = "eslogger not permitted (grant Full Disk Access)" } }
    }

    static func hx9Checks() {
        hx9RateLimitNeverDropsHighPriority()
        hx9CriticalEventsSurviveBufferOverflow()
        hx9Sanitize()
        hx9EsloggerFieldsSanitized()
        hx9MachOFuzz()
        hx9SigningCacheSwapDuringInspection()
        hx9FeedLostWhenSourceGoesBlind()
        hx9ImpostorDetection()
    }

    // Losing the real-time feed (e.g. FDA revoked) must raise a high-severity Detection, exactly once.
    private static func hx9FeedLostWhenSourceGoesBlind() {
        let hub = EventHub()
        let src = StubSource(name: "eslogger-stub")
        hub.add(src)
        let detLock = NSLock(); var dets: [Detection] = []
        hub.onDetection = { d in detLock.lock(); dets.append(d); detLock.unlock() }
        hub.start { _ in }
        hub.checkHealthNow()
        check(detLock.withLock { dets.isEmpty }, "no feed-lost Detection while the source is healthy")
        src.goBlind()
        hub.checkHealthNow()
        func lostCount() -> Int { detLock.withLock { dets.filter { $0.name.contains("lost its real-time event feed") }.count } }
        let lost = detLock.withLock { dets.filter { $0.name.contains("lost its real-time event feed") } }
        check(lost.count == 1 && lost.first?.severity == .high && lost.first?.confidence == 85,
              "a blinded primary source raises exactly one high-severity feed-lost Detection")
        hub.checkHealthNow()   // still down
        check(lostCount() == 1, "the feed-lost Detection is not repeated on every tick while the source stays down")
        hub.stop()
    }

    private static func hx9ImpostorDetection() {
        check(RampartService.impostorReason(name: "rampartd", path: "/tmp/rampartd", signingID: nil) != nil,
              "rampartd running from /tmp is flagged as an impostor")
        check(RampartService.impostorReason(name: "rampartd",
                                            path: "/Library/Application Support/RamPart/rampartd",
                                            signingID: "app.rampart.daemon") == nil,
              "the real installed, RamPart-signed rampartd is not flagged")
        check(RampartService.impostorReason(name: "rampartd",
                                            path: "/Library/Application Support/RamPart/rampartd",
                                            signingID: "com.evil.spoof") != nil,
              "an installed-path binary with a foreign signing id is flagged")
        check(RampartService.impostorReason(name: "zsh", path: "/bin/zsh", signingID: nil) == nil,
              "an ordinary process is not flagged as a RamPart impostor")
        let hub = EventHub()
        let detLock = NSLock(); var dets: [Detection] = []
        hub.onDetection = { d in detLock.lock(); dets.append(d); detLock.unlock() }
        hub.start { _ in }
        hub.ingest(SecurityEvent(kind: .exec,
                                 process: ProcessInfoLite(pid: 7777, ppid: 1, path: "/tmp/rampartd"),
                                 path: "/tmp/rampartd", source: "procsweep"))
        let got = hx9WaitUntil(1) { detLock.withLock { dets.contains { $0.name.contains("impersonating") } } }
        check(got, "an exec of /tmp/rampartd raises an impersonation Detection through the hub")
        hub.stop()
    }

    // A flood of cheap low-priority events must not exhaust the token bucket and hide a real detection.
    private static func hx9RateLimitNeverDropsHighPriority() {
        var cfg = EventHub.Config()
        cfg.perSourceBurst = 3; cfg.perSourceRate = 0      // bucket empties after 3 events, never refills
        cfg.dedupeWindow = 60; cfg.bufferCapacity = 100_000
        let hub = EventHub(config: cfg)
        let box = Box()
        hub.start { box.add($0) }
        // Drain the bucket with low-priority file events (unique paths so dedupe doesn't collapse them).
        for i in 0..<50 {
            hub.ingest(SecurityEvent(kind: .fileWrite, path: "/tmp/flood/\(i)", detail: ["n": "\(i)"], source: "flood"))
        }
        // Bucket is now empty. A high-priority exec and a critical xprotect detection must still get through.
        hub.ingest(SecurityEvent(kind: .exec,
                                 process: ProcessInfoLite(pid: 4242, ppid: 1, path: "/tmp/flood/evil"),
                                 path: "/tmp/flood/evil", detail: ["k": "exec"], source: "flood"))
        hub.ingest(SecurityEvent(kind: .xprotectDetection, path: "/tmp/flood/malware",
                                 detail: ["malware_identifier": "MACOS.FAKE"], source: "flood"))
        let got = hx9WaitUntil(2) {
            let d = box.all
            return d.contains { $0.kind == .exec } && d.contains { $0.kind == .xprotectDetection }
        }
        check(got, "rate limit never drops the high-priority exec or the critical xprotect under a low-priority flood")
        let s = hub.currentStats
        check(s.rateLimited > 0, "low-priority flood is actually rate-limited (otherwise the test proves nothing)")
        check(s.rateLimitExempt > 0, "high-priority events are recorded as admitted past the empty bucket")
        hub.stop()
    }

    // Under buffer backpressure, non-critical events are shed but critical ones are always delivered.
    private static func hx9CriticalEventsSurviveBufferOverflow() {
        var cfg = EventHub.Config()
        cfg.perSourceBurst = 1_000_000; cfg.perSourceRate = 1_000_000   // no rate limiting here
        cfg.dedupeWindow = 60; cfg.bufferCapacity = 10
        let hub = EventHub(config: cfg)
        let box = Box()
        let gate = DispatchSemaphore(value: 0)
        let blocked = NSLock(); var didBlock = false
        hub.start { ev in
            box.add(ev)
            blocked.lock(); let first = !didBlock; didBlock = true; blocked.unlock()
            if first { gate.wait() }   // block the delivery queue so the buffer fills while we ingest
        }
        // First event occupies (and blocks) the delivery queue.
        hub.ingest(SecurityEvent(kind: .fileWrite, path: "/tmp/seed", source: "ov"))
        _ = hx9WaitUntil(1) { !box.all.isEmpty }
        // Now flood: many non-critical high-priority execs + a handful of critical detections.
        let critPaths = (0..<5).map { "/tmp/crit/\($0)" }
        for i in 0..<200 {
            hub.ingest(SecurityEvent(kind: .exec,
                                     process: ProcessInfoLite(pid: Int32(10_000 + i), ppid: 1, path: "/tmp/e/\(i)"),
                                     path: "/tmp/e/\(i)", source: "ov"))
        }
        for p in critPaths {
            hub.ingest(SecurityEvent(kind: .persistenceAdded, path: p, detail: ["kind": "launchAgent"], source: "ov"))
        }
        let mid = hub.currentStats
        check(mid.overflowDropped > 0, "non-critical events are shed when the buffer overflows")
        check(mid.criticalDropped == 0, "critical events are never shed by normal backpressure")
        gate.signal()   // release the delivery queue
        let delivered = hx9WaitUntil(3) {
            let paths = Set(box.all.filter { $0.kind == .persistenceAdded }.compactMap(\.path))
            return critPaths.allSatisfy(paths.contains)
        }
        check(delivered, "every critical persistence event is delivered despite the exec flood")
        hub.stop()
    }

    private static func hx9Sanitize() {
        let nl = TelemetrySanitize.clean("line1\nline2\tx\r")
        check(!nl.contains("\n") && !nl.contains("\t") && !nl.contains("\r") && nl.contains("\\x0a"),
              "sanitizer escapes control characters (log-injection defence)")
        check(TelemetrySanitize.clean("a\u{0}b") == "a\\0b", "sanitizer escapes NUL")
        let bidi = TelemetrySanitize.clean("safe\u{202E}gnp.exe")
        check(!bidi.unicodeScalars.contains("\u{202E}"), "sanitizer removes bidi override (UI-spoofing defence)")
        let long = TelemetrySanitize.clean(String(repeating: "a", count: 100_000))
        check(long.count <= TelemetrySanitize.maxLen + 1, "sanitizer caps length")
        check(TelemetrySanitize.clean("/usr/bin/curl -fsSL") == "/usr/bin/curl -fsSL", "sanitizer leaves benign text intact")
    }

    private static func hx9EsloggerFieldsSanitized() {
        let obj: [String: Any] = [
            "schema_version": 1,
            "process": ["audit_token": ["pid": 100], "executable": ["path": "/bin/zsh"]],
            "event": ["exec": [
                "target": ["audit_token": ["pid": 101], "executable": ["path": "/tmp/x"]],
                "cwd": ["path": "/tmp/evil\nFAKE RAMPART: all clear"],
            ]],
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj) else { check(false, "build eslogger fixture"); return }
        let ev = EsloggerParser().parse(data: data)
        check(ev != nil, "hostile eslogger line still parses")
        if let cwd = ev?.detail["cwd"] {
            check(!cwd.contains("\n"), "eslogger detail fields are sanitised (newline cannot forge a log line)")
        } else {
            check(false, "cwd detail present")
        }
    }

    private static func hx9MachOFuzz() {
        var rng = SystemRandomNumberGenerator()
        // Random garbage of assorted sizes must never crash the parser (it returns or throws).
        for _ in 0..<400 {
            let n = Int.random(in: 0...2048, using: &rng)
            let bytes = (0..<n).map { _ in UInt8.random(in: 0...255, using: &rng) }
            _ = try? MachOFile(data: Data(bytes))
        }
        // Valid-looking magic followed by hostile header fields (huge ncmds/sizeofcmds) must stay bounded.
        for magic: [UInt8] in [[0xcf, 0xfa, 0xed, 0xfe], [0xfe, 0xed, 0xfa, 0xcf], [0xca, 0xfe, 0xba, 0xbe]] {
            var d = magic
            d.append(contentsOf: [UInt8](repeating: 0xff, count: 60))
            _ = try? MachOFile(data: Data(d))
        }
        check(true, "Mach-O parser survives fuzzed and hostile input without crashing")
    }

    private static func hx9SigningCacheSwapDuringInspection() {
        let cache = SigningCache<Int>(capacity: 16)
        let dir = NSTemporaryDirectory() + "rampart-hx9-\(getpid())"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let p = dir + "/bin"
        try? "a".write(toFile: p, atomically: true, encoding: .utf8)

        var calls = 0
        // The attacker swaps the file (changing its size) while the "inspection" is running.
        let v1 = cache.value(for: p) {
            calls += 1
            try? "bb".write(toFile: p, atomically: true, encoding: .utf8)
            return 10
        }
        // Because the identity changed during compute, the verdict must NOT have been cached.
        let v2 = cache.value(for: p) { calls += 1; return 20 }
        check(v1 == 10 && v2 == 20 && calls == 2,
              "signing cache refuses to cache a verdict for a file swapped during inspection (TOCTOU)")
        // A stable file is cached normally.
        let v3 = cache.value(for: p) { calls += 1; return 30 }
        check(v3 == 20 && calls == 2, "signing cache serves a hit for an unchanged file")
    }
}

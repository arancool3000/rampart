import Foundation
import RampartShared
import RampartTelemetry

// Owned by the telemetry build agent. Add checks with check(cond, "name").
private final class EventBox: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [SecurityEvent] = []
    func add(_ e: SecurityEvent) { lock.lock(); items.append(e); lock.unlock() }
    var all: [SecurityEvent] { lock.lock(); defer { lock.unlock() }; return items }
}

private func waitUntil(_ timeout: TimeInterval, _ cond: () -> Bool) -> Bool {
    let end = Date().addingTimeInterval(timeout)
    while Date() < end { if cond() { return true }; Thread.sleep(forTimeInterval: 0.05) }
    return cond()
}

private func realPath(_ p: String) -> String {
    guard let r = realpath(p, nil) else { return p }
    defer { free(r) }
    return String(cString: r)
}

private func cpuSeconds() -> Double {
    var ru = rusage(); getrusage(RUSAGE_SELF, &ru)
    return Double(ru.ru_utime.tv_sec) + Double(ru.ru_utime.tv_usec) / 1e6 + Double(ru.ru_stime.tv_sec) + Double(ru.ru_stime.tv_usec) / 1e6
}

extension SelfTest {
    static func telemetry() {
        telemetryLineSplitter()
        telemetryEsloggerFixtures()
        telemetryUnifiedLogParser()
        telemetryHub()
        telemetryFSEvents()
        telemetryProcessSweep()
        telemetryUnifiedLogLive()
    }

    static var telemetryScratch: URL {
        let base = ProcessInfo.processInfo.environment["RAMPART_SCRATCH"] ?? NSTemporaryDirectory()
        let u = URL(fileURLWithPath: base).appendingPathComponent("com.rampart.test.telemetry-\(getpid())")
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    static func telemetryLineSplitter() {
        let s = LineSplitter(maxLineBytes: 16)
        var lines = s.feed(Data("ab".utf8))
        check(lines.isEmpty, "splitter: partial held")
        lines = s.feed(Data("c\r\nde\n\nfg".utf8))
        check(lines.map { String(decoding: $0, as: UTF8.self) } == ["abc", "de"], "splitter: split + CRLF + empty skipped")
        lines = s.feed(Data("hhhhhhhhhhhhhhhhhhhhhhhh\nok\n".utf8))
        check(lines.map { String(decoding: $0, as: UTF8.self) } == ["ok"] && s.droppedOversized == 1, "splitter: oversized line dropped")
        _ = s.feed(Data("tail".utf8))
        check(s.flush().map { String(decoding: $0, as: UTF8.self) } == "tail", "splitter: flush")
    }

    static func telemetryEsloggerFixtures() {
        let p = EsloggerParser()
        let exec = p.parse(line: EsloggerFixtures.exec)
        check(exec?.kind == .exec, "eslogger: exec kind")
        check(exec?.process?.path == "/usr/bin/curl" && exec?.process?.pid == 4243 && exec?.process?.ppid == 4242, "eslogger: exec target")
        check(exec?.process?.args.first == "curl" && exec?.process?.args.count == 5, "eslogger: exec argv")
        check(exec?.process?.isPlatformBinary == true && exec?.process?.signingID == "com.apple.curl", "eslogger: exec signing")
        check(exec?.detail["prev_path"] == "/bin/zsh" && exec?.detail["cwd"] == "/Users/tester", "eslogger: exec detail")
        check(exec?.detail["responsible_pid"] == "612", "eslogger: responsible pid")
        if let d = exec?.date {
            let c = Calendar(identifier: .gregorian).dateComponents(in: TimeZone(identifier: "UTC")!, from: d)
            check(c.year == 2026 && c.minute == 15 && c.second == 31, "eslogger: nanosecond timestamp parsed")
        } else { check(false, "eslogger: timestamp") }
        let create = p.parse(line: EsloggerFixtures.createNew)
        check(create?.kind == .fileCreate && create?.path == "/private/tmp/com.rampart.test.txt", "eslogger: create new_path")
        let close = p.parse(line: EsloggerFixtures.closeModified)
        check(close?.kind == .fileClose && close?.detail["modified"] == "1", "eslogger: close modified")
        check(p.parse(line: EsloggerFixtures.closeUnmodified) == nil, "eslogger: unmodified close dropped")
        let rn = p.parse(line: EsloggerFixtures.rename)
        check(rn?.kind == .fileRename && rn?.path == "/private/tmp/com.rampart.test.agent.plist"
              && rn?.destPath == "/Users/tester/Library/LaunchAgents/com.rampart.test.agent.plist", "eslogger: rename")
        check(rn?.process?.teamID == nil && rn?.process?.isPlatformBinary == false, "eslogger: null team_id")
        let xa = p.parse(line: EsloggerFixtures.deleteXattr)
        check(xa?.kind == .xattrDelete && xa?.detail["xattr"] == "com.apple.quarantine", "eslogger: deleteextattr")
        let btm = p.parse(line: EsloggerFixtures.btmAdd)
        check(btm?.kind == .persistenceAdded && btm?.path == "/Users/tester/Library/LaunchAgents/com.rampart.test.agent.plist", "eslogger: btm add path")
        check(btm?.detail["executable"] == "/Users/Shared/com.rampart.test.helper" && btm?.detail["item_type"] == "agent"
              && btm?.process?.pid == 5150, "eslogger: btm detail + instigator")
        let xp = p.parse(line: EsloggerFixtures.xpDetected)
        check(xp?.kind == .xprotectDetection && xp?.detail["malware_identifier"] == "com.rampart.test.signature"
              && xp?.path == "/Users/Shared/com.rampart.test.helper", "eslogger: xp_malware_detected")
        let before = p.stats.schemaMismatches
        let fut = p.parse(line: EsloggerFixtures.futureSchema)
        check(fut?.kind == .other && fut?.detail["schema_mismatch"] == "1" && fut?.path == "/private/tmp/com.rampart.test.flux"
              && p.stats.schemaMismatches == before + 1, "eslogger: future schema best-effort + counted")
        let strict = EsloggerParser(); strict.strictSchema = true
        check(strict.parse(line: EsloggerFixtures.futureSchema) == nil, "eslogger: strict schema rejects")
        let malformedBefore = p.stats.malformed
        for m in EsloggerFixtures.malformed { check(p.parse(line: m) == nil, "eslogger: malformed '\(m.prefix(20))' rejected") }
        check(p.stats.malformed == malformedBefore + EsloggerFixtures.malformed.count, "eslogger: malformed counted")
        // Streaming: all fixtures concatenated, split at awkward boundaries.
        let blob = Data((EsloggerFixtures.all.joined(separator: "\n") + "\n").utf8)
        let sp = LineSplitter(); let p2 = EsloggerParser(); var n = 0
        var i = 0
        while i < blob.count { let j = min(blob.count, i + 37); for l in sp.feed(blob[i..<j]) { if p2.parse(data: l) != nil { n += 1 } }; i = j }
        check(n == EsloggerFixtures.all.count - 1, "eslogger: chunked stream parse (\(n))")
        let src = EsloggerSource()
        if getuid() != 0 {
            check(!src.isAvailable, "eslogger: unavailable when not root")
            var threw = false
            do { try src.start { _ in } } catch { threw = true }
            check(threw, "eslogger: start throws when not root")
        }
        check(EsloggerSource.supportedEvents()?.contains("exec") == true, "eslogger: --list-events readable")
        check(EsloggerSource.defaultEvents.allSatisfy { EsloggerSource.supportedEvents()?.contains($0) ?? true }, "eslogger: default events supported on this OS")
    }

    static func telemetryUnifiedLogParser() {
        let p = UnifiedLogParser()
        check(p.parse(line: "Filtering the log data using \"subsystem == ...\"") == nil, "ulog: banner skipped")
        let xp = #"{"traceID":1,"eventMessage":"XProtect detected malware com.rampart.test.signature at /Users/Shared/com.rampart.test.helper","eventType":"logEvent","source":null,"formatString":"%s","activityIdentifier":0,"subsystem":"com.apple.xprotect","category":"xprotect","threadID":42,"senderImageUUID":"00000000-0000-0000-0000-000000000000","backtrace":{"frames":[]},"bootUUID":"","processImagePath":"/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect","senderImagePath":"/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect","timestamp":"2026-11-05 10:20:30.123456-0800","machTimestamp":1,"messageType":"Default","processImageUUID":"00000000-0000-0000-0000-000000000000","processID":901,"senderProgramCounter":0,"parentActivityIdentifier":0,"timezoneName":""}"#
        let e = p.parse(line: xp)
        check(e?.kind == .xprotectDetection && e?.path == "/Users/Shared/com.rampart.test.helper" && e?.process?.pid == 901, "ulog: xprotect detection")
        check(e.map { abs($0.date.timeIntervalSince1970 - 1793902830.123) < 0.01 } == true, "ulog: timestamp")
        let tcc = #"{"eventMessage":"AUTHREQ_CTX: msgID=401.1, function=TCCAccessRequest, service=kTCCServiceAppleEvents, preflight=no","eventType":"logEvent","subsystem":"com.apple.TCC","category":"access","processImagePath":"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd","processID":180,"timestamp":"2026-11-05 10:20:31.000000-0800"}"#
        let t = p.parse(line: tcc)
        check(t?.kind == .tccRequest && t?.detail["service"] == "kTCCServiceAppleEvents" && t?.process?.isPlatformBinary == true, "ulog: tcc authreq")
        let btm = #"{"eventMessage":"Registered new item: com.rampart.test.agent url: file:///Users/tester/Library/LaunchAgents/com.rampart.test.agent.plist","eventType":"logEvent","subsystem":"com.apple.backgroundtaskmanagement","category":"main","processImagePath":"/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Resources/backgroundtaskmanagementd","processID":380,"timestamp":"2026-11-05 10:20:32.000000-0800"}"#
        let b = p.parse(line: btm)
        check(b?.kind == .persistenceAdded && b?.path == "/Users/tester/Library/LaunchAgents/com.rampart.test.agent.plist", "ulog: btm registered")
        check(p.parse(line: #"{"eventType":"timesyncEvent"}"#) == nil, "ulog: non-log events skipped")
    }

    static func telemetryHub() {
        let plat = ProcessInfoLite(pid: 10, ppid: 1, path: "/usr/libexec/somed", isPlatformBinary: true)
        let zsh = ProcessInfoLite(pid: 11, ppid: 10, path: "/bin/zsh", isPlatformBinary: true)
        let third = ProcessInfoLite(pid: 12, ppid: 11, path: "/Users/Shared/com.rampart.test.helper", isPlatformBinary: false)
        check(EventHub.shouldMute(SecurityEvent(kind: .fileWrite, process: plat, path: "/x", source: "t"), policy: .standard), "hub: mute platform file event")
        check(EventHub.shouldMute(SecurityEvent(kind: .exec, process: plat, path: plat.path, source: "t"), policy: .standard), "hub: mute system daemon exec")
        check(!EventHub.shouldMute(SecurityEvent(kind: .exec, process: zsh, path: zsh.path, source: "t"), policy: .standard), "hub: shell exec kept")
        check(!EventHub.shouldMute(SecurityEvent(kind: .fileWrite, process: zsh, path: "/x", source: "t"), policy: .allPlatform), "hub: LOLBin never muted")
        check(!EventHub.shouldMute(SecurityEvent(kind: .fileWrite, process: third, path: "/x", source: "t"), policy: .allPlatform), "hub: third-party kept")

        // Dedupe across sources + delivery.
        let hub = EventHub()
        let box = EventBox()
        hub.start { box.add($0) }
        hub.ingest(SecurityEvent(kind: .exec, process: third, path: third.path, source: "eslogger"))
        hub.ingest(SecurityEvent(kind: .exec, process: third, path: third.path, source: "procsweep"))
        hub.ingest(SecurityEvent(kind: .fileWrite, process: plat, path: "/tmp/a", source: "eslogger"))
        hub.ingest(SecurityEvent(kind: .fileCreate, path: "/tmp/b", source: "fsevents"))
        check(waitUntil(2) { box.all.count == 2 }, "hub: delivered 2")
        let st = hub.currentStats
        check(st.deduped == 1 && st.muted == 1 && st.received == 4, "hub: stats dedupe/mute (\(st))")

        // Rate limiting.
        var cfg = EventHub.Config(); cfg.perSourceRate = 1; cfg.perSourceBurst = 10
        let rl = EventHub(config: cfg); let rbox = EventBox()
        rl.start { rbox.add($0) }
        for i in 0..<100 { rl.ingest(SecurityEvent(kind: .fileWrite, path: "/tmp/r\(i)", source: "flood")) }
        rl.ingest(SecurityEvent(kind: .exec, process: third, path: third.path, source: "other"))
        check(waitUntil(2) { rbox.all.count == 11 }, "hub: rate limited to burst (+ other source) \(rbox.all.count)")
        check(rl.currentStats.rateLimited == 90, "hub: rate-limited count")

        // Backpressure: slow consumer, small buffer; high-priority events survive.
        var bcfg = EventHub.Config(); bcfg.bufferCapacity = 50
        let bp = EventHub(config: bcfg); let bbox = EventBox()
        let gate = DispatchSemaphore(value: 0)
        bp.start { ev in if ev.path == "/tmp/gate" { gate.wait() }; bbox.add(ev) }
        bp.ingest(SecurityEvent(kind: .fileWrite, path: "/tmp/gate", source: "s"))
        Thread.sleep(forTimeInterval: 0.1)
        for i in 0..<500 { bp.ingest(SecurityEvent(kind: .fileWrite, path: "/tmp/f\(i)", source: "s")) }
        for i in 0..<10 { bp.ingest(SecurityEvent(kind: .exec, process: ProcessInfoLite(pid: Int32(100 + i), ppid: 1, path: "/tmp/x"), path: "/tmp/x", source: "s")) }
        let bstats = bp.currentStats
        check(bstats.buffered <= 50 && bstats.overflowDropped >= 460, "hub: bounded buffer (\(bstats.buffered), dropped \(bstats.overflowDropped))")
        gate.signal()
        check(waitUntil(2) { bbox.all.filter { $0.kind == .exec }.count == 10 }, "hub: high-priority survive overflow")
        check(bbox.all.firstIndex { $0.kind == .exec } ?? 99 <= 1, "hub: high priority delivered first")
        hub.stop(); rl.stop(); bp.stop()
    }

    static func telemetryFSEvents() {
        let dir = telemetryScratch.appendingPathComponent("fsevents")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let stateURL = telemetryScratch.appendingPathComponent("fsevents-state.json")
        try? FileManager.default.removeItem(at: stateURL)
        let src = FSEventsSource(paths: [dir.path], latency: 0.2, stateURL: stateURL)
        check(src.isAvailable, "fsevents: available")
        let box = EventBox()
        do { try src.start { box.add($0) } } catch { check(false, "fsevents: start \(error)"); return }
        Thread.sleep(forTimeInterval: 0.3)
        let file = dir.appendingPathComponent("com.rampart.test.created.txt")
        let t0 = Date()
        FileManager.default.createFile(atPath: file.path, contents: Data("hello".utf8))
        let real = realPath(dir.path) + "/" + file.lastPathComponent
        let seen = waitUntil(5) { box.all.contains { $0.path == real || $0.destPath == real } }
        check(seen, "fsevents: sees created file within 5s")
        if seen { print("  fsevents latency: \(String(format: "%.2f", Date().timeIntervalSince(t0)))s") }
        // FileManager.createFile is an atomic save (temp + rename) => one rename event with destPath, temp suppressed.
        let ev = box.all.first { $0.path == real || $0.destPath == real }
        check(ev?.kind == .fileRename && ev?.destPath == real && ev?.detail["atomic_save"] == "1", "fsevents: atomic save -> rename to (\(String(describing: ev?.kind)))")
        check(!box.all.contains { ($0.path ?? "").contains(".sb-") && $0.destPath == nil }, "fsevents: atomic temp suppressed")
        // Plain open/write/close creates.
        let plain = dir.appendingPathComponent("com.rampart.test.plain.txt")
        let plainReal = realPath(dir.path) + "/" + plain.lastPathComponent
        let fd = open(plain.path, O_CREAT | O_WRONLY, 0o644); _ = write(fd, "abc", 3); close(fd)
        check(waitUntil(5) { box.all.contains { $0.path == plainReal && ($0.kind == .fileCreate || $0.kind == .fileWrite) } }, "fsevents: plain create/write")
        try? FileManager.default.removeItem(at: file)
        check(waitUntil(5) { box.all.contains { $0.path == real && $0.kind == .fileDelete } }, "fsevents: sees delete")
        try? FileManager.default.removeItem(at: plain)
        src.stop()
        let st = src.loadState()
        check(st != nil && st!.lastEventID > 0 && st!.deviceUUID != nil, "fsevents: state persisted (\(String(describing: st?.lastEventID)))")

        // Resume: create a file while stopped; a restarted source replays it from the persisted ID.
        let offline = dir.appendingPathComponent("com.rampart.test.offline.txt")
        FileManager.default.createFile(atPath: offline.path, contents: Data("x".utf8))
        Thread.sleep(forTimeInterval: 0.5)
        let src2 = FSEventsSource(paths: [dir.path], latency: 0.2, stateURL: stateURL)
        let box2 = EventBox()
        try? src2.start { box2.add($0) }
        let offReal = realPath(dir.path) + "/" + offline.lastPathComponent
        let replayed = waitUntil(5) { box2.all.contains { $0.destPath == offReal && $0.detail["replay"] == "1" } }
        check(replayed, "fsevents: replays offline events from persisted ID")
        if !replayed { print("  state \(String(describing: st)) events: \(box2.all.map { ($0.path ?? "", $0.detail) })") }
        src2.stop()
        try? FileManager.default.removeItem(at: offline)
    }

    static func telemetryProcessSweep() {
        let src = ProcessSweepSource(interval: 0.2)
        let box = EventBox()
        do { try src.start { box.add($0) } } catch { check(false, "procsweep: start"); return }
        Thread.sleep(forTimeInterval: 0.5)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sleep")
        p.arguments = ["3"]
        try? p.run()
        let pid = p.processIdentifier
        let seen = waitUntil(3) { box.all.contains { $0.process?.pid == pid } }
        check(seen, "procsweep: sees spawned /bin/sleep")
        let ev = box.all.first { $0.process?.pid == pid }
        check(ev?.kind == .exec && ev?.path == "/bin/sleep", "procsweep: exec path (\(String(describing: ev?.path)))")
        check(ev?.process?.args == ["/bin/sleep", "3"], "procsweep: argv (\(String(describing: ev?.process?.args)))")
        check(ev?.process?.ppid == getpid() && ev?.process?.uid == getuid(), "procsweep: ppid/uid")
        check(ev?.process?.isPlatformBinary == true && ev?.process?.signingID == "com.apple.sleep" && ev?.detail["signing"] == "apple",
              "procsweep: platform signing (\(String(describing: ev?.process?.signingID)) \(String(describing: ev?.detail["signing"])))")
        check(box.all.filter { $0.process?.pid == pid }.count == 1, "procsweep: emitted once")
        p.terminate(); p.waitUntilExit()
        src.stop()
        // Non-platform identity: an unsigned script file isn't platform.
        let id = ProcInspector.codeIdentity(path: "/bin/ls")
        check(id.isPlatformBinary && id.tier == "apple", "procsweep: /bin/ls is apple platform")
        let tmp = telemetryScratch.appendingPathComponent("com.rampart.test.script.sh")
        try? "#!/bin/sh\necho hi\n".write(to: tmp, atomically: true, encoding: .utf8)
        let sid = ProcInspector.codeIdentity(path: tmp.path)
        check(!sid.isPlatformBinary && (sid.tier == "unsigned" || sid.tier == "unknown"), "procsweep: unsigned file not platform (\(sid.tier))")

        // CPU cost: steady-state sweeps (no new pids) measured with getrusage.
        let bench = ProcessSweepSource(interval: 1)
        bench.sweepNow()   // baseline: enriches nothing (baseline does not emit)
        let n = 200
        let c0 = cpuSeconds(); let w0 = Date()
        for _ in 0..<n { bench.sweepNow() }
        let cpu = (cpuSeconds() - c0) / Double(n) * 1000
        let wall = Date().timeIntervalSince(w0) / Double(n) * 1000
        let pids = ProcInspector.allPids().count
        print(String(format: "  procsweep: %d pids, %.3f ms CPU / sweep (wall %.3f ms) => %.2f%% CPU @0.5s, %.2f%% @0.1s, %.2f%% @1s",
                     pids, cpu, wall, cpu / 5, cpu / 1, cpu / 10))
        check(cpu < 25, "procsweep: sweep under 25 ms CPU")
        // Live timers, steady state (after the baseline sweep), 4 s each.
        for iv in [0.1, 0.5] {
            let live = ProcessSweepSource(interval: iv)
            try? live.start { _ in }
            Thread.sleep(forTimeInterval: 1)
            let c = cpuSeconds()
            Thread.sleep(forTimeInterval: 4)
            let pct = (cpuSeconds() - c) / 4 * 100
            live.stop()
            print(String(format: "  procsweep live @%.1fs: %.2f%% CPU steady state (avg sweep incl. baseline %.3f ms)", iv, pct, live.averageSweepMillis))
            // Only the shipping interval (0.5 s) is a hard limit; 0.1 s is reported for information.
            if iv >= 0.5 { check(pct < 5, "procsweep: live CPU under 5% @\(iv)s") }
        }
    }

    static func telemetryUnifiedLogLive() {
        let src = UnifiedLogSource()
        check(src.isAvailable, "ulog: available")
        let box = EventBox()
        do { try src.start { box.add($0) } } catch { check(false, "ulog: start \(error)"); return }
        check(waitUntil(2) { src.isRunning }, "ulog: running")
        Thread.sleep(forTimeInterval: 1.5)
        check(src.isRunning && src.launches == 1, "ulog: still running, no restarts (\(src.launches)) \(src.lastError ?? "")")
        src.stop()
        check(!src.isRunning, "ulog: stopped")
        Thread.sleep(forTimeInterval: 0.5)
        // No orphaned `log stream` child of ours.
        let mine = ProcInspector.allPids().filter { pid in
            ProcInspector.bsdInfo(pid)?.ppid == getpid() && ProcInspector.path(pid) == "/usr/bin/log"
        }
        check(mine.isEmpty, "ulog: child reaped (\(mine))")
        print("  ulog: \(box.all.count) events in 1.5s, parser parsed \(src.parser.parsed) skipped \(src.parser.skipped)")
    }
}

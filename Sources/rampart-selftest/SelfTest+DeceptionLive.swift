import Foundation
import Darwin
import RampartShared
import RampartGuard

// Cat & Mouse in user mode (no eslogger): persisted config applied at start, access-time read catches,
// actor-less write/rename/delete/attribute catches, copy landing, no self-catches, no double reports,
// and a tarpit that is really listening after a restart. Scratch home only; attackers are child processes.
extension SelfTest {
    static func deceptionUserModeChecks() {
        let base = NSTemporaryDirectory() + "com.rampart.test.deception-live-\(getpid())-\(UInt32.random(in: 0...UInt32.max))"
        defer { try? FileManager.default.removeItem(atPath: base) }
        let home = base + "/home"
        for d in ["Documents", "Desktop", "Downloads", "Library/Application Support/Google/Chrome", "loot"] {
            try? FileManager.default.createDirectory(atPath: home + "/" + d, withIntermediateDirectories: true)
        }
        let state = URL(fileURLWithPath: base + "/state")
        try? FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)

        @discardableResult func run(_ exe: String, _ args: [String]) -> Int32 {
            let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
            p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
            do { try p.run() } catch { return -1 }
            p.waitUntilExit(); return p.terminationStatus
        }
        final class Box<T>: @unchecked Sendable { let l = NSLock(); var v: [T] = []; func add(_ x: T) { l.lock(); v.append(x); l.unlock() }; var all: [T] { l.lock(); defer { l.unlock() }; return v } }

        DeceptionService.tarpitLineDelay = 0
        defer { DeceptionService.tarpitLineDelay = 6 }
        // --- Persisted config is applied by init: watchers + lure start without any IPC call.
        let port = freeLoopbackPort()
        var cfg = DeceptionConfig(); cfg.tarpitEnabled = true; cfg.tarpitPort = port
        try? JSONEncoder().encode(cfg).write(to: state.appendingPathComponent("config.json"))
        guard let boot = try? DeceptionService(directory: state, home: home, pollInterval: 3600) else { check(false, "deception.live.init"); return }
        check(boot.status().tarpitListening && boot.status().tarpitError == nil, "deception.live.initStartsPersistedTarpit")
        let lureAlerts = Box<CatMouseAlert>()
        boot.onAlert = { a in lureAlerts.add(a) }
        check(!loopbackExchange(port: port, send: "admin\r\nhunter2\r\n").isEmpty, "deception.live.tarpitAnswers")
        var w = 0; while boot.status().tarpitAttempts.isEmpty && w < 60 { usleep(50_000); w += 1 }
        let att = boot.status().tarpitAttempts.first
        check(att?.credentialAttempts == 1 && (att?.replies?.contains { $0.contains("Login incorrect") || $0.contains("login:") } ?? false), "deception.live.tarpitRecordsReplies")
        check(FileManager.default.fileExists(atPath: state.path + "/tarpit.json"), "deception.live.tarpitPersisted")
        check(lureAlerts.all.count == 1 && lureAlerts.all[0].timeSensitive && lureAlerts.all[0].body.contains("password"), "deception.live.tarpitNotification")
        boot.shutdown()
        check(!boot.status().tarpitListening, "deception.live.shutdownStopsLure")

        // --- Restart: a new service on the same state listens again (this is what failed live).
        if let again = try? DeceptionService(directory: state, home: home, pollInterval: 3600) {
            check(again.status().tarpitListening && again.tarpitBoundPort == port, "deception.live.tarpitListeningAfterRestart")
            check(again.status().tarpitAttempts.count >= 1, "deception.live.tarpitHistoryAfterRestart")
            again.shutdown()
        } else { check(false, "deception.live.restartInit") }

        // --- Port in use: no throw, status says so honestly, and tarpitListening is false.
        let blocker = listenLoopback(port)
        if let busy = try? DeceptionService(directory: state, home: home, pollInterval: 3600) {
            let st = busy.status()
            check(!st.tarpitListening && (st.tarpitError ?? "").contains("already in use"), "deception.live.bindErrorShown")
            check((try? busy.setTarpit(true, port: port)) != nil && busy.status().tarpitError != nil, "deception.live.bindErrorNoThrow")
            busy.shutdown()
        } else { check(false, "deception.live.busyInit") }
        if blocker >= 0 { close(blocker) }

        // --- Decoys in user mode.
        var off = DeceptionConfig(); off.tarpitEnabled = false
        try? JSONEncoder().encode(off).write(to: state.appendingPathComponent("config.json"))
        guard let svc = try? DeceptionService(directory: state, home: home, ownPaths: ["/Applications/RamPart.app"], pollInterval: 3600) else { check(false, "deception.live.svc"); return }
        let msgs = Box<DeceptionMessage>(), dets = Box<Detection>(), alerts = Box<CatMouseAlert>()
        svc.notify = { m in msgs.add(m) }
        svc.onAlert = { a in alerts.add(a) }
        svc.onDetection = { d in dets.add(d) }
        svc.watcher.settleSeconds = 0
        let rep = svc.setDecoys(true)
        check(rep.planted >= 4 && svc.watcher.isRunning, "deception.live.plantedAndWatching (\(rep.planted))")
        let files = svc.registry.all.filter { $0.kind.isFile }.map(\.path)
        var armedAll = true
        for f in files { var st = stat(); if lstat(f, &st) != 0 || !DecoyIO.isArmed(st) { armedAll = false } }
        check(armedAll, "deception.live.armedAtPlanting")
        guard files.count >= 4 else { check(false, "deception.live.enoughDecoys"); return }
        func catches() -> [DeceptionCatch] { svc.status().catches }

        // RamPart's own stat polling and its own content reads (Finder visibility check) are never catches.
        for _ in 0..<3 { svc.watcher.pollNow() }
        svc.setDecoysVisible(true); svc.setDecoysVisible(false)
        svc.watcher.pollNow()
        var stillArmed = true
        for f in files { var st = stat(); if lstat(f, &st) != 0 || !DecoyIO.isArmed(st) { stillArmed = false } }
        check(catches().isEmpty && stillArmed, "deception.live.noCatchForOwnPolling")

        // A plain `cat` (another process) is caught from the access time, without an actor.
        let target = files[0]
        run("/bin/cat", [target])
        svc.watcher.pollNow()
        let read = catches().first { $0.decoyPath == target && $0.access == .read }
        check(read != nil && read?.attribution == .unknown && read?.pid == 0, "deception.live.atimeReadCatch")
        check(msgs.all.contains { $0.body.contains(DeceptionVoice.unattributedLimit) }, "deception.live.unattributedWording")
        check(((try? Data(contentsOf: state.appendingPathComponent("catches.json"))).flatMap { String(data: $0, encoding: .utf8) } ?? "").contains("\"read\""), "deception.live.catchesJSONWritten")
        var tst = stat(); _ = lstat(target, &tst)
        check(DecoyIO.isArmed(tst), "deception.live.rearmedAfterRead")
        check(dets.all.isEmpty, "deception.live.unattributedNoDetection")
        // Every catch emits one notification alert (posted by the app's menu bar process), playful by default.
        let first = alerts.all.first
        check(alerts.all.count == 1 && first?.title == "🐱 The cat caught a mouse!" && first?.body.hasPrefix("Something grabbed '") == true
              && first?.timeSensitive == false && first?.severity == .medium && first?.catchID == read?.id, "deception.live.catchEmitsNotification")   // no known program: Medium, not time-sensitive
        check(svc.status().alerts?.contains { $0.id == first?.id } == true, "deception.live.alertsInStatusForLateApp")

        // A burst is one story: the next catch replaces the same notification with a count.
        run("/bin/cat", [files[3]]); svc.watcher.pollNow()
        check(alerts.all.count == 2 && alerts.all[1].identifier == first?.identifier && alerts.all[1].count == 2 && alerts.all[1].title.contains("(2)"), "deception.live.burstOneNotification")
        // Planner: serious tone, attributed actor, refused lure attempts never alert.
        var planner = CatMouseAlertPlanner()
        var named = DeceptionCatch(date: Date(), decoyPath: "/h/seed.txt", decoyKind: .cryptoSeed, access: .read, pid: 77, processPath: "/tmp/stealer", processName: "stealer", signingID: nil, teamID: nil, destPath: nil)
        named.attribution = .eventActor
        let na = planner.alert(for: named, tone: .serious)
        check(na.title == "Decoy file accessed" && na.body.hasPrefix("'stealer' read 'seed.txt'") && na.pid == 77, "deception.live.alertSeriousNamed")
        var later = CatMouseAlertPlanner(); _ = later.alert(for: named, tone: .playful, now: Date().addingTimeInterval(-600))
        check(later.alert(for: named, tone: .playful).count == 1, "deception.live.alertNewStoryAfterWindow")
        // The system service later forwards the eslogger event for the same read: the catch is upgraded, not doubled.
        let before = catches().count
        let cat = ProcessInfoLite(pid: 4242, ppid: 4000, path: "/bin/cat", signingID: "com.apple.cat", isPlatformBinary: true)
        let fwd = svc.handle(SecurityEvent(kind: .fileClose, process: cat, path: target, detail: ["modified": "0"], source: "eslogger"))
        let up = catches().first { $0.id == read?.id }
        check(fwd.count == 1 && catches().count == before && up?.pid == 4242 && up?.attribution == .eventActor, "deception.live.forwardedUpgradesNoDouble")
        // ...and the other order: attributed first, then the watcher's touch adds nothing.
        let t2 = files[1]
        _ = svc.handle(SecurityEvent(kind: .fileClose, process: ProcessInfoLite(pid: 4243, ppid: 4000, path: "/bin/cat"), path: t2, detail: ["modified": "0"], source: "eslogger"))
        let mid = catches().count
        run("/bin/cat", [t2]); svc.watcher.pollNow()
        check(catches().count == mid, "deception.live.watcherAfterForwardedNoDouble")

        // cp: the read is caught, and when the copy lands (FSEvents create, no actor) it becomes a copy with a destination.
        let t3 = files[2], dest = home + "/loot/stolen.txt"
        run("/bin/cp", [t3, dest]); svc.watcher.pollNow()
        _ = svc.handle(SecurityEvent(kind: .fileCreate, path: dest, source: "fsevents"))
        let cp = catches().first { $0.decoyPath == t3 }
        check(cp?.access == .copy && cp?.destPath?.hasSuffix("/loot/stolen.txt") == true, "deception.live.copyLanding")
        check(catches().filter { $0.decoyPath == t3 }.count == 1, "deception.live.copyOneCatch")

        // Actor-less write / attribute change / rename / delete (kqueue + lstat, no eslogger).
        let t4 = files[3]
        run("/bin/sh", ["-c", "echo pwned >> \"$0\"", t4]); usleep(200_000); svc.watcher.pollNow()
        check(catches().contains { $0.decoyPath == t4 && $0.access == .write && $0.isUnattributed }, "deception.live.unattributedWrite")
        run("/bin/chmod", ["644", t4]); usleep(200_000); svc.watcher.pollNow()
        check(catches().contains { $0.decoyPath == t4 && $0.access == .xattr }, "deception.live.unattributedAttr")
        run("/bin/rm", ["-f", t2]); usleep(200_000); svc.watcher.pollNow()
        check(catches().contains { $0.decoyPath == t2 && $0.access == .delete }, "deception.live.unattributedDelete")

        // A program still holding a decoy open is attributed (open-file sweep) and goes to the detection pipeline.
        if files.count >= 5 {
            let t5 = files[4]
            let tail = Process(); tail.executableURL = URL(fileURLWithPath: "/usr/bin/tail"); tail.arguments = ["-f", t5]
            tail.standardOutput = FileHandle.nullDevice; tail.standardError = FileHandle.nullDevice
            if (try? tail.run()) != nil {
                usleep(500_000); svc.watcher.pollNow()
                let held = catches().last { $0.decoyPath == t5 && $0.access == .read }
                check(held?.attribution == .openFile && held?.pid == tail.processIdentifier && held?.processName == "tail", "deception.live.openFileAttribution")
                check(dets.all.contains { $0.pid == tail.processIdentifier }, "deception.live.openFileDetection")
                tail.terminate(); tail.waitUntilExit()
            } else { check(false, "deception.live.tailSpawn") }
            let moved = home + "/loot/moved-away"
            run("/bin/mv", [t5, moved]); usleep(300_000); svc.watcher.pollNow()
            check(catches().contains { $0.decoyPath == t5 && $0.access == .rename && $0.destPath?.hasSuffix("moved-away") == true }, "deception.live.unattributedRename")
        } else { check(false, "deception.live.fiveDecoys") }

        // Maze walk without eslogger: folder access times.
        try? svc.setMaze(true)
        svc.watcher.pollNow()
        let mazeBefore = catches().filter { $0.access == .mazeWalk }.count
        run("/usr/bin/find", [svc.mazeRoot]); svc.watcher.pollNow()
        let walks = catches().filter { $0.access == .mazeWalk }
        // A folder walk with no known program (find, Finder, backups) proves nothing and is not recorded.
        check(walks.count == mazeBefore, "deception.live.mazeWalkUnattributedIgnored")

        // Read while the daemon wasn't running: reported at the next start, marked as such.
        svc.shutdown()
        let late = svc.registry.all.first { $0.kind == .mazeNote }?.path ?? files[0]
        run("/bin/cat", [late])
        if let next = try? DeceptionService(directory: state, home: home, pollInterval: 3600, applyPersisted: false) {
            next.watcher.settleSeconds = 0
            next.applyPersistedConfig()
            check(next.status().catches.contains { $0.decoyPath == late && $0.note != nil && $0.access == .read }, "deception.live.offlineReadReported")
            check(next.watcher.isRunning, "deception.live.initAppliesPersistedDecoys")
            _ = next.removeAll()
            next.shutdown()
        } else { check(false, "deception.live.nextInit") }
    }

    /// A loopback TCP port that was free a moment ago.
    static func freeLoopbackPort() -> UInt16 {
        let s = listenLoopback(0); defer { if s >= 0 { close(s) } }
        var a = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
        return UInt16(bigEndian: a.sin_port)
    }

    /// Listening socket on 127.0.0.1:port (no SO_REUSEADDR so it really blocks the port). -1 on failure.
    static func listenLoopback(_ port: UInt16) -> Int32 {
        let s = socket(AF_INET, SOCK_STREAM, 0); guard s >= 0 else { return -1 }
        var addr = sockaddr_in(); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian; inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard rc == 0, listen(s, 4) == 0 else { close(s); return -1 }
        return s
    }
}

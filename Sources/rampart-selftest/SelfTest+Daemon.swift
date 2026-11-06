import Foundation
import RampartShared

// Owned by the daemon build agent (B9). rampartd is an executable target, so these checks cover the
// IPC contract directly and then drive a real `rampartd --user` (if built next to this binary) over its socket.
extension SelfTest {
    static func daemon() {
        // 1. Framing round-trip over a socketpair.
        var fds: [Int32] = [0, 0]
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0, "daemon: socketpair")
        let reqs: [IPCRequest] = [.status, .scan(paths: ["/tmp"], quick: true), .listDetections, .listQuarantine,
                                  .quarantine(detectionID: UUID()), .restore(id: UUID(), allow: true), .deleteQuarantined(id: UUID()),
                                  .allow(sha256: String(repeating: "a", count: 64)), .posture, .fixPosture(checkID: "firewall"),
                                  .persistence, .setWebProtection(on: false), .updateSignatures, .subscribeEvents,
                                  .activity(limit: 5), .connections, .wifi, .networkStats, .getSettings, .setSettings(RampartSettings()),
                                  .pauseScan(paused: true), .cancelScan, .setRealtime(on: false), .previewRemediation(persistenceID: "x"),
                                  .remediate(persistenceID: "x"), .listAllowRules,
                                  .addAllowRule(AllowRuleSpec(scope: .folder, value: "/tmp/a", name: "a")), .removeAllowRule(id: UUID()), .health]
        var roundTrips = 0
        for r in reqs {
            guard let d = try? IPC.encode(r), IPC.writeFrame(fd: fds[0], d), let back = IPC.readFrame(fd: fds[1]),
                  let decoded = try? JSONDecoder.rampart.decode(IPCRequest.self, from: back) else { continue }
            let enc = JSONEncoder.rampart; enc.outputFormatting = .sortedKeys
            if (try? enc.encode(decoded)) == (try? enc.encode(r)) { roundTrips += 1 }
        }
        check(roundTrips == reqs.count, "daemon: every IPCRequest survives framing (\(roundTrips)/\(reqs.count))")
        close(fds[1])
        check(IPC.readFrame(fd: fds[1]) == nil, "daemon: readFrame on closed fd returns nil")
        close(fds[0])

        // 2. Live daemon test.
        let binDir = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent()
        let daemonBin = binDir.appendingPathComponent("rampartd").path
        guard FileManager.default.isExecutableFile(atPath: daemonBin) else {
            print("  (skipping live daemon checks: \(daemonBin) not built)")
            return
        }
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("rampart-selftest-\(getpid())")
        let root = tmp.appendingPathComponent("state"), files = tmp.appendingPathComponent("files")
        try? FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try? Data(#"{"realtime":false,"scheduledQuickScanHours":0}"#.utf8).write(to: root.appendingPathComponent("config.json"))
        defer { try? FileManager.default.removeItem(at: tmp) }
        let sock = tmp.appendingPathComponent("d.sock").path
        let p = Process()
        p.executableURL = URL(fileURLWithPath: daemonBin)
        p.arguments = ["--user", "--root", root.path, "--socket", sock, "--no-scheduler", "--no-realtime"]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { check(false, "daemon: launch rampartd"); return }
        defer { if p.isRunning { p.terminate(); p.waitUntilExit() } }
        var up = false
        for _ in 0..<100 where !up { usleep(100_000); up = FileManager.default.fileExists(atPath: sock) }
        check(up, "daemon: socket appears")
        guard up else { return }

        func call(_ r: IPCRequest) -> [IPCResponse] {
            var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
            let bytes = Array(sock.utf8)
            withUnsafeMutableBytes(of: &addr.sun_path) { raw in for (i, b) in bytes.enumerated() { raw[i] = b }; raw[bytes.count] = 0 }
            let fd = socket(AF_UNIX, SOCK_STREAM, 0); defer { close(fd) }
            let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } } == 0
            guard ok, let d = try? IPC.encode(r), IPC.writeFrame(fd: fd, d) else { return [] }
            var out: [IPCResponse] = []
            while let f = IPC.readFrame(fd: fd), let resp = try? JSONDecoder.rampart.decode(IPCResponse.self, from: f) {
                out.append(resp)
                if case .scanProgress = resp { continue }
                break
            }
            return out
        }

        if case .status(let s)? = call(.status).last { check(s.signatureVersion != "", "daemon: status over socket") }
        else { check(false, "daemon: status over socket") }

        // Harmless EICAR fixture assembled at runtime.
        let eicar = ["X5O!P%@AP[4\\PZX5", "4(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-", "FILE!$H+H*"].joined()
        let fixture = files.appendingPathComponent("com.rampart.test.eicar.com")
        try? Data(eicar.utf8).write(to: fixture)
        try? Data("hello".utf8).write(to: files.appendingPathComponent("com.rampart.test.clean.txt"))
        if case .scanFinished(let n, let ds, _)? = call(.scan(paths: [files.path], quick: false)).last {
            check(n == 2, "daemon: scanned both fixtures (\(n))")
            check(ds.count == 1 && ds.first?.name.contains("EICAR") == true, "daemon: EICAR detected")
            check(!FileManager.default.fileExists(atPath: fixture.path), "daemon: EICAR auto-quarantined")
        } else { check(false, "daemon: scan over socket") }

        if case .quarantine(let qs)? = call(.listQuarantine).last, let q = qs.first {
            check(qs.count == 1, "daemon: one quarantine record")
            if case .ok? = call(.restore(id: q.id, allow: false)).last {
                check(FileManager.default.fileExists(atPath: fixture.path), "daemon: restore puts the file back")
            } else { check(false, "daemon: restore") }
            // Restored item must not be re-quarantined by the next scan.
            _ = call(.scan(paths: [files.path], quick: false))
            check(FileManager.default.fileExists(atPath: fixture.path), "daemon: restored file left alone")
        } else { check(false, "daemon: quarantine list") }

        if case .detections(let ds)? = call(.listDetections).last { check(!ds.isEmpty, "daemon: detection history persisted") }
        else { check(false, "daemon: list detections") }
        if case .error? = call(.allow(sha256: "nothex")).last { check(true, "daemon: rejects bad sha256") }
        else { check(false, "daemon: rejects bad sha256") }
        if case .persistence? = call(.persistence).last { check(true, "daemon: persistence") } else { check(false, "daemon: persistence") }

        // v2 requests.
        if case .activity(let es)? = call(.activity(limit: 50)).last {
            check(es.contains { $0.kind == .scan } && es.contains { $0.kind == .quarantine } && es.contains { $0.kind == .restore },
                  "daemon: activity has scan, quarantine and restore rows (\(es.count))")
        } else { check(false, "daemon: activity") }
        if case .health(let h)? = call(.health).last {
            check(h.mode == "user" && h.version == Product.version && h.residentMB > 1 && h.uptimeSeconds > 0, "daemon: health (\(h.residentMB) MB)")
        } else { check(false, "daemon: health") }
        if case .settings(var st)? = call(.getSettings).last {
            st.autoQuarantine = false; st.scheduledScanHour = 7; st.webProtection = true
            if case .settings(let saved)? = call(.setSettings(st)).last {
                check(!saved.autoQuarantine && saved.scheduledScanHour == 7, "daemon: settings round-trip")
                check(!saved.webProtection, "daemon: web protection refused in user mode")
            } else { check(false, "daemon: setSettings") }
            let cfg = (try? Data(contentsOf: root.appendingPathComponent("config.json"))).flatMap { String(data: $0, encoding: .utf8) } ?? ""
            check(cfg.contains("\"scheduledScanHour\" : 7"), "daemon: settings persisted")
        } else { check(false, "daemon: getSettings") }
        // With auto-quarantine off a new EICAR stays put but is still detected.
        let fx2 = files.appendingPathComponent("com.rampart.test.eicar2.com")
        try? Data(eicar.utf8).write(to: fx2)
        if case .scanFinished(_, let ds, _)? = call(.scan(paths: [fx2.path], quick: false)).last {
            check(ds.count == 1 && !ds[0].resolved && FileManager.default.fileExists(atPath: fx2.path), "daemon: autoQuarantine=false is applied live")
        } else { check(false, "daemon: scan 2") }
        // Folder allow rule suppresses detections inside it.
        if case .allowRules(let rules)? = call(.addAllowRule(AllowRuleSpec(scope: .folder, value: files.path, name: "fixtures"))).last,
           let rule = rules.first {
            if case .scanFinished(_, let ds, _)? = call(.scan(paths: [fx2.path], quick: false)).last {
                check(ds.isEmpty, "daemon: folder allow rule applied")
            } else { check(false, "daemon: scan 3") }
            if case .allowRules(let left)? = call(.removeAllowRule(id: rule.id)).last { check(left.isEmpty, "daemon: allow rule removed") }
            else { check(false, "daemon: removeAllowRule") }
        } else { check(false, "daemon: addAllowRule") }
        if case .error? = call(.addAllowRule(AllowRuleSpec(scope: .folder, value: "/", name: "everything"))).last { check(true, "daemon: refuses allow-listing /") }
        else { check(false, "daemon: refuses allow-listing /") }
        if case .error? = call(.pauseScan(paused: true)).last { check(true, "daemon: pause with no scan is an error") }
        else { check(false, "daemon: pause with no scan is an error") }
        if case .error? = call(.previewRemediation(persistenceID: "launchDaemon:/nonexistent.plist")).last { check(true, "daemon: preview of unknown item is an error") }
        else { check(false, "daemon: preview of unknown item is an error") }
        if case .networkStats(let n)? = call(.networkStats).last {
            check(!n.webProtectionAvailable && !n.webProtectionOn && n.blockedByDay.count == 14, "daemon: network stats in user mode")
        } else { check(false, "daemon: networkStats") }
        if case .wifi? = call(.wifi).last { check(true, "daemon: wifi") } else { check(false, "daemon: wifi") }
        if case .ok? = call(.setRealtime(on: false)).last { check(true, "daemon: setRealtime") } else { check(false, "daemon: setRealtime") }
        try? FileManager.default.removeItem(at: fx2)
        // v3 (RampartGuard).
        if case .tamper(let data)? = call(.tamperStatus).last { check(!data.isEmpty, "daemon: tamper status") } else { check(false, "daemon: tamper status") }
        if case .remoteAccess(let data)? = call(.remoteAccessReport).last { check(!data.isEmpty, "daemon: remote-access report") }
        else { check(false, "daemon: remote-access report") }
        if case .disableToken(let tok)? = call(.requestDisableProtection(authorization: nil, reason: "selftest")).last {
            if case .ok? = call(.disableProtection(token: tok, minutes: 1)).last { check(true, "daemon: disable-protection flow") }
            else { check(false, "daemon: disable-protection flow (redeem)") }
            if case .error? = call(.disableProtection(token: tok, minutes: 1)).last { check(true, "daemon: disable token is single-use") }
            else { check(false, "daemon: disable token is single-use") }
        } else { check(false, "daemon: disable-protection flow (token)") }
        if case .ok? = call(.forwardEvents([SecurityEvent(kind: .other, detail: ["type": "selftest"], source: "selftest")])).last {
            check(true, "daemon: forwardEvents") } else { check(false, "daemon: forwardEvents") }

        p.terminate(); p.waitUntilExit()
        check(!FileManager.default.fileExists(atPath: sock), "daemon: socket removed on SIGTERM")
        try? FileManager.default.removeItem(at: fixture)
    }
}

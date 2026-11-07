import Foundation
import RampartShared
import RampartGuard
import RampartTelemetry

// Attack suite X4 — "Blind or disable RamPart without the user noticing".
// Adversarial, INERT: every "attack" is a synthetic SecurityEvent (plain data) or a scratch fixture.
// Nothing is executed, no real process is killed, no live system state is changed.
//
// Each scenario drives RampartGuard's TamperDetector / SealedStore / ProtectionDisableFlow (the self-defence
// layer that is supposed to catch "turn the AV off" moves) and records caught / partial / missed.
// Misses are asserted against the CURRENT behaviour (so the check passes and the gap is documented), and
// written up in docs/security/needs-<module>.md.
extension SelfTest {

    static func attackX4Checks() {
        let fm = FileManager.default
        let scratch = (ProcessInfo.processInfo.environment["RAMPART_SCRATCH"] ?? NSTemporaryDirectory())
            + "/rampart-attackX4-\(UUID().uuidString.prefix(8))"
        try? fm.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: scratch) }
        let paths = GuardPaths.scratch(scratch)
        let ownPID: Int32 = 4242

        // Fresh detector per scenario so the 5 s dedupe window never swallows a distinct attack.
        func detector() -> TamperDetector { TamperDetector(paths: paths, ownPIDs: { [ownPID] }) }
        var pidSeq: Int32 = 5000
        func exec(_ det: TamperDetector, _ args: [String], signingID: String? = nil, uid: UInt32 = 501) -> [Detection] {
            pidSeq += 1
            let p = ProcessInfoLite(pid: pidSeq, ppid: 1, path: args.first ?? "/bin/sh", args: args, uid: uid, signingID: signingID)
            return det.inspect(SecurityEvent(date: Date(), kind: .exec, process: p, detail: [:], source: "test"))
        }
        func fileEvent(_ det: TamperDetector, _ kind: SecurityEventKind, path: String? = nil, dest: String? = nil,
                       detail: [String: String] = [:]) -> [Detection] {
            pidSeq += 1
            let p = ProcessInfoLite(pid: pidSeq, ppid: 1, path: "/bin/sh", uid: 501)
            return det.inspect(SecurityEvent(date: Date(), kind: kind, process: p, path: path, destPath: dest, detail: detail, source: "test"))
        }

        print("   --- Attack X4: blind / disable RamPart ---")

        // 1. CAUGHT — launchctl bootout of the root daemon (classic "stop the service").
        check(exec(detector(), ["/bin/launchctl", "bootout", "system/\(paths.daemonLabel)"])
                .contains { $0.name.contains("unloadAttempt") && $0.severity == .critical }, "X4.1 launchctl bootout of daemon → unloadAttempt (caught)")

        // 2. CAUGHT — pkill / kill -9 aimed at the service.
        check(exec(detector(), ["/usr/bin/pkill", "-9", "rampartd"]).contains { $0.name.contains("killAttempt") }, "X4.2 pkill rampartd → killAttempt (caught)")

        // 3. CAUGHT — the watchdog / sentinel of the guardian ring is the real kill target.
        check(exec(detector(), ["/usr/bin/killall", "app.rampart.watchdog"]).contains { $0.name.contains("killAttempt") }, "X4.3 killall watchdog → killAttempt (caught)")

        // 4. CAUGHT — ES `signal` event (SIGKILL) delivered to our pid without going through a named tool.
        check(detector().inspect(SecurityEvent(kind: .other, process: ProcessInfoLite(pid: 6001, ppid: 1, path: "/bin/sh", uid: 501),
              detail: ["es_event": "signal", "sig": "9", "target_pid": "\(ownPID)"], source: "test"))
              .contains { $0.severity == .critical }, "X4.4 ES SIGKILL to daemon pid → killAttempt (caught)")

        // 5. CAUGHT — delete the daemon LaunchDaemon plist (seen via eslogger unlink, no tool name).
        check(fileEvent(detector(), .fileDelete, path: paths.daemonPlist).contains { $0.severity == .critical }, "X4.5 unlink daemon plist → plistTamper critical (caught)")

        // 6. CAUGHT — clear the immutable (schg) flag before deleting a protected binary.
        check(exec(detector(), ["/usr/bin/chflags", "noschg", paths.daemonBinary])
                .contains { $0.name.contains("plistTamper") && $0.severity == .critical }, "X4.6 chflags noschg on binary → critical (caught)")

        // 7. CAUGHT — revoke RamPart's Full Disk Access via tccutil naming our bundle id.
        check(exec(detector(), ["/usr/bin/tccutil", "reset", "SystemPolicyAllFiles", "app.rampart.daemon"]).count == 1,
              "X4.7 tccutil reset FDA for app.rampart.daemon → caught")

        // 8. CAUGHT (fixed in hx5 #12) — tccutil reset of ALL apps' FDA (no bundle id) strips RamPart's FDA too.
        check(exec(detector(), ["/usr/bin/tccutil", "reset", "SystemPolicyAllFiles"]).count == 1,
              "X4.8 tccutil reset ALL FDA (unqualified) → caught")

        // 9. CAUGHT (fixed in hx5 #13) — changing the system clock is reported as clockTamper.
        check(exec(detector(), ["/usr/sbin/systemsetup", "-setdate", "01:01:2020"]).count == 1
              && exec(detector(), ["/usr/bin/sntp", "-sS", "evil.ntp.test"]).count == 1,
              "X4.9 clock rollback (systemsetup/sntp) → caught")

        // 10. CAUGHT — corrupt the hash / scan-cache DB under the support root (write by a foreign pid).
        check(fileEvent(detector(), .fileWrite, path: paths.supportRoot + "/DB/hashes.sqlite").contains { $0.severity == .high },
              "X4.10 write to scan-cache DB under support root → fileTamper (caught)")

        // 11. CAUGHT — rename a prepared file onto the agent plist (swap the job definition).
        check(fileEvent(detector(), .fileRename, path: scratch + "/evil.plist", dest: paths.agentPlist).count == 1,
              "X4.11 rename onto agent plist → plistTamper (caught)")

        // 12. CAUGHT — BTM reports our launch item removed (sfltool / System Settings login-items pane).
        check(detector().inspect(SecurityEvent(kind: .persistenceRemoved, process: ProcessInfoLite(pid: 6002, ppid: 1, path: "/bin/sh", uid: 501),
              detail: ["label": paths.daemonLabel, "es_event": "btm_launch_item_remove"], source: "test"))
              .contains { $0.name.contains("launchItemRemoved") }, "X4.12 BTM launch-item removed → caught")

        // 13. CAUGHT — ask the daemon to exclude RamPart's own paths from scanning (blind the scanner on itself).
        check(detector().exclusionsCoveringSelf(["/Users/x/Projects", paths.supportRoot, "/"]) == [paths.supportRoot, "/"],
              "X4.13 exclude RamPart paths from scanning → refused (caught)")

        // 14. CAUGHT — corrupt the sealed config / allow-rules out of band. SealedStore HMAC catches the edit.
        do {
            let key = try! IntegrityKey.loadOrCreate(at: paths.keyFile)
            let store = SealedStore(key: key, backupDir: paths.backupDir)
            let good = Data(#"{"realtimeOn":true,"exclusions":[]}"#.utf8)
            try! store.write(good, to: paths.configFile)
            check(store.verify(paths.configFile).isIntact, "X4.14a sealed config verifies")
            // Attacker rewrites the payload (disable realtime, exclude /) but cannot forge the MAC.
            var env = try! JSONSerialization.jsonObject(with: fm.contents(atPath: paths.configFile)!) as! [String: Any]
            env["payload"] = Data(#"{"realtimeOn":false,"exclusions":["/"]}"#.utf8).base64EncodedString()
            try! JSONSerialization.data(withJSONObject: env).write(to: URL(fileURLWithPath: paths.configFile))
            check(!store.verify(paths.configFile).isIntact, "X4.14b tampered sealed config → detected (caught)")
            let (_, restored) = store.restoreIfNeeded(paths.configFile, dryRun: false)
            check(restored && store.verify(paths.configFile).isIntact, "X4.14c sealed config auto-restored (caught)")
        }

        // 15. CAUGHT — racing the update-hold grace window: a foreign tool replaces the app bundle, then the
        //     grace flush finds the bundle is NOT a valid RamPart build → the held change is reported.
        do {
            let det = detector()
            // Simulate the post-replacement bundle being invalid (scratch bundle does not exist → invalid anyway).
            det.updateGrace = 0
            let held = det.inspect(SecurityEvent(kind: .fileWrite, process: ProcessInfoLite(pid: 6100, ppid: 1, path: "/bin/sh", uid: 501),
                                                 path: paths.appBundle + "/Contents/MacOS/RamPart", source: "test"))
            check(held.isEmpty, "X4.15a bundle write is held during grace (no immediate alert)")
            let flushed = det.flushPending(force: true)
            check(flushed.contains { $0.name.contains("fileTamper") }, "X4.15b invalid bundle after grace → reported (caught)")
        }

        // 16. NO FALSE POSITIVE — a genuine update that leaves a valid RamPart bundle must NOT alert after grace.
        do {
            let det = detector()
            det.updateGrace = 0
            det.bundleValidator = { _ in true }      // stand in for a valid post-update RamPart build
            det.serviceAlive = { true }
            _ = det.inspect(SecurityEvent(kind: .fileWrite, process: ProcessInfoLite(pid: 6101, ppid: 1, path: "/usr/bin/ditto", uid: 0),
                                          path: paths.appBundle + "/Contents/MacOS/RamPart", source: "test"))
            check(det.flushPending(force: true).isEmpty, "X4.16 legit update (valid bundle) raises no false tamper alert")
        }

        // 17. MISS (telemetry blinded) — eslogger is RamPart's only exec feed. If it exits because FDA was
        //     revoked, EsloggerSource records lastError and STOPS its restart loop, but nothing turns that
        //     "we are now blind" state into a Detection the user sees. Without root/FDA isAvailable is false.
        do {
            let src = EsloggerSource()
            check(src.isAvailable == (getuid() == 0), "X4.17a eslogger availability reflects root/FDA only")
            check(!src.isRunning, "X4.17b eslogger not running in test (blind)")
            // There is no public API that promotes a dead primary event source into an alert.
            check(true, "X4.17c telemetry-blind is silent → NOT surfaced as a detection (miss)")
        }

        // 18. PARTIAL — clock manipulation defeats time-boxed trust. A redeemed disable/uninstall session is
        //     bounded by wall-clock only; rolling the clock backward keeps the protection-exempt session alive
        //     indefinitely, and rolling it forward can expire allowances early. No monotonic clock guard.
        do {
            let key = try! IntegrityKey.loadOrCreate(at: paths.keyFile)
            let t0 = Date()
            final class Box: @unchecked Sendable { var now: Date; init(_ d: Date) { now = d } }
            let box = Box(t0)
            let flow = ProtectionDisableFlow(key: key, clock: GuardClock(now: { box.now }))
            guard case .success(let token) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) else {
                check(false, "X4.18 token issued"); return
            }
            _ = flow.redeem(token, peerUID: 501, purpose: .uninstall, sessionSeconds: 600)
            check(flow.hasActiveSession(uid: 501), "X4.18a authenticated session open")
            box.now = t0.addingTimeInterval(-1_000_000)   // attacker rolls the wall clock far backward
            check(flow.hasActiveSession(uid: 501), "X4.18b clock rollback keeps the exempt session alive (partial/miss)")
            box.now = t0.addingTimeInterval(10_000_000)    // and forward expires it
            check(!flow.hasActiveSession(uid: 501), "X4.18c clock jump forward expires the session")
        }

        // 19. PARTIAL — a decoy process that impersonates RamPart (same process name) to spoof the user's
        //     trust / menu-bar presence is NOT a kill target, so it is correctly ignored by the tamper layer;
        //     but nothing here flags an impostor "rampartd" running from a non-install path. Signing-based
        //     impostor detection would live in the app/telemetry layer, not Guard.
        check(exec(detector(), ["/tmp/rampartd"], signingID: "com.evil.fake").isEmpty,
              "X4.19 impostor /tmp/rampartd launch → not flagged by Guard (partial; needs signing check)")

        // 20. CAUGHT — process launched by us (our own pid / our signing id) is never self-attacked (no self-DoS).
        // A bare ad-hoc signing ID is no longer trusted (hx5 #1); our installer counts as self as a child of our pid.
        let installer = ProcessInfoLite(pid: 6999, ppid: ownPID, path: "/bin/launchctl", args: ["/bin/launchctl", "bootout", "system/\(paths.daemonLabel)"],
                                        uid: 0, signingID: "app.rampart.installer")
        check(detector().inspect(SecurityEvent(date: Date(), kind: .exec, process: installer, detail: [:], source: "test")).isEmpty
              && det20SelfPidExempt(paths: paths, ownPID: ownPID),
              "X4.20 our own installer/pid touching our files is exempt (no self-inflicted alerts)")

        print("   X4: 20 scenarios — see docs/security/attacks-X4.md for the caught/partial/missed table.")
    }

    private static func det20SelfPidExempt(paths: GuardPaths, ownPID: Int32) -> Bool {
        let det = TamperDetector(paths: paths, ownPIDs: { [ownPID] })
        let p = ProcessInfoLite(pid: ownPID, ppid: 1, path: "/bin/launchctl",
                                args: ["/bin/launchctl", "bootout", "system/\(paths.daemonLabel)"], uid: 0)
        return det.inspect(SecurityEvent(kind: .exec, process: p, source: "test")).isEmpty
    }
}

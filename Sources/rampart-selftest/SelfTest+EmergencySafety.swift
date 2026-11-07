import Foundation
import RampartShared
import RampartGuard

// User incident 2026-11-07: a root daemon without Full Disk Access (eslogger NOT_PERMITTED) produced dozens of
// "lost its real-time event feed" detections, auto-lockdown read it as tampering, cut the network through
// com.apple/249.RampartEmergency, and the user couldn't lift it. Fixtures only: nothing is signalled, no pf rule is
// loaded; the kill switch script runs in dry-run mode.
extension SelfTest {
    static func emergencySafetyChecks() {
        let tmp = URL(fileURLWithPath: SelfTest.fixtureTempDir).appendingPathComponent("com.rampart.test.emsafety-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        final class Box: @unchecked Sendable { var now = Date(timeIntervalSince1970: 1_800_000_000) }
        let clock = Box()
        let gc = GuardClock(now: { clock.now })
        let fw = EmergencyFirewall(directory: tmp.path)
        func det(_ name: String, cat: ThreatCategory = .suspicious, sev: Severity = .high, conf: Int = 90, src: DetectionSource = .behaviour,
                 title: String = "t", detail: String = "fixture", path: String? = nil, pid: Int32? = nil) -> Detection {
            Detection(path: path, pid: pid, name: name, category: cat, severity: sev, confidence: conf,
                      evidence: [Evidence(source: src, title: title, detail: detail, score: conf)])
        }

        // 1. Telemetry source failures are never tamper.
        let feed = det("\(Product.name) lost its real-time event feed", conf: 85, title: "Telemetry source 'eslogger' is down",
                       detail: "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED")
        check(EmergencyTriggerPolicy.isHealthIssue(feed) && EmergencyTriggerPolicy.evaluate(feed) == nil, "safety: eslogger not-permitted never triggers emergency")
        let feedAsTamper = det("Tampering with \(Product.name): killAttempt", sev: .critical, conf: 95, title: "eslogger is down", detail: "eslogger not permitted (Full Disk Access)")
        check(EmergencyTriggerPolicy.evaluate(feedAsTamper) == nil, "safety: a 'tamper' that is really eslogger not permitted is a health issue")
        check(EmergencyTriggerPolicy.evaluate(det("Tampering with \(Product.name): clockTamper", sev: .critical, conf: 95)) == nil,
              "safety: tamper kinds without an external actor are not tampering triggers")
        let n = HealthNote.sourceDown("eslogger", lastError: "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED")
        check(n.fix == .fullDiskAccess && n.message == "Real-time monitoring needs Full Disk Access", "safety: not permitted -> Full Disk Access status note")
        check(HealthNote.sourceDown("eslogger", lastError: "exited with status 1").fix == .restartService, "safety: a crashed source is a health note too")
        let cFeed = EmergencyController(path: tmp.appendingPathComponent("feed.json").path, clock: gc)
        for _ in 0..<40 { if let r = EmergencyTriggerPolicy.evaluate(feed) { _ = cFeed.assess(r) } }
        check(!cFeed.isActive, "safety: 40 feed-lost signals never engage lockdown")

        // 2. A single signal never cuts the network; corroboration does.
        let tamper = EmergencyTriggerPolicy.evaluate(det("Tampering with \(Product.name): unloadAttempt", conf: 90, detail: "launchctl bootout by evil (pid 666)"))!
        let cT = EmergencyController(path: tmp.appendingPathComponent("t.json").path, clock: gc)
        let aT = cT.assess(tamper)
        check(!aT.engage && !aT.containNetwork, "safety: a single tamper signal produces no lockdown and no network block")
        let malware = EmergencyTriggerReason(kind: .confirmedMalware, summary: "Known malware", detectionName: "OSX.Fixture", path: "/tmp/x", confidence: 100)
        let cM = EmergencyController(path: tmp.appendingPathComponent("m.json").path, clock: gc)
        let aM = cM.assess(malware)
        check(aM.engage && !aM.containNetwork, "safety: a single malware signal freezes/quarantines but keeps the internet on")
        let planM = EmergencyPlanner.plan(malware, context: EmergencyContext(), firewall: fw, containNetwork: aM.containNetwork)
        check(planM.first { $0.kind == .networkContainment }?.state == .skipped && planM.first { $0.kind == .clearClipboard }?.state == .skipped,
              "safety: automatic plan without network skips network and disruptive steps")
        check(cM.engage(malware, actions: planM, dryRun: true) && !cM.state.isNetworkBlocked, "safety: automatic lockdown without network block")
        let aM2 = cM.assess(tamper)
        check(aM2.containNetwork, "safety: two independent strong signals may cut the network")
        check(cM.upgradeToNetwork(why: aM2.why) && cM.state.isNetworkBlocked && cM.networkSecondsLeft() == 600, "safety: upgrade to network starts the 10-minute timer")
        let ransom = EmergencyTriggerReason(kind: .ransomware, summary: "Ransomware burst", confidence: 95)
        check(EmergencyNetworkPolicy.assess(ransom, recent: [], now: clock.now).containNetwork, "safety: a ransomware burst cuts the network")
        let exfil = EmergencyTriggerReason(kind: .exfiltration, summary: "exfil", confidence: 95)
        check(!EmergencyNetworkPolicy.assess(exfil, recent: [], now: clock.now).containNetwork, "safety: exfiltration alone keeps the internet on")
        check(EmergencyNetworkPolicy.assess(exfil, recent: [EmergencySignal(kind: .confirmedMalware, key: "m", date: clock.now)], now: clock.now).containNetwork,
              "safety: exfiltration plus a malicious detection cuts the network")
        check(!EmergencyNetworkPolicy.assess(exfil, recent: [EmergencySignal(kind: .confirmedMalware, key: "m", date: clock.now.addingTimeInterval(-3600))], now: clock.now).containNetwork,
              "safety: corroboration must be recent")
        check(!EmergencyNetworkPolicy.assess(tamper, recent: [EmergencySignal(kind: .confirmedMalware, key: "m", date: clock.now)], now: clock.now,
                                             liftedAt: clock.now.addingTimeInterval(-60)).engage, "safety: right after an admin lift, tamper signals don't re-lock")

        // 3. Automatic network containment expires; Keep blocking keeps it.
        let cE = EmergencyController(path: tmp.appendingPathComponent("e.json").path, clock: gc)
        check(cE.engage(ransom, actions: EmergencyPlanner.plan(ransom, context: EmergencyContext(), firewall: fw), dryRun: true) && cE.state.isNetworkBlocked,
              "safety: ransomware lockdown blocks the network")
        clock.now = clock.now.addingTimeInterval(599)
        check(!cE.expireNetworkIfDue() && cE.networkSecondsLeft() == 1, "safety: auto block still on before 10 minutes")
        clock.now = clock.now.addingTimeInterval(2)
        check(cE.expireNetworkIfDue() && !cE.state.isNetworkBlocked && cE.networkSecondsLeft() == nil, "safety: auto network containment expires after 10 minutes")
        check(cE.state.actions.first { $0.kind == .networkContainment }?.state == .undone, "safety: expired block recorded as undone")
        let cK = EmergencyController(path: tmp.appendingPathComponent("k.json").path, clock: gc)
        cK.engage(ransom, actions: EmergencyPlanner.plan(ransom, context: EmergencyContext(), firewall: fw), dryRun: true)
        cK.keepBlocking()
        clock.now = clock.now.addingTimeInterval(3600)
        check(!cK.expireNetworkIfDue() && cK.state.isNetworkBlocked, "safety: Keep blocking stops the expiry")

        // 4. A restart never re-applies an automatic block; a manual one persists.
        let autoPath = tmp.appendingPathComponent("auto.json").path
        let cA = EmergencyController(path: autoPath, clock: gc)
        cA.engage(ransom, actions: EmergencyPlanner.plan(ransom, context: EmergencyContext(), firewall: fw), dryRun: true)
        let cA2 = EmergencyController(path: autoPath, clock: gc)
        check(cA2.prepareForRestart() == false && cA2.isActive && !cA2.state.isNetworkBlocked, "safety: restart doesn't re-apply an automatic network block")
        check(EmergencyController(path: autoPath, clock: gc).prepareForRestart() == false, "safety: a second restart still doesn't re-apply it")
        let manPath = tmp.appendingPathComponent("man.json").path
        let cMan = EmergencyController(path: manPath, clock: gc)
        cMan.engage(.manual(uid: 501), actions: EmergencyPlanner.plan(.manual(uid: 501), context: EmergencyContext(), firewall: fw), dryRun: true)
        check(EmergencyController(path: manPath, clock: gc).prepareForRestart() == true, "safety: a manual lockdown is re-applied after a restart")
        // Older state files (no safety fields) still decode.
        let legacyPath = tmp.appendingPathComponent("legacy.json").path
        var legacy = cMan.state; legacy.automatic = nil; legacy.networkBlocked = nil; legacy.networkExpiresAt = nil; legacy.keepBlocking = nil
        if let d = try? JSONEncoder.rampart.encode(legacy) { FileManager.default.createFile(atPath: legacyPath, contents: d) }
        check(EmergencyController(path: legacyPath, clock: gc).isActive, "safety: an emergency.json without the new fields still loads")

        // 5. An admin lift always succeeds; unauthenticated is refused.
        let cL = EmergencyController(path: tmp.appendingPathComponent("l.json").path, clock: gc)
        cL.engage(tamper, actions: EmergencyPlanner.plan(tamper, context: EmergencyContext(), firewall: fw), dryRun: true)
        check((try? cL.lift(authorized: false)) == nil && cL.isActive, "safety: unauthenticated lift refused")
        check(cL.readiness()?.ready == false, "safety: (fixture) lockdown not ready")
        let undo = (try? cL.lift(authorized: true, force: false)) ?? []
        check(!cL.isActive && undo.contains { $0.kind == .networkContainment }, "safety: an admin lift always succeeds and always unloads the network")
        let cF = EmergencyController(path: tmp.appendingPathComponent("f.json").path, clock: gc)
        cF.engage(ransom, actions: EmergencyPlanner.plan(ransom, context: EmergencyContext(), firewall: fw), dryRun: true)
        cF.updateAction(.networkContainment, state: .failed, result: "pfctl failed")
        check(((try? cF.lift(authorized: true)) ?? []).contains { $0.kind == .networkContainment }, "safety: lift unloads the anchor even when loading it was recorded as failed")
        let cR = EmergencyController(path: tmp.appendingPathComponent("r.json").path, clock: gc)
        cR.engage(ransom, actions: EmergencyPlanner.plan(ransom, context: EmergencyContext(), firewall: fw), dryRun: true)
        check((try? cR.restoreNetwork(authorized: false)) == nil && cR.state.isNetworkBlocked, "safety: restore internet needs auth")
        check((try? cR.restoreNetwork(authorized: true)) != nil && !cR.state.isNetworkBlocked && cR.isActive, "safety: Restore internet now works with no readiness gate")

        // 6. Root CLI lift works without the daemon: anchor flushed, frozen processes resumed, state lifted.
        let cliPath = tmp.appendingPathComponent("cli.json").path
        let cC = EmergencyController(path: cliPath, clock: gc)
        var planC = EmergencyPlanner.plan(ransom, context: EmergencyContext(processTree: [(4242, "/Users/x/evil")]), firewall: fw)
        if let i = planC.firstIndex(where: { $0.kind == .suspendProcesses }) { planC[i].state = .done }
        cC.engage(ransom, actions: planC, dryRun: false)
        var ran: [String] = [], signalled: [Int32] = []
        let lines = EmergencyRecovery.offline(statePath: cliPath, firewall: fw, dryRun: false,
                                              run: { ran.append($0.description); return true }, signal: { signalled.append($0); return true })
        check(ran.contains { $0.contains("-a \(fw.anchor) -F all") } && signalled == [4242] && lines.contains("lockdown marked lifted")
              && !EmergencyController(path: cliPath, clock: gc).isActive, "safety: root CLI lift flushes the anchor, SIGCONTs, lifts")

        // 7. SIGTERM / bootout always unloads the anchor.
        let cS = EmergencyController(path: tmp.appendingPathComponent("s.json").path, clock: gc)
        cS.engage(ransom, actions: EmergencyPlanner.plan(ransom, context: EmergencyContext(), firewall: fw), dryRun: true)
        let sc = EmergencyRecovery.onShutdown(cS, firewall: fw)
        check(sc.contains { $0.executable == EmergencyFirewall.pfctl && $0.arguments == ["-a", fw.anchor, "-F", "all"] } && !cS.state.isNetworkBlocked,
              "safety: SIGTERM unloads the emergency anchor")
        let idle = EmergencyController(path: tmp.appendingPathComponent("idle.json").path, clock: gc)
        check(!EmergencyRecovery.onShutdown(idle, firewall: fw).isEmpty, "safety: SIGTERM unloads the anchor even with no lockdown recorded")
        if let src = try? String(contentsOfFile: repoRoot + "/Sources/rampartd/main.swift", encoding: .utf8) {
            check(src.range(of: "Emergency.shutdown(protection)") != nil, "safety: the SIGTERM handler calls Emergency.shutdown")
        }

        // 8. Notifications: engaging emits the user-facing notice; lifting says the internet is back.
        let cN = EmergencyController(path: tmp.appendingPathComponent("n.json").path, clock: gc)
        let before = cN.status(mode: "dry run")
        cN.engage(ransom, actions: EmergencyPlanner.plan(ransom, context: EmergencyContext(), firewall: fw), dryRun: true)
        let on = EmergencyNotice.transition(from: before, to: cN.status(mode: "dry run"))
        check(on?.kind == .engaged && on?.body.hasPrefix("\(Product.name) turned on Emergency Lockdown: Ransomware burst") == true
              && on?.body.contains("Internet is blocked for 10 min.") == true && on?.timeSensitive == true
              && on?.actions == [EmergencyNotice.restoreAction, EmergencyNotice.detailsAction], "safety: engaging a lockdown emits the notification event")
        check(EmergencyNotice.transition(from: nil, to: cN.status(mode: "x"))?.kind == .engaged, "safety: an app started during a lockdown notifies too")
        let mid = cN.status(mode: "x")
        _ = try? cN.lift(authorized: true)
        check(EmergencyNotice.transition(from: mid, to: cN.status(mode: "x"))?.title == "Internet restored", "safety: lifting notifies 'Internet restored'")
        let cX = EmergencyController(path: tmp.appendingPathComponent("x.json").path, clock: gc)
        cX.engage(ransom, actions: EmergencyPlanner.plan(ransom, context: EmergencyContext(), firewall: fw), dryRun: true)
        let preExpire = cX.status(mode: "x")
        clock.now = clock.now.addingTimeInterval(700); _ = cX.expireNetworkIfDue()
        check(EmergencyNotice.transition(from: preExpire, to: cX.status(mode: "x"))?.kind == .expired, "safety: expiry notifies 'Internet restored'")

        killSwitchChecks(tmp)
    }

    static var repoRoot: String {
        var u = URL(fileURLWithPath: #filePath)
        for _ in 0..<3 { u.deleteLastPathComponent() }
        return u.path
    }

    private static func killSwitchChecks(_ tmp: URL) {
        struct Boom: Error {}
        var ran: [KillSwitch.StepID] = []
        let r = KillSwitch.run(KillSwitch.StepID.allCases.map { id in
            (id, { ran.append(id); if id == .liftLockdown || id == .restoreDNS { throw Boom() }; return "ok" })
        }, via: "test")
        check(ran == KillSwitch.StepID.allCases && r.steps.count == 6 && r.steps.filter { !$0.ok }.map(\.id) == [.liftLockdown, .restoreDNS],
              "killswitch: each step is independent (failures never block the rest)")
        check(!r.allOK && r.summary.contains("didn't fully work"), "killswitch: the report says what failed")
        let anchors = KillSwitch.rampartAnchors(listing: "  com.apple/200.AirDrop\n  com.apple/252.RampartPublicWiFi\n  com.apple/254.RampartDNS; rm -rf /\n")
        check(anchors.contains("com.apple/249.RampartEmergency") && anchors.contains("com.apple/250.Rampart") && anchors.contains("com.apple/251.RampartRemote")
              && anchors.contains("app.rampart/lure") && anchors.contains("com.apple/252.RampartPublicWiFi") && !anchors.contains { $0.contains("AirDrop") || $0.contains(";") },
              "killswitch: every RamPart anchor (known + listed), nothing else")
        check(KillSwitch.networkServices(listing: "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100\n")
              == ["Wi-Fi", "Thunderbolt Bridge", "USB 10/100"], "killswitch: every network service parsed")
        check(KillSwitch.buttonVisible(lockdownActive: true, networkBlocked: false, webProtectionOn: false, daemonReachable: true)
              && KillSwitch.buttonVisible(lockdownActive: false, networkBlocked: false, webProtectionOn: true, daemonReachable: true)
              && KillSwitch.buttonVisible(lockdownActive: false, networkBlocked: false, webProtectionOn: false, daemonReachable: false)
              && !KillSwitch.buttonVisible(lockdownActive: false, networkBlocked: false, webProtectionOn: false, daemonReachable: true),
              "killswitch: the button always shows when lockdown or web protection is active")
        // Unauthenticated kill switch IPC is refused (not RamPart's app/CLI, or not an admin).
        let lvl = IPCAuthz.level(.killSwitch(token: nil))
        check(IPCAuthz.denial(lvl, AuthzCaller(uid: 501, isAdmin: true, isConsole: true, client: nil), name: "killSwitch") != nil
              && IPCAuthz.denial(lvl, AuthzCaller(uid: 502, isAdmin: false, isConsole: true, client: .app), name: "killSwitch") != nil,
              "killswitch: an unauthenticated IPC call is refused")
        check(IPCAuthz.denial(IPCAuthz.level(.emergencyNetwork(keep: false, token: nil)), AuthzCaller(uid: 501, isAdmin: true, isConsole: true, client: nil), name: "x") != nil,
              "safety: restore-internet IPC refused from an unknown client")

        // Path B script, dry run (RAMPART_NO_PRIVILEGED_TOOLS): every anchor and every network service.
        let script = repoRoot + "/Packaging/killswitch.sh"
        guard FileManager.default.fileExists(atPath: script) else { check(false, "killswitch: script exists"); return }
        let root = tmp.appendingPathComponent("ksroot")
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let st = #"{"active":true,"actions":[{"kind":"suspendProcesses","pids":[4242,4243]}]}"#
        FileManager.default.createFile(atPath: root.appendingPathComponent("emergency.json").path, contents: Data(st.utf8))
        let p = Process(); let pipe = Pipe()
        p.executableURL = URL(fileURLWithPath: "/bin/sh"); p.arguments = [script]
        p.environment = ["RAMPART_NO_PRIVILEGED_TOOLS": "1", "RAMPART_KS_ROOT": root.path,
                         "RAMPART_KS_ANCHORS": "  com.apple/250.Rampart\n  com.apple/252.RampartPublicWiFi\n  com.apple/253.RampartNetscan\n  com.apple/200.AirDrop",
                         "RAMPART_KS_SERVICES": "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100 LAN"]
        p.standardOutput = pipe; p.standardError = pipe
        try? p.run(); p.waitUntilExit()
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let wantAnchors = ["com.apple/249.RampartEmergency", "com.apple/250.Rampart", "com.apple/251.RampartRemote", "app.rampart/lure",
                           "com.apple/252.RampartPublicWiFi", "com.apple/253.RampartNetscan"]
        check(wantAnchors.allSatisfy { out.contains("DRY-RUN: pfctl -a \($0) -F all") } && !out.contains("AirDrop"), "killswitch: dry-run script covers every anchor")
        check(["Wi-Fi", "Thunderbolt Bridge", "USB 10/100 LAN"].allSatisfy { out.contains("DRY-RUN: networksetup -setdnsservers \($0) Empty") },
              "killswitch: dry-run script covers every network service")
        check(out.contains("DRY-RUN: kill -CONT 4242") && out.contains("DRY-RUN: kill -CONT 4243") && out.contains("DRY-RUN: launchctl bootout system/app.rampart.daemon")
              && out.contains("DONE: 6 ok, 0 failed") && FileManager.default.fileExists(atPath: root.appendingPathComponent("emergency.json").path),
              "killswitch: dry-run resumes frozen pids, stops the service, changes nothing")
        check(!out.contains("/Applications/") && !out.contains("rampartd ") && !out.contains("Helpers/rampart"), "killswitch: the script never depends on RamPart binaries")
    }
}

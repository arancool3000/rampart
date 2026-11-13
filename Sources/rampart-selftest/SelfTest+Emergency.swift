import Foundation
import RampartShared
import RampartGuard

// Emergency Lockdown + Protect Everything: fixtures only. Nothing is signalled, no pf rule is loaded,
// no command runs (the planner only produces GuardCommand values).
extension SelfTest {
    static func emergencyChecks() {
        let tmp = URL(fileURLWithPath: SelfTest.fixtureTempDir).appendingPathComponent("com.rampart.test.emergency-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        // MARK: trigger evaluation
        func det(_ name: String, cat: ThreatCategory = .malware, sev: Severity = .critical, conf: Int = 100,
                 src: DetectionSource = .hash, score: Int = 100, path: String? = "/Users/x/Downloads/evil.bin", pid: Int32? = 4242,
                 sha: String? = String(repeating: "a", count: 64), resolved: Bool = false, title: String = "match") -> Detection {
            Detection(path: path, pid: pid, sha256: sha, name: name, category: cat, severity: sev, confidence: conf,
                      evidence: [Evidence(source: src, title: title, detail: "fixture", score: score)], resolved: resolved)
        }
        check(EmergencyTriggerPolicy.evaluate(det("OSX.Fixture.A"))?.kind == .confirmedMalware, "emergency fires on hash critical")
        check(EmergencyTriggerPolicy.evaluate(det("XProtect.Fixture", src: .xprotect, score: 95, path: "/tmp/a", pid: nil))?.kind == .confirmedMalware, "emergency fires on XProtect")
        check(EmergencyTriggerPolicy.evaluate(det("OSX.Fixture.A", conf: 94)) == nil, "emergency not below 95 for file hits")
        check(EmergencyTriggerPolicy.evaluate(det("Unsigned thing", sev: .high, conf: 99, src: .signing, score: 50)) == nil, "emergency not on signing heuristics")
        check(EmergencyTriggerPolicy.evaluate(det("Note", sev: .info, conf: 100)) == nil, "emergency not on info notes")
        check(EmergencyTriggerPolicy.evaluate(det("Low", sev: .low)) == nil && EmergencyTriggerPolicy.evaluate(det("Med", sev: .medium)) == nil, "emergency not on low/medium")
        check(EmergencyTriggerPolicy.evaluate(det("EICAR-Test-File", cat: .test)) == nil, "emergency not on EICAR (category test)")
        check(EmergencyTriggerPolicy.evaluate(det("EICAR-Test-File", cat: .malware)) == nil, "emergency not on EICAR by name")
        check(EmergencyTriggerPolicy.evaluate(det("X", path: "/tmp/com.rampart.test.sample")) == nil, "emergency not on com.rampart.test fixtures")
        check(EmergencyTriggerPolicy.evaluate(det("OSX.Fixture.A"), isAllowlisted: { _ in true }) == nil, "emergency not on allow-listed")
        check(EmergencyTriggerPolicy.evaluate(det("OSX.Fixture.A", pid: nil, resolved: true)) == nil, "emergency not on already-quarantined file that never ran")
        check(EmergencyTriggerPolicy.evaluate(det("Ransomware: canary files modified", cat: .ransomware, conf: 95, src: .behaviour, score: 95))?.kind == .ransomware, "emergency fires on ransomware canary")
        check(EmergencyTriggerPolicy.evaluate(det("Ransomware-like", cat: .ransomware, conf: 70, src: .behaviour, score: 70)) == nil, "emergency not on weak ransomware")
        check(EmergencyTriggerPolicy.evaluate(det("Unsigned code read browser credentials", cat: .infostealer, conf: 92, src: .behaviour, score: 92))?.kind == .credentialTheft, "emergency fires on credential theft")
        check(EmergencyTriggerPolicy.evaluate(det("Data exfiltration to paste site", cat: .suspicious, sev: .high, conf: 93, src: .behaviour, score: 93))?.kind == .exfiltration, "emergency fires on exfiltration")
        check(EmergencyTriggerPolicy.evaluate(det("Mass mailing burst", cat: .suspicious, sev: .high, conf: 91, src: .behaviour, score: 91))?.kind == .exfiltration, "emergency fires on mass mailing")
        check(EmergencyTriggerPolicy.evaluate(det("Tampering with \(Product.name): unloadAttempt", cat: .suspicious, sev: .high, conf: 90, src: .behaviour, score: 90))?.kind == .tampering, "emergency fires on tamper attempt")
        check(EmergencyTriggerPolicy.evaluate(det("Self-defence: x", cat: .suspicious, sev: .high, conf: 85, src: .behaviour, score: 85)) == nil, "emergency not on self-defence note")

        // MARK: action plan
        let tree: [(pid: Int32, path: String)] = [(4242, "/Users/x/Downloads/evil.bin"), (4243, "/bin/zsh"), (4244, "/usr/bin/curl"),
                                                   (4245, "/Users/x/.local/payload"), (1, "/sbin/launchd"), (4246, "/opt/fake/WindowServer"),
                                                   (4247, "/Applications/Rampart.app/Contents/MacOS/RampartApp"), (4248, "/Users/x/platformish")]
        let la = PersistenceItem(kind: .launchAgent, label: "com.evil.agent", location: "/Users/x/Library/LaunchAgents/com.evil.agent.plist")
        let apple = PersistenceItem(kind: .launchAgent, label: "com.apple.something", location: "/Library/LaunchAgents/com.apple.something.plist")
        let inj = PersistenceItem(kind: .launchDaemon, label: "bad;rm -rf /", location: "/Library/LaunchDaemons/bad.plist")
        let ctx = EmergencyContext(processTree: tree, files: ["/Users/x/Downloads/evil.bin", "/System/Library/foo", "relative/path"],
                                   newLaunchItems: [la, apple, inj], uid: 501, isPlatformBinary: { $0 == 4248 })
        let reason = EmergencyTriggerPolicy.evaluate(det("OSX.Fixture.A"))!
        let fw = EmergencyFirewall(directory: tmp.path)
        let plan = EmergencyPlanner.plan(reason, context: ctx, firewall: fw)
        check(Set(plan.map(\.kind)) == Set(EmergencyAction.Kind.allCases), "emergency plan covers all 9 actions")
        let sus = plan.first { $0.kind == .suspendProcesses }!
        // wms-o7 (F4): a process merely NAMED WindowServer outside the system folders is no longer exempt (malware could
        // pick the name). Stricter than before: it must be frozen; real RamPart and platform binaries stay spared.
        check(sus.pids == [4242, 4245, 4246], "emergency suspends only non-platform pids")
        check(sus.protectedPIDs.contains(4243) && sus.protectedPIDs.contains(4244) && sus.protectedPIDs.contains(1), "emergency spares /bin /usr launchd")
        check(!sus.protectedPIDs.contains(4246) && sus.protectedPIDs.contains(4247) && sus.protectedPIDs.contains(4248), "emergency spares RamPart and platform flag, not a WindowServer look-alike")
        check(sus.commands.map(\.description).joined(separator: "|").contains("/bin/kill -STOP 4242") && sus.undoCommands.allSatisfy { $0.arguments.first == "-CONT" }, "emergency SIGSTOP dry-run commands + SIGCONT undo")
        check(plan.first { $0.kind == .quarantineFiles }!.paths == ["/Users/x/Downloads/evil.bin"], "emergency quarantines only absolute non-system files")
        let snap = plan.first { $0.kind == .snapshot }!
        check(snap.commands.first?.executable == "/usr/bin/tmutil" && snap.commands.first?.arguments == ["localsnapshot"], "emergency APFS snapshot command")
        let li = plan.first { $0.kind == .pauseLaunchItems }!
        let lcs = li.commands.map { $0.arguments.joined(separator: " ") }
        check(lcs.contains("bootout gui/501/com.evil.agent") && lcs.contains("disable gui/501/com.evil.agent"), "emergency disables new launch agent")
        check(!lcs.contains { $0.contains("com.apple.") }, "emergency never disables com.apple launch items")
        check(!lcs.contains { $0.contains(";") || $0.contains(" -rf") }, "emergency sanitises launch labels")
        check(li.undoCommands.contains { $0.arguments == ["enable", "gui/501/com.evil.agent"] }, "emergency launch item undo")
        check(plan.filter { $0.runner == .app }.map(\.kind).sorted { $0.rawValue < $1.rawValue } == [.alert, .clearClipboard, .lockVault], "emergency app-side actions")
        let net = plan.first { $0.kind == .networkContainment }!
        check(net.commands.map(\.arguments) == [["-E"], ["-a", fw.anchor, "-f", fw.rulesPath]] && net.undoCommands.first?.arguments == ["-a", fw.anchor, "-F", "all"], "emergency pf load/unload commands")
        check(fw.unloadCommands(token: "123").last?.arguments == ["-X", "123"] && fw.unloadCommands(token: "1;x").count == 1, "emergency pf token release validated")

        // MARK: pf rules text
        let rules = fw.anchorRules()
        let lines = rules.split(separator: "\n").map(String.init).filter { !$0.hasPrefix("#") && !$0.isEmpty }
        check(lines.last == "block drop in quick log all" && lines.dropLast().last == "block return out quick log all", "emergency pf blocks all in/out last")
        let passes = lines.filter { $0.hasPrefix("pass") }
        check(passes.count == 7 && passes.allSatisfy { $0.contains("quick") }, "emergency pf passes are all quick")
        check(passes.contains("pass quick on lo0 all"), "emergency pf allows loopback")
        check(passes.contains { $0.contains("port 68 to any port 67") }, "emergency pf allows DHCP")
        check(passes.contains { $0.contains("<rampart_doh> port 443") } && !passes.contains { $0.contains("port 53") }, "emergency pf allows DoH 443 only, no plain DNS")
        check(passes.contains { $0.contains("<rampart_apple_update>") }, "emergency pf allows Apple updates")
        check(!passes.contains { $0.contains("from any to any") && !$0.contains("port") }, "emergency pf has no pass-all")
        check(EmergencyFirewall.dohResolvers.allSatisfy(EmergencyFirewall.isAddress) && rules.contains("1.1.1.2") && rules.contains("9.9.9.9"), "emergency pf DoH table literal IPs")
        let lb = lines.firstIndex(of: "pass quick on lo0 all")!, blk = lines.firstIndex(of: "block return out quick log all")!
        check(lb < blk, "emergency pf loopback before block")
        let table = fw.appleTable(["17.253.1.1", "2620:149::1", "bad host", "1.2.3.4 }\npass out all", "17.253.1.1"])
        check(table == "17.253.1.1\n2620:149::1\n", "emergency pf apple table drops non-IPs and injection")

        // MARK: persistence across a restart
        final class Box: @unchecked Sendable { var now = Date(timeIntervalSince1970: 1_800_000_000) }
        let clock = Box()
        let gc = GuardClock(now: { clock.now })
        let statePath = tmp.appendingPathComponent("emergency.json").path
        let c1 = EmergencyController(path: statePath, clock: gc)
        check(c1.engage(reason, actions: plan, dryRun: true), "emergency engages")
        check(!c1.engage(.manual(uid: 501), actions: [], dryRun: true), "emergency second engage is logged, not restarted")
        c1.updateAction(.networkContainment, state: .dryRun, result: "fixture")
        let c2 = EmergencyController(path: statePath, clock: gc)   // simulated daemon restart
        check(c2.isActive && c2.state.reason?.kind == .confirmedMalware && c2.state.actions.count == 9, "emergency state survives restart")
        check(c2.state.actions.first { $0.kind == .networkContainment }?.state == .dryRun, "emergency action state survives restart")
        var st = stat(); _ = stat(statePath, &st)
        check(st.st_mode & 0o077 == 0, "emergency state file is 0600")

        // MARK: readiness + lift requires a token
        let key = IntegrityKey(data: Data(repeating: 7, count: 32))
        let flow = ProtectionDisableFlow(key: key, clock: gc)
        func redeem(_ t: String?) -> Bool { guard let t else { return false }; if case .success = flow.redeem(t, peerUID: 501, purpose: .settings, sessionSeconds: 300) { return true }; return false }
        check(c2.readiness()?.ready == false, "emergency not ready right away")
        check((try? c2.lift(authorized: redeem(nil))) == nil, "emergency lift without token refused")
        check((try? c2.lift(authorized: redeem("forged.501.9999999999.deadbeef"))) == nil, "emergency lift with forged token refused")
        if case .success(let tok) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) {
            // User incident 2026-11-07: an authenticated admin lift always succeeds (readiness is advice, never a gate).
            let c2b = EmergencyController(path: tmp.appendingPathComponent("e2b.json").path, clock: gc)
            c2b.engage(reason, actions: plan, dryRun: true)
            let ok = c2b.readiness()?.ready == false && (try? c2b.lift(authorized: redeem(tok))) != nil
            check(ok && !c2b.isActive, "emergency admin lift always succeeds, even before every check passed")
            check(!redeem(tok), "emergency token is single-use")
        } else { check(false, "emergency token issue") }
        c2.noteRescan(clean: true, triggerGone: true)
        clock.now = clock.now.addingTimeInterval(60)
        check(c2.readiness()?.ready == false && (c2.readiness()?.secondsUntilQuiet ?? 0) == 60, "emergency waits for 2 quiet minutes")
        c2.noteDetection(det("Other critical", path: "/tmp/other", sha: String(repeating: "b", count: 64)))
        clock.now = clock.now.addingTimeInterval(119)
        check(c2.readiness()?.ready == false, "emergency new critical resets quiet timer and rescan")
        c2.noteRescan(clean: true, triggerGone: true)
        clock.now = clock.now.addingTimeInterval(2)
        check(c2.readiness()?.ready == true, "emergency ready after rescan + resolved + quiet")
        if case .success(let tok) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) {
            let undo = (try? c2.lift(authorized: redeem(tok))) ?? []
            check(!c2.isActive && undo.contains { $0.kind == .networkContainment }, "emergency lift with valid token undoes network")
        }
        check(EmergencyController(path: statePath, clock: gc).isActive == false, "emergency lifted state persists")
        check(flow.issueToken(peerUID: 502, isAdmin: false, authorizationOK: true).isFailure, "emergency token needs admin")

        // Force lift: still needs the token.
        let c3 = EmergencyController(path: tmp.appendingPathComponent("e3.json").path, clock: gc)
        c3.engage(.manual(uid: 501), actions: plan, dryRun: true)
        check((try? c3.lift(authorized: false, force: true)) == nil, "emergency force lift still needs auth")
        check((try? c3.lift(authorized: true, force: true)) != nil && !c3.isActive, "emergency force lift with auth (never locked out)")

        // MARK: escalation
        let c4 = EmergencyController(path: tmp.appendingPathComponent("e4.json").path, clock: gc)
        c4.engage(reason, actions: plan, dryRun: true)
        check(c4.escalation() == nil, "emergency no escalation at start")
        c4.update { $0.quarantinedHashes = [String(repeating: "a", count: 64)]; $0.pausedLaunchLabels = ["com.evil.agent"] }
        check(c4.noteDetection(det("OSX.Fixture.A")) == [.payloadReappeared], "emergency escalates when payload re-appears")
        check(c4.noteDetection(det("Tampering with \(Product.name): x", cat: .suspicious, sev: .high, src: .behaviour, sha: nil)).isEmpty, "emergency one tamper is not escalation")
        check(c4.noteDetection(det("Tampering with \(Product.name): y", cat: .suspicious, sev: .high, src: .behaviour, sha: nil)) == [.tamperingContinues], "emergency escalates when tampering continues")
        check(c4.noteDetection(det("New launch agent", cat: .persistence, sev: .high, path: "/Users/x/Library/LaunchAgents/com.evil.agent.plist", sha: nil)) == [.persistenceReappeared], "emergency escalates on persistence re-appearing")
        c4.noteSignal(.processWontStop)
        let esc = c4.escalation()
        check(esc?.signals.count == 4 && esc?.steps.count == 3 && esc!.steps[0].contains("Wi-Fi") && esc!.steps[2].contains("passwords"), "emergency escalation steps")
        let note = det("Note", sev: .info, conf: 100, src: .heuristic, score: 10)
        let c5 = EmergencyController(path: tmp.appendingPathComponent("e5.json").path, clock: gc)
        c5.engage(reason, actions: plan, dryRun: true)
        check(c5.noteDetection(note).isEmpty && c5.escalation() == nil, "emergency notes never escalate")
        let rep = c4.status(mode: "dry run").report
        check(rep.contains("nothing was sent anywhere") && rep.contains(String(repeating: "a", count: 64)) && rep.contains("Escalation"), "emergency evidence report")
        check(EmergencyStatus.encryptionNote.contains("NetworkExtension") && EmergencyStatus.encryptionNote.contains("VPN"), "emergency honest encryption note")

        // MARK: Protect Everything
        var s0 = RampartSettings(); s0.autoQuarantine = false; s0.ransomwareCanaries = false; s0.webProtection = false
        let snap0 = ProtectSnapshot(settings: s0, remoteLockdown: false, webProtectionAvailable: false, postureFailing: ["firewall"], pasteGuard: "needsPermission",
                                    publicWiFiGuardOn: true, publicWiFiDisconnect: false, tamperEnforcing: false, breachChecksOn: false, systemService: false)
        let steps = ProtectEverythingPlanner.plan(snap0)
        func status(of id: ProtectStep.ID) -> ProtectStep.Status? { steps.first { $0.id == id }?.status }
        check(Set(steps.map(\.id)) == Set(ProtectStep.ID.allCases), "protect-all covers every protection")
        check(status(of: .realtime) == .alreadyOn && status(of: .autoQuarantine) == .willTurnOn && status(of: .ransomwareCanaries) == .willTurnOn, "protect-all settings steps")
        check(status(of: .webProtection) == .needsAdmin && status(of: .firewall) == .needsAdmin && status(of: .stealthMode) == .alreadyOn, "protect-all admin steps in user mode")
        check(status(of: .pasteGuard) == .needsPermission && status(of: .breachChecks) == .needsPermission && status(of: .remoteLockdown) == .willTurnOn, "protect-all permission steps")
        let on = ProtectEverythingPlanner.everythingOn(s0, webAvailable: false)
        check(on.autoQuarantine && on.ransomwareCanaries && on.scanArchives && on.autoUpdate && !on.webProtection, "protect-all turns daemon flags on")
        var cur = on; cur.exclusions = ["/Users/x/Projects"]
        let back = ProtectEverythingPlanner.revert(current: cur, previous: s0)
        check(!back.autoQuarantine && !back.ransomwareCanaries && back.exclusions == ["/Users/x/Projects"], "protect-all revert restores only its own flags")
    }
}

private extension Result { var isFailure: Bool { if case .failure = self { return true }; return false } }

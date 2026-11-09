import Foundation
import RampartShared
import RampartGuard

// Reliability fixes (2026-11-09): self-triggered Emergency Lockdown on RamPart's own files, lifting from the app,
// stale user helper holding the state lock, Full Disk Access lost after an update.
extension SelfTest {
    static func reliabilityChecks() {
        let tmp = URL(fileURLWithPath: SelfTest.fixtureTempDir).appendingPathComponent("com.rampart.test.reliability-\(UUID().uuidString)").path
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        ownInstallChecks(tmp)
        falseAlarmChecks(tmp)
        tamperInstallChecks()
        liftFlowChecks()
        staleHelperChecks()
        fdaAfterUpdateChecks()
    }

    // MARK: 1. own installed files

    static let goodCD = String(repeating: "a", count: 40), lookAlikeCD = String(repeating: "b", count: 40)

    static func writePlist(_ path: String, label: String, program: [String], extra: [String: Any] = [:]) {
        try? FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        var d: [String: Any] = ["Label": label, "ProgramArguments": program, "RunAtLoad": true]
        for (k, v) in extra { d[k] = v }
        let data = try! PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0)
        FileManager.default.createFile(atPath: path, contents: data)
    }

    static func ownInstallChecks(_ tmp: String) {
        let paths = GuardPaths.scratch(tmp + "/own")
        let appExe = paths.appBundle + "/Contents/MacOS/Rampart"
        writePlist(paths.agentPlist, label: paths.agentLabel, program: [appExe, "--background"])
        // Signature facts injected: the app executable is a valid RamPart build with a trusted cdhash.
        func trust(_ cd: String, id: String = "app.rampart.app", valid: Bool = true, manifest: InstallManifest? = nil) -> OwnInstallTrust {
            OwnInstallTrust(paths: paths, manifest: manifest, trustedCDHashes: [goodCD], signature: { p in
                p.hasSuffix("/Contents/MacOS/Rampart") ? OwnCodeSignature(identifier: id, teamID: nil, cdhash: cd, valid: valid) : nil
            })
        }
        check(trust(goodCD).isVerifiedOwnFile(paths.agentPlist), "own: agent plist pointing at our verified app binary is verified")
        check(!trust(lookAlikeCD).isVerifiedOwnFile(paths.agentPlist), "own: same plist but an untrusted (look-alike) cdhash is not verified")
        check(!trust(goodCD, id: "com.evil.app").isVerifiedOwnFile(paths.agentPlist), "own: a binary not signed as app.rampart.* is not verified")
        check(!trust(goodCD, valid: false).isVerifiedOwnFile(paths.agentPlist), "own: an invalid signature is not verified")
        // Manifest pin works without any signature.
        let m = InstallManifest.build(paths: [paths.agentPlist])
        check(trust(lookAlikeCD, manifest: m).isVerifiedOwnFile(paths.agentPlist), "own: a plist pinned by the Guard manifest is verified")
        // A plist neutered or pointed elsewhere is not ours.
        let evil = tmp + "/own/LaunchAgents/evil/app.rampart.agent.plist"
        writePlist(evil, label: paths.agentLabel, program: ["/tmp/evil"])
        check(!trust(goodCD).isVerifiedOwnFile(evil), "own: a plist outside our paths is never treated as ours")
        writePlist(paths.agentPlist, label: paths.agentLabel, program: ["/private/tmp/evil", "--background"])
        check(!trust(goodCD).isVerifiedOwnFile(paths.agentPlist), "own: our plist pointed at another program is not verified")
        writePlist(paths.agentPlist, label: paths.agentLabel, program: [appExe, "--background"], extra: ["Disabled": true])
        check(!trust(goodCD).isVerifiedOwnFile(paths.agentPlist), "own: a disabled (neutered) plist is not verified")
        writePlist(paths.agentPlist, label: paths.agentLabel, program: [appExe, "--background"])
        try? FileManager.default.removeItem(atPath: paths.agentPlist)
        check(!trust(goodCD).isVerifiedOwnFile(paths.agentPlist), "own: a deleted plist is not verified")
        writePlist(paths.agentPlist, label: paths.agentLabel, program: [appExe, "--background"])
        check(OwnInstallTrust.parseCDHashList("arm64=\(goodCD.uppercased()),x86_64=\(lookAlikeCD)") == [goodCD, lookAlikeCD], "own: install identity cdhash list parsed")

        // Manifest reseal after a verified install / upgrade, never for symlinks or a missing plist.
        let upgraded = [ManifestMismatch(path: paths.agentPlist, kind: .hashChanged, expected: "x", actual: "y")]
        check(trust(goodCD).isVerifiedUpgrade(upgraded), "own: a changed plist that verifies is a verified upgrade (resealed, not tamper)")
        check(!trust(lookAlikeCD).isVerifiedUpgrade(upgraded), "own: a changed plist that doesn't verify is not an upgrade")
        check(!trust(goodCD).isVerifiedUpgrade([ManifestMismatch(path: paths.agentPlist, kind: .symlink, expected: nil, actual: nil)]), "own: a symlinked file is never an upgrade")
        check(!trust(goodCD).isVerifiedUpgrade([ManifestMismatch(path: paths.daemonPlist, kind: .missing, expected: "x", actual: nil)]), "own: a missing plist is never an upgrade")
        check(trust(goodCD).isVerifiedUpgrade([ManifestMismatch(path: paths.appBundle + "/Contents/Resources/old.png", kind: .missing, expected: "x", actual: nil)]),
              "own: a bundle file removed by an update is fine")
    }

    // MARK: 1b. false-alarm lockdown re-check, escalation

    static func falseAlarmChecks(_ tmp: String) {
        let paths = GuardPaths.scratch(tmp + "/fa")
        let appExe = paths.appBundle + "/Contents/MacOS/Rampart"
        writePlist(paths.agentPlist, label: paths.agentLabel, program: [appExe, "--background"])
        let trust = OwnInstallTrust(paths: paths, trustedCDHashes: [goodCD], signature: { p in
            p.hasSuffix("/Contents/MacOS/Rampart") ? OwnCodeSignature(identifier: "app.rampart.app", teamID: nil, cdhash: goodCD, valid: true) : nil
        })
        let verified: (String) -> Bool = { trust.isVerifiedOwnFile($0) }
        let ownPath: (String) -> Bool = { paths.isProtected($0) || paths.isPlist($0) }
        let tamper = Detection(path: paths.agentPlist, name: "Tampering with \(Product.name): plistTamper", category: .suspicious, severity: .critical,
                               confidence: 92, evidence: [Evidence(source: .behaviour, title: "fileWrite on a protected RamPart file", detail: paths.agentPlist, score: 92)])
        let reason = EmergencyTriggerReason(kind: .tampering, summary: "Another program tried to alter RamPart (plistTamper)", detectionID: tamper.id,
                                            detectionName: tamper.name, path: paths.agentPlist, confidence: 92)
        func controller(_ name: String, _ r: EmergencyTriggerReason, quarantined: [String]) -> EmergencyController {
            let c = EmergencyController(path: tmp + "/\(name).json")
            let actions = [EmergencyAction(kind: .quarantineFiles, title: "Quarantine", detail: "", paths: quarantined, undoable: true, undoNote: "", state: .done),
                           EmergencyAction(kind: .networkContainment, title: "Net", detail: "", undoable: true, undoNote: "")]
            c.engage(r, actions: actions, dryRun: true, networkWhy: "Two independent signals: confirmedMalware + tampering.")
            return c
        }
        // The incident: our own plist quarantined, reinstalled (present and verifying) -> false alarm.
        let c = controller("own", reason, quarantined: [paths.agentPlist])
        let why = EmergencyFalseAlarm.reason(state: c.state, detection: tamper, isVerifiedOwnFile: verified, isOwnPath: ownPath)
        check(why?.contains("own files") == true, "false alarm: lockdown triggered by our own verified plist is recognised (\(why ?? "nil"))")
        // Escalation: our own file coming back is not "a quarantined file came back".
        c.update { $0.quarantinedHashes = ["feed"] }
        var back = tamper; back.sha256 = "feed"; back.name = "Something"
        check(c.noteDetection(back, isVerifiedOwnFile: verified).isEmpty && c.state.signals.isEmpty, "escalation: our own verified file returning is not an escalation")
        var evil = back; evil.path = tmp + "/payload.bin"
        check(c.noteDetection(evil, isVerifiedOwnFile: verified) == [.payloadReappeared], "escalation: an unverified quarantined file coming back still escalates")
        // Lift (no password): inactive, actions undone, false-alarm reason kept for the notice.
        let undo = c.liftFalseAlarm(why: why ?? "")
        check(undo != nil && !c.isActive && c.state.falseAlarm != nil && c.state.signals.isEmpty, "false alarm: auto-lift ends the lockdown and clears escalation")
        check(undo?.contains { $0.kind == .networkContainment } == true && undo?.contains { $0.kind == .quarantineFiles } == true, "false alarm: auto-lift undoes network and quarantine")
        check(c.state.log.contains { $0.text.contains("false alarm") }, "false alarm: logged")
        let n = EmergencyNotice.transition(from: EmergencyStatus(state: { var s = c.state; s.active = true; return s }(), readiness: nil, escalation: nil, mode: "x", honestNote: "", report: ""),
                                           to: c.status(mode: "x"))
        check(n?.kind == .falseAlarm && n?.title.lowercased().contains("lockdown lifted: false alarm") == true, "false alarm: notice says 'lockdown lifted: false alarm'")
        check(EmergencyNotice.transition(from: nil, to: c.status(mode: "x"))?.kind == .falseAlarm, "false alarm: an app opened afterwards still hears about it")
        // A manual lockdown is never auto-lifted.
        let m = EmergencyController(path: tmp + "/manual.json")
        m.engage(.manual(uid: 501), actions: [EmergencyAction(kind: .quarantineFiles, title: "Q", detail: "", paths: [paths.agentPlist], undoable: true, undoNote: "", state: .done)], dryRun: true)
        check(EmergencyFalseAlarm.reason(state: m.state, detection: nil, isVerifiedOwnFile: verified, isOwnPath: ownPath) == nil && m.liftFalseAlarm(why: "x") == nil && m.isActive,
              "false alarm: a manual lockdown is never auto-lifted")
        // A real, confirmed threat (known-bad hash) on a foreign file stays.
        let badPath = "/Users/Shared/evil-reliability-fixture.bin"   // not a com.rampart.test path: test artifacts never qualify
        let bad = Detection(path: badPath, sha256: String(repeating: "c", count: 64), name: "Known malware", category: .malware, severity: .critical,
                            confidence: 100, evidence: [Evidence(source: .hash, title: "Known-bad hash", detail: "MalwareBazaar", score: 100)])
        let r2 = EmergencyTriggerReason(kind: .confirmedMalware, summary: "Known malware", detectionID: bad.id, detectionName: bad.name, path: bad.path, confidence: 100)
        let c2 = controller("real", r2, quarantined: [badPath])
        check(EmergencyFalseAlarm.reason(state: c2.state, detection: bad, isVerifiedOwnFile: verified, isOwnPath: ownPath) == nil, "false alarm: a confirmed threat lockdown is kept")
        // A lone tamper signal on a foreign path no longer qualifies under today's policy.
        var lone = reason; lone.path = tmp + "/elsewhere"
        let c3 = EmergencyController(path: tmp + "/lone.json")
        c3.engage(lone, actions: [], dryRun: true, networkWhy: "Signal")
        check(EmergencyFalseAlarm.reason(state: c3.state, detection: nil, isVerifiedOwnFile: verified, isOwnPath: ownPath) != nil, "false alarm: a single tamper signal no longer qualifies")
        // The stored (calibrated) score is re-raised before re-evaluating: a corroborated likely threat is kept.
        let likely = Detection(path: tmp + "/evil.bin", name: "Stealer", category: .infostealer, severity: .high, confidence: 89,
                               evidence: [Evidence(source: .behaviour, title: "R12 Reads browser passwords", detail: "x", score: 80),
                                          Evidence(source: .behaviour, title: "R20 Sends data out", detail: "y", score: 70)])
        check(EmergencyFalseAlarm.uncalibrated(likely).confidence >= 90, "false alarm: re-check uses the engine's raw score, not the capped one")
    }

    // MARK: 1c. install / upgrade reloading the session jobs is not tampering

    static func tamperInstallChecks() {
        let det = TamperDetector(paths: GuardPaths(), ownPIDs: { [4242] })
        func ev(_ args: [String], pid: Int32, at: Date = Date()) -> SecurityEvent {
            SecurityEvent(date: at, kind: .exec, process: ProcessInfoLite(pid: pid, ppid: 1, path: args[0], args: args, uid: 0), source: "test")
        }
        check(det.inspect(ev(["/bin/launchctl", "bootout", "gui/501/app.rampart.agent"], pid: 7001)).isEmpty, "install: agent bootout is held, not reported at once")
        _ = det.inspect(ev(["/bin/launchctl", "bootstrap", "gui/501", "/Library/LaunchAgents/app.rampart.agent.plist"], pid: 7002))
        check(det.flushPending(force: true).isEmpty, "install: agent bootout followed by bootstrap (install / upgrade reload) is not tampering")
        let det2 = TamperDetector(paths: GuardPaths(), ownPIDs: { [4242] })
        _ = det2.inspect(ev(["/bin/launchctl", "bootout", "gui/501/app.rampart.agent"], pid: 7003))
        check(det2.flushPending(force: true).contains { $0.name.contains("unloadAttempt") }, "install: an agent bootout that is never reloaded is still tampering")
        check(det2.inspect(ev(["/bin/launchctl", "bootout", "system/app.rampart.daemon"], pid: 7004)).contains { $0.name.contains("unloadAttempt") },
              "install: system service bootout is still reported at once")
    }

    // MARK: 2. lifting from the app

    static func liftFlowChecks() {
        let flow = ProtectionDisableFlow(key: IntegrityKey(data: Data(repeating: 7, count: 32)))
        guard case .success(let t1) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true),
              case .success(let t2) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) else { check(false, "lift: tokens issued"); return }
        check(t1 != t2, "lift: every attempt gets a fresh token")
        func ok(_ r: Result<Void, ProtectionDisableFlow.Failure>) -> Bool { if case .success = r { return true }; return false }
        func failed(_ r: Result<Void, ProtectionDisableFlow.Failure>, _ f: ProtectionDisableFlow.Failure) -> Bool { if case .failure(let e) = r { return e == f }; return false }
        check(failed(flow.redeem("garbage", peerUID: 501, purpose: .settings), .tokenInvalid), "lift: a bad token fails")
        check(ok(flow.redeem(t2, peerUID: 501, purpose: .settings)), "lift: a failed attempt doesn't block the next fresh token")
        check(failed(flow.redeem(t2, peerUID: 501, purpose: .settings), .tokenInvalid), "lift: a token is single use (never replayed)")
        if case .failure(let f) = ProtectionDisableFlow.verifyExternalForm(Data([1, 2, 3])) {
            check(f.description.contains("bad external form"), "lift: an unusable authorization is refused with the exact reason")
        } else { check(false, "lift: garbage authorization refused") }
        // App source: the authorization outlives the IPC round trip, is freed with destroyRights, errors persist.
        let root = SelfTest.repoRoot
        let bridge = (try? String(contentsOfFile: root + "/Sources/RampartApp/Features/Emergency/EmergencyBridge.swift", encoding: .utf8)) ?? ""
        let model = (try? String(contentsOfFile: root + "/Sources/RampartApp/Features/Emergency/EmergencyModel.swift", encoding: .utf8)) ?? ""
        check(!bridge.isEmpty && !bridge.contains("defer { AuthorizationFree(ref, []) }"), "lift: the authorization is no longer freed before the service reads it")
        check(bridge.contains("AuthorizationFree(r, [.destroyRights])") && bridge.contains("defer { handle.release() }"), "lift: freed with rights destroyed after the call (prompts again next time)")
        check(bridge.contains("AuthorizationCreate(nil, nil, [], &ref)") && !bridge.contains("static func adminToken("), "lift: a brand-new authorization per click, no reused token path")
        let applyBody = model.components(separatedBy: "private func apply(").dropFirst().first?.components(separatedBy: "func updateBadge").first ?? ""
        check(model.contains("var actionError: String?") && !applyBody.isEmpty && !applyBody.contains("actionError"), "lift: action errors aren't wiped by the next status poll")
        check(model.contains("func dismissActionError()"), "lift: errors stay until dismissed")
    }

    // MARK: 3. stale user helper

    static func staleHelperChecks() {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let me = HelperSelfFacts(pid: 200, uid: 501, path: "/Applications/RamPart.app/Contents/Helpers/rampartd", installTime: t0,
                                 signingID: "app.rampart.daemon", teamID: nil)
        let stale = HelperProcessFacts(pid: 100, uid: 501, ruid: 501, path: me.path, startTime: t0.addingTimeInterval(-60),
                                       signingID: "app.rampart.daemon", teamID: nil, pathStillOurs: true)
        check(StaleHelperPolicy.decide(holder: stale, me: me).shouldStop, "stale helper: same path, same user and signer, started before install -> stopped")
        var h = stale; h.startTime = t0.addingTimeInterval(5)
        check(!StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "stale helper: started after our install -> kept")
        h = stale; h.uid = 502; h.ruid = 502
        check(!StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "stale helper: another user's process -> kept")
        h = stale; h.signingID = "com.other.tool"
        check(!StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "stale helper: not signed as app.rampart.daemon -> kept")
        h = stale; h.teamID = "ABCDE12345"
        check(!StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "stale helper: a different signer -> kept")
        h = stale; h.path = "/Users/x/Downloads/RamPart.app/Contents/Helpers/rampartd"
        check(!StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "stale helper: another still-installed copy -> kept")
        h.pathStillOurs = false
        check(StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "stale helper: a copy moved to the Trash / deleted -> stopped")
        h = stale; h.path = "/usr/bin/rampartd-ish"
        check(!StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "stale helper: not a rampartd executable -> kept")
        h = stale; h.pid = me.pid
        check(!StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "stale helper: never stops itself")
        var root = me; root.uid = 0
        check(!StaleHelperPolicy.decide(holder: stale, me: root).shouldStop, "stale helper: never as root")
        // install time = later of mtime and ctime (ditto keeps the build's mtime; ctime moves on copy)
        let f = SelfTest.fixtureTempDir + "/com.rampart.test.stale-\(UUID().uuidString)"
        FileManager.default.createFile(atPath: f, contents: Data("x".utf8))
        defer { try? FileManager.default.removeItem(atPath: f) }
        try? FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1_000_000_000)], ofItemAtPath: f)
        check((StaleHelperPolicy.installTime(of: f) ?? .distantPast).timeIntervalSinceNow > -60, "stale helper: install time uses ctime when mtime was preserved")
        // Source: the daemon and the app both use the policy.
        let main = (try? String(contentsOfFile: SelfTest.repoRoot + "/Sources/rampartd/main.swift", encoding: .utf8)) ?? ""
        let launcher = (try? String(contentsOfFile: SelfTest.repoRoot + "/Sources/RampartApp/DaemonLauncher.swift", encoding: .utf8)) ?? ""
        check(main.contains("StaleHelperPolicy.stopIfStale") && launcher.contains("StaleHelperPolicy.stopIfStale") && launcher.contains("terminationStatus == 75"),
              "stale helper: daemon and app launcher both handle it")
    }

    // MARK: 4. Full Disk Access lost after an update

    static func fdaAfterUpdateChecks() {
        let a = String(repeating: "1", count: 40), b = String(repeating: "2", count: 40)
        check(ServiceFDAAdvice.state(hasAccess: true, grantedCDHash: a, currentCDHash: b) == .ok, "fda: access present -> ok")
        check(ServiceFDAAdvice.state(hasAccess: false, grantedCDHash: nil, currentCDHash: b) == .missing, "fda: never granted -> plain missing")
        check(ServiceFDAAdvice.state(hasAccess: false, grantedCDHash: a, currentCDHash: a) == .missing, "fda: same build, switched off -> plain missing")
        check(ServiceFDAAdvice.state(hasAccess: false, grantedCDHash: a, currentCDHash: b.uppercased()) == .lostAfterUpdate, "fda: new build after an update -> lost after update")
        let n = ServiceFDAAdvice.note()
        let steps = ServiceFDAAdvice.steps().joined(separator: " ")
        check(n.id == ServiceFDAAdvice.noteID && n.fix == .fullDiskAccess && n.message.contains("lost Full Disk Access after an update"), "fda: health note with the Fix button")
        check(steps.contains("app.rampart.daemon") && steps.contains("−") && steps.lowercased().contains("remove") && steps.contains("+")
              && steps.contains("/Library/PrivilegedHelperTools/app.rampart.daemon") && steps.contains("not enough"), "fda: steps say remove, re-add (exact path), and that toggling isn't enough")
        let panel = (try? String(contentsOfFile: SelfTest.repoRoot + "/Sources/RampartApp/PermissionGuidePanel.swift", encoding: .utf8)) ?? ""
        check(panel.contains("ServiceFDAAdvice.steps()") && panel.contains("Remove app.rampart.daemon and add it again"), "fda: the guide panel shows the remove / re-add steps")
    }
}

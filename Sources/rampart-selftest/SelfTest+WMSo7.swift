import Foundation
import RampartShared
import RampartGuard

// wms-o7: self-protection red team (same-user and admin-without-password attacker). Each check is a regression test for a
// finding in docs/security/wms-o7.md. Fixtures live in temp dirs; nothing here signals, unloads or prompts.
extension SelfTest {
    static func wmsO7Checks() {
        let tmp = URL(fileURLWithPath: SelfTest.fixtureTempDir).appendingPathComponent("com.rampart.test.wmso7-\(UUID().uuidString)").path
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        o7OwnInstall(tmp)
        o7TamperUnload()
        o7NetworkPolicy(tmp)
        o7ProcessAndLaunchItems()
        o7KillSwitchScript(tmp)
        o7RemoteAllowance()
        o7StaleHelper()
        o7TokenPurpose()
        o7Sources()
    }

    // MARK: F9 disable tokens bound to a purpose at issue time

    static func o7TokenPurpose() {
        let flow = ProtectionDisableFlow(key: IntegrityKey(data: Data(repeating: 9, count: 32)))
        func failure(_ r: Result<Void, ProtectionDisableFlow.Failure>) -> ProtectionDisableFlow.Failure? { if case .failure(let f) = r { return f }; return nil }
        func issue(_ p: Set<ProtectionDisableFlow.Purpose>) -> String? {
            if case .success(let t) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true, purposes: p) { return t }; return nil
        }
        guard let pauseTok = issue(ProtectionDisableFlow.generalPurposes), let uninstTok = issue([.uninstall]),
              let settingsTok = issue(ProtectionDisableFlow.generalPurposes), let reuse = issue([.uninstall]) else { check(false, "o7 F9: tokens issued"); return }
        check(failure(flow.redeem(pauseTok, peerUID: 501, purpose: .uninstall)) == .tokenWrongPurpose && !flow.hasActiveSession(uid: 501, purpose: .uninstall),
              "o7 F9: a token issued for pause/settings can't be redeemed for an uninstall")
        check(failure(flow.redeem(pauseTok, peerUID: 501, purpose: .pause)) == .tokenInvalid, "o7 F9: a wrong-purpose attempt burns the token")
        check(failure(flow.redeem(uninstTok, peerUID: 501, purpose: .settings)) == .tokenWrongPurpose, "o7 F9: an uninstall token can't open a settings session (lift / Kill Switch)")
        check(failure(flow.redeem(settingsTok, peerUID: 501, purpose: .settings)) == nil && flow.hasActiveSession(uid: 501, purpose: .settings),
              "o7 F9 control: a general token still opens a settings session (lift, restore internet, Kill Switch)")
        check(failure(flow.redeem(reuse, peerUID: 501, purpose: .uninstall)) == nil, "o7 F9 control: an uninstall token redeems for uninstall")
        if case .failure(let f) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true, purposes: []) {
            check(f == .tokenWrongPurpose, "o7 F9: a token bound to nothing is never issued")
        } else { check(false, "o7 F9: a token bound to nothing is never issued") }
        let router = (try? String(contentsOfFile: SelfTest.repoRoot + "/Sources/rampartd/Core/Router.swift", encoding: .utf8)) ?? ""
        check(router.contains("requestDisable(peer: peer, authorization: auth, purposes: [.uninstall])"), "o7 F9: the daemon issues uninstall-only tokens for requestUninstall")
    }

    // MARK: F1 fake "own install" files

    static func o7OwnInstall(_ tmp: String) {
        let paths = GuardPaths.scratch(tmp + "/own")
        let helper = paths.appBundle + "/Contents/Helpers/rampartd"
        let mainExe = paths.appBundle + "/Contents/MacOS/Rampart"
        let evilExe = paths.appBundle + "/Contents/MacOS/evil"
        let evilRes = paths.appBundle + "/Contents/Resources/payload.sh"
        for f in [helper, mainExe, evilExe, evilRes] {
            try? FileManager.default.createDirectory(atPath: (f as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: f, contents: Data("o7 marker".utf8))
        }
        let good = SelfTest.goodCD, bad = SelfTest.lookAlikeCD
        // The genuine helper and app verify; the dropped binary is ad-hoc signed as app.rampart.* with an unknown cdhash.
        let sig: @Sendable (String) -> OwnCodeSignature? = { p in
            if p.hasSuffix("/Contents/Helpers/rampartd") { return OwnCodeSignature(identifier: "app.rampart.daemon", teamID: nil, cdhash: good, valid: true) }
            if p.hasSuffix("/Contents/MacOS/Rampart") { return OwnCodeSignature(identifier: "app.rampart.app", teamID: nil, cdhash: good, valid: true) }
            if p.hasSuffix("/Contents/MacOS/evil") { return OwnCodeSignature(identifier: "app.rampart.evil", teamID: nil, cdhash: bad, valid: true) }
            return nil
        }
        func trust(strict: Bool, sealed: Bool) -> OwnInstallTrust {
            OwnInstallTrust(paths: paths, trustedCDHashes: [good], signature: sig, requireRootOwnership: strict, bundleSealed: { _ in sealed })
        }
        // Control: the old rule (scratch layout, seal assumed) vouches for both dropped files: this is the hole.
        let loose = trust(strict: false, sealed: true)
        check(loose.isVerifiedOwnFile(evilExe) && loose.isVerifiedOwnFile(evilRes), "o7 F1 control: without the new checks dropped bundle files read as RamPart's own")
        // A broken seal (file added to the bundle) means neither is ours.
        let unsealed = trust(strict: false, sealed: false)
        check(!unsealed.isVerifiedOwnFile(evilExe), "o7 F1: an app.rampart.* binary dropped into a bundle whose seal is broken is not ours")
        check(!unsealed.isVerifiedOwnFile(evilRes), "o7 F1: a resource dropped into a bundle whose seal is broken is not ours")
        // Ownership: the attacker's files (here: owned by the test user, not root) are never vouched for.
        let strict = trust(strict: true, sealed: true)
        check(!strict.isVerifiedOwnFile(evilExe) && !strict.isVerifiedOwnFile(evilRes) && !strict.isVerifiedOwnFile(mainExe),
              "o7 F1: files not owned by root (a bundle swapped in by an admin) are not ours")
        // So a manifest mismatch caused by the dropped file is never resealed as a "verified upgrade".
        let unlisted = [ManifestMismatch(path: evilRes, kind: .unlisted, expected: nil, actual: "x")]
        check(loose.isVerifiedUpgrade(unlisted), "o7 F1 control: the old rule resealed an added bundle file")
        check(!strict.isVerifiedUpgrade(unlisted) && !unsealed.isVerifiedUpgrade(unlisted), "o7 F1: an added bundle file is never resealed as an upgrade")
        // Defaults: the real install layout is strict, scratch layouts (dev / tests) are not.
        check(OwnInstallTrust(paths: .standard).requireRootOwnership && !OwnInstallTrust(paths: paths).requireRootOwnership,
              "o7 F1: root-ownership rule is on by default for the real install")
        // The real ownership check.
        check(OwnInstallTrust.rootOwnedChain("/bin/ls", stopAt: "/bin"), "o7 F1: a root-owned system file passes the ownership check")
        check(!OwnInstallTrust.rootOwnedChain(evilRes, stopAt: paths.appBundle), "o7 F1: a user-owned file fails the ownership check")
        // The real seal check: a fake bundle folder is not sealed.
        check(!BundleSeal.isSealed(paths.appBundle), "o7 F1: an unsigned fake bundle is not sealed")
    }

    // MARK: F2 LaunchAgent unload hidden behind a reload

    static func o7TamperUnload() {
        func ev(_ args: [String], pid: Int32) -> SecurityEvent {
            SecurityEvent(date: Date(), kind: .exec, process: ProcessInfoLite(pid: pid, ppid: 1, path: args[0], args: args, uid: 501), source: "test")
        }
        let real = GuardPaths().agentPlist
        // bootout, bootstrap, bootout: the job ends up unloaded.
        let d1 = TamperDetector(paths: GuardPaths(), ownPIDs: { [4242] })
        _ = d1.inspect(ev(["/bin/launchctl", "bootout", "gui/501/app.rampart.agent"], pid: 7101))
        _ = d1.inspect(ev(["/bin/launchctl", "bootstrap", "gui/501", real], pid: 7102))
        _ = d1.inspect(ev(["/bin/launchctl", "bootout", "gui/501/app.rampart.agent"], pid: 7103))
        check(d1.flushPending(force: true).contains { $0.name.contains("unloadAttempt") }, "o7 F2: bootout, bootstrap, bootout again is still reported")
        // A look-alike plist under our label is not a reload.
        let d2 = TamperDetector(paths: GuardPaths(), ownPIDs: { [4242] })
        _ = d2.inspect(ev(["/bin/launchctl", "bootout", "gui/501/app.rampart.agent"], pid: 7104))
        _ = d2.inspect(ev(["/bin/launchctl", "bootstrap", "gui/501", "/tmp/o7/app.rampart.agent.plist"], pid: 7105))
        check(d2.flushPending(force: true).contains { $0.name.contains("unloadAttempt") }, "o7 F2: bootstrapping a look-alike app.rampart.agent.plist doesn't excuse the unload")
        // kickstart can't load an unloaded job.
        let d3 = TamperDetector(paths: GuardPaths(), ownPIDs: { [4242] })
        _ = d3.inspect(ev(["/bin/launchctl", "bootout", "gui/501/app.rampart.agent"], pid: 7106))
        _ = d3.inspect(ev(["/bin/launchctl", "kickstart", "gui/501/app.rampart.agent"], pid: 7107))
        check(d3.flushPending(force: true).contains { $0.name.contains("unloadAttempt") }, "o7 F2: a kickstart doesn't excuse the unload")
        // Control: the real install reload is still quiet.
        let d4 = TamperDetector(paths: GuardPaths(), ownPIDs: { [4242] })
        _ = d4.inspect(ev(["/bin/launchctl", "bootout", "gui/501/app.rampart.agent"], pid: 7108))
        _ = d4.inspect(ev(["/bin/launchctl", "bootstrap", "gui/501", real], pid: 7109))
        check(d4.flushPending(force: true).isEmpty, "o7 F2 control: install / upgrade reload of our own plist is not tampering")
        // `kill -0` delivers nothing; a real kill is still reported.
        let d5 = TamperDetector(paths: GuardPaths(), ownPIDs: { [4242] })
        check(d5.inspect(ev(["/bin/kill", "-0", "4242"], pid: 7110)).isEmpty && d5.inspect(ev(["/bin/kill", "-s", "0", "4242"], pid: 7111)).isEmpty,
              "o7 F2: kill -0 (is it running?) is not a kill attempt")
        check(d5.inspect(ev(["/bin/kill", "-9", "4242"], pid: 7112)).contains { $0.name.contains("killAttempt") }, "o7 F2 control: kill -9 is still a kill attempt")
    }

    // MARK: F3 forged tamper + decoy signals cutting the internet (DoS)

    static func o7NetworkPolicy(_ tmp: String) {
        let now = Date()
        let tamper = EmergencyTriggerReason(kind: .tampering, summary: "pkill rampartd", confidence: 95)
        let decoy = EmergencyTriggerReason(kind: .deception, summary: "decoy opened", confidence: 95)
        let a = EmergencyNetworkPolicy.assess(decoy, recent: [EmergencySignal(kind: .tampering, key: "t", date: now)], now: now)
        check(a.engage && !a.containNetwork, "o7 F3: tamper + decoy signals lock down but never cut the internet")
        let b = EmergencyNetworkPolicy.assess(tamper, recent: [EmergencySignal(kind: .deception, key: "d", date: now)], now: now)
        check(b.engage && !b.containNetwork, "o7 F3: decoy + tamper (other order) never cut the internet")
        let c = EmergencyNetworkPolicy.assess(tamper, recent: [EmergencySignal(kind: .confirmedMalware, key: "m", date: now)], now: now)
        check(c.containNetwork, "o7 F3 control: tamper + confirmed malware still cuts the internet")
        // Repeated forging after the 10-minute expiry can't re-cut it.
        let ctl = EmergencyController(path: tmp + "/o7-dos.json")
        _ = ctl.assess(tamper)
        let a1 = ctl.assess(decoy)
        let plan = EmergencyPlanner.plan(decoy, context: EmergencyContext(), containNetwork: a1.containNetwork)
        check(ctl.engage(decoy, actions: plan, dryRun: true) && !ctl.state.isNetworkBlocked, "o7 F3: the forged lockdown leaves the internet on")
        for _ in 0..<5 { _ = ctl.assess(tamper); _ = ctl.assess(decoy) }
        check(!ctl.assess(tamper).containNetwork, "o7 F3: repeating the forged signals never cuts the internet")
        // Owner can always lift.
        check((try? ctl.lift(authorized: true, force: true)) != nil && !ctl.isActive, "o7 F3: the owner can always lift")
    }

    // MARK: F4 name-based exemptions from freezing / pausing

    static func o7ProcessAndLaunchItems() {
        let notPlatform: (Int32) -> Bool = { _ in false }
        check(!EmergencyProcessGuard.isProtected(pid: 5000, path: "/Users/x/Downloads/Rampart.app/Contents/MacOS/Rampart", isPlatformBinary: notPlatform),
              "o7 F4: a Rampart.app outside /Applications is frozen like anything else")
        check(!EmergencyProcessGuard.isProtected(pid: 5001, path: "/tmp/rampartd", isPlatformBinary: notPlatform)
              && !EmergencyProcessGuard.isProtected(pid: 5002, path: "/Users/x/Library/WindowServer", isPlatformBinary: notPlatform),
              "o7 F4: malware named rampartd / WindowServer is not exempt")
        check(EmergencyProcessGuard.isProtected(pid: 5003, path: "/Applications/RamPart.app/Contents/MacOS/RamPart", isPlatformBinary: notPlatform)
              && EmergencyProcessGuard.isProtected(pid: 5004, path: "/Library/PrivilegedHelperTools/app.rampart.daemon", isPlatformBinary: notPlatform)
              && EmergencyProcessGuard.isProtected(pid: 5005, path: "/usr/sbin/sshd", isPlatformBinary: notPlatform),
              "o7 F4 control: installed RamPart and system binaries are never frozen")
        let fake = PersistenceItem(kind: .launchAgent, label: "app.rampart.update", location: "/Users/x/Library/LaunchAgents/app.rampart.update.plist")
        let fake2 = PersistenceItem(kind: .launchAgent, label: "app.rampart.agent", location: "/Users/x/Library/LaunchAgents/app.rampart.agent.plist")
        let own = PersistenceItem(kind: .launchAgent, label: "app.rampart.agent", location: "/Library/LaunchAgents/app.rampart.agent.plist")
        let r = EmergencyTriggerReason(kind: .ransomware, summary: "burst", confidence: 95)
        let plan = EmergencyPlanner.plan(r, context: EmergencyContext(newLaunchItems: [fake, fake2, own]))
        let paused = plan.first { $0.kind == .pauseLaunchItems }?.paths ?? []
        check(paused.contains(fake.location) && paused.contains(fake2.location), "o7 F4: look-alike app.rampart.* launch items are paused")
        check(!paused.contains(own.location), "o7 F4 control: RamPart's real agent is never paused")
    }

    // MARK: F5 kill switch script swapped behind the password prompt

    static func o7KillSwitchScript(_ tmp: String) {
        let bundle = tmp + "/ks/RamPart.app"
        let res = bundle + "/Contents/Resources"
        try? FileManager.default.createDirectory(atPath: res, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: res + "/" + KillSwitch.scriptName, contents: Data("echo o7\n".utf8), attributes: [.posixPermissions: 0o755])
        check(KillSwitch.bundledScript(inBundle: bundle) == nil, "o7 F5: a script in a bundle the user can write is never run through the admin prompt")
        check(KillSwitch.bundledScript(inBundle: bundle, requireRootOwned: false) != nil, "o7 F5 control: the dry run still finds it")
    }

    // MARK: F6 remote-access allowances

    static func o7RemoteAllowance() {
        let now = Date()
        func report(_ procs: [ProcessInfoLite], _ pol: RemoteAccessPolicy) -> RemoteAccessReport {
            RemoteAccessMonitor(probe: RemoteAccessProbe(processes: { procs }, listeners: { [] }, launchItems: { [] }, sharing: { SharingServiceState() },
                                                         inbound: { [] }, now: { now })).report(policy: pol)
        }
        var pol = RemoteAccessPolicy()
        pol.allow(RemoteToolCatalogue.tool("anydesk")!, minutes: 60, now: now)   // granted while nothing ran: no pins
        let lookalike = [ProcessInfoLite(pid: 811, ppid: 1, path: "/Users/x/Downloads/anydesk/agent", uid: 501, signingID: "com.philandro.anydesk", teamID: nil)]
        check(report(lookalike, pol).findings.first { $0.toolID == "anydesk" }?.allowed == false, "o7 F6: an ad-hoc look-alike doesn't ride on an unpinned allowance")
        let real = [ProcessInfoLite(pid: 812, ppid: 1, path: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk", uid: 501, signingID: "com.philandro.anydesk", teamID: "KU6W3B6JMZ")]
        check(report(real, pol).findings.first { $0.toolID == "anydesk" }?.allowed == true, "o7 F6 control: the real signed tool is covered")
        var ssh = RemoteAccessPolicy(); ssh.allow(RemoteToolCatalogue.tool("apple.ssh")!, minutes: nil, now: now)
        let sshd = [ProcessInfoLite(pid: 813, ppid: 1, path: "/usr/sbin/sshd", uid: 0, signingID: "com.openssh.sshd", teamID: nil)]
        check(report(sshd, ssh).findings.first { $0.toolID == "apple.ssh" }?.allowed == true, "o7 F6 control: an allowed Apple service (no Team ID) stays allowed")
    }

    // MARK: F7 stale-helper spoofing

    static func o7StaleHelper() {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let me = HelperSelfFacts(pid: 200, uid: 501, path: "/Applications/RamPart.app/Contents/Helpers/rampartd", installTime: t0,
                                 signingID: "app.rampart.daemon", teamID: nil, cdhash: SelfTest.goodCD)
        var h = HelperProcessFacts(pid: 100, uid: 501, ruid: 501, path: me.path, startTime: t0.addingTimeInterval(-60),
                                   signingID: "app.rampart.daemon", teamID: nil, pathStillOurs: true, cdhash: SelfTest.goodCD)
        check(!StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "o7 F7: a bumped ctime can't make the current helper (same build) look stale")
        h.cdhash = SelfTest.lookAlikeCD
        check(StaleHelperPolicy.decide(holder: h, me: me).shouldStop, "o7 F7 control: a helper from a replaced build is still stopped")
    }

    // MARK: daemon wiring (source checks: rampartd isn't a library)

    static func o7Sources() {
        let root = SelfTest.repoRoot
        func src(_ p: String) -> String { (try? String(contentsOfFile: root + "/" + p, encoding: .utf8)) ?? "" }
        let em = src("Sources/rampartd/Core/Emergency.swift")
        check(!em.isEmpty && !em.contains("if p.subscriberCount == 0 { launchAppForNotice() }") && em.contains("\"bootstrap\", \"gui/"),
              "o7 F8: lockdown notices start the app whoever is subscribed, and re-load a booted-out agent")
        let gw = src("Sources/rampartd/Core/GuardWiring.swift")
        check(gw.contains("signingCache.enrich(baseProcesses())") && gw.contains("anchor apple generic"),
              "o7 F6: the live remote-access probe carries Apple-anchored Team IDs (pinned allowances work)")
        let model = src("Sources/RampartApp/Features/Emergency/EmergencyModel.swift")
        check(model.contains("KillSwitchScript.locate(dryRun: noPriv)"), "o7 F5: the app asks for a root-owned script for the real run")
        let ks = src("Sources/rampartd/Core/KillSwitchExec.swift")
        check(ks.contains("try Emergency.authorize(p, token: token, peer: peer)"), "o7: the kill switch still needs Touch ID / password (admin token) or root")
    }
}

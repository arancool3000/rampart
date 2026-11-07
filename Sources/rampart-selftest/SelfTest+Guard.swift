import Foundation
import RampartShared
import RampartGuard

// Guard suite: synthetic events and fixtures only. Never kills real processes, never runs launchctl/pfctl/chflags,
// nothing with sudo. HMAC checks use scratch files; sharing-state probes are read-only.
extension SelfTest {
    static func guardSuite() {
        guardMDMRegression()
        let scratch = ProcessInfo.processInfo.environment["RAMPART_SCRATCH"]
            ?? "/private/tmp/claude-501/-Users-arankeyhan/ab330a0d-96bf-4eec-a6ed-51d815d3bfd2/scratchpad/guard"
        let root = scratch + "/run-\(getpid())"
        try? FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: root) }
        let paths = GuardPaths.scratch(root)

        // MARK: Integrity: key, seal, tamper, restore
        let key = try! IntegrityKey.loadOrCreate(at: paths.keyFile)
        let perms = (try? FileManager.default.attributesOfItem(atPath: paths.keyFile))?[.posixPermissions] as? Int
        check(perms == 0o600, "integrity key is 0600")
        check((try? IntegrityKey.loadOrCreate(at: paths.keyFile))?.mac(Data("x".utf8)) == key.mac(Data("x".utf8)), "key reload is stable")
        let store = SealedStore(key: key, backupDir: paths.backupDir)
        let config = Data(#"{"realtimeOn":true,"exclusions":[]}"#.utf8)
        try! store.write(config, to: paths.configFile)
        check(store.verify(paths.configFile) == .intact(config), "sealed config verifies")
        check(store.hasBackup(for: paths.configFile), "sealed backup exists")
        // Edit outside the daemon: rewrite payload with a plausible exclusion but the old MAC.
        var env = try! JSONSerialization.jsonObject(with: FileManager.default.contents(atPath: paths.configFile)!) as! [String: Any]
        env["payload"] = Data(#"{"realtimeOn":false,"exclusions":["/"]}"#.utf8).base64EncodedString()
        try! JSONSerialization.data(withJSONObject: env).write(to: URL(fileURLWithPath: paths.configFile))
        check(store.verify(paths.configFile) == .tampered(.macMismatch), "edited payload -> macMismatch")
        try! Data("plain json".utf8).write(to: URL(fileURLWithPath: paths.configFile))
        check(store.verify(paths.configFile) == .tampered(.notSealed), "unsealed file -> notSealed")
        let dry = store.restoreIfNeeded(paths.configFile, dryRun: true)
        check(dry.restored && !store.verify(paths.configFile).isIntact, "dryRun restore changes nothing")
        let wet = store.restoreIfNeeded(paths.configFile, dryRun: false)
        check(wet.restored && store.verify(paths.configFile) == .intact(config), "restore from sealed backup")
        try! FileManager.default.removeItem(atPath: paths.configFile)
        check(store.verify(paths.configFile) == .missing, "missing verdict")
        check(store.restoreIfNeeded(paths.configFile, dryRun: false).restored, "restore after delete")
        let otherKey = IntegrityKey(data: Data(repeating: 7, count: 32))
        check(Sealed.open(Sealed.seal(config, key: key), key: otherKey) == .failure(.macMismatch), "different key fails")

        // MARK: Manifest / binary hash
        try! FileManager.default.createDirectory(atPath: root + "/bin", withIntermediateDirectories: true)
        try! Data("#!/bin/sh\necho daemon\n".utf8).write(to: URL(fileURLWithPath: paths.daemonBinary))
        try! Data("#!/bin/sh\necho watchdog\n".utf8).write(to: URL(fileURLWithPath: paths.watchdogBinary))
        let manifest = InstallManifest.build(paths: [paths.daemonBinary, paths.watchdogBinary])
        check(manifest.entries.count == 2 && manifest.verify().isEmpty, "manifest builds and verifies")
        try! manifest.save(to: store, path: paths.manifestFile)
        check(InstallManifest.load(from: store, path: paths.manifestFile)?.entries == manifest.entries, "manifest round-trips sealed")
        try! Data("#!/bin/sh\necho evil\n".utf8).write(to: URL(fileURLWithPath: paths.daemonBinary))
        let bad = manifest.verify()
        check(bad.count == 1 && bad.first?.kind == .hashChanged && bad.first?.path == paths.daemonBinary, "binary swap detected")
        try! FileManager.default.removeItem(atPath: paths.watchdogBinary)
        check(manifest.verify().contains { $0.kind == .missing }, "missing binary detected")

        // MARK: Immutable flags plan (generated only)
        let lock = ImmutableFlagsPlan.lockCommands(paths)
        check(lock.allSatisfy { $0.executable == "/usr/bin/chflags" } && lock.contains { $0.arguments == ["schg", paths.daemonPlist] }, "chflags schg plan")
        check(ImmutableFlagsPlan.unlockCommands(paths).contains { $0.arguments == ["noschg", paths.daemonBinary] }, "unlock plan clears schg")
        check(ImmutableFlagsPlan.uninstallScriptLines(paths).allSatisfy { $0.hasSuffix("|| true") }, "uninstall lines tolerant")
        check(ImmutableFlagsPlan.currentFlags(paths)[paths.daemonBinary] == [], "stat flags read-only: none set")

        // MARK: TamperDetector
        let det = TamperDetector(paths: paths, ownPIDs: { [4242] })
        func ev(_ kind: SecurityEventKind, pid: Int32 = 900, path: String? = nil, dest: String? = nil, args: [String] = [], signingID: String? = nil,
                detail: [String: String] = [:], at: Date = Date()) -> SecurityEvent {
            SecurityEvent(date: at, kind: kind, process: ProcessInfoLite(pid: pid, ppid: 1, path: args.first ?? "/bin/sh", args: args, uid: 501, signingID: signingID),
                          path: path, destPath: dest, detail: detail, source: "test")
        }
        let bootout = det.inspect(ev(.exec, args: ["/bin/launchctl", "bootout", "system/app.rampart.daemon"]))
        check(bootout.count == 1 && bootout[0].severity == .critical && bootout[0].name.contains("unloadAttempt"), "launchctl bootout detected")
        check(det.inspect(ev(.exec, pid: 901, args: ["/bin/launchctl", "bootout", "system/app.rampart.daemon"], at: Date().addingTimeInterval(1))).isEmpty, "dedupe within window")
        check(det.inspect(ev(.exec, pid: 902, args: ["/bin/launchctl", "list"])).isEmpty, "launchctl list ignored")
        check(det.inspect(ev(.exec, pid: 903, args: ["/usr/bin/pkill", "-9", "rampartd"])).first?.name.contains("killAttempt") == true, "pkill rampartd detected")
        check(det.inspect(ev(.exec, pid: 904, args: ["/bin/rm", "-f", paths.daemonPlist])).first?.severity == .critical, "rm of plist critical")
        check(det.inspect(ev(.exec, pid: 905, args: ["/usr/bin/chflags", "noschg", paths.daemonBinary])).first?.name.contains("plistTamper") == true, "chflags noschg flagged critical")
        check(det.inspect(ev(.exec, pid: 906, args: ["/usr/bin/tccutil", "reset", "SystemPolicyAllFiles", "app.rampart.daemon"])).count == 1, "tccutil reset detected")
        check(det.inspect(ev(.exec, pid: 907, args: ["/bin/rm", "-rf", "/Users/x/Downloads/junk"])).isEmpty, "rm elsewhere ignored")
        check(det.inspect(ev(.exec, pid: 4242, args: ["/bin/launchctl", "bootout", "system/app.rampart.daemon"])).isEmpty, "own pid exempt")
        check(det.inspect(ev(.exec, pid: 908, args: ["/bin/launchctl", "bootout", "system/app.rampart.daemon"], signingID: "app.rampart.installer")).isEmpty, "own signing id exempt")
        check(det.inspect(ev(.fileDelete, pid: 909, path: paths.daemonPlist)).first?.severity == .critical, "unlink of plist (eslogger) critical")
        check(det.inspect(ev(.fileRename, pid: 910, path: "/tmp/x.plist", dest: paths.agentPlist)).count == 1, "rename onto plist detected")
        check(det.inspect(ev(.fileWrite, pid: 911, path: paths.supportRoot + "/DB/hashes.sqlite")).first?.severity == .high, "write under support root high")
        check(det.inspect(ev(.fileClose, pid: 912, path: paths.configFile, detail: ["modified": "0"])).isEmpty, "unmodified close ignored")
        check(det.inspect(ev(.persistenceRemoved, pid: 913, detail: ["label": "app.rampart.daemon", "es_event": "btm_launch_item_remove"])).first?.name.contains("launchItemRemoved") == true, "btm remove detected")
        check(det.inspect(ev(.other, pid: 914, detail: ["es_event": "signal", "sig": "9", "target_pid": "4242"])).first?.severity == .critical, "ES signal to our pid")
        check(det.inspect(ev(.other, pid: 915, detail: ["es_event": "signal", "sig": "15", "target_pid": "77"])).isEmpty, "signal to others ignored")
        check(det.exclusionsCoveringSelf(["/Users/me/Projects", paths.supportRoot, "/"]) == [paths.supportRoot, "/"], "exclusion of self refused")
        check(det.exclusionDetection([paths.supportRoot], peerUID: 501, peerPID: 1).severity == .high, "exclusion detection")

        // MARK: Self-defence policy + responder
        let policy = SelfDefencePolicy(paths: paths, store: store)
        try! store.write(Data("<plist/>".utf8), to: paths.daemonPlist)
        try! FileManager.default.removeItem(atPath: paths.daemonPlist)
        let resp = policy.respond(to: .plistTamper, path: paths.daemonPlist, dryRun: true)
        check(resp.restoredFiles == [paths.daemonPlist] && !FileManager.default.fileExists(atPath: paths.daemonPlist), "dryRun response plans restore only")
        check(resp.commands.contains { $0.arguments.first == "bootstrap" } && resp.commands.contains { $0.arguments.first == "kickstart" }, "re-bootstrap commands")
        let live = policy.respond(to: .plistTamper, path: paths.daemonPlist, dryRun: false)
        check(live.restoredFiles.count == 1 && FileManager.default.fileExists(atPath: paths.daemonPlist), "live response restores plist from backup")
        check(policy.respond(to: .binaryTamper, path: paths.daemonBinary).commands.contains { $0.arguments.first == "bootout" }, "replaced binary -> bootout")
        let sweep = policy.sweep(manifest: manifest, dryRun: true)
        check(sweep.contains { $0.kind == .binaryTamper }, "sweep reports manifest mismatch")

        final class KillLog: @unchecked Sendable { var calls: [(Int32, Int32)] = []; let l = NSLock() }
        let klog = KillLog()
        let flow = ProtectionDisableFlow(key: key)
        let responder = TamperResponder(policy: policy, flow: flow, kill: { pid, sig in klog.l.lock(); klog.calls.append((pid, sig)); klog.l.unlock(); return true },
                                        processTree: { root in [root + 2, root + 1, root] })
        let d = bootout[0]
        let o1 = responder.respond(to: d, kind: .unloadAttempt, actorPID: 900, actorUID: 501, dryRun: true)
        check(o1.attackerPIDs == [902, 901, 900] && o1.stopped.isEmpty && klog.calls.isEmpty, "dryRun: attacker tree planned, nothing signalled")
        let o2 = responder.respond(to: d, kind: .unloadAttempt, actorPID: 900, actorUID: 501, dryRun: false)
        check(o2.stopped == [902, 901, 900] && klog.calls.count == 6 && klog.calls.prefix(3).allSatisfy { $0.1 == SIGSTOP }, "live: SIGSTOP tree leaves-first, then SIGKILL (hook only)")
        check(responder.respond(to: d, kind: .unloadAttempt, actorPID: 1, actorUID: 0, dryRun: false).attackerPIDs.isEmpty, "never touches pid 1")

        // MARK: Disable flow: admin + authorization + short-lived single-use token + sessions
        func fail(_ r: Result<Void, ProtectionDisableFlow.Failure>) -> ProtectionDisableFlow.Failure? { if case .failure(let f) = r { return f }; return nil }
        let t0 = Date()
        var now = t0
        let clockFlow = ProtectionDisableFlow(key: key, clock: GuardClock(now: { now }))
        check(clockFlow.issueToken(peerUID: 501, isAdmin: false, authorizationOK: true) == .failure(.notAdmin), "non-admin refused")
        check(clockFlow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: false) == .failure(.authorizationMissing), "no authorization refused")
        guard case .success(let token) = clockFlow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) else { check(false, "token issued"); return }
        check(token.split(separator: ".").count == 4, "token shape")
        check(fail(clockFlow.redeem(token, peerUID: 502)) == .tokenForOtherUser, "token bound to uid")
        check(fail(clockFlow.redeem(token + "x", peerUID: 501)) == .tokenInvalid, "forged token rejected")
        check(fail(clockFlow.redeem(token, peerUID: 501, purpose: .uninstall, sessionSeconds: 300)) == nil, "token redeemed")
        check(fail(clockFlow.redeem(token, peerUID: 501)) == .tokenInvalid, "token single use")
        check(clockFlow.hasActiveSession(uid: 501, purpose: .uninstall) && !clockFlow.hasActiveSession(uid: 502), "uninstall session open for uid")
        let exempt = TamperResponder(policy: policy, flow: clockFlow, kill: { _, _ in true }, processTree: { [$0] })
            .respond(to: d, kind: .fileTamper, actorPID: 900, actorUID: 501, dryRun: false)
        check(exempt.exempt && exempt.attackerPIDs.isEmpty, "authenticated uninstall is not attacked")
        now = t0.addingTimeInterval(301)
        check(!clockFlow.hasActiveSession(uid: 501), "session expires")
        guard case .success(let t2) = clockFlow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) else { return }
        now = now.addingTimeInterval(121)
        check(fail(clockFlow.redeem(t2, peerUID: 501)) == .tokenExpired, "token expires after TTL")
        let un = clockFlow.uninstallCommands(paths: paths)
        check(un.first?.executable == "/usr/bin/chflags" && un.contains { $0.arguments == ["bootout", "system/app.rampart.sentinel"] } && un.last?.arguments == ["-rf", paths.supportRoot], "uninstall order: unlock, sentinel/watchdog/daemon bootout, remove")
        check(!ProtectionDisableFlow.honestLimitCopy.isEmpty && TamperCopy.limit.contains("Recovery"), "honest copy present")

        // MARK: Guardian ring
        let ring = GuardianRing(paths: paths)
        check(ring.jobs.count == 3 && Set(ring.labels).count == 3 && Set(ring.binaries).count == 3, "three distinct guardians")
        check(ring.partners(of: .daemon).map(\.role) == [.watchdog, .sentinel], "daemon guards watchdog+sentinel")
        let xml = ring.plistXML(for: .sentinel)
        check(xml.contains("<string>app.rampart.sentinel</string>") && xml.contains("--role") && xml.contains("<key>ThrottleInterval</key><integer>1</integer>"), "sentinel plist")
        try! Data("#!/bin/sh\necho watchdog\n".utf8).write(to: URL(fileURLWithPath: paths.watchdogBinary))
        try! Data("#!/bin/sh\necho daemon\n".utf8).write(to: URL(fileURLWithPath: paths.daemonBinary))
        try! store.write(Data("<plist/>".utf8), to: paths.watchdogPlist)
        try! store.write(FileManager.default.contents(atPath: paths.watchdogBinary)!, to: paths.watchdogBinary)
        let ringManifest = InstallManifest.build(paths: [paths.daemonBinary, paths.watchdogBinary, paths.daemonPlist, paths.watchdogPlist])
        final class Tick: @unchecked Sendable { var v = 0.0 }
        let tick = Tick()
        let loop = GuardianLoop(role: .daemon, ring: ring, store: store, manifest: ringManifest,
                                clock: GuardClock(now: { t0.addingTimeInterval(tick.v) }), isRunning: { _ in false })
        let tk1 = loop.tick(dryRun: true)
        let wd1 = tk1.checks.first { $0.label == paths.watchdogLabel }!
        check(!wd1.healthy && wd1.commands.contains { $0.arguments == ["kickstart", "-k", "system/\(paths.watchdogLabel)"] }, "watchdog down -> kickstart planned")
        check(tk1.checks.first { $0.label == "app.rampart.sentinel" }?.commands.isEmpty == false, "sentinel (never running in test) re-bootstrapped")
        tick.v = 0.5
        let tk2 = loop.tick(dryRun: true)
        check(tk2.checks.first { $0.label == paths.watchdogLabel }?.commands.isEmpty == true, "back-off suppresses immediate retry")
        tick.v = 1.5
        check(loop.tick(dryRun: true).checks.first { $0.label == paths.watchdogLabel }?.commands.isEmpty == false, "retry after back-off")
        try! FileManager.default.removeItem(atPath: paths.watchdogPlist)
        tick.v = 10
        let tk3 = loop.tick(dryRun: false)
        check(tk3.checks.first { $0.label == paths.watchdogLabel }?.restoredFiles == [paths.watchdogPlist] && FileManager.default.fileExists(atPath: paths.watchdogPlist), "deleted plist restored within a tick")

        // MARK: Remote access: identification from fixture signing data
        func idTool(sign: String? = nil, team: String? = nil, path: String? = nil, label: String? = nil) -> String? {
            RemoteToolCatalogue.identify(signingID: sign, teamID: team, path: path, label: label)?.0.id
        }
        check(idTool(sign: "com.teamviewer.TeamViewer", team: "H7UGFYMTCW", path: "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer") == "teamviewer", "TeamViewer by signing id")
        check(idTool(sign: "com.philandro.anydesk", path: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk") == "anydesk", "AnyDesk")
        check(idTool(sign: "com.carriez.rustdesk") == "rustdesk" && idTool(sign: "com.hoptodesk.hoptodesk") == "hoptodesk", "RustDesk/HopToDesk")
        check(idTool(team: "EQHXZ8M8AV", path: "/Library/PrivilegedHelperTools/x") == "chromeremotedesktop", "Google Team ID is strong")
        check(idTool(team: "H7UGFYMTCW") == nil, "unverified team id alone is not enough")
        check(idTool(team: "H7UGFYMTCW", path: "/opt/teamviewer/tv_bin/TeamViewer") == "teamviewer", "hint team id + path corroborate")
        check(idTool(path: "/usr/sbin/sshd") == "apple.ssh" && idTool(path: "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd") == "apple.screensharing", "Apple services by path")
        check(idTool(sign: "com.apple.Safari", path: "/Applications/Safari.app/Contents/MacOS/Safari") == nil, "Safari not a remote tool")
        check(idTool(label: "com.splashtop.streamer.launchd") == "splashtop" && idTool(label: "screenconnect-abc123") == "screenconnect", "launch labels")
        check(RemoteToolCatalogue.inboundPorts.contains(22) && RemoteToolCatalogue.inboundPorts.contains(5900) && RemoteToolCatalogue.inboundPorts.contains(3283), "inbound port set")

        // MARK: lsof parsers
        let lsof = "p123\ncsshd\nn*:22\np555\ncTeamViewer\nn*:5938\nn127.0.0.1:5939\np777\ncscreensha\nn[::1]:5900->[::1]:60000\n"
        let ls = RemoteAccessParsers.listeners(fromLsof: lsof)
        check(ls.count == 3 && ls[0] == ListeningPort(port: 22, pid: 123, process: "sshd") && ls[1].port == 5938, "lsof listener parse")
        let inb = RemoteAccessParsers.inbound(fromLsof: "p777\ncscreensha\nn192.168.1.5:5900->192.168.1.9:51000\np1\ncfoo\nn10.0.0.1:443->1.2.3.4:5\n")
        check(inb.count == 1 && inb[0].localPort == 5900 && inb[0].remoteAddress == "192.168.1.9" && inb[0].remotePort == 51000, "lsof inbound parse")

        // MARK: Monitor + policy + enforcement on fixtures
        let now0 = Date()
        let procs = [ProcessInfoLite(pid: 555, ppid: 1, path: "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer", uid: 501, signingID: "com.teamviewer.TeamViewer", teamID: "H7UGFYMTCW"),
                     ProcessInfoLite(pid: 556, ppid: 555, path: "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Desktop", uid: 501, signingID: "com.teamviewer.TeamViewer.Desktop"),
                     ProcessInfoLite(pid: 600, ppid: 1, path: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk", uid: 501, signingID: "com.philandro.anydesk"),
                     ProcessInfoLite(pid: 1, ppid: 0, path: "/sbin/launchd", uid: 0, signingID: "com.apple.xpc.launchd", isPlatformBinary: true)]
        var scam = ScamContext()
        let probe = RemoteAccessProbe(processes: { procs }, listeners: { ls }, launchItems: {
            [PersistenceItem(kind: .launchDaemon, label: "com.teamviewer.teamviewer_service", location: "/Library/LaunchDaemons/com.teamviewer.teamviewer_service.plist", target: "/Applications/TeamViewer.app/Contents/Helpers/TeamViewer_Service")]
        }, sharing: { SharingServiceState(screenSharing: true, remoteManagement: false, remoteLogin: true, remoteAppleEvents: false) },
           inbound: { inb }, scam: { scam }, now: { now0 })
        let monitor = RemoteAccessMonitor(probe: probe)
        var rpolicy = RemoteAccessPolicy()
        let r1 = monitor.report(policy: rpolicy)
        let tv = r1.findings.first { $0.toolID == "teamviewer" }
        check(tv?.pids == [555, 556] && tv?.launchItems.count == 1 && tv?.listeningPorts == [5938, 5939] && tv?.allowed == false && tv?.severity == .high, "TeamViewer finding aggregates pids, launch item, port")
        check(r1.findings.first { $0.toolID == "apple.ssh" }?.serviceEnabled == true && r1.findings.first { $0.toolID == "apple.ssh" }?.listeningPorts == [22], "SSH service + listener")
        check(r1.findings.first { $0.toolID == "apple.screensharing" }?.inboundSessions == 1, "screen sharing inbound session counted")
        check(r1.findings.first { $0.toolID == "apple.ard" } == nil, "ARD off -> no finding")
        check(r1.activeUnapproved.count == 4 && r1.blockedPorts.contains(5938) && r1.blockedPorts.contains(22), "default deny: everything unapproved, ports blocked")
        let dets = monitor.detections(from: r1)
        check(dets.count == 4 && dets.contains { $0.name.contains("TeamViewer") && $0.category == .backdoor }, "detections per unapproved tool")

        rpolicy.allow(RemoteToolCatalogue.tool("teamviewer")!, minutes: 60, now: now0)
        let r2 = monitor.report(policy: rpolicy)
        let tv2 = r2.findings.first { $0.toolID == "teamviewer" }
        check(tv2?.allowed == true && tv2?.allowedUntil == now0.addingTimeInterval(3600) && tv2?.severity == .low, "allow for 1 hour")
        check(!r2.blockedPorts.contains(5938) && r2.blockedPorts.contains(7070), "allowed tool's port unblocked, others stay blocked")
        check(rpolicy.allowance(for: "teamviewer", at: now0.addingTimeInterval(3601)) == nil, "allowance expires")
        rpolicy.prune(now: now0.addingTimeInterval(3601))
        check(rpolicy.allowances.isEmpty, "prune removes expired")
        rpolicy.allow(RemoteToolCatalogue.tool("anydesk")!, minutes: nil, now: now0)
        check(rpolicy.allowance(for: "anydesk", at: now0.addingTimeInterval(1e9)) != nil, "permanent allowance")
        rpolicy.revoke("anydesk")

        scam = ScamContext(frontmostBundleID: "com.apple.Safari")
        let r3 = monitor.report(policy: rpolicy)
        check(r3.findings.first { $0.toolID == "anydesk" }?.severity == .critical && r3.findings.first { $0.toolID == "anydesk" }?.scamContext == true, "browser frontmost -> critical scam context")
        check(r3.findings.first { $0.toolID == "apple.ssh" }?.scamContext == false, "Apple services never get scam context")
        scam = ScamContext(lastScamPageAt: now0.addingTimeInterval(-600))
        check(monitor.detections(from: monitor.report(policy: rpolicy)).first { $0.name.contains("AnyDesk") }?.evidence.contains { $0.title.contains("scam") } == true, "scam page within window raises evidence")
        scam = ScamContext(lastScamPageAt: now0.addingTimeInterval(-3600))
        check(monitor.report(policy: rpolicy).findings.first { $0.toolID == "anydesk" }?.scamContext == false, "scam page outside window ignored")

        final class RKill: @unchecked Sendable { var calls: [(Int32, Int32)] = []; let l = NSLock() }
        let rk = RKill()
        let fw = RemoteAccessFirewall(directory: root + "/pf")
        let enforcer = RemoteAccessEnforcer(kill: { p, s in rk.l.lock(); rk.calls.append((p, s)); rk.l.unlock(); return true }, firewall: fw)
        let savedPath = RemoteAccessEnforcer.processPath
        RemoteAccessEnforcer.processPath = { _ in "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer" }
        defer { RemoteAccessEnforcer.processPath = savedPath }
        let plan = enforcer.plan(report: r1, policy: RemoteAccessPolicy(), dryRun: true)
        check(plan.suspendPIDs.sorted() == [555, 556, 600] && plan.killPIDs.isEmpty && plan.signalled.isEmpty && rk.calls.isEmpty, "dryRun plan: suspend, no signals sent")
        check(plan.commands.contains { $0.arguments == ["bootout", "system/com.teamviewer.teamviewer_service"] } && plan.commands.contains { $0.arguments == ["-f", "-setremotelogin", "off"] }
              && plan.commands.contains { $0.arguments == ["bootout", "system/com.apple.screensharing"] }, "launch item disabled, SSH and Screen Sharing turned off")
        check(!plan.commands.contains { $0.arguments.first == "-deactivate" }, "ARD untouched when off")
        check(plan.pfRules.contains("block drop in quick log proto tcp from any to any port {") && plan.pfRules.contains("5938") && plan.commands.contains { $0.executable == "/sbin/pfctl" && $0.arguments.contains("-f") }, "pf anchor rules + load commands")
        check(plan.commands.allSatisfy { $0.executable.hasPrefix("/") }, "all commands absolute")
        try! fw.writeRules(plan.pfRules)
        check(FileManager.default.fileExists(atPath: fw.rulesPath), "pf rules file written to scratch")
        let livePlan = enforcer.plan(report: r1, policy: RemoteAccessPolicy(), dryRun: false)
        check(livePlan.signalled.sorted() == [555, 556, 600] && rk.calls.allSatisfy { $0.1 == SIGSTOP }, "live plan suspends via hook only (SIGSTOP)")
        check(enforcer.resume([555], dryRun: false) == [555] && rk.calls.last?.1 == SIGCONT, "resume via hook")
        var off = RemoteAccessPolicy(); off.lockdownEnabled = false
        check(enforcer.plan(report: monitor.report(policy: off), policy: off).commands.isEmpty, "lockdown off -> no actions")
        check(fw.anchorRules(blockedPorts: []).contains("nothing blocked"), "empty rules")

        // MARK: Codable round-trip (ZERO POP-UPS RULE: no live probes of this Mac during development)
        let data = try! JSONEncoder.rampart.encode(r1)
        check((try? JSONDecoder.rampart.decode(RemoteAccessReport.self, from: data))?.findings.count == r1.findings.count, "report codable")
        setenv("RAMPART_NO_PRIVILEGED_TOOLS", "1", 1)
        let runnerBlocked = GuardProcessRunner().run("/bin/launchctl", ["print", "system/com.openssh.sshd"], timeout: 1)
        check(runnerBlocked.launchFailed && runnerBlocked.stderr.contains("RAMPART_NO_PRIVILEGED_TOOLS"), "runner refuses privileged tools in dev")
        let quiet = RemoteAccessProbe.live().sharing()
        check(quiet == SharingServiceState(), "live probe stays silent under RAMPART_NO_PRIVILEGED_TOOLS")
    }
}

extension SelfTest {
    /// Regression: Apple's MDM framework (organisation-managed Macs) must never be treated as remote access.
    static func guardMDMRegression() {
        let e = RemoteAccessEnforcer(kill: { _, _ in true })
        let saved = RemoteAccessEnforcer.processPath
        RemoteAccessEnforcer.processPath = { _ in "/System/Library/PrivateFrameworks/RemoteManagement.framework/remotemanagementd" }
        _ = e
        RemoteAccessEnforcer.processPath = saved
        let mdm = ["/System/Library/PrivateFrameworks/RemoteManagement.framework/remotemanagementd",
                   "/System/Library/PrivateFrameworks/RemoteManagement.framework/XPCServices/ExtensibleSSOSubscriber.xpc/Contents/MacOS/ExtensibleSSOSubscriber",
                   "/System/Library/PrivateFrameworks/RemoteManagement.framework/RemoteManagementAgent"]
        for path in mdm { check(RemoteToolCatalogue.identify(signingID: nil, teamID: nil, path: path) == nil, "MDM not remote access: \(path)") }
        check(RemoteToolCatalogue.identify(signingID: nil, teamID: nil,
              path: "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent")?.0.id == "apple.ard", "real ARD agent still identified")
    }
}

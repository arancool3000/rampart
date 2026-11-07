import Foundation
import RampartShared
import RampartGuard

// hx5: tamper-protection and remote-access hardening regressions. Synthetic events, scratch files and injected
// clocks only. Never runs launchctl, kill, chflags, codesign against anything real.
extension SelfTest {
    static func hx5Checks() {
        print("   --- hx5: tamper protection + remote-access hardening ---")
        let fm = FileManager.default
        let scratch = (ProcessInfo.processInfo.environment["RAMPART_SCRATCH"]
            ?? "/private/tmp/claude-501/-Users-arankeyhan/ab330a0d-96bf-4eec-a6ed-51d815d3bfd2/scratchpad/hx5") + "/run-\(getpid())"
        try? fm.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: scratch) }
        let paths = GuardPaths.scratch(scratch)
        try? fm.createDirectory(atPath: scratch + "/bin", withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: scratch + "/LaunchDaemons", withIntermediateDirectories: true)

        var pidSeq: Int32 = 7000
        func det() -> TamperDetector { TamperDetector(paths: paths, ownPIDs: { [4242] }) }
        func exec(_ d: TamperDetector, _ args: [String], path: String? = nil, ppid: Int32 = 1, signingID: String? = nil, teamID: String? = nil) -> [Detection] {
            pidSeq += 1
            let p = ProcessInfoLite(pid: pidSeq, ppid: ppid, path: path ?? args.first ?? "/bin/sh", args: args, uid: 501, signingID: signingID, teamID: teamID)
            return d.inspect(SecurityEvent(date: Date(), kind: .exec, process: p, detail: [:], source: "test"))
        }
        func file(_ d: TamperDetector, _ kind: SecurityEventKind, _ path: String, procPath: String = "/bin/sh") -> [Detection] {
            pidSeq += 1
            let p = ProcessInfoLite(pid: pidSeq, ppid: 1, path: procPath, uid: 501)
            return d.inspect(SecurityEvent(date: Date(), kind: kind, process: p, path: path, detail: [:], source: "test"))
        }

        // 1. Self-attribution can't be forged with an ad-hoc signing identifier.
        check(exec(det(), ["/bin/launchctl", "bootout", "system/app.rampart.daemon"], signingID: "app.rampart.evil").count == 1,
              "hx5: ad-hoc 'app.rampart.*' signing id is not self-exempt")
        check(exec(det(), ["/bin/launchctl", "bootout", "system/app.rampart.daemon"], ppid: 4242).isEmpty,
              "hx5: child of the daemon is self")
        let teamDet = TamperDetector(paths: paths, ownPIDs: { [4242] }, trustedTeamIDs: ["TEAMTEST01"])
        check(exec(teamDet, ["/bin/launchctl", "bootout", "system/app.rampart.daemon"], signingID: "app.rampart.installer", teamID: "TEAMTEST01").isEmpty,
              "hx5: trusted Team ID is self")
        // Dropped binary inside the (user-writable) app bundle is not self.
        check(exec(det(), ["/bin/launchctl", "bootout", "system/app.rampart.daemon"], path: paths.appBundle + "/Contents/Helpers/evil").count == 1,
              "hx5: process running from inside the app bundle is not self without a manifest match")

        // 2. Sentinel is a protected guardian.
        check(paths.labels.contains("app.rampart.sentinel") && paths.isProtected(paths.sentinelBinary) && paths.isPlist(paths.sentinelPlist),
              "hx5: sentinel binary/plist/label protected")
        check(exec(det(), ["/usr/bin/killall", "app.rampart.sentinel"]).count == 1, "hx5: killall sentinel detected")
        check(exec(det(), ["/bin/rm", "-f", paths.sentinelBinary]).count == 1, "hx5: rm sentinel binary detected")
        check(GuardianRing(paths: paths).job(.sentinel).binary == paths.sentinelBinary, "hx5: ring and paths agree on sentinel")

        // 3. Kill variants.
        check(exec(det(), ["/bin/kill", "-9", "-1"]).count == 1, "hx5: kill -9 -1 detected")
        check(exec(det(), ["/bin/kill", "-STOP", "4242"]).count == 1, "hx5: kill -STOP daemon detected")
        check(exec(det(), ["/bin/kill", "-s", "STOP", "4242"]).count == 1, "hx5: kill -s STOP daemon detected")
        check(exec(det(), ["/bin/kill", "-15", "5555"]).isEmpty, "hx5: kill of a foreign pid ignored")
        check(exec(det(), ["/usr/bin/pkill", "r.mpartd"]).count == 1, "hx5: pkill regex pattern detected")
        check(exec(det(), ["/usr/bin/pkill", "[r]ampartd"]).count == 1, "hx5: pkill bracket regex detected")
        check(exec(det(), ["/usr/bin/killall", "-m", "ramp.*"]).count == 1, "hx5: killall -m regex detected")
        check(exec(det(), ["/usr/bin/killall", "-u", "root"]).count == 1, "hx5: killall -u root detected")
        check(exec(det(), ["/usr/bin/pkill", "-x", "Safari"]).isEmpty, "hx5: unrelated pkill ignored")
        // Renamed copies of Apple tools.
        check(exec(det(), ["/tmp/lc", "bootout", "system/app.rampart.daemon"], signingID: "com.apple.xpc.launchctl").count == 1,
              "hx5: renamed launchctl (signing id) detected")
        check(exec(det(), ["/tmp/x", "bootout", "system/app.rampart.watchdog"]).count == 1, "hx5: renamed launchctl (no signing info) detected")
        check(exec(det(), ["/tmp/k", "-9", "4242"], signingID: "com.apple.kill").count == 1, "hx5: renamed kill detected")
        check(exec(det(), ["/bin/launchctl", "bsexec", "1", "/bin/launchctl", "bootout", "system/app.rampart.daemon"]).count == 1,
              "hx5: bsexec wrapper detected")
        // Symlinked plist path.
        try? Data("<plist/>".utf8).write(to: URL(fileURLWithPath: paths.daemonPlist))
        let link = scratch + "/innocent.plist"
        try? fm.createSymbolicLink(atPath: link, withDestinationPath: paths.daemonPlist)
        check(exec(det(), ["/bin/launchctl", "unload", link]).count == 1, "hx5: unload through a symlink to our plist detected")

        // 4. tccutil + clock (X4.8 / X4.9 proposals).
        check(exec(det(), ["/usr/bin/tccutil", "reset", "SystemPolicyAllFiles"]).first?.severity == .high, "hx5: unqualified tccutil reset FDA detected")
        check(exec(det(), ["/usr/bin/tccutil", "reset", "Camera", "com.example.test"]).isEmpty, "hx5: unrelated tccutil reset ignored")
        check(exec(det(), ["/usr/sbin/systemsetup", "-setdate", "01:01:2020"]).first?.name.contains("clockTamper") == true, "hx5: systemsetup -setdate detected")
        check(exec(det(), ["/usr/sbin/systemsetup", "-setusingnetworktime", "off"]).count == 1, "hx5: network time off detected")
        check(exec(det(), ["/usr/bin/sntp", "-sS", "evil.ntp.test"]).count == 1, "hx5: sntp -sS detected")
        check(exec(det(), ["/usr/bin/sntp", "time.apple.com"]).isEmpty, "hx5: sntp query only ignored")
        check(exec(det(), ["/bin/date", "0101000020"]).count == 1, "hx5: date set detected")
        check(exec(det(), ["/bin/date", "+%Y-%m-%d"]).isEmpty, "hx5: date format ignored")

        // 5. Update-hold window: cannot be extended forever; clock rollback does not freeze it.
        do {
            let d = det(); d.updateGrace = 0.3; d.maxHold = 0.6
            d.bundleValidator = { _ in false }
            var hits = 0
            for _ in 0..<6 { hits += file(d, .fileWrite, paths.appBundle + "/Contents/Resources/x").count; usleep(150_000); hits += d.flushPending().count }
            check(hits >= 1, "hx5: repeated bundle touches cannot hold a swap past maxHold")
            let d2 = det(); d2.updateGrace = 30; d2.bundleValidator = { _ in false }
            _ = file(d2, .fileWrite, paths.appBundle + "/Contents/Resources/y")
            check(d2.flushPending(now: Date().addingTimeInterval(-86400)).count == 1, "hx5: clock rolled back -> held change decided, not frozen")
        }

        // 6. Plist validation: our label is not enough.
        func job(_ extra: [String: Any], program: String? = nil) -> [String: Any] {
            var p: [String: Any] = ["Label": paths.daemonLabel, "ProgramArguments": [program ?? paths.daemonBinary], "KeepAlive": true]
            for (k, v) in extra { p[k] = v }
            return p
        }
        check(RamPartIdentity.isOurJob(job([:]), paths: paths), "hx5: genuine job accepted")
        check(!RamPartIdentity.isOurJob(job([:], program: paths.appBundle + "/Contents/Helpers/evil"), paths: paths), "hx5: Helpers/evil program rejected")
        check(!RamPartIdentity.isOurJob(job(["Disabled": true]), paths: paths), "hx5: Disabled job rejected")
        check(!RamPartIdentity.isOurJob(job(["KeepAlive": false]), paths: paths), "hx5: KeepAlive=false rejected")
        check(!RamPartIdentity.isOurJob(job(["EnvironmentVariables": ["DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"]]), paths: paths), "hx5: DYLD injection rejected")
        check(!RamPartIdentity.isOurJob(job(["EnvironmentVariables": ["RAMPART_NO_PRIVILEGED_TOOLS": "1"]]), paths: paths), "hx5: RAMPART_ env neutering rejected")
        check(!RamPartIdentity.isOurJob(job(["UserName": "nobody"]), paths: paths), "hx5: de-privileged daemon rejected")
        check(!RamPartIdentity.isOurJob(["Label": paths.daemonLabel, "ProgramArguments": [paths.daemonBinary, "--no-scheduler"]], paths: paths), "hx5: neutering argument rejected")
        try? fm.removeItem(atPath: paths.watchdogPlist)
        try? Data(GuardianRing(paths: paths).plistXML(for: .daemon).utf8).write(to: URL(fileURLWithPath: scratch + "/real.plist"))
        try? fm.createSymbolicLink(atPath: paths.watchdogPlist, withDestinationPath: scratch + "/real.plist")
        check(!RamPartIdentity.isOurPlist(paths.watchdogPlist, paths: paths), "hx5: symlinked plist rejected")

        // 7. Look-alike bundle: no trusted team and no manifest pin -> not genuine.
        check(!RamPartIdentity.isGenuineBundle(scratch + "/nonexistent.app", trustedTeamIDs: [], manifest: nil), "hx5: missing bundle not genuine")

        // 8. Sealed v2: path-bound; cross-file swap fails; raw restore writes payload.
        let key = try! IntegrityKey.loadOrCreate(at: paths.keyFile)
        let store = SealedStore(key: key, backupDir: paths.backupDir)
        try! store.write(Data("{\"a\":1}".utf8), to: paths.configFile)
        try! store.write(Data("{\"allow\":[\"/\"]}".utf8), to: paths.allowRulesFile)
        try? fm.removeItem(atPath: paths.configFile)
        try! fm.copyItem(atPath: paths.allowRulesFile, toPath: paths.configFile)
        check(store.verify(paths.configFile) == .tampered(.macMismatch), "hx5: sealed file copied over another -> macMismatch")
        check(store.restoreIfNeeded(paths.configFile, dryRun: false).restored && store.verify(paths.configFile) == .intact(Data("{\"a\":1}".utf8)),
              "hx5: swapped sealed file restored from its own backup")
        let v1 = Sealed.seal(Data("x".utf8), key: key)
        check((try? Sealed.open(v1, key: key).get()) == Data("x".utf8), "hx5: legacy v1 envelope still opens")
        check(Sealed.open(v1, key: key, allowV1: false) == .failure(.macMismatch), "hx5: v1 refused when v2 required")
        let bin = Data("#!/bin/sh\necho sentinel\n".utf8)
        try! bin.write(to: URL(fileURLWithPath: paths.sentinelBinary))
        try! store.backupOnly(bin, for: paths.sentinelBinary)
        let sha = InstallManifest.sha256(ofFile: paths.sentinelBinary)
        try! Data("evil".utf8).write(to: URL(fileURLWithPath: paths.sentinelBinary))
        check(store.restoreRawIfNeeded(paths.sentinelBinary, expectedSHA: sha, mode: 0o755, dryRun: false)
              && fm.contents(atPath: paths.sentinelBinary) == bin, "hx5: raw binary restored as payload, not envelope")
        try! Data("evil".utf8).write(to: URL(fileURLWithPath: paths.sentinelBinary))
        check(!store.restoreRawIfNeeded(paths.sentinelBinary, expectedSHA: String(repeating: "0", count: 64), dryRun: false), "hx5: backup not matching manifest refused")
        check(Sealed.open(Data(count: Sealed.maxEnvelopeBytes + 1), key: key) == .failure(.badEnvelope), "hx5: oversized envelope refused")

        // Key file hygiene.
        let kdir = scratch + "/k"; try? fm.createDirectory(atPath: kdir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? Data(repeating: 1, count: 31).write(to: URL(fileURLWithPath: kdir + "/short.key")); chmod(kdir + "/short.key", 0o600)
        check((try? IntegrityKey.loadOrCreate(at: kdir + "/short.key")) == nil, "hx5: truncated key refused, not silently regenerated")
        try? fm.createSymbolicLink(atPath: kdir + "/link.key", withDestinationPath: paths.keyFile)
        check((try? IntegrityKey.loadOrCreate(at: kdir + "/link.key")) == nil, "hx5: symlinked key refused")
        let wdir = scratch + "/w"; try? fm.createDirectory(atPath: wdir, withIntermediateDirectories: true); chmod(wdir, 0o777)
        check((try? IntegrityKey.loadOrCreate(at: wdir + "/g.key")) == nil, "hx5: key in world-writable folder refused")

        // 9. Manifest: unlisted file, symlink swap.
        let appDir = scratch + "/mf"; try? fm.createDirectory(atPath: appDir, withIntermediateDirectories: true)
        try? Data("a".utf8).write(to: URL(fileURLWithPath: appDir + "/a"))
        let m = InstallManifest.build(paths: [appDir, paths.sentinelBinary])
        check(m.verify().filter { $0.kind != .hashChanged }.isEmpty, "hx5: fresh manifest has no unlisted/symlink findings")
        try? Data("dylib".utf8).write(to: URL(fileURLWithPath: appDir + "/inject.dylib"))
        check(m.verify().contains { $0.kind == .unlisted && $0.path.hasSuffix("inject.dylib") }, "hx5: dropped file in bundle reported unlisted")
        let cur = fm.contents(atPath: paths.sentinelBinary)!
        try? cur.write(to: URL(fileURLWithPath: scratch + "/copy"))
        try? fm.removeItem(atPath: paths.sentinelBinary)
        try? fm.createSymbolicLink(atPath: paths.sentinelBinary, withDestinationPath: scratch + "/copy")
        check(m.verify().contains { $0.kind == .symlink && $0.path == paths.sentinelBinary }, "hx5: binary swapped for a symlink reported")
        check(InstallManifest(entries: [appDir + "/a": InstallManifest.sha256(ofFile: appDir + "/a")!]).verify(requireOwner: 0).contains { $0.kind == .unsafeOwnership },
              "hx5: user-owned installed file reported unsafe ownership")

        // 10. Guardian ring: SIGSTOP is not 'running', back-off bounded, clock rollback doesn't freeze it.
        check(!GuardianLoop.isLive(printOutput: "\tpid = 321\n", state: { _ in 4 /* SSTOP */ }), "hx5: stopped guardian is not live")
        check(GuardianLoop.isLive(printOutput: "\tpid = 321\n", state: { _ in 2 /* SRUN */ }), "hx5: running guardian is live")
        check(!GuardianLoop.isLive(printOutput: "state = not running\n", state: { _ in 2 }), "hx5: no pid is not live")
        check(!GuardianLoop.isLive(printOutput: "\tpid = 321\n", state: { _ in nil }), "hx5: vanished pid is not live")
        final class T: @unchecked Sendable { var v = 0.0 }
        let t = T(); let t0 = Date()
        let loop = GuardianLoop(role: .daemon, ring: GuardianRing(paths: paths), store: nil, manifest: nil,
                                clock: GuardClock(now: { t0.addingTimeInterval(t.v) }), isRunning: { _ in false })
        var maxB = 0.0
        for i in 0..<20 { t.v = Double(i) * 100; maxB = max(maxB, loop.tick(dryRun: true).backoffSeconds) }
        check(maxB <= 8, "hx5: restart back-off capped at 8 s")
        t.v = 5000; _ = loop.tick(dryRun: true)
        t.v = -1_000_000
        check(loop.tick(dryRun: true).checks.allSatisfy { !$0.commands.isEmpty }, "hx5: clock rollback does not stretch back-off")

        // 11. Disable flow: monotonic budget beats a clock rollback; session length capped; tokens domain-separated.
        final class M: @unchecked Sendable { var wall = Date(); var mono = 1000.0 }
        let mk = M(); let w0 = mk.wall
        let flow = ProtectionDisableFlow(key: key, clock: GuardClock(now: { mk.wall }, monotonic: { mk.mono }))
        if case .success(let tok) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) {
            check(Sealed.open(Data("{\"rampart_sealed\":1,\"mac\":\"\(tok.split(separator: ".")[3])\",\"payload\":\"\(Data(tok.split(separator: ".")[0...2].joined(separator: ".").utf8).base64EncodedString())\"}".utf8), key: key) == .failure(.macMismatch),
                  "hx5: disable token MAC is not a valid seal (domain separation)")
            mk.mono += 200   // past tokenTTL on the monotonic clock, wall clock rolled back
            mk.wall = w0.addingTimeInterval(-3600)
            check({ if case .failure(.tokenExpired) = flow.redeem(tok, peerUID: 501) { return true }; return false }(), "hx5: token expires on monotonic time despite clock rollback")
        } else { check(false, "hx5: token issued") }
        mk.wall = w0; mk.mono = 2000
        if case .success(let tok) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) {
            _ = flow.redeem(tok, peerUID: 501, purpose: .pause, sessionSeconds: 1e12)
            mk.mono += 4 * 3600 + 1; mk.wall = w0.addingTimeInterval(-86400)
            check(!flow.hasActiveSession(uid: 501), "hx5: session capped and bounded by monotonic time")
        } else { check(false, "hx5: token issued 2") }

        // 12. Remote access: allowance abuse.
        let now = Date()
        var pol = RemoteAccessPolicy()
        let tv = RemoteToolCatalogue.tool("teamviewer")!
        pol.allow(tv, minutes: Int.max, now: now)
        check(pol.allowances.first!.expires! <= now.addingTimeInterval(Double(RemoteAllowance.maxMinutes) * 60), "hx5: huge minutes clamped")
        pol.allow(tv, minutes: 0, now: now)
        check(pol.allowances.first!.expires != nil, "hx5: 0 minutes is not forever")
        pol.allow(tv, minutes: 60, now: now)
        check(pol.allowance(for: "teamviewer", at: now.addingTimeInterval(-3600)) == nil, "hx5: clock rolled back before grant voids timed allowance")
        let forged = RemoteAllowance(toolID: "teamviewer", name: "TV", created: now, expires: now.addingTimeInterval(1e9))
        check(!forged.isActive(at: now.addingTimeInterval(10)), "hx5: allowance longer than max is void")
        // Pinned Team ID: look-alike with the same identifier but no/other team is not covered.
        var pinned = RemoteAccessPolicy()
        pinned.allow(tv, minutes: 60, now: now, pinTeamIDs: ["H7UGFYMTCW"])
        let fakeProcs = [ProcessInfoLite(pid: 801, ppid: 1, path: "/Users/x/Downloads/TeamViewer", uid: 501, signingID: "com.teamviewer.TeamViewer", teamID: nil)]
        let realProcs = [ProcessInfoLite(pid: 802, ppid: 1, path: "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer", uid: 501, signingID: "com.teamviewer.TeamViewer", teamID: "H7UGFYMTCW")]
        func probe(_ procs: [ProcessInfoLite], _ ls: [ListeningPort] = []) -> RemoteAccessMonitor {
            RemoteAccessMonitor(probe: RemoteAccessProbe(processes: { procs }, listeners: { ls }, launchItems: { [] }, sharing: { SharingServiceState() },
                                                         inbound: { [] }, now: { now }))
        }
        check(probe(fakeProcs).report(policy: pinned).findings.first { $0.toolID == "teamviewer" }?.allowed == false, "hx5: look-alike not covered by pinned allowance")
        check(probe(realProcs).report(policy: pinned).findings.first { $0.toolID == "teamviewer" }?.allowed == true, "hx5: real tool covered by pinned allowance")
        // Renamed, re-signed tool on an odd port.
        let renamed = [ProcessInfoLite(pid: 900, ppid: 1, path: "/Users/x/Library/helper", uid: 501, signingID: "helper-55554444", teamID: nil)]
        let rr = probe(renamed, [ListeningPort(port: 44123, pid: 900, process: "helper", address: "*"),
                                 ListeningPort(port: 44124, pid: 900, process: "helper", address: "127.0.0.1")]).report(policy: RemoteAccessPolicy())
        check(rr.unsignedListeners.map(\.port) == [44123], "hx5: unsigned non-loopback listener on an odd port reported")
        check(probe(renamed, [ListeningPort(port: 44123, pid: 900, process: "helper", address: "*")]).detections(from: rr).contains { $0.name.contains("44123") },
              "hx5: unsigned listener becomes a low-severity detection")
        let lsof = "p900\nchelper\nn*:44123\nn127.0.0.1:631\nn[::1]:9999\nn*:99999999999\n"
        let parsed = RemoteAccessParsers.listeners(fromLsof: lsof)
        check(parsed.count == 3 && parsed[0].address == "*" && parsed[2].isLoopback, "hx5: lsof listener parse keeps address, rejects absurd port")
        // /usr/local is not a system path.
        RemoteAccessEnforcer.processPath = { _ in "/usr/local/bin/anydesk-copy" }
        let rk = RemoteAccessEnforcer(kill: { _, _ in true })
        let anyd = probe([ProcessInfoLite(pid: 950, ppid: 1, path: "/usr/local/bin/anydesk-copy", uid: 501, signingID: "com.philandro.anydesk")]).report(policy: RemoteAccessPolicy())
        check(rk.plan(report: anyd, policy: RemoteAccessPolicy(), dryRun: true).suspendPIDs == [950], "hx5: remote tool in /usr/local is still suspended")
        RemoteAccessEnforcer.processPath = { GuardProc.path(of: $0) }
    }
}

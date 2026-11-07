import Foundation
import RampartShared
import RampartPosture
import RampartGuard

// hx10: root-daemon authorization matrix, client code identity via audit token, posture-fix injection,
// settings-session token, state-file permissions, log redaction. IPCAuthz.swift is a symlink to rampartd's copy.
extension SelfTest {
    static func hx10Checks() {
        hx10Matrix()
        hx10ClientIdentity()
        hx10Forwarded()
        hx10Posture()
        hx10Session()
        hx10Store()
        hx10Redaction()
    }

    /// One sample of every IPCRequest case.
    static var hx10AllRequests: [IPCRequest] {
        let u = UUID()
        return [.status, .scan(paths: [], quick: true), .listDetections, .listQuarantine, .quarantine(detectionID: u),
                .restore(id: u, allow: false), .deleteQuarantined(id: u), .allow(sha256: String(repeating: "a", count: 64)),
                .posture, .fixPosture(checkID: "firewall"), .persistence, .setWebProtection(on: true), .setWebProtection(on: false),
                .updateSignatures, .subscribeEvents, .activity(limit: 5), .connections, .wifi, .networkStats, .getSettings,
                .setSettings(RampartSettings()), .pauseScan(paused: true), .cancelScan, .setRealtime(on: true), .setRealtime(on: false),
                .previewRemediation(persistenceID: "x"), .remediate(persistenceID: "x"), .listAllowRules,
                .addAllowRule(AllowRuleSpec(scope: .fileHash, value: String(repeating: "b", count: 64), name: "t")), .removeAllowRule(id: u), .health,
                .remoteAccessReport, .allowRemoteTool(id: "x", minutes: 5), .revokeRemoteTool(id: "x"), .setRemoteLockdown(on: true),
                .setRemoteLockdown(on: false), .tamperStatus, .requestDisableProtection(authorization: nil, reason: "r"),
                .disableProtection(token: "t", minutes: 0), .requestUninstall(authorization: nil), .uninstall(token: "t"),
                .forwardEvents([]), .checkURL(url: "https://a.test"), .scamCheck(text: "x", kind: "email"), .webLookup(host: "a.test"),
                .webVerdict(url: "https://a.test", verdict: "block", score: 90, headline: "h"),
                .restoreQuarantinedTo(id: u, path: "/tmp/x", allow: false), .exportQuarantined(id: u, path: "/tmp/x"),
                .sandboxRun(id: u, confirmation: "x")]
    }

    static func hx10Matrix() {
        typealias C = AuthzCaller
        let root = C(uid: 0, isAdmin: true, isConsole: false, client: nil)
        let unauth = C(credentialed: false, uid: 0, isAdmin: true, isConsole: true, client: .app)
        func ca(_ k: RampartClientKind?, session: Bool = false) -> C { C(uid: 501, isAdmin: true, isConsole: true, client: k, hasSettingsSession: session) }
        let consoleStd = C(uid: 502, isAdmin: false, isConsole: true, client: .app)
        let otherAdmin = C(uid: 503, isAdmin: true, isConsole: false, client: .app)
        let otherAdminCLI = C(uid: 503, isAdmin: true, isConsole: false, client: .cli)
        let otherStd = C(uid: 504, isAdmin: false, isConsole: false, client: .app)
        check(root.column == .root && ca(.app).column == .consoleAdmin && consoleStd.column == .consoleStandard &&
              otherAdmin.column == .otherAdmin && otherStd.column == .otherStandard && unauth.column == .unauthenticated, "hx10: matrix columns")

        // Expected cells: (caller, allowed per level [anyLocal, sessionUser, adminClient, adminClientWeakening]).
        let cells: [(String, C, [Bool])] = [
            ("root", root, [true, true, true, true]),
            ("console admin + app", ca(.app), [true, true, true, true]),
            ("console admin + cli", ca(.cli), [true, true, true, false]),
            ("console admin + cli + settings session", ca(.cli, session: true), [true, true, true, true]),
            ("console admin + unverified client (script / raw socket)", ca(nil), [true, true, false, false]),
            ("console admin + unverified client + session", ca(nil, session: true), [true, true, false, false]),
            ("console admin + nmh", ca(.nmh), [true, true, false, false]),
            ("console admin + daemon id", ca(.daemon), [true, true, false, false]),
            ("console standard user + app", consoleStd, [true, true, false, false]),
            ("other admin + app", otherAdmin, [true, true, true, true]),
            ("other admin + cli", otherAdminCLI, [true, true, true, false]),
            ("other standard user + app", otherStd, [true, false, false, false]),
            ("unauthenticated", unauth, [false, false, false, false]),
        ]
        for (label, c, want) in cells {
            for (i, level) in AuthzLevel.allCases.enumerated() {
                let allowed = IPCAuthz.denial(level, c, name: "x") == nil
                check(allowed == want[i], "hx10: matrix \(label) / \(level) -> \(want[i] ? "allow" : "deny")")
            }
        }

        // Every request: its level, and the result for every caller (each cell exercised end-to-end).
        let privileged: Set<String> = ["quarantine", "restore", "deleteQuarantined", "allow", "fixPosture", "setWebProtection",
                                       "updateSignatures", "setSettings", "setRealtime", "remediate", "addAllowRule", "removeAllowRule",
                                       "allowRemoteTool", "revokeRemoteTool", "setRemoteLockdown", "disableProtection", "requestUninstall",
                                       "uninstall", "restoreQuarantinedTo", "exportQuarantined", "sandboxRun", "requestDisableProtection"]
        let weakening: Set<String> = ["allow", "addAllowRule", "allowRemoteTool", "restore", "restoreQuarantinedTo", "exportQuarantined", "sandboxRun"]
        let reads: Set<String> = ["listDetections", "listQuarantine", "posture", "persistence", "activity", "connections", "wifi",
                                  "networkStats", "getSettings", "previewRemediation", "listAllowRules", "remoteAccessReport",
                                  "tamperStatus", "subscribeEvents", "pauseScan", "cancelScan", "webVerdict"]
        var names = Set<String>()
        for r in hx10AllRequests {
            let n = hx10Name(r); names.insert(n)
            let lv = IPCAuthz.level(r)
            if privileged.contains(n) { check(lv >= .adminClient, "hx10: \(n) needs an admin + RamPart client") }
            if weakening.contains(n) { check(lv == .adminClientWeakening, "hx10: \(n) is protection-weakening") }
            if reads.contains(n) { check(lv == .sessionUser, "hx10: \(n) hidden from other standard users") }
            if !privileged.contains(n) && !reads.contains(n) { check(lv == .anyLocal, "hx10: \(n) open to local users") }
            for (label, c, want) in cells {
                let allowed = IPCAuthz.denial(lv, c, name: n) == nil
                check(allowed == want[lv.rawValue], "hx10: \(n) for \(label)")
            }
        }
        check(names.count == 46, "hx10: every IPCRequest case sampled (\(names.count))")
        check(IPCAuthz.level(.setRealtime(on: true)) == .adminClient && IPCAuthz.level(.setRealtime(on: false)) == .adminClientWeakening,
              "hx10: turning real-time off is weakening, on is not")
        check(IPCAuthz.level(.setWebProtection(on: false)) == .adminClientWeakening && IPCAuthz.level(.setRemoteLockdown(on: false)) == .adminClientWeakening,
              "hx10: web protection / lockdown off are weakening")
        check(IPCAuthz.level(.setSettings(RampartSettings()), settingsWeakens: false) == .adminClient, "hx10: harmless settings change needs only admin + client")

        let d = RampartSettings()
        func w(_ f: (inout RampartSettings) -> Void) -> Bool { var n = d; f(&n); return IPCAuthz.settingsWeaken(old: d, new: n) }
        check(!w { _ in }, "hx10: unchanged settings do not weaken")
        check(w { $0.realtimeOn = false } && w { $0.autoQuarantine = false } && w { $0.scanArchives = false } && w { $0.notifyThreats = false },
              "hx10: protections off weaken")
        var dl = d; dl.learningMode = false
        var dl2 = dl; dl2.learningMode = true
        check(IPCAuthz.settingsWeaken(old: dl, new: dl2), "hx10: learning mode on weakens")
        check(w { $0.developerMode = true }, "hx10: developer mode on weakens")
        check(!w { $0.notifyInfo.toggle() } && !w { $0.scheduledScanHour = 3 }, "hx10: cosmetic settings do not weaken")
        var on = d; on.realtimeOn = false
        check(!IPCAuthz.settingsWeaken(old: on, new: d), "hx10: turning protection back on is not weakening")
        let msg = IPCAuthz.denial(.adminClientWeakening, ca(.cli), name: "setRealtime") ?? ""
        check(msg.contains("administrator confirmation"), "hx10: CLI weakening refusal explains the session step")
        check((IPCAuthz.denial(.adminClient, ca(nil), name: "remediate") ?? "").contains("own app or command line tool"), "hx10: unverified client refusal")
    }

    static func hx10Name(_ r: IPCRequest) -> String {
        // The enum's coding key is its case name.
        guard let d = try? JSONEncoder().encode(r), let o = try? JSONSerialization.jsonObject(with: d) else { return "?" }
        if let s = o as? String { return s }
        return (o as? [String: Any])?.keys.first ?? "?"
    }

    static func hx10ClientIdentity() {
        let good = ClientIdentity(identifier: "app.rampart.cli", teamID: nil, cdhash: "ab12", path: "/x", valid: true,
                                  hardenedRuntime: true, linkerSignedOnly: false, dangerousEntitlements: [])
        check(good.trustedKind(daemonTeamID: nil, pinnedCDHashes: nil) == .cli, "hx10: signed RamPart CLI trusted")
        var g = good; g.identifier = "app.rampart.app"
        check(g.trustedKind(daemonTeamID: nil, pinnedCDHashes: nil) == .app, "hx10: signed RamPart app trusted")
        var bad = good; bad.valid = false
        check(bad.trustedKind(daemonTeamID: nil, pinnedCDHashes: nil) == nil, "hx10: broken signature not trusted")
        bad = good; bad.hardenedRuntime = false
        check(bad.trustedKind(daemonTeamID: nil, pinnedCDHashes: nil) == nil, "hx10: no hardened runtime (DYLD injection) not trusted")
        bad = good; bad.linkerSignedOnly = true
        check(bad.trustedKind(daemonTeamID: nil, pinnedCDHashes: nil) == nil, "hx10: linker-signed build not trusted")
        bad = good; bad.dangerousEntitlements = ["com.apple.security.get-task-allow"]
        check(bad.trustedKind(daemonTeamID: nil, pinnedCDHashes: nil) == nil, "hx10: debuggable client not trusted")
        for id in ["app.rampart.cli.evil", "App.Rampart.CLI", "app.rampart.cli ", "com.evil", "", "rampart"] {
            bad = good; bad.identifier = id
            check(bad.trustedKind(daemonTeamID: nil, pinnedCDHashes: nil) == nil, "hx10: identifier '\(id)' not trusted")
        }
        check(good.trustedKind(daemonTeamID: "ABCDE12345", pinnedCDHashes: nil) == nil, "hx10: Team ID must match a signed daemon")
        var t = good; t.teamID = "ABCDE12345"
        check(t.trustedKind(daemonTeamID: "ABCDE12345", pinnedCDHashes: nil) == .cli, "hx10: matching Team ID trusted")
        check(good.trustedKind(daemonTeamID: nil, pinnedCDHashes: ["ffff"]) == nil, "hx10: cdhash not in install pins refused")
        check(good.trustedKind(daemonTeamID: nil, pinnedCDHashes: ["ab12"]) == .cli, "hx10: pinned cdhash trusted")

        // Real kernel audit token over a socketpair: identity of this (untrusted) self-test binary.
        var sv: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) == 0 else { check(false, "hx10: socketpair"); return }
        defer { close(sv[0]); close(sv[1]) }
        var tok = audit_token_t(); var len = socklen_t(MemoryLayout<audit_token_t>.size)
        check(getsockopt(sv[0], SOL_LOCAL, LOCAL_PEERTOKEN, &tok, &len) == 0, "hx10: LOCAL_PEERTOKEN available")
        check(pid_t(bitPattern: tok.val.5) == getpid(), "hx10: audit token carries the peer pid")
        let me = ClientIdentity.of(auditToken: tok)
        check(me != nil && me?.cdhash.isEmpty == false, "hx10: code identity read through the audit token")
        check(me?.trustedKind(daemonTeamID: nil, pinnedCDHashes: nil) == nil, "hx10: the self-test binary is not a trusted RamPart client")
        var stale = tok; stale.val.7 &+= 1   // pidversion of an exec'd / reused pid
        check(ClientIdentity.of(auditToken: stale) == nil, "hx10: stale audit token (pid reuse / exec) gives no identity")

        // Pins file: ignored unless root-owned and not group/other-writable.
        let dir = NSTemporaryDirectory() + "hx10-pins-\(getpid())"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let pins = dir + "/trusted-clients.json"
        FileManager.default.createFile(atPath: pins, contents: Data(#"["AB12"]"#.utf8))
        check(ClientIdentity.loadPins(pins) == (getuid() == 0 ? ["ab12"] : nil), "hx10: user-owned pins file ignored")
        symlink(pins, dir + "/link.json")
        check(ClientIdentity.loadPins(dir + "/link.json") == nil, "hx10: symlinked pins file ignored")
    }

    static func hx10Forwarded() {
        let me = getuid()
        let mine = ProcessInfoLite(pid: getpid(), ppid: 1, path: "/x", uid: 0, signingID: "com.apple.Safari", teamID: "APPLE", isPlatformBinary: true)
        let e = SecurityEvent(kind: .other, process: mine, detail: ["type": "clipboard"], source: "pasteguard")
        let s = IPCAuthz.sanitizeForwarded(e, peerUID: me)
        check(s != nil && s?.process?.uid == me && s?.process?.isPlatformBinary == false && s?.process?.signingID == nil,
              "hx10: forwarded own process kept, claimed signing facts dropped")
        let launchd = ProcessInfoLite(pid: 1, ppid: 0, path: "/sbin/launchd", uid: me)
        check(me == 0 || IPCAuthz.sanitizeForwarded(SecurityEvent(kind: .exec, process: launchd, source: "session"), peerUID: me) == nil,
              "hx10: forwarded event naming another user's process dropped")
        check(IPCAuthz.sanitizeForwarded(SecurityEvent(kind: .exec, process: ProcessInfoLite(pid: 99_999_999, ppid: 1, path: "/x"), source: "s"), peerUID: me) == nil,
              "hx10: forwarded event for a nonexistent pid dropped")
        check(me == 0 || IPCAuthz.sanitizeForwarded(SecurityEvent(kind: .fileCreate, path: "/private/etc/hosts", source: "s"), peerUID: me) == nil,
              "hx10: forwarded event naming a root-owned file dropped")
        let own = NSTemporaryDirectory() + "hx10-own-\(getpid())"
        FileManager.default.createFile(atPath: own, contents: Data())
        defer { unlink(own) }
        check(IPCAuthz.sanitizeForwarded(SecurityEvent(kind: .fileCreate, path: own, source: "s"), peerUID: me) != nil, "hx10: forwarded event on own file kept")
        var flood: [String: String] = ["ok": "1"]; flood[String(repeating: "k", count: 100)] = "x"; flood["big"] = String(repeating: "v", count: 5000)
        check(IPCAuthz.sanitizeForwarded(SecurityEvent(kind: .other, detail: flood, source: "s"), peerUID: me)?.detail.count == 1,
              "hx10: oversized forwarded detail fields dropped")
        check(IPCAuthz.sanitizeForwarded(SecurityEvent(kind: .exec, process: launchd, source: "s"), peerUID: 0) != nil, "hx10: root peer events untouched")
    }

    static func hx10Posture() {
        for id in ["firewall", "stealthMode", "guestAccount", "remoteLogin", "autoUpdates"] {
            check(IPCAuthz.isValidCheckID(id), "hx10: check id \(id) valid")
            check(PostureFixer.fix(for: id).map(PostureFixer.isSafe) == true, "hx10: built-in fix \(id) passes the safety gate")
        }
        for id in ["firewall; rm -rf /", "$(id)", "`id`", "firewall\n", "", String(repeating: "a", count: 41), "fírewall", "../firewall", "fire wall"] {
            check(!IPCAuthz.isValidCheckID(id) || !PostureFixer.canFix(id), "hx10: hostile check id refused: \(id.debugDescription)")
            check(PostureFixer.fix(for: id) == nil, "hx10: no fix for \(id.debugDescription)")
        }
        check(PostureFixer.fix(for: "Firewall") == nil && PostureFixer.fix(for: "firewall ") == nil, "hx10: check ids match exactly")
        var f = PostureFixer.fix(for: "firewall")!
        f.commands = [["/bin/sh", "-c", "id"]]
        check(!PostureFixer.isSafe(f), "hx10: shell command refused")
        f = PostureFixer.fix(for: "firewall")!; f.commands[0].append("on;id")
        check(!PostureFixer.isSafe(f), "hx10: metacharacter argument refused")
        f = PostureFixer.fix(for: "firewall")!; f.commands[0][1] = "--set globalstate"
        check(!PostureFixer.isSafe(f), "hx10: argument with a space refused")
        f = PostureFixer.fix(for: "firewall")!; f.revertCommands = [["/usr/bin/curl", "x"]]
        check(!PostureFixer.isSafe(f), "hx10: revert command outside the allow-list refused")
        f = PostureFixer.fix(for: "firewall")!; f.commands = []
        check(!PostureFixer.isSafe(f), "hx10: empty fix refused")
        f = PostureFixer.fix(for: "firewall")!; f.checkID = "evil"
        check(!PostureFixer.isSafe(f), "hx10: fix for an unknown check refused")
        check(PostureFixer.fix(for: "firewall")?.dryRun == true, "hx10: fixes default to dry run")
    }

    static func hx10Session() {
        check(IPCAuthz.sameProcess(ownerPID: 900, ownerVersion: 7, pid: 900, version: 7), "hx10: session for the redeeming process")
        check(!IPCAuthz.sameProcess(ownerPID: 900, ownerVersion: 7, pid: 900, version: 8), "hx10: session not inherited by a reused pid")
        check(!IPCAuthz.sameProcess(ownerPID: 900, ownerVersion: 7, pid: 901, version: 7), "hx10: session not usable by another process of the user")
        check(!IPCAuthz.sameProcess(ownerPID: 0, ownerVersion: nil, pid: 0, version: nil), "hx10: no session for pid 0")

        // Settings-session token: single use, uid-bound, expiry, replay, forgery, purpose.
        let key = IntegrityKey(data: Data((0..<32).map { UInt8($0) }))
        final class Clock: @unchecked Sendable { var now = Date() }
        let clock = Clock()
        let flow = ProtectionDisableFlow(key: key, clock: GuardClock(now: { clock.now }))
        func failure(_ r: Result<Void, ProtectionDisableFlow.Failure>) -> ProtectionDisableFlow.Failure? { if case .failure(let f) = r { return f }; return nil }
        guard case .success(let tok) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) else { check(false, "hx10: token"); return }
        check(failure(flow.redeem(tok, peerUID: 502, purpose: .settings)) == .tokenForOtherUser, "hx10: settings token bound to uid")
        check(failure(flow.redeem(tok, peerUID: 501, purpose: .settings, sessionSeconds: 600)) == nil, "hx10: right uid redeems after a wrong-uid try")
        check(flow.hasActiveSession(uid: 501, purpose: .settings) && !flow.hasActiveSession(uid: 501, purpose: .pause), "hx10: session purpose recorded")
        check(failure(flow.redeem(tok, peerUID: 501, purpose: .settings)) == .tokenInvalid, "hx10: settings token replay refused")
        var parts = tok.split(separator: ".").map(String.init); parts[1] = "0"
        check(failure(flow.redeem(parts.joined(separator: "."), peerUID: 0, purpose: .settings)) == .tokenInvalid, "hx10: token re-bound to root refused (MAC)")
        guard case .success(let t2) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) else { return }
        clock.now = clock.now.addingTimeInterval(flow.tokenTTL + 1)
        check(failure(flow.redeem(t2, peerUID: 501, purpose: .settings)) == .tokenExpired, "hx10: expired settings token refused")
        check(failure(flow.redeem(t2, peerUID: 501, purpose: .settings)) == .tokenInvalid, "hx10: expired token consumed")
        clock.now = clock.now.addingTimeInterval(601)
        check(!flow.hasActiveSession(uid: 501, purpose: .settings), "hx10: settings session expires")
        check(flow.issueToken(peerUID: 501, isAdmin: false, authorizationOK: true) == .failure(.notAdmin), "hx10: non-admin gets no token")
        check(failure(flow.redeem("", peerUID: 501)) == .tokenInvalid && failure(flow.redeem("a.b.c.d", peerUID: 501)) == .tokenInvalid,
              "hx10: malformed tokens refused")
    }

    static func hx10Store() {
        let dir = NSTemporaryDirectory() + "hx10-store-\(getpid())"
        let fm = FileManager.default
        try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: dir) }
        func mode(_ p: String) -> mode_t { var s = stat(); return lstat(p, &s) == 0 ? s.st_mode & 0o7777 : 0o7777 }
        let target = URL(fileURLWithPath: dir + "/detections.json")
        let old = umask(0); defer { umask(old) }
        check((try? SecureStore.writeJSON(["a": 1], to: target)) != nil, "hx10: secure write")
        check(mode(target.path) == 0o600, "hx10: store file 0600 even with umask 0")
        check((try? SecureStore.writeJSON(["a": 1], to: URL(fileURLWithPath: dir + "/config.json"), mode: 0o644)) != nil && mode(dir + "/config.json") == 0o644,
              "hx10: config keeps its declared mode")
        // A planted symlink at the target is replaced, never followed.
        let victim = dir + "/victim"
        fm.createFile(atPath: victim, contents: Data("keep".utf8))
        let link = URL(fileURLWithPath: dir + "/state.json")
        symlink(victim, link.path)
        check(SecureStore.read(link) == nil, "hx10: store read refuses a symlink")
        try? SecureStore.write(Data("new".utf8), to: link)
        check(fm.contents(atPath: victim) == Data("keep".utf8), "hx10: write through planted symlink did not touch the victim")
        var st = stat(); lstat(link.path, &st)
        check((st.st_mode & S_IFMT) == S_IFREG, "hx10: symlink replaced by a regular file")
        // Loose permissions from an older version are tightened on read.
        let loose = dir + "/activity.jsonl"
        fm.createFile(atPath: loose, contents: Data("{}".utf8), attributes: [.posixPermissions: 0o666])
        check(SecureStore.read(URL(fileURLWithPath: loose)) == Data("{}".utf8) && mode(loose) == 0o600, "hx10: loose store file tightened to 0600")
        check(SecureStore.read(URL(fileURLWithPath: dir)) == nil, "hx10: directory is not read as a store file")
        let leftovers = ((try? fm.contentsOfDirectory(atPath: dir)) ?? []).filter { $0.contains(".tmp-") }
        check(leftovers.isEmpty, "hx10: no temp files left behind")
        check((try? SecureStore.write(Data(), to: URL(fileURLWithPath: dir + "/missing/x.json"))) == nil, "hx10: write into a missing folder fails cleanly")
    }

    static func hx10Redaction() {
        let forged = LogRedact.clean("ok\n2026-11-07T00:00:00Z [info] protection disabled by admin\r")
        check(!forged.contains("\n") && !forged.contains("\r"), "hx10: no forged log lines")
        check(!LogRedact.clean("invoice\u{202E}fdp.exe").unicodeScalars.contains { $0.value == 0x202E }, "hx10: bidi override removed")
        check(!LogRedact.clean("a\u{200B}b\u{0007}c\u{2028}").unicodeScalars.contains { [0x200B, 0x7, 0x2028].contains($0.value) }, "hx10: invisible and control characters removed")
        let long = LogRedact.clean(String(repeating: "x", count: 10_000), max: 100)
        check(long.count <= 101, "hx10: length capped")
        let nonce = String(repeating: "0123456789abcdef", count: 2)
        let tok = "\(nonce).501.1762500000.\(String(repeating: "Zm9v", count: 10))"
        check(!LogRedact.clean("redeem \(tok) now").contains(nonce), "hx10: disable token redacted")
        check(!LogRedact.clean("password=hunter2 rest").contains("hunter2"), "hx10: password redacted")
        check(!LogRedact.clean("Authorization: Bearer abc.def.ghi").contains("abc.def"), "hx10: bearer token redacted")
        check(!LogRedact.clean("key AIzaSyA1234567890abcdefghijKLMNOP").contains("AIzaSyA1234567890"), "hx10: API key redacted")
        let sha = String(repeating: "ab", count: 32)
        check(LogRedact.clean("allowed \(sha)").contains(sha), "hx10: SHA-256 kept (user needs it)")
        check(LogRedact.clean("Scan finished: 3 threats in /Users/a/Downloads") == "Scan finished: 3 threats in /Users/a/Downloads", "hx10: ordinary text unchanged")
        check(LogRedact.clean("Ünïcödé 名前 ok") == "Ünïcödé 名前 ok", "hx10: ordinary Unicode kept")
    }
}

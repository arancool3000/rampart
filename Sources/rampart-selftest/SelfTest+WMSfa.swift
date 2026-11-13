import Foundation
import RampartShared
import RampartNetwork
import RampartVPN

// wms-fa: privilege boundaries and cross-component chains (root daemon <-> user helper <-> app <-> CLI <-> nmh).
// Property-style checks over IPCAuthz (symlinked from rampartd) plus source invariants for the parts of the daemon
// that rampart-selftest cannot link (Router, IPCServer).
extension SelfTest {
    static func wmsFaChecks() {
        wmsFaEveryRequestHasALevel()
        wmsFaWeakeningOps()
        wmsFaUserModeMatrix()
        wmsFaForwarding()
        wmsFaPeerPolicy()
        wmsFaSourceInvariants()
    }

    /// One sample per IPCRequest case (two for on/off style cases). Kept in sync with Models.swift by the test below.
    static var wmsFaSamples: [IPCRequest] {
        let u = UUID()
        let ng = { (op: NetGuardCommand.Op) in NetGuardCommand(op: op, key: "k").encoded() }
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
                .sandboxRun(id: u, confirmation: "x"),
                .emergencyStatus, .emergencyLockdown(reason: "r"), .emergencyRescan, .liftEmergencyLockdown(token: "t", force: false),
                .emergencyAck(actionIDs: []), .emergencyNetwork(keep: true, token: nil), .emergencyNetwork(keep: false, token: nil),
                .killSwitch(token: nil), .checkURLChain(url: "https://a.test"),
                .deceptionStatus, .deceptionSetDecoys(on: true), .deceptionSetDecoys(on: false), .deceptionSetMaze(on: true),
                .deceptionSetMaze(on: false), .deceptionRemoveAll, .deceptionSetTarpit(on: true, port: 2222, scope: "loopback"),
                .deceptionSetTone(serious: true), .deceptionEvidence(catchID: u), .deceptionSetDecoysVisible(visible: true),
                .deceptionContain(catchID: u),
                .vpn(op: "status", body: nil), .vpn(op: "connect", body: nil), .vpn(op: "disconnect", body: nil),
                .vpn(op: "importConfig", body: nil), .vpn(op: "setupHome", body: nil), .vpn(op: "setOptions", body: nil),
                .vpn(op: "remove", body: nil), .vpn(op: "bogus", body: nil),
                .netGuard(ng(.classifyHosts)), .netGuard(ng(.status)), .netGuard(ng(.filterSet)), .netGuard(ng(.firewallForget)),
                .downloadGateStatus, .downloadGateSetEnabled(on: true), .downloadGateSetEnabled(on: false),
                .downloadGateDecide(id: u, allow: true), .downloadGateDecide(id: u, allow: false),
                .mediaGuardStatus, .mediaGuardSetEnabled(on: true), .mediaGuardSetEnabled(on: false),
                .mediaGuardTrust(appID: "a", trusted: true), .mediaGuardTrust(appID: "a", trusted: false),
                .mediaGuardStop(appID: "a"), .mediaGuardSetTone(serious: true)]
    }

    /// Case names declared in the IPCRequest enum (parsed from the shared contract's source).
    static func wmsFaDeclaredCases() -> Set<String> {
        guard let src = try? String(contentsOfFile: repoRoot + "/Sources/RampartShared/Models.swift", encoding: .utf8),
              let start = src.range(of: "public enum IPCRequest"), let end = src.range(of: "public enum IPCResponse") else { return [] }
        var out = Set<String>()
        for line in src[start.upperBound..<end.lowerBound].split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard t.hasPrefix("case ") else { continue }
            let name = t.dropFirst(5).prefix { $0.isLetter || $0.isNumber || $0 == "_" }
            if !name.isEmpty { out.insert(String(name)) }
        }
        return out
    }

    static func wmsFaEveryRequestHasALevel() {
        typealias C = AuthzCaller
        let declared = wmsFaDeclaredCases()
        let sampled = Set(wmsFaSamples.map(hx10Name))
        check(declared.count >= 70, "fa: IPCRequest cases parsed from Models.swift (\(declared.count))")
        check(declared.subtracting(sampled).isEmpty, "fa: every IPCRequest case has an authz sample (missing: \(declared.subtracting(sampled).sorted()))")
        check(sampled.subtracting(declared).isEmpty, "fa: no stale samples (\(sampled.subtracting(declared).sorted()))")

        // Every sample resolves to an explicit level (the switch is exhaustive; this pins the runtime value too), and
        // the matrix is monotone: a column allowed at a level is allowed at every lower level.
        let root = C(uid: 0, isAdmin: true, isConsole: false, client: nil)
        let unauth = C(credentialed: false, uid: 501, isAdmin: true, isConsole: true, client: .app)
        let app = C(uid: 501, isAdmin: true, isConsole: true, client: .app)
        let cli = C(uid: 501, isAdmin: true, isConsole: true, client: .cli)
        let cliSession = C(uid: 501, isAdmin: true, isConsole: true, client: .cli, hasSettingsSession: true)
        let script = C(uid: 501, isAdmin: true, isConsole: true, client: nil)
        let nmh = C(uid: 501, isAdmin: true, isConsole: true, client: .nmh)
        let consoleStd = C(uid: 502, isAdmin: false, isConsole: true, client: .app)
        let otherStd = C(uid: 504, isAdmin: false, isConsole: false, client: .app)
        let columns = [("root", root), ("app", app), ("cli", cli), ("cli+session", cliSession), ("script", script), ("nmh", nmh),
                       ("console standard", consoleStd), ("other standard", otherStd), ("unauthenticated", unauth)]
        for r in wmsFaSamples {
            let n = hx10Name(r)
            let lv = IPCAuthz.level(r)
            check(AuthzLevel.allCases.contains(lv), "fa: \(n) has an explicit level")
            for (label, c) in columns {
                let allowed = IPCAuthz.denial(lv, c, name: n) == nil
                for lower in AuthzLevel.allCases where lower < lv {
                    if allowed { check(IPCAuthz.denial(lower, c, name: n) == nil, "fa: matrix monotone for \(n) / \(label)") }
                }
                if label == "unauthenticated" { check(!allowed, "fa: \(n) refused without peer credentials") }
                if label == "root" { check(allowed, "fa: \(n) allowed for root") }
                if lv >= .adminClient {
                    check(label != "script" || !allowed, "fa: \(n) refused from an unverified client")
                    check(label != "nmh" || !allowed, "fa: \(n) refused from the native messaging host")
                    check(label != "console standard" || !allowed, "fa: \(n) refused for a standard user")
                }
                if lv >= .sessionUser { check(label != "other standard" || !allowed, "fa: \(n) hidden from other standard users") }
                if lv == .adminClientWeakening { check(label != "cli" || !allowed, "fa: \(n) from the CLI needs an admin-confirmed session") }
            }
        }
    }

    /// Weakening operations: every "off / allow / restore / remove / disconnect" direction is adminClientWeakening,
    /// and the matching "on / block / keep" direction is never stricter than it.
    static func wmsFaWeakeningOps() {
        let u = UUID()
        let pairs: [(String, IPCRequest, IPCRequest)] = [
            ("setRealtime", .setRealtime(on: true), .setRealtime(on: false)),
            ("setWebProtection", .setWebProtection(on: true), .setWebProtection(on: false)),
            ("setRemoteLockdown", .setRemoteLockdown(on: true), .setRemoteLockdown(on: false)),
            ("downloadGateSetEnabled", .downloadGateSetEnabled(on: true), .downloadGateSetEnabled(on: false)),
            ("downloadGateDecide", .downloadGateDecide(id: u, allow: false), .downloadGateDecide(id: u, allow: true)),
            ("mediaGuardSetEnabled", .mediaGuardSetEnabled(on: true), .mediaGuardSetEnabled(on: false)),
            ("mediaGuardTrust", .mediaGuardTrust(appID: "a", trusted: false), .mediaGuardTrust(appID: "a", trusted: true)),
            ("deceptionSetDecoys", .deceptionSetDecoys(on: true), .deceptionSetDecoys(on: false)),
            ("deceptionSetMaze", .deceptionSetMaze(on: true), .deceptionSetMaze(on: false)),
            ("vpn connect/disconnect", .vpn(op: "connect", body: nil), .vpn(op: "disconnect", body: nil)),
        ]
        for (n, on, off) in pairs {
            check(IPCAuthz.level(off) == .adminClientWeakening, "fa: \(n) off is weakening")
            check(IPCAuthz.level(on) <= IPCAuthz.level(off) && IPCAuthz.level(on) >= .adminClient, "fa: \(n) on needs admin + client, not stricter than off")
        }
        let alwaysWeakening: [(String, IPCRequest)] = [
            ("allow", .allow(sha256: "a")), ("addAllowRule", .addAllowRule(AllowRuleSpec(scope: .fileHash, value: "b", name: "t"))),
            ("allowRemoteTool", .allowRemoteTool(id: "x", minutes: nil)), ("restore", .restore(id: u, allow: false)),
            ("restoreQuarantinedTo", .restoreQuarantinedTo(id: u, path: "/x", allow: false)), ("exportQuarantined", .exportQuarantined(id: u, path: "/x")),
            ("sandboxRun", .sandboxRun(id: u, confirmation: "x")), ("liftEmergencyLockdown", .liftEmergencyLockdown(token: "t", force: true)),
            ("deceptionRemoveAll", .deceptionRemoveAll), ("vpn importConfig", .vpn(op: "importConfig", body: nil)),
            ("vpn setupHome", .vpn(op: "setupHome", body: nil)), ("vpn setOptions", .vpn(op: "setOptions", body: nil)),
            ("vpn remove", .vpn(op: "remove", body: nil)), ("vpn unknown op", .vpn(op: "bogus", body: nil)),
            ("setSettings (weakening)", .setSettings(RampartSettings())),
        ]
        for (n, r) in alwaysWeakening { check(IPCAuthz.level(r) == .adminClientWeakening, "fa: \(n) is weakening") }
        // RampartVPN's own op list agrees with the matrix (a new op added there lands on the strictest level).
        for op in VPNOp.allCases {
            let want: AuthzLevel = op.readOnly ? .sessionUser : op == .connect ? .adminClient : .adminClientWeakening
            check(IPCAuthz.level(.vpn(op: op.rawValue, body: nil)) == want, "fa: vpn.\(op.rawValue) -> \(want)")
            if op.weakens { check(want == .adminClientWeakening, "fa: vpn.\(op.rawValue) flagged weakening by RampartVPN is weakening here") }
        }
        // Chain closed: malware running the real CLI cannot import its own WireGuard endpoint without the admin prompt.
        let cli = AuthzCaller(uid: 501, isAdmin: true, isConsole: true, client: .cli)
        check(IPCAuthz.denial(IPCAuthz.level(.vpn(op: "importConfig", body: nil)), cli, name: "vpn") != nil, "fa: CLI cannot import a VPN config without confirmation")
        // Keep-blocking makes a temporary network block permanent: own clients only now.
        let script = AuthzCaller(uid: 501, isAdmin: true, isConsole: true, client: nil)
        check(IPCAuthz.denial(IPCAuthz.level(.emergencyNetwork(keep: true, token: nil)), script, name: "x") != nil, "fa: a script cannot make a network block permanent")
        check(IPCAuthz.level(.emergencyNetwork(keep: true, token: nil)) == .adminClient, "fa: keep blocking is adminClient")
        // Exclusions hide files from the scanner: adding one weakens, removing one does not.
        let d = RampartSettings()
        var ex = d; ex.exclusions = ["/Users/x/Downloads/drop"]
        check(IPCAuthz.settingsWeaken(old: d, new: ex), "fa: a new exclusion weakens")
        check(!IPCAuthz.settingsWeaken(old: ex, new: d), "fa: removing an exclusion does not weaken")
        check(!IPCAuthz.settingsWeaken(old: ex, new: ex), "fa: unchanged exclusions do not weaken")
        check(IPCAuthz.denial(IPCAuthz.level(.setSettings(ex), settingsWeakens: IPCAuthz.settingsWeaken(old: d, new: ex)), cli, name: "setSettings") != nil,
              "fa: CLI needs confirmation to add an exclusion")
    }

    /// The user-session helper (wms-fa): same-uid peers only, but privileged calls need RamPart's own app or CLI.
    static func wmsFaUserModeMatrix() {
        typealias C = AuthzCaller
        func cell(_ c: C, _ lv: AuthzLevel) -> Bool { IPCAuthz.denial(lv, c, name: "x", userMode: true) == nil }
        let std = { (k: RampartClientKind?, s: Bool) in C(uid: 502, isAdmin: false, isConsole: true, client: k, hasSettingsSession: s) }
        let cells: [(String, C, [Bool])] = [
            ("root", C(uid: 0, isAdmin: true, isConsole: false, client: nil), [true, true, true, true]),
            ("owner (standard user) + app", std(.app, false), [true, true, true, true]),
            ("owner + cli", std(.cli, false), [true, true, true, false]),
            ("owner + cli + session", std(.cli, true), [true, true, true, true]),
            ("owner + script", std(nil, false), [true, true, false, false]),
            ("owner + script + session", std(nil, true), [true, true, false, false]),
            ("owner + nmh", std(.nmh, false), [true, true, false, false]),
            ("owner + daemon id", std(.daemon, false), [true, true, false, false]),
            ("unauthenticated", C(credentialed: false, uid: 502, isAdmin: false, isConsole: true, client: .app), [false, false, false, false]),
        ]
        for (label, c, want) in cells {
            for (i, lv) in AuthzLevel.allCases.enumerated() { check(cell(c, lv) == want[i], "fa: user-mode matrix \(label) / \(lv) -> \(want[i] ? "allow" : "deny")") }
        }
        // The chain this closes: a same-user script turning the user's protections off in the helper.
        for r in [IPCRequest.downloadGateSetEnabled(on: false), .downloadGateDecide(id: UUID(), allow: true), .mediaGuardSetEnabled(on: false),
                  .deceptionRemoveAll, .setRealtime(on: false), .restore(id: UUID(), allow: true), .exportQuarantined(id: UUID(), path: "/x"),
                  .requestDisableProtection(authorization: nil, reason: ""), .disableProtection(token: "t", minutes: 0), .vpn(op: "disconnect", body: nil)] {
            check(!cell(std(nil, false), IPCAuthz.level(r)), "fa: user helper refuses \(hx10Name(r)) from a script")
            check(cell(std(.app, false), IPCAuthz.level(r)), "fa: user helper accepts \(hx10Name(r)) from the app")
        }
        // Reads and the nmh's calls keep working for same-uid processes.
        for r in [IPCRequest.status, .webLookup(host: "a"), .webVerdict(url: "u", verdict: "v", score: 1, headline: "h"), .scan(paths: [], quick: true),
                  .netGuard(NetGuardCommand(op: .classifyHosts, hosts: ["a"]).encoded()), .listDetections, .subscribeEvents] {
            check(cell(std(nil, false), IPCAuthz.level(r)), "fa: user helper still answers \(hx10Name(r)) for any same-uid process")
        }

        // Enforcement switch: only a packaged helper checks clients; this development binary does not.
        let packaged = ClientIdentity(identifier: Product.bundlePrefix + ".daemon", teamID: nil, cdhash: "ab", path: "/x", valid: true,
                                      hardenedRuntime: true, linkerSignedOnly: false, dangerousEntitlements: [])
        check(IPCAuthz.userModeClientChecks(selfIdentity: packaged), "fa: packaged helper enforces client checks")
        check(!IPCAuthz.userModeClientChecks(selfIdentity: nil), "fa: unsigned helper does not")
        var v = packaged; v.linkerSignedOnly = true
        check(!IPCAuthz.userModeClientChecks(selfIdentity: v), "fa: linker-signed dev helper does not")
        v = packaged; v.hardenedRuntime = false
        check(!IPCAuthz.userModeClientChecks(selfIdentity: v), "fa: non-hardened helper does not")
        v = packaged; v.identifier = Product.bundlePrefix + ".app"
        check(!IPCAuthz.userModeClientChecks(selfIdentity: v), "fa: only the daemon identifier counts")
        v = packaged; v.dangerousEntitlements = ["com.apple.security.get-task-allow"]
        check(!IPCAuthz.userModeClientChecks(selfIdentity: v), "fa: debuggable helper does not")
        check(!IPCAuthz.userModeClientChecks(selfIdentity: ClientIdentity.ofSelf()), "fa: the self-test binary is a development build")

        // Sibling pins: nothing outside a bundle; inside one, the cdhashes of a verifying app / CLI only.
        check(IPCAuthz.siblingClientPins(executable: "/usr/bin/true") == nil, "fa: no pins outside an app bundle")
        let dir = NSTemporaryDirectory() + "wmsfa-bundle-\(getpid())/Fake.app/Contents"
        try? FileManager.default.createDirectory(atPath: dir + "/Helpers", withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(atPath: dir + "/MacOS", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: NSTemporaryDirectory() + "wmsfa-bundle-\(getpid())") }
        check(IPCAuthz.siblingClientPins(executable: dir + "/Helpers/rampartd") == nil, "fa: no pins when no sibling exists")
        let me = CommandLine.arguments[0].hasPrefix("/") ? CommandLine.arguments[0] : (Bundle.main.executablePath ?? "")
        try? FileManager.default.copyItem(atPath: me, toPath: dir + "/Helpers/rampart")
        try? FileManager.default.copyItem(atPath: me, toPath: dir + "/MacOS/\(Product.name)")
        // A copy of this (unverified, linker-signed) binary never becomes a pin: trustedKind must say app / cli first.
        check(IPCAuthz.siblingClientPins(executable: dir + "/Helpers/rampartd") == nil, "fa: unverified siblings are not pinned")
        check(ClientIdentity.ofFile(me) != nil && ClientIdentity.ofFile(me)?.cdhash.isEmpty == false, "fa: ofFile reads a static identity")
        symlink(me, dir + "/MacOS/link")
        check(ClientIdentity.ofFile(dir + "/MacOS/link") == nil, "fa: ofFile refuses a symlink")
    }

    /// forwardEvents: who may inject telemetry, and what the kernel overrides in it.
    static func wmsFaForwarding() {
        check(IPCAuthz.forwardDenial(peerUID: 0, client: nil, clientChecks: true) == nil, "fa: root may forward")
        check(IPCAuthz.forwardDenial(peerUID: 501, client: .app, clientChecks: true) == nil, "fa: the app may forward (PasteGuard)")
        check(IPCAuthz.forwardDenial(peerUID: 501, client: .daemon, clientChecks: true) == nil, "fa: a RamPart service may forward")
        check(IPCAuthz.forwardDenial(peerUID: 501, client: nil, clientChecks: true) != nil, "fa: a script may not forward telemetry")
        check(IPCAuthz.forwardDenial(peerUID: 501, client: .nmh, clientChecks: true) != nil, "fa: the nmh may not forward telemetry")
        check(IPCAuthz.forwardDenial(peerUID: 501, client: nil, clientChecks: false) == nil, "fa: development helper unchanged")

        guard getuid() != 0 else { return }
        let me = getuid()
        let forged = ProcessInfoLite(pid: getpid(), ppid: 1, path: "/Applications/Safari.app/Contents/MacOS/Safari", uid: 0,
                                     signingID: "com.apple.Safari", teamID: "APPLE", isPlatformBinary: true)
        let s = IPCAuthz.sanitizeForwarded(SecurityEvent(kind: .exec, process: forged, source: "session"), peerUID: me)
        let real = IPCAuthz.executablePath(pid: getpid()) ?? ""
        check(s?.process?.path == real && !real.isEmpty, "fa: forged image path replaced by the kernel's (\(s?.process?.path ?? "nil"))")
        check(s?.process?.ppid == getppid(), "fa: forged parent replaced by the kernel's")
        check(s?.process?.uid == me && s?.process?.isPlatformBinary == false && s?.process?.signingID == nil, "fa: forged signing facts cleared")
        check(IPCAuthz.sanitizeForwarded(SecurityEvent(kind: .exec, process: ProcessInfoLite(pid: 1, ppid: 0, path: "/sbin/launchd", uid: me), source: "s"), peerUID: me) == nil,
              "fa: event about another user's process dropped")
        check(IPCAuthz.procFacts(pid: getpid())?.ppid == getppid() && IPCAuthz.procFacts(pid: 0) == nil, "fa: procFacts")
    }

    /// Which daemon identities a client accepts behind the socket.
    static func wmsFaPeerPolicy() {
        let daemon = Product.bundlePrefix + ".daemon"
        for selfID in [Product.bundlePrefix + ".cli", Product.bundlePrefix + ".nmh", Product.bundlePrefix + ".app"] {
            check(DaemonPeerPolicy.daemonIdentifierAcceptable(daemon, selfIdentifier: selfID, peerHardened: true), "fa: packaged \(selfID) accepts the packaged daemon")
            check(!DaemonPeerPolicy.daemonIdentifierAcceptable(daemon, selfIdentifier: selfID, peerHardened: false), "fa: packaged \(selfID) wants a hardened daemon")
            for dev in ["rampartd", "rampartd-abc123"] {
                check(!DaemonPeerPolicy.daemonIdentifierAcceptable(dev, selfIdentifier: selfID, peerHardened: true), "fa: packaged \(selfID) refuses dev identifier \(dev)")
            }
        }
        for selfID in ["rampart-abc", "rampart-selftest-1", nil] {
            check(DaemonPeerPolicy.daemonIdentifierAcceptable("rampartd-abc", selfIdentifier: selfID, peerHardened: false), "fa: dev client accepts a dev daemon")
            check(DaemonPeerPolicy.daemonIdentifierAcceptable(daemon, selfIdentifier: selfID, peerHardened: false), "fa: dev client accepts the packaged daemon")
        }
        for bad in [daemon + ".evil", Product.bundlePrefix + ".cli", "evil-rampartd", "rampartd evil", "", "Rampartd"] {
            check(!DaemonPeerPolicy.daemonIdentifierAcceptable(bad, selfIdentifier: nil, peerHardened: true), "fa: identifier '\(bad)' refused")
        }
        check(DaemonPeerPolicy.selfIdentifier?.hasPrefix(Product.bundlePrefix + ".") != true, "fa: the self-test is not a packaged client")
    }

    static func wmsFaSourceInvariants() {
        func read(_ rel: String) -> String { (try? String(contentsOfFile: repoRoot + "/" + rel, encoding: .utf8)) ?? "" }
        let router = read("Sources/rampartd/Core/Router.swift"), server = read("Sources/rampartd/IPCServer.swift")
        check(router.contains("IPCAuthz.forwardDenial(peerUID: peer.uid, client: peer.client, clientChecks: requireAdminForPrivileged || userModeClientChecks)"),
              "fa: Router gates forwardEvents on client identity")
        check(router.contains("authorizationDenial(req, peer: peer, userMode: true)"), "fa: Router applies the user-mode matrix")
        check(server.contains("userModeClientChecks: userMode && Self.userModeClientChecks"), "fa: IPCServer passes the user-mode switch")
        check(server.contains("if !userMode || Self.userModeClientChecks, let id = ClientIdentity.of(auditToken: token)"), "fa: IPCServer reads client identity in user mode")
        check(server.contains("userMode ? Self.userModePins"), "fa: user helper pins its bundle's app and CLI")
        check(read("Sources/rampart-nmh/main.swift").contains("DaemonPeerPolicy.connectedPeerProblem(fd: fd, path: path) == nil"), "fa: nmh verifies the daemon behind the socket")
        check(read("Sources/rampart/Client.swift").contains("DaemonPeerPolicy.connectedPeerProblem(fd: fd, path: path)"), "fa: CLI verifies the daemon behind the socket")
        check(read("Sources/RampartBrowser/Engine/BrowserDaemonClient.swift").contains("DaemonPeerPolicy.connectedPeerProblem(fd: fd, path: path)"), "fa: browser verifies the daemon")
        check(!router.contains("requireAdminForPrivileged: false, send:"), "fa: no in-daemon bypass of the matrix")
        check(read("Sources/RampartShared/DaemonPeerPolicy.swift").contains("daemonIdentifierAcceptable(ident, selfIdentifier: selfIdentifier, peerHardened:"),
              "fa: peerLooksLikeDaemon uses the identifier policy")
    }
}

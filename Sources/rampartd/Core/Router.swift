import Foundation
import RampartShared
import RampartPosture
import RampartGuard

/// Identity of the IPC caller (from getpeereid), or the local process in CLI --local mode.
struct Peer {
    var uid: uid_t
    var gid: gid_t
    var pid: pid_t
    /// Kernel audit token of the connecting process (LOCAL_PEERTOKEN); pins pid + pidversion, so a reused pid
    /// or an exec after connecting never inherits this connection's identity.
    var auditToken: audit_token_t? = nil
    /// Verified RamPart client behind the connection (root daemon only; nil = not one of ours).
    var client: RampartClientKind? = nil
    var isAdmin: Bool { Util.isAdmin(uid: uid) }
    var pidVersion: UInt32? { auditToken.map { $0.val.7 } }
    static var local: Peer { Peer(uid: getuid(), gid: getgid(), pid: getpid()) }
}

enum RouteResult { case done, keepOpen(UUID) }

/// Maps every IPCRequest to an action. `send` returns false when the peer went away.
final class Router {
    let p: Protection
    init(_ p: Protection) { self.p = p }

    static func isPrivileged(_ r: IPCRequest) -> Bool {
        switch r {
        case .quarantine, .restore, .deleteQuarantined, .allow, .fixPosture, .setWebProtection, .updateSignatures,
             .setSettings, .setRealtime, .remediate, .addAllowRule, .removeAllowRule,
             .allowRemoteTool, .revokeRemoteTool, .setRemoteLockdown, .disableProtection, .requestUninstall, .uninstall,
             .restoreQuarantinedTo, .exportQuarantined, .sandboxRun, .liftEmergencyLockdown, .killSwitch: return true
        default: return false
        }
    }

    static func name(_ r: IPCRequest) -> String {
        switch r {
        case .status: return "status"; case .scan: return "scan"; case .listDetections: return "listDetections"
        case .listQuarantine: return "listQuarantine"; case .quarantine: return "quarantine"; case .restore: return "restore"
        case .deleteQuarantined: return "deleteQuarantined"; case .allow: return "allow"; case .posture: return "posture"
        case .fixPosture: return "fixPosture"; case .persistence: return "persistence"; case .setWebProtection: return "setWebProtection"
        case .updateSignatures: return "updateSignatures"; case .subscribeEvents: return "subscribeEvents"
        case .activity: return "activity"; case .connections: return "connections"; case .wifi: return "wifi"
        case .networkStats: return "networkStats"; case .getSettings: return "getSettings"; case .setSettings: return "setSettings"
        case .pauseScan: return "pauseScan"; case .cancelScan: return "cancelScan"; case .setRealtime: return "setRealtime"
        case .previewRemediation: return "previewRemediation"; case .remediate: return "remediate"
        case .listAllowRules: return "listAllowRules"; case .addAllowRule: return "addAllowRule"
        case .removeAllowRule: return "removeAllowRule"; case .health: return "health"
        case .remoteAccessReport: return "remoteAccessReport"; case .allowRemoteTool: return "allowRemoteTool"
        case .revokeRemoteTool: return "revokeRemoteTool"; case .setRemoteLockdown: return "setRemoteLockdown"
        case .tamperStatus: return "tamperStatus"; case .requestDisableProtection: return "requestDisableProtection"
        case .disableProtection: return "disableProtection"; case .requestUninstall: return "requestUninstall"
        case .uninstall: return "uninstall"; case .forwardEvents: return "forwardEvents"
        case .checkURL: return "checkURL"; case .scamCheck: return "scamCheck"; case .webLookup: return "webLookup"
        case .webVerdict: return "webVerdict"
        case .restoreQuarantinedTo: return "restoreQuarantinedTo"; case .exportQuarantined: return "exportQuarantined"
        case .sandboxRun: return "sandboxRun"
        case .emergencyStatus: return "emergencyStatus"; case .emergencyLockdown: return "emergencyLockdown"
        case .emergencyRescan: return "emergencyRescan"; case .liftEmergencyLockdown: return "liftEmergencyLockdown"
        case .emergencyAck: return "emergencyAck"; case .checkURLChain: return "checkURLChain"
        case .emergencyNetwork: return "emergencyNetwork"; case .killSwitch: return "killSwitch"
        case .deceptionStatus: return "deceptionStatus"; case .deceptionSetDecoys: return "deceptionSetDecoys"
        case .deceptionSetMaze: return "deceptionSetMaze"; case .deceptionRemoveAll: return "deceptionRemoveAll"
        case .deceptionSetTarpit: return "deceptionSetTarpit"; case .deceptionSetTone: return "deceptionSetTone"
        case .deceptionEvidence: return "deceptionEvidence"; case .deceptionSetDecoysVisible: return "deceptionSetDecoysVisible"
        case .deceptionContain: return "deceptionContain"
        }
    }

    /// The root daemon reads everything; a standard (non-admin) user may only have it scan places they own
    /// or shared locations, so scan results can't be used to probe other users' files.
    static func standardUserScanDenial(paths: [String], quick: Bool, uid: uid_t) -> String? {
        if paths.isEmpty { return quick ? nil : "a full scan requires an administrator account" }
        let home = getpwuid(uid).map { String(cString: $0.pointee.pw_dir) } ?? "/nonexistent"
        let allowed = [home, "/Applications", "/Users/Shared", "/private/tmp", "/tmp", "/Volumes"]
        for p in paths {
            let r = ((p as NSString).standardizingPath as NSString).resolvingSymlinksInPath
            if !allowed.contains(where: { r == $0 || r.hasPrefix($0 + "/") }) {
                return "standard users can scan only their home folder, /Applications, /Users/Shared, /tmp and /Volumes (\(p))"
            }
        }
        return nil
    }

    /// The matrix cell for this request and peer on the root daemon (nil = allowed). See IPCAuthz.swift.
    func authorizationDenial(_ req: IPCRequest, peer: Peer) -> String? {
        var weakens = true
        if case .setSettings(let s) = req { weakens = IPCAuthz.settingsWeaken(old: p.settings(), new: s) }
        let level = IPCAuthz.level(req, settingsWeakens: weakens)
        let caller = AuthzCaller(uid: peer.uid, isAdmin: peer.isAdmin, isConsole: AuthzCaller.consoleUID() == peer.uid,
                                 client: peer.client,
                                 hasSettingsSession: level == .adminClientWeakening && (p.services.guardian?.hasAuthenticatedSession(peer) ?? false))
        return IPCAuthz.denial(level, caller, name: Self.name(req))
    }

    private func deception() throws -> DeceptionService {
        guard let d = p.services.deception else { throw ServiceError.unavailable("Cat & Mouse (it runs in your session's protection service)") }
        return d
    }

    @discardableResult
    func handle(_ req: IPCRequest, peer: Peer, requireAdminForPrivileged: Bool, send: @escaping (IPCResponse) -> Bool) -> RouteResult {
        if requireAdminForPrivileged && Self.isPrivileged(req) && !peer.isAdmin {
            _ = send(.error("'\(Self.name(req))' requires an administrator account"))
            return .done
        }
        if requireAdminForPrivileged, let why = authorizationDenial(req, peer: peer) {
            logWarn("IPC denied \(Self.name(req)) for uid \(peer.uid) pid \(peer.pid) (\(peer.client?.rawValue ?? "unverified client"))")
            _ = send(.error(why)); return .done
        }
        if requireAdminForPrivileged && !peer.isAdmin, case .scan(let paths, let quick) = req,
           let why = Self.standardUserScanDenial(paths: paths, quick: quick, uid: peer.uid) {
            _ = send(.error(why)); return .done
        }
        do {
            switch req {
            case .status:
                _ = send(.status(p.status()))
            case .scan(let paths, let quick):
                var last = Date.distantPast
                let lock = NSLock()
                var gone = false
                let out = p.scan(paths: paths, quick: quick, progress: { n, total, cur, tick in
                    lock.lock(); defer { lock.unlock() }
                    guard !gone, Date().timeIntervalSince(last) > 0.25 else { return }
                    last = Date()
                    if !send(.scanProgress(scanned: n, total: total, current: cur, walkFinished: tick.walkFinished,
                                           timedOut: tick.timedOut, secondsSinceLastCompletion: tick.secondsSinceLastCompletion)) { gone = true }
                }, cancelled: { lock.lock(); defer { lock.unlock() }; return gone })
                _ = send(.scanFinished(scanned: out.scanned, detections: out.detections, seconds: out.seconds))
            case .listDetections:
                _ = send(.detections(p.store.all()))
            case .listQuarantine:
                _ = send(.quarantine(p.services.quarantine.list()))
            case .quarantine(let id):
                guard let d = p.store.get(id) else { throw ServiceError.notFound("detection \(id)") }
                guard let path = d.path else { throw ServiceError.failed("detection has no file path") }
                let qrec = try p.services.quarantine.quarantine(path: path, detection: d)
                _ = p.store.update(id) { $0.resolved = true }
                p.markDecoyCatchContained(d, quarantineID: qrec.id)
                p.activity.add(.quarantine, "Quarantined \(d.name)", detail: path, outcome: "quarantined", severity: d.severity, detectionID: d.id,
                               event: .quarantined, actor: .user, target: path, score: d.confidence,
                               action: "Moved the file to quarantine because you asked.", sha256: d.sha256, refID: qrec.id.uuidString,
                               facts: ["threat": d.name])
                _ = send(.ok)
            case .restore(let id, let allow):
                // hx3: a non-admin may restore only items that were theirs (same rule as restoreQuarantinedTo).
                if !peer.isAdmin && peer.uid != 0 {
                    guard let rec = p.services.quarantine.list().first(where: { $0.id == id }) else { throw ServiceError.notFound("quarantine item \(id)") }
                    try QuarantineSandbox.checkItemAccess(rec, peer: peer)
                }
                _ = try p.restore(id: id, allow: allow)
                _ = send(.ok)
            case .deleteQuarantined(let id):
                let drec = p.services.quarantine.list().first { $0.id == id }
                try p.services.quarantine.delete(id: id)
                p.activity.add(.quarantine, "Deleted \(drec.map { ($0.originalPath as NSString).lastPathComponent } ?? "a quarantined item")",
                               detail: drec?.originalPath ?? "", outcome: "deleted", event: .deleted, actor: .user, target: drec?.originalPath,
                               sha256: drec?.sha256, facts: ["threat": drec?.detectionName ?? ""])
                _ = send(.ok)
            case .allow(let sha):
                guard sha.count == 64, sha.allSatisfy(\.isHexDigit) else { throw ServiceError.failed("not a SHA-256") }
                p.allow(sha256: sha)
                _ = send(.ok)
            case .posture:
                _ = send(.posture(try p.posture()))
            case .fixPosture(let id):
                guard IPCAuthz.isValidCheckID(id), PostureFixer.canFix(id),
                      let planned = PostureFixer.fix(for: id), PostureFixer.isSafe(planned) else {
                    throw ServiceError.failed("no one-click fix for that check")
                }
                guard let ps = p.services.posture else { throw ServiceError.unavailable("posture fixer") }
                do {
                    let msg = try ps.fix(checkID: id, dryRun: p.runtime.userMode || getuid() != 0)
                    logInfo("posture fix \(id): \(LogRedact.clean(msg))")
                    let checkTitle = (try? p.posture())?.first { $0.id == id }?.title ?? id
                    p.activity.add(.posture, "Fixed \(id)", detail: msg, outcome: "fixed", event: .postureFixed, actor: .user, facts: ["check": checkTitle])
                } catch {
                    p.activity.add(.posture, "Could not fix \(id)", detail: error.localizedDescription, outcome: "failed", severity: .low,
                                   event: .postureFixFailed, actor: .user, reason: error.localizedDescription, facts: ["check": id])
                    throw error
                }
                _ = send(.ok)
            case .persistence:
                _ = send(.persistence(try p.persistence()))
            case .setWebProtection(let on):
                guard let w = p.services.web else { throw ServiceError.unavailable("web protection") }
                if on && p.runtime.userMode {
                    throw ServiceError.failed("web protection needs the Rampart system service (it changes DNS settings); not available in user mode")
                }
                try w.setOn(on)
                p.runtime.updateConfig { $0.webProtection = on }
                p.activity.add(.settings, "Web protection \(on ? "on" : "off")", outcome: on ? "on" : "off", severity: on ? .info : .medium,
                               event: .protectionToggled, actor: .user, facts: ["setting": "Web protection", "value": on ? "on" : "off"])
                _ = send(.ok)
            case .updateSignatures:
                _ = p.updateSignatures(actor: .user)
                _ = send(.ok)
            case .activity(let limit):
                _ = send(.activity(p.activity.list(limit: limit)))
            case .connections:
                guard let n = p.services.network else { throw ServiceError.unavailable("connection monitor") }
                _ = send(.connections(n.connections()))
            case .wifi:
                guard let n = p.services.network else { throw ServiceError.unavailable("Wi-Fi guard") }
                _ = send(.wifi(n.wifi()))
            case .networkStats:
                guard let n = p.services.network else { throw ServiceError.unavailable("network stats") }
                _ = send(.networkStats(n.stats(available: !p.runtime.userMode && getuid() == 0)))
            case .getSettings:
                _ = send(.settings(p.settings()))
            case .setSettings(let s):
                // New exclusions broader than one user-owned subfolder need an admin-authenticated session
                // (requestDisableProtection + disableProtection(token, minutes: 0)).
                let old = Set(p.runtime.config.exclusions)
                let added = s.exclusions.map { ($0 as NSString).expandingTildeInPath }.filter { $0.hasPrefix("/") && !old.contains($0) }
                if let broad = added.first(where: { !PathScope.isNarrowUserScope($0, uid: peer.uid) }),
                   !(p.services.guardian?.hasAuthenticatedSession(peer) ?? false) {
                    throw ServiceError.denied("excluding \(broad) needs administrator confirmation (authenticate first)")
                }
                _ = send(.settings(p.setSettings(s)))
            case .pauseScan(let paused):
                if p.scanControl.setPaused(paused) == 0 { throw ServiceError.failed("no scan is running") }
                p.activity.add(.scan, paused ? "Scan paused" : "Scan resumed", event: paused ? .scanPaused : .scanResumed, actor: .user)
                _ = send(.ok)
            case .cancelScan:
                if p.scanControl.cancelAll() == 0 { throw ServiceError.failed("no scan is running") }
                _ = send(.ok)
            case .setRealtime(let on):
                p.setRealtime(on)
                _ = send(.ok)
            case .previewRemediation(let id):
                _ = send(.remediationPreview(try p.previewRemediation(id)))
            case .remediate(let id):
                _ = try p.remediatePersistence(id)
                _ = send(.ok)
            case .listAllowRules:
                _ = send(.allowRules(p.allowRules.all()))
            case .addAllowRule(let r):
                // Hash / file / signing rules stay token-free ("Not a Threat"); folder rules broader than one
                // user-owned subfolder need an admin-authenticated session.
                if r.scope == .folder, !PathScope.isNarrowUserScope(r.value, uid: peer.uid),
                   !(p.services.guardian?.hasAuthenticatedSession(peer) ?? false) {
                    if let why = AllowRuleStore.validate(r) { throw ServiceError.failed(why) }
                    throw ServiceError.denied("trusting the folder \(r.value) needs administrator confirmation (authenticate first)")
                }
                _ = try p.addAllowRule(r)
                _ = send(.allowRules(p.allowRules.all()))
            case .removeAllowRule(let id):
                try p.removeAllowRule(id)
                _ = send(.allowRules(p.allowRules.all()))
            case .health:
                _ = send(.health(p.health()))
            case .remoteAccessReport:
                guard let g = p.services.guardian else { throw ServiceError.unavailable("remote-access monitor (daemon only)") }
                _ = send(.remoteAccess(try JSONEncoder.rampart.encode(g.report())))
            case .allowRemoteTool(let id, let minutes):
                if let m = minutes, !(1...(7 * 24 * 60)).contains(m) { throw ServiceError.failed("minutes must be between 1 and 10080") }
                guard let g = p.services.guardian else { throw ServiceError.unavailable("remote-access lockdown") }
                try g.allow(id, minutes: minutes, pinCurrentSigners: true)
                p.activity.add(.settings, "Allowed remote tool \(id)", detail: minutes.map { "for \($0) min" } ?? "until revoked", outcome: "allowed",
                               event: .remoteAccessAllowed, actor: .user, refID: id, facts: ["tool": RemoteToolCatalogue.tool(id)?.name ?? id, "for": minutes.map { "\($0) minutes" } ?? "until you remove it"])
                _ = send(.ok)
            case .revokeRemoteTool(let id):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("remote-access lockdown") }
                g.revoke(id); p.activity.add(.settings, "Revoked remote tool \(id)", outcome: "revoked", event: .remoteAccessRevoked, actor: .user, refID: id,
                                             facts: ["tool": RemoteToolCatalogue.tool(id)?.name ?? id]); _ = send(.ok)
            case .setRemoteLockdown(let on):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("remote-access lockdown") }
                g.setLockdown(on); p.activity.add(.settings, "Remote-access lockdown \(on ? "on" : "off")", outcome: on ? "on" : "off",
                                                  event: .remoteLockdownChanged, actor: .user, facts: ["value": on ? "on" : "off"]); _ = send(.ok)
            case .tamperStatus:
                guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection (daemon only)") }
                _ = send(.tamper(try JSONEncoder.rampart.encode(g.status())))
            case .requestDisableProtection(let auth, let reason):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection") }
                let t = try g.requestDisable(peer: peer, authorization: auth)
                logInfo("disable-protection token issued to uid \(peer.uid): \(LogRedact.clean(reason, max: 120))")
                _ = send(.disableToken(t))
            case .disableProtection(let token, let minutes):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection") }
                guard minutes <= 24 * 60 else { throw ServiceError.failed("protection can be paused for at most 24 hours") }
                if minutes <= 0 {
                    // minutes == 0: authenticate a 10-minute settings session (broad exclusions / folder rules)
                    // without pausing protection.
                    try g.redeem(token, peer: peer, purpose: .settings, minutes: 10)
                    p.activity.add(.settings, "Administrator confirmed a settings change", outcome: "settings session (10 min)", event: .adminSession, actor: .user)
                } else {
                    try g.redeem(token, peer: peer, purpose: .pause, minutes: minutes)
                    p.pauseProtection(minutes: minutes)
                }
                _ = send(.ok)
            case .requestUninstall(let auth):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection") }
                _ = send(.disableToken(try g.requestDisable(peer: peer, authorization: auth)))
            case .uninstall(let token):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection") }
                try g.redeem(token, peer: peer, purpose: .uninstall, minutes: 10)
                Emergency.shutdown(p)   // the emergency anchor goes before anything else
                try p.beginUninstall()
                _ = send(.ok)
            case .checkURL(let url):
                guard let w = p.services.webCheck else { throw ServiceError.unavailable("web checks") }
                _ = send(.urlVerdict(try w.checkURL(url)))
            case .scamCheck(let text, let kind):
                guard let w = p.services.webCheck else { throw ServiceError.unavailable("scam check") }
                guard text.utf8.count <= 2 << 20 else { throw ServiceError.failed("input too large") }
                _ = send(.scamReport(try w.scamCheck(text, kind: kind)))
            case .webLookup(let host):
                guard let w = p.services.webCheck else { throw ServiceError.unavailable("web lookups") }
                _ = send(.webLookup(try w.lookup(host)))
            case .webVerdict(let url, let verdict, let score, let headline):
                let sev: Severity = score >= 80 ? .high : score >= 50 ? .medium : .low
                let host = URL(string: url)?.host ?? url
                // Attacker-influenced text (page title, URL): no control/bidi characters, bounded, score clamped.
                let h = LogRedact.clean(host, max: 120), line = LogRedact.clean(headline, max: 140)
                let clamped = max(0, min(100, score))
                let blocked = verdict == "likelyScam"
                let ctx = ActivityFacts.urlContext(url)
                p.activity.add(.webBlock, line.isEmpty ? "Web warning: \(h)" : line,
                               detail: LogRedact.clean(url, max: 300), outcome: "\(LogRedact.clean(verdict, max: 24)) (\(clamped))", severity: sev,
                               event: blocked ? .scamBlocked : .webWarning, actor: .system, target: LogRedact.clean(url, max: 300),
                               rule: ctx.rule, reason: line.isEmpty ? ctx.reason : line + (ctx.reason.map { " · " + $0 } ?? ""), score: clamped,
                               action: blocked ? "The browser extension stopped the page and showed a warning." : "The browser extension showed a warning on the page.",
                               facts: ["brand": ctx.brand ?? "", "verdict": blocked ? "Likely scam" : "Suspicious"])
                _ = send(.ok)
            case .forwardEvents(let events):
                guard let rt = p.services.realtime as? RealtimePipeline else { throw ServiceError.unavailable("real-time pipeline") }
                guard events.count <= 500 else { throw ServiceError.failed("too many events in one batch") }
                for raw in events {
                    guard var e = IPCAuthz.sanitizeForwarded(raw, peerUID: peer.uid) else { continue }
                    e.detail["forwarded_uid"] = String(peer.uid)
                    if e.source.isEmpty { e.source = "session" }
                    if e.kind == .other, e.detail["type"] == "clipboard" || e.source == "pasteguard" { DaemonHooks.ingestClipboard?(e) } else { rt.inject(e) }
                }
                _ = send(.ok)
            case .restoreQuarantinedTo(let id, let path, let allow):
                _ = try QuarantineSandbox.restore(p, id: id, to: path, allow: allow, peer: peer); _ = send(.ok)
            case .exportQuarantined(let id, let path):
                let r = try QuarantineSandbox.export(p, id: id, to: path, peer: peer); _ = send(.exported(path: r.path, password: r.password))
            case .sandboxRun(let id, let confirmation):
                _ = send(.sandboxReport(try JSONEncoder.rampart.encode(QuarantineSandbox.run(p, id: id, confirmation: confirmation, peer: peer))))
            case .emergencyStatus:
                _ = send(.emergency(try Emergency.status(p)))
            case .emergencyLockdown(let reason):
                _ = send(.emergency(try Emergency.manual(p, peer: peer, reason: LogRedact.clean(reason, max: 200))))
            case .emergencyRescan:
                _ = send(.emergency(try Emergency.rescan(p)))
            case .liftEmergencyLockdown(let token, let force):
                _ = send(.emergency(try Emergency.lift(p, token: token, force: force, peer: peer)))
            case .emergencyAck(let ids):
                _ = send(.emergency(try Emergency.ack(p, ids)))
            case .emergencyNetwork(let keep, let token):
                _ = send(.emergency(try keep ? Emergency.keepBlocking(p) : Emergency.restoreNetwork(p, token: token, peer: peer)))
            case .killSwitch(let token):
                _ = send(.killSwitch(try KillSwitchExec.authorizedRun(p, token: token, peer: peer)))
            case .checkURLChain(let url):
                guard let deep = p.services.deep else { throw ServiceError.unavailable("link-chain checks") }
                guard url.utf8.count <= 8192 else { throw ServiceError.failed("URL too long") }
                // Network I/O: run on a worker queue with a hard ceiling, so this connection never hangs forever.
                let done = DispatchSemaphore(value: 0)
                var result: Result<Data, Error> = .failure(ServiceError.failed("link-chain check timed out"))
                let box = NSLock()
                DispatchQueue.global(qos: .userInitiated).async {
                    let r = Result { try deep.checkChain(url) }
                    box.lock(); result = r; box.unlock(); done.signal()
                }
                _ = done.wait(timeout: .now() + 45)
                box.lock(); let r = result; box.unlock()
                _ = send(.urlVerdict(try r.get()))
            case .deceptionStatus:
                _ = send(.deception(try JSONEncoder.rampart.encode(try deception().status())))
            case .deceptionSetDecoys(let on):
                let d = try deception(); _ = d.setDecoys(on)
                p.activity.add(.settings, "Cat & Mouse decoys \(on ? "on" : "off")", outcome: on ? "on" : "off", event: .protectionToggled, actor: .user, facts: ["setting": "Cat & Mouse decoys", "value": on ? "on" : "off"])
                _ = send(.deception(try JSONEncoder.rampart.encode(d.status())))
            case .deceptionSetMaze(let on):
                let d = try deception(); try d.setMaze(on)
                p.activity.add(.settings, "Cat & Mouse maze \(on ? "on" : "off")", outcome: on ? "on" : "off", event: .protectionToggled, actor: .user, facts: ["setting": "Cat & Mouse maze", "value": on ? "on" : "off"])
                _ = send(.deception(try JSONEncoder.rampart.encode(d.status())))
            case .deceptionRemoveAll:
                let d = try deception(); _ = d.removeAll()
                p.activity.add(.settings, "Cat & Mouse decoys removed", outcome: "removed", event: .settingsChanged, actor: .user, facts: ["changes": "Cat & Mouse decoys removed"])
                _ = send(.deception(try JSONEncoder.rampart.encode(d.status())))
            case .deceptionSetTarpit(let on, let port, let scopeRaw):
                guard let scope = LureScope(rawValue: scopeRaw) else { throw ServiceError.failed("unknown scope") }
                if scope != .loopback && !(peer.isAdmin || peer.uid == 0) { throw ServiceError.denied("a lure reachable from other devices needs an administrator") }
                guard port >= 1024 else { throw ServiceError.failed("the lure port must be 1024 or higher") }
                let d = try deception(); try d.setTarpit(on, port: port, scope: scope)
                _ = send(.deception(try JSONEncoder.rampart.encode(d.status())))
            case .deceptionSetDecoysVisible(let visible):
                let d = try deception(); d.setDecoysVisible(visible)
                p.activity.add(.settings, "Cat & Mouse decoys \(visible ? "shown" : "hidden") in Finder", outcome: visible ? "visible" : "hidden", event: .settingsChanged, actor: .user, facts: ["changes": "Cat & Mouse decoys \(visible ? "shown" : "hidden") in Finder"])
                _ = send(.deception(try JSONEncoder.rampart.encode(d.status())))
            case .deceptionSetTone(let serious):
                let d = try deception(); d.setTone(serious ? .serious : .playful)
                _ = send(.deception(try JSONEncoder.rampart.encode(d.status())))
            case .deceptionContain(let id):
                let d = try deception()
                do {
                    let c = try d.contain(catchID: id)
                    p.activity.add(.detection, "Cat & Mouse: stopped \(c.processName)", detail: c.processPath, outcome: "contained", severity: .high,
                                   event: .deceptionEvent, actor: .user, facts: ["decoy": (c.decoyPath as NSString).lastPathComponent])
                } catch { throw ServiceError.failed("\(error)") }
                _ = send(.deception(try JSONEncoder.rampart.encode(d.status())))
            case .deceptionEvidence(let id):
                guard let e = try deception().evidence(catchID: id) else { throw ServiceError.notFound("catch \(id)") }
                _ = send(.deceptionEvidence(try JSONEncoder.rampart.encode(e)))
            case .subscribeEvents:
                let token = p.subscribe(send)
                _ = send(.ok)
                return .keepOpen(token)
            }
        } catch {
            _ = send(.error(error.localizedDescription))
        }
        return .done
    }
}

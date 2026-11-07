import Foundation
import RampartShared

/// Identity of the IPC caller (from getpeereid), or the local process in CLI --local mode.
struct Peer {
    var uid: uid_t
    var gid: gid_t
    var pid: pid_t
    var isAdmin: Bool { Util.isAdmin(uid: uid) }
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
             .restoreQuarantinedTo, .exportQuarantined, .sandboxRun: return true
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

    @discardableResult
    func handle(_ req: IPCRequest, peer: Peer, requireAdminForPrivileged: Bool, send: @escaping (IPCResponse) -> Bool) -> RouteResult {
        if requireAdminForPrivileged && Self.isPrivileged(req) && !peer.isAdmin {
            _ = send(.error("'\(Self.name(req))' requires an administrator account"))
            return .done
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
                let out = p.scan(paths: paths, quick: quick, progress: { n, total, cur in
                    lock.lock(); defer { lock.unlock() }
                    guard !gone, Date().timeIntervalSince(last) > 0.25 else { return }
                    last = Date()
                    if !send(.scanProgress(scanned: n, total: total, current: cur)) { gone = true }
                }, cancelled: { lock.lock(); defer { lock.unlock() }; return gone })
                _ = send(.scanFinished(scanned: out.scanned, detections: out.detections, seconds: out.seconds))
            case .listDetections:
                _ = send(.detections(p.store.all()))
            case .listQuarantine:
                _ = send(.quarantine(p.services.quarantine.list()))
            case .quarantine(let id):
                guard let d = p.store.get(id) else { throw ServiceError.notFound("detection \(id)") }
                guard let path = d.path else { throw ServiceError.failed("detection has no file path") }
                _ = try p.services.quarantine.quarantine(path: path, detection: d)
                _ = p.store.update(id) { $0.resolved = true }
                _ = send(.ok)
            case .restore(let id, let allow):
                _ = try p.restore(id: id, allow: allow)
                _ = send(.ok)
            case .deleteQuarantined(let id):
                try p.services.quarantine.delete(id: id)
                _ = send(.ok)
            case .allow(let sha):
                guard sha.count == 64, sha.allSatisfy(\.isHexDigit) else { throw ServiceError.failed("not a SHA-256") }
                p.allow(sha256: sha)
                _ = send(.ok)
            case .posture:
                _ = send(.posture(try p.posture()))
            case .fixPosture(let id):
                guard let ps = p.services.posture else { throw ServiceError.unavailable("posture fixer") }
                do {
                    let msg = try ps.fix(checkID: id, dryRun: p.runtime.userMode || getuid() != 0)
                    logInfo("posture fix \(id): \(msg)")
                    p.activity.add(.posture, "Fixed \(id)", detail: msg, outcome: "fixed")
                    _ = try? p.posture()
                } catch {
                    p.activity.add(.posture, "Could not fix \(id)", detail: error.localizedDescription, outcome: "failed", severity: .low)
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
                p.activity.add(.settings, "Web protection \(on ? "on" : "off")", outcome: on ? "on" : "off")
                _ = send(.ok)
            case .updateSignatures:
                _ = p.updateSignatures()
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
                p.activity.add(.scan, paused ? "Scan paused" : "Scan resumed")
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
                guard let g = p.services.guardian else { throw ServiceError.unavailable("remote-access lockdown") }
                try g.allow(id, minutes: minutes)
                p.activity.add(.settings, "Allowed remote tool \(id)", detail: minutes.map { "for \($0) min" } ?? "until revoked", outcome: "allowed")
                _ = send(.ok)
            case .revokeRemoteTool(let id):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("remote-access lockdown") }
                g.revoke(id); p.activity.add(.settings, "Revoked remote tool \(id)", outcome: "revoked"); _ = send(.ok)
            case .setRemoteLockdown(let on):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("remote-access lockdown") }
                g.setLockdown(on); p.activity.add(.settings, "Remote-access lockdown \(on ? "on" : "off")", outcome: on ? "on" : "off"); _ = send(.ok)
            case .tamperStatus:
                guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection (daemon only)") }
                _ = send(.tamper(try JSONEncoder.rampart.encode(g.status())))
            case .requestDisableProtection(let auth, let reason):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection") }
                let t = try g.requestDisable(peer: peer, authorization: auth)
                logInfo("disable-protection token issued to uid \(peer.uid): \(reason)")
                _ = send(.disableToken(t))
            case .disableProtection(let token, let minutes):
                guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection") }
                if minutes <= 0 {
                    // minutes == 0: authenticate a 10-minute settings session (broad exclusions / folder rules)
                    // without pausing protection.
                    try g.redeem(token, peer: peer, purpose: .settings, minutes: 10)
                    p.activity.add(.settings, "Administrator confirmed a settings change", outcome: "settings session (10 min)")
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
                p.activity.add(.webBlock, headline.isEmpty ? "Web warning: \(host)" : headline,
                               detail: String(url.prefix(300)), outcome: "\(verdict) (\(score))", severity: sev)
                _ = send(.ok)
            case .forwardEvents(let events):
                guard let rt = p.services.realtime as? RealtimePipeline else { throw ServiceError.unavailable("real-time pipeline") }
                guard events.count <= 500 else { throw ServiceError.failed("too many events in one batch") }
                for var e in events {
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

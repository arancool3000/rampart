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
        case .quarantine, .restore, .deleteQuarantined, .allow, .fixPosture, .setWebProtection, .updateSignatures: return true
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
                let msg = try ps.fix(checkID: id, dryRun: p.runtime.userMode || getuid() != 0)
                logInfo("posture fix \(id): \(msg)")
                _ = send(.ok)
            case .persistence:
                _ = send(.persistence(try p.persistence()))
            case .setWebProtection(let on):
                guard let w = p.services.web else { throw ServiceError.unavailable("web protection") }
                try w.setOn(on)
                p.runtime.updateConfig { $0.webProtection = on }
                _ = send(.ok)
            case .updateSignatures:
                _ = p.updateSignatures()
                _ = send(.ok)
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

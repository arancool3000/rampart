import Foundation
import Security
import RampartShared

// User incident 2026-11-09: a user helper (`rampartd --user`) left running from a REPLACED copy of the app held the state
// lock, so the new helper exited with "another rampartd is using …" and the app said "Basic protection stopped right
// after starting". The old helper never restarts by itself. The new helper (and the app before starting it) stops it,
// but only when ALL of these hold, so nothing else can ever be stopped this way:
//  - it is a different process, owned by the same user (effective and real uid), not root;
//  - it is a RamPart service binary: signing identifier `app.rampart.daemon` and the same signer as us (same Team ID,
//    or both ad-hoc), and its executable is named rampartd;
//  - it started before our own binary was installed (the later of its mtime and ctime: copying or moving a new build
//    into place updates ctime even when `ditto` keeps the build's mtime);
//  - it runs from our own path (a copy replaced in place), or its executable is gone / no longer a RamPart build there
//    (a copy moved to the Trash or replaced by an update).

public struct HelperProcessFacts: Sendable, Equatable {
    public var pid: Int32
    public var uid: uid_t
    public var ruid: uid_t
    public var path: String
    public var startTime: Date
    public var signingID: String?
    public var teamID: String?
    /// The executable at `path` still exists and is a RamPart service build.
    public var pathStillOurs: Bool
    /// cdhash the kernel holds for the running process (nil = unknown).
    public var cdhash: String?
    public init(pid: Int32, uid: uid_t, ruid: uid_t, path: String, startTime: Date, signingID: String?, teamID: String?, pathStillOurs: Bool,
                cdhash: String? = nil) {
        self.pid = pid; self.uid = uid; self.ruid = ruid; self.path = path; self.startTime = startTime
        self.signingID = signingID; self.teamID = teamID; self.pathStillOurs = pathStillOurs; self.cdhash = cdhash
    }
}

public struct HelperSelfFacts: Sendable, Equatable {
    public var pid: Int32
    public var uid: uid_t
    public var path: String
    /// When our binary was put in place: max(mtime, ctime).
    public var installTime: Date
    public var signingID: String?
    public var teamID: String?
    /// cdhash of our binary on disk (nil = unknown).
    public var cdhash: String?
    public init(pid: Int32, uid: uid_t, path: String, installTime: Date, signingID: String?, teamID: String?, cdhash: String? = nil) {
        self.pid = pid; self.uid = uid; self.path = path; self.installTime = installTime; self.signingID = signingID; self.teamID = teamID
        self.cdhash = cdhash
    }
}

public enum StaleHelperPolicy {
    public static let serviceSigningID = Product.bundlePrefix + ".daemon"

    public enum Decision: Equatable, Sendable {
        case stop(String)
        case keep(String)
        public var shouldStop: Bool { if case .stop = self { return true }; return false }
        public var why: String { switch self { case .stop(let w), .keep(let w): return w } }
    }

    public static func decide(holder h: HelperProcessFacts, me: HelperSelfFacts) -> Decision {
        guard h.pid > 1, h.pid != me.pid else { return .keep("not another process") }
        guard me.uid != 0, h.uid == me.uid, h.ruid == me.uid else { return .keep("owned by another user") }
        guard (h.path as NSString).lastPathComponent == "rampartd" else { return .keep("not a \(Product.name) helper (\(h.path))") }
        guard h.signingID == serviceSigningID, me.signingID == serviceSigningID else { return .keep("not signed as \(serviceSigningID)") }
        let ht = h.teamID ?? "", mt = me.teamID ?? ""
        guard ht == mt else { return .keep("signed by a different identity (\(ht.isEmpty ? "ad-hoc" : ht) vs \(mt.isEmpty ? "ad-hoc" : mt))") }
        guard h.startTime < me.installTime else { return .keep("started after this copy was installed (not stale)") }
        let samePath = GuardPaths.normalize(h.path).lowercased() == GuardPaths.normalize(me.path).lowercased()
        // wms-o7: "installed after it started" is read from the binary's ctime, which anyone who can see the file can bump
        // without writing it (a hard link to it, then removing the link). That made the CURRENT helper look stale, so a
        // second instance started by any local program stopped it and took its place. A running helper that is this
        // very build (same cdhash) is never stale.
        if samePath, let a = h.cdhash?.lowercased(), let b = me.cdhash?.lowercased(), !a.isEmpty, a == b {
            return .keep("the running helper is this same build (not stale)")
        }
        guard samePath || !h.pathStillOurs else { return .keep("a different, still-installed copy at \(h.path)") }
        return .stop(samePath ? "a helper from the copy this one replaced (pid \(h.pid))" : "a helper whose copy was moved or deleted (pid \(h.pid), \(h.path))")
    }

    // MARK: live facts

    static func signing(pid: Int32) -> (id: String?, team: String?) { let s = signingFull(pid: pid); return (s.id, s.team) }

    static func signingFull(pid: Int32) -> (id: String?, team: String?, cdhash: String?) {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary, [], &code) == errSecSuccess,
              let code else { return (nil, nil, nil) }
        // A SecCode may be passed where a SecStaticCode is expected (Security.framework); this reads the identity the
        // kernel holds for the running process, so it works even when its executable was deleted or replaced.
        let asStatic = unsafeBitCast(code, to: SecStaticCode.self)
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(asStatic, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let d = info as? [String: Any] else { return (nil, nil, nil) }
        let cd = (d[kSecCodeInfoUnique as String] as? Data).map { $0.map { String(format: "%02x", $0) }.joined() }
        return (d[kSecCodeInfoIdentifier as String] as? String, d[kSecCodeInfoTeamIdentifier as String] as? String, cd)
    }

    static func signing(path: String) -> (id: String?, team: String?) {
        guard let s = OwnCodeSignature.read(path), s.valid else { return (nil, nil) }
        return (s.identifier, s.teamID)
    }

    public static func holderFacts(pid: Int32) -> HelperProcessFacts? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        var info = proc_bsdinfo()
        guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0,
              proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == Int32(MemoryLayout<proc_bsdinfo>.size) else { return nil }
        let path = String(cString: buf)
        let sig = signingFull(pid: pid)
        let onDisk = signing(path: path)
        let start = Date(timeIntervalSince1970: TimeInterval(info.pbi_start_tvsec) + TimeInterval(info.pbi_start_tvusec) / 1_000_000)
        return HelperProcessFacts(pid: pid, uid: info.pbi_uid, ruid: info.pbi_ruid, path: path, startTime: start,
                                  signingID: sig.id, teamID: sig.team, pathStillOurs: onDisk.id == serviceSigningID, cdhash: sig.cdhash)
    }

    public static func installTime(of path: String) -> Date? {
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        let m = Double(st.st_mtimespec.tv_sec) + Double(st.st_mtimespec.tv_nsec) / 1e9
        let c = Double(st.st_ctimespec.tv_sec) + Double(st.st_ctimespec.tv_nsec) / 1e9
        return Date(timeIntervalSince1970: max(m, c))
    }

    /// Facts about a helper binary we are (the daemon) or are about to start (the app).
    public static func selfFacts(binary: String, pid: Int32 = getpid()) -> HelperSelfFacts? {
        let path = URL(fileURLWithPath: binary).resolvingSymlinksInPath().path
        guard let t = installTime(of: path) else { return nil }
        let s = OwnCodeSignature.read(path).flatMap { $0.valid ? $0 : nil }
        return HelperSelfFacts(pid: pid, uid: getuid(), path: path, installTime: t, signingID: s?.identifier, teamID: s?.teamID, cdhash: s?.cdhash)
    }

    /// The pid recorded in a state root's `rampartd.lock` (written by the helper that holds it).
    public static func lockHolder(stateRoot: String) -> Int32? {
        let p = (stateRoot as NSString).appendingPathComponent("rampartd.lock")
        guard let d = FileManager.default.contents(atPath: p), d.count < 64,
              let pid = Int32(String(decoding: d, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1 else { return nil }
        return pid
    }

    /// Stops `pid` if the policy says it is a stale helper: SIGTERM, then SIGKILL after `grace`. Returns the decision.
    @discardableResult
    public static func stopIfStale(pid: Int32, me: HelperSelfFacts, grace: TimeInterval = 3) -> Decision {
        guard let h = holderFacts(pid: pid) else { return .keep("pid \(pid) is not running") }
        let d = decide(holder: h, me: me)
        guard d.shouldStop else { return d }
        _ = kill(pid, SIGTERM)
        let deadline = Date().addingTimeInterval(grace)
        while Date() < deadline, kill(pid, 0) == 0 { usleep(100_000) }
        // Same process still there (not a reused pid): force it.
        if kill(pid, 0) == 0, let again = holderFacts(pid: pid), again.startTime == h.startTime { _ = kill(pid, SIGKILL); usleep(200_000) }
        return d
    }
}

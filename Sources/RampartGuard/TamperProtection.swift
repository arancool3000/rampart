import Foundation
import Security
import RampartShared

// Tamper detection, the self-defence response policy, and the admin-authenticated disable flow.

public enum TamperKind: String, Codable, Sendable, CaseIterable {
    case unloadAttempt        // launchctl bootout/unload/disable/remove of our label
    case killAttempt          // kill/pkill/killall aimed at rampartd, or an ES signal event targeting us
    case fileTamper           // write/delete/rename under our install paths
    case plistTamper          // our LaunchDaemon/LaunchAgent plist edited or removed
    case binaryTamper         // installed binary hash differs from the manifest
    case configTamper         // sealed config / allow rules edited outside the daemon
    case exclusionOfSelf      // someone tried to exclude our own paths from scanning
    case launchItemRemoved    // BTM reported our launch item removed
}

/// Turns SecurityEvents into Detections when they aim at RamPart itself.
/// Self-attribution: events whose actor is one of our own pids, signed as app.rampart.*, or running from our
/// install paths are ignored (the daemon rewrites its config, the installer replaces binaries).
public final class TamperDetector: @unchecked Sendable {
    public let paths: GuardPaths
    /// Our own pids (daemon, watchdog, CLI run by the daemon). Evaluated on every event.
    public let ownPIDs: @Sendable () -> Set<Int32>
    /// Team IDs allowed to touch our files (an installer signed by us). Ad-hoc builds have none.
    public let trustedTeamIDs: Set<String>
    private let lock = NSLock()
    private var recent: [String: Date] = [:]
    public var dedupeWindow: TimeInterval = 5

    public init(paths: GuardPaths = .standard, ownPIDs: @escaping @Sendable () -> Set<Int32> = { [getpid()] },
                trustedTeamIDs: Set<String> = []) {
        self.paths = paths; self.ownPIDs = ownPIDs; self.trustedTeamIDs = trustedTeamIDs
    }

    public static let launchctlUnloadVerbs: Set<String> = ["bootout", "unload", "disable", "remove", "kill", "stop"]
    public static let killers: Set<String> = ["kill", "pkill", "killall"]
    public static let fileMutators: Set<String> = ["rm", "mv", "cp", "chflags", "chmod", "chown", "plutil", "defaults", "truncate", "tee", "install", "ln"]
    /// Tools that reset system state we depend on (TCC grants such as Full Disk Access, configuration profiles).
    public static let resetters: Set<String> = ["tccutil", "profiles"]

    private func isSelf(_ p: ProcessInfoLite?) -> Bool {
        guard let p else { return false }
        if ownPIDs().contains(p.pid) { return true }
        if let s = p.signingID, s.hasPrefix(Product.bundlePrefix) { return true }
        if let t = p.teamID, trustedTeamIDs.contains(t) { return true }
        if paths.isProtected(p.path) { return true }
        return false
    }

    private func dedupe(_ key: String, at date: Date) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if let last = recent[key], date.timeIntervalSince(last) < dedupeWindow { return false }
        recent[key] = date
        if recent.count > 2000 { recent = recent.filter { date.timeIntervalSince($0.value) < 60 } }
        return true
    }

    private func detection(_ kind: TamperKind, severity: Severity, score: Int, title: String, detail: String,
                           ev: SecurityEvent, path: String?) -> Detection {
        let actor = ev.process.map { "\(($0.path as NSString).lastPathComponent) (pid \($0.pid), uid \($0.uid))" } ?? "unknown process"
        let evidence = [
            Evidence(source: .behaviour, title: title, detail: detail + " by " + actor, score: score),
            Evidence(source: .behaviour, title: "Why this matters",
                     detail: "Malware and tech-support scammers turn security software off before acting. \(Product.name) cannot block this without an Endpoint Security entitlement, so it alerts and restores instead.", score: 0),
        ]
        return Detection(date: ev.date, path: path, pid: ev.process?.pid, name: "Tampering with \(Product.name): \(kind.rawValue)",
                         category: .suspicious, severity: severity, confidence: score, evidence: evidence)
    }

    public func inspect(_ ev: SecurityEvent) -> [Detection] {
        if isSelf(ev.process) { return [] }
        var out: [Detection] = []
        switch ev.kind {
        case .exec:
            out += inspectExec(ev)
        case .fileWrite, .fileCreate, .fileClose, .fileDelete, .fileRename, .xattrDelete:
            for p in [ev.path, ev.destPath].compactMap({ $0 }) where paths.isProtected(p) {
                if ev.kind == .fileClose, ev.detail["modified"] == "0" { continue }
                let isPlist = paths.isPlist(p)
                let kind: TamperKind = isPlist ? .plistTamper : (paths.isCritical(p) ? .configTamper : .fileTamper)
                let sev: Severity = isPlist || paths.isCritical(p) ? .critical : .high
                guard dedupe("\(kind.rawValue):\(p):\(ev.process?.pid ?? 0)", at: ev.date) else { continue }
                out.append(detection(kind, severity: sev, score: sev == .critical ? 92 : 80, title: "\(ev.kind.rawValue) on a protected \(Product.name) file",
                                     detail: p, ev: ev, path: p))
            }
        case .persistenceRemoved:
            let label = ev.detail["label"] ?? ev.detail["executable"] ?? ev.path ?? ""
            if paths.isOurLabel(label) || paths.isProtected(ev.detail["executable"] ?? ""), dedupe("btm:\(label)", at: ev.date) {
                out.append(detection(.launchItemRemoved, severity: .critical, score: 90, title: "\(Product.name) launch item removed",
                                     detail: label, ev: ev, path: ev.path))
            }
        case .other:
            if ev.detail["es_event"] == "signal" {
                let targetPID = ev.detail["target_pid"].flatMap { Int32($0) }
                let targetPath = ev.detail["target_path"] ?? ""
                let sig = ev.detail["sig"] ?? "?"
                if (targetPID.map { ownPIDs().contains($0) } ?? false) || paths.isProtected(targetPath),
                   dedupe("signal:\(targetPID ?? 0):\(ev.process?.pid ?? 0)", at: ev.date) {
                    out.append(detection(.killAttempt, severity: .critical, score: 90, title: "Signal \(sig) sent to \(Product.name)",
                                         detail: "target pid \(targetPID ?? 0) \(targetPath)", ev: ev, path: targetPath.isEmpty ? nil : targetPath))
                }
            }
        default: break
        }
        return out
    }

    private func inspectExec(_ ev: SecurityEvent) -> [Detection] {
        guard let p = ev.process else { return [] }
        let args = p.args.isEmpty ? [p.path] : p.args
        let tool = ((args.first ?? p.path) as NSString).lastPathComponent
        let joined = args.joined(separator: " ")
        let lower = joined.lowercased()
        let mentionsUs = paths.isOurLabel(joined) || lower.contains("rampartd") || lower.contains("rampart")
            || args.contains(where: { paths.isProtected($0) })
        guard mentionsUs else { return [] }

        if tool == "launchctl", args.dropFirst().contains(where: { Self.launchctlUnloadVerbs.contains($0) }), paths.isOurLabel(joined) || args.contains(where: paths.isProtected) {
            guard dedupe("unload:\(joined)", at: ev.date) else { return [] }
            return [detection(.unloadAttempt, severity: .critical, score: 95, title: "launchctl used against \(Product.name)", detail: joined, ev: ev, path: nil)]
        }
        if Self.killers.contains(tool), lower.contains("rampart") {
            guard dedupe("kill:\(p.pid)", at: ev.date) else { return [] }
            return [detection(.killAttempt, severity: .critical, score: 90, title: "\(tool) aimed at \(Product.name)", detail: joined, ev: ev, path: nil)]
        }
        if Self.fileMutators.contains(tool), let target = args.first(where: paths.isProtected) {
            guard dedupe("mutate:\(p.pid):\(target)", at: ev.date) else { return [] }
            let isPlist = paths.isPlist(target)
            let unlocking = tool == "chflags" && args.contains(where: { $0.contains("noschg") || $0.contains("nouchg") })
            return [detection(isPlist || unlocking ? .plistTamper : .fileTamper, severity: isPlist || unlocking ? .critical : .high, score: isPlist || unlocking ? 92 : 80,
                              title: unlocking ? "Immutable flag being cleared on a \(Product.name) file" : "\(tool) run on a protected \(Product.name) path",
                              detail: joined, ev: ev, path: target)]
        }
        if Self.resetters.contains(tool), paths.isOurLabel(joined) {
            guard dedupe("reset:\(p.pid)", at: ev.date) else { return [] }
            return [detection(.fileTamper, severity: .critical, score: 90, title: "\(tool) aimed at \(Product.name) (TCC/profile reset)", detail: joined, ev: ev, path: nil)]
        }
        if (lower.contains("exclu") || lower.contains("allow")) && args.contains(where: paths.isProtected) {
            guard dedupe("excl:\(p.pid)", at: ev.date) else { return [] }
            return [detection(.exclusionOfSelf, severity: .high, score: 85, title: "Attempt to exclude \(Product.name) from scanning", detail: joined, ev: ev, path: nil)]
        }
        return []
    }

    /// For the daemon's settings handler: refuse exclusions that cover our own install paths and raise a detection.
    /// Returns the offending entries. Call before persisting `RampartSettings.exclusions`.
    public func exclusionsCoveringSelf(_ exclusions: [String]) -> [String] {
        exclusions.filter { e in
            let n = GuardPaths.normalize(e)
            return paths.isProtected(n) || n == "/" || paths.protectedPrefixes.contains { $0.hasPrefix(n + "/") } || n == "/Library" || n == "/Applications"
        }
    }

    public func exclusionDetection(_ offending: [String], peerUID: uid_t, peerPID: pid_t) -> Detection {
        Detection(pid: peerPID, name: "Tampering with \(Product.name): \(TamperKind.exclusionOfSelf.rawValue)", category: .suspicious,
                  severity: .high, confidence: 85,
                  evidence: [Evidence(source: .behaviour, title: "Exclusion would hide \(Product.name)'s own files",
                                      detail: offending.joined(separator: ", ") + " requested by uid \(peerUID) pid \(peerPID); refused", score: 85)])
    }
}

// MARK: - Self-defence response

public struct SelfDefenceResponse: Codable, Sendable {
    public var dryRun: Bool
    public var kind: TamperKind
    public var restoredFiles: [String]
    public var commands: [GuardCommand]
    public var notes: [String]
    public var alert: Detection?
}

/// Decides what to do after a tamper detection or a periodic integrity sweep: restore sealed files from backup,
/// re-bootstrap the jobs, raise an alert. File restores happen here (when !dryRun); launchctl runs in the daemon.
public struct SelfDefencePolicy: Sendable {
    public static let launchctl = "/bin/launchctl"
    public let paths: GuardPaths
    public let store: SealedStore?
    public init(paths: GuardPaths = .standard, store: SealedStore?) { self.paths = paths; self.store = store }

    public func rebootstrapCommands(label: String, plist: String) -> [GuardCommand] {
        [GuardCommand(Self.launchctl, ["enable", "system/\(label)"], acceptableExitCodes: [0], note: "undo `launchctl disable`"),
         GuardCommand(Self.launchctl, ["bootstrap", "system", plist], acceptableExitCodes: [5, 17, 37], note: "already loaded is fine"),
         GuardCommand(Self.launchctl, ["kickstart", "-k", "system/\(label)"], note: "restart if stopped")]
    }

    public func respond(to kind: TamperKind, path: String?, dryRun: Bool = true) -> SelfDefenceResponse {
        var r = SelfDefenceResponse(dryRun: dryRun, kind: kind, restoredFiles: [], commands: [], notes: [], alert: nil)
        switch kind {
        case .unloadAttempt, .launchItemRemoved, .killAttempt:
            r.commands += rebootstrapCommands(label: paths.daemonLabel, plist: paths.daemonPlist)
            r.commands += rebootstrapCommands(label: paths.watchdogLabel, plist: paths.watchdogPlist)
            r.notes.append("launchd KeepAlive restarts a killed daemon; the watchdog re-bootstraps a booted-out one")
        case .plistTamper, .configTamper, .fileTamper:
            for p in [path].compactMap({ $0 }) + (path == nil ? paths.plists + [paths.configFile, paths.allowRulesFile] : []) {
                if let store, store.hasBackup(for: p) {
                    let (verdict, restored) = store.restoreIfNeeded(p, dryRun: dryRun)
                    if restored { r.restoredFiles.append(p); r.notes.append("\(p): \(String(describing: verdict)) -> restored from sealed backup") }
                } else { r.notes.append("\(p): no sealed backup; reinstall needed") }
                if paths.isPlist(p) {
                    let label = (p as NSString).lastPathComponent.replacingOccurrences(of: ".plist", with: "")
                    r.commands += rebootstrapCommands(label: label, plist: p)
                }
            }
        case .binaryTamper:
            r.notes.append("binary hash mismatch: refuse to trust the installed binary; ask the user to reinstall from a fresh download")
            r.commands.append(GuardCommand(Self.launchctl, ["bootout", "system/\(paths.daemonLabel)"], acceptableExitCodes: [3, 113],
                                           note: "do not keep running a replaced binary as root"))
        case .exclusionOfSelf:
            r.notes.append("exclusion refused; nothing to restore")
        }
        r.alert = Detection(path: path, name: "Self-defence: \(kind.rawValue)", category: .suspicious, severity: .high, confidence: 85,
                            evidence: [Evidence(source: .behaviour, title: "Automatic response", detail: r.notes.joined(separator: "; "), score: 85)])
        return r
    }

    /// Periodic sweep: verify sealed files and the manifest, restore what can be restored, report the rest.
    public func sweep(manifest: InstallManifest?, dryRun: Bool = true) -> [SelfDefenceResponse] {
        var out: [SelfDefenceResponse] = []
        if let store {
            for p in [paths.configFile, paths.allowRulesFile, paths.remotePolicyFile] where FileManager.default.fileExists(atPath: p) || store.hasBackup(for: p) {
                let v = store.verify(p)
                if !v.isIntact { out.append(respond(to: .configTamper, path: p, dryRun: dryRun)) }
            }
        }
        if let m = manifest {
            let bad = m.verify()
            if !bad.isEmpty {
                var r = respond(to: .binaryTamper, path: bad.first?.path, dryRun: dryRun)
                r.notes += bad.map { "\($0.path): \($0.kind.rawValue)" }
                out.append(r)
            }
        }
        return out
    }
}

// MARK: - Admin-authenticated disable

/// IPC flow for turning protection off legitimately, so that everything else is tampering:
///  1. App calls `requestDisableProtection(authorization: Data?, reason:)`. The daemon checks the peer:
///     uid must be in the admin group (getpeereid), AND either (a) `authorization` is a 32-byte
///     AuthorizationExternalForm the app obtained for right `app.rampart.disable-protection`
///     (falls back to `system.privilege.admin`), verified here with AuthorizationCopyRights without UI, or
///     (b) the daemon runs in `--user` dev mode. The daemon then returns a short-lived single-use token.
///  2. App calls `disableProtection(token:, minutes:)` within `tokenTTL`. The daemon redeems the token and pauses.
/// A scripted `launchctl bootout` / `pkill` never goes through this path, so it is flagged by `TamperDetector`.
public final class ProtectionDisableFlow: @unchecked Sendable {
    public static let rightName = Product.bundlePrefix + ".disable-protection"
    public static let fallbackRight = "system.privilege.admin"
    public let key: IntegrityKey
    public let clock: GuardClock
    public var tokenTTL: TimeInterval = 120
    private let lock = NSLock()
    private var issued: [String: (uid: uid_t, expires: Date)] = [:]
    /// Active authenticated sessions (pause or uninstall) by uid; tamper responses exempt these actors.
    private var sessions: [uid_t: (purpose: Purpose, until: Date)] = [:]

    public enum Purpose: String, Codable, Sendable { case pause, uninstall, settings }

    public init(key: IntegrityKey, clock: GuardClock = .live) { self.key = key; self.clock = clock }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case notAdmin, authorizationMissing, authorizationDenied(String), tokenInvalid, tokenExpired, tokenForOtherUser
        public var description: String {
            switch self {
            case .notAdmin: return "an administrator account is required to turn protection off"
            case .authorizationMissing: return "administrator authentication is required"
            case .authorizationDenied(let s): return "authorization denied: \(s)"
            case .tokenInvalid: return "disable token is invalid or already used"
            case .tokenExpired: return "disable token expired; authenticate again"
            case .tokenForOtherUser: return "disable token belongs to a different user"
            }
        }
    }

    /// Verifies an AuthorizationExternalForm produced by the app (AuthorizationCreate + AuthorizationMakeExternalForm).
    /// Must run as root (or the same user) to succeed; no UI is ever shown from the daemon.
    public static func verifyExternalForm(_ data: Data, right: String = rightName) -> Result<Void, Failure> {
        guard data.count == MemoryLayout<AuthorizationExternalForm>.size else { return .failure(.authorizationDenied("bad external form size")) }
        var form = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &form) { data.copyBytes(to: $0) }
        var auth: AuthorizationRef?
        let cs = AuthorizationCreateFromExternalForm(&form, &auth)
        guard cs == errAuthorizationSuccess, let auth else { return .failure(.authorizationDenied("external form rejected (\(cs))")) }
        defer { AuthorizationFree(auth, []) }
        func check(_ name: String) -> OSStatus {
            name.withCString { cname in
                var item = AuthorizationItem(name: cname, valueLength: 0, value: nil, flags: 0)
                return withUnsafeMutablePointer(to: &item) { ip in
                    var rights = AuthorizationRights(count: 1, items: ip)
                    return AuthorizationCopyRights(auth, &rights, nil, [.extendRights], nil)   // no .interactionAllowed
                }
            }
        }
        var st = check(right)
        if st != errAuthorizationSuccess && right != fallbackRight { st = check(fallbackRight) }
        return st == errAuthorizationSuccess ? .success(()) : .failure(.authorizationDenied("right not held (\(st))"))
    }

    /// Step 1. `authorizationOK` is the outcome of `verifyExternalForm` (or true in user mode).
    public func issueToken(peerUID: uid_t, isAdmin: Bool, authorizationOK: Bool) -> Result<String, Failure> {
        guard isAdmin else { return .failure(.notAdmin) }
        guard authorizationOK else { return .failure(.authorizationMissing) }
        var nonce = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce)
        let expires = clock.now().addingTimeInterval(tokenTTL)
        let body = "\(nonce.map { String(format: "%02x", $0) }.joined()).\(peerUID).\(Int(expires.timeIntervalSince1970))"
        let token = body + "." + key.mac(Data(body.utf8))
        lock.lock(); issued[token] = (peerUID, expires); lock.unlock()
        return .success(token)
    }

    /// Step 2. Single use; checks MAC, expiry and that the same uid redeems it. On success opens an authenticated
    /// session for `purpose` lasting `sessionSeconds` (a pause window, or the few minutes an uninstall takes), during
    /// which that uid's actions on our files are not treated as attacks.
    public func redeem(_ token: String, peerUID: uid_t, purpose: Purpose = .pause, sessionSeconds: TimeInterval = 600) -> Result<Void, Failure> {
        let parts = token.split(separator: ".").map(String.init)
        guard parts.count == 4, key.mac(Data(parts[0...2].joined(separator: ".").utf8)) == parts[3] else { return .failure(.tokenInvalid) }
        lock.lock(); defer { lock.unlock() }
        guard let rec = issued[token] else { return .failure(.tokenInvalid) }
        guard rec.uid == peerUID else { return .failure(.tokenForOtherUser) }   // not consumed: the right user may still redeem
        issued[token] = nil
        guard clock.now() <= rec.expires else { return .failure(.tokenExpired) }
        sessions[peerUID] = (purpose, clock.now().addingTimeInterval(sessionSeconds))
        return .success(())
    }

    public func hasActiveSession(uid: uid_t, purpose: Purpose? = nil) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let s = sessions[uid], clock.now() <= s.until else { return false }
        return purpose == nil || s.purpose == purpose
    }
    public func endSession(uid: uid_t) { lock.lock(); sessions[uid] = nil; lock.unlock() }

    /// Uninstall: the only sanctioned path. The app/CLI obtains a token (admin + Authorization), redeems it with
    /// purpose `.uninstall`, and the daemon then runs these in order. Anything else deleting our files is tampering.
    public func uninstallCommands(paths: GuardPaths) -> [GuardCommand] {
        let ring = GuardianRing(paths: paths)
        var c = ImmutableFlagsPlan.unlockCommands(paths)
        c += ring.plists.map { GuardCommand(ImmutableFlagsPlan.chflags, ["noschg", $0]) }
        for j in ring.jobs.reversed() {   // sentinel and watchdog first so they do not restore the daemon mid-uninstall
            c.append(GuardCommand("/bin/launchctl", ["bootout", "system/\(j.label)"], acceptableExitCodes: [3, 113]))
            c.append(GuardCommand("/bin/rm", ["-f", j.plist, j.binary]))
        }
        c.append(GuardCommand("/bin/launchctl", ["bootout", "gui/\(getuid())/\(paths.agentLabel)"], acceptableExitCodes: [3, 113]))
        c.append(GuardCommand("/bin/rm", ["-f", paths.agentPlist]))
        c.append(GuardCommand("/bin/rm", ["-rf", paths.supportRoot]))
        return c
    }

    /// Copy for the UI; true in every build. Keep it next to the toggle.
    public static let honestLimitCopy =
        "Turning protection off needs an administrator password. A script cannot do it through \(Product.name). " +
        "macOS still lets a root process stop any background service, so \(Product.name) watches for that, alerts you, and restarts itself."
}

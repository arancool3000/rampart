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
    case clockTamper          // hx5/X4.9: system clock set (expires allowances, stretches/defeats time-boxed trust)
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

    // Update awareness: app-bundle changes and launch-plist edits by tools are held for `updateGrace` seconds and
    // reported only if the bundle / plist is not RamPart's afterwards. Pending items are flushed on every inspect()
    // and by flushPending() (the daemon should call it from a timer every few seconds).
    public var updateGrace: TimeInterval = 30
    /// Is the bundle at this path a valid RamPart build? Default: RamPartIdentity.isValidBundle (static code check).
    public var bundleValidator: @Sendable (String) -> Bool
    /// Is the launch plist at this path RamPart's own job? Default: RamPartIdentity.isOurPlist.
    public var plistValidator: @Sendable (String) -> Bool
    /// Is the RamPart service still running? The detector lives in the service, so true by default.
    public var serviceAlive: @Sendable () -> Bool = { true }
    /// hx5: a held change can be extended by new activity, but never beyond `maxHold` after it was first seen, so an
    /// attacker who keeps touching the bundle cannot keep a swap pending forever.
    public var maxHold: TimeInterval = 120
    /// hx5: the sealed install manifest. When set, the default bundle validator also requires the bundle's helpers to
    /// match it (or a trusted Team ID), so an ad-hoc look-alike signed as `app.rampart.daemon` no longer passes, and
    /// processes running from inside the user-writable app bundle count as RamPart only if they match it.
    public var manifestProvider: (@Sendable () -> InstallManifest?)? {
        didSet {
            guard let mp = manifestProvider else { return }
            let teams = trustedTeamIDs
            bundleValidator = { RamPartIdentity.isGenuineBundle($0, trustedTeamIDs: teams, manifest: mp()) }
        }
    }
    /// hx5: signing identifiers without a trusted Team ID are attacker-chosen (`codesign -s - --identifier app.rampart.x`).
    /// They no longer exempt a process. Leave false in production.
    public var trustUnverifiedSigningIDs = false
    private struct Pending { var detection: Detection; let path: String; let isPlist: Bool; var due: Date; let firstSeen: Date }
    private var pending: [String: Pending] = [:]

    public init(paths: GuardPaths = .standard, ownPIDs: @escaping @Sendable () -> Set<Int32> = { [getpid()] },
                trustedTeamIDs: Set<String> = []) {
        self.paths = paths; self.ownPIDs = ownPIDs; self.trustedTeamIDs = trustedTeamIDs
        let p = paths
        bundleValidator = { RamPartIdentity.isValidBundle($0, trustedTeamIDs: trustedTeamIDs) }
        plistValidator = { RamPartIdentity.isOurPlist($0, paths: p) }
    }

    /// Number of held (not yet decided) bundle/plist changes.
    public var pendingCount: Int { lock.lock(); defer { lock.unlock() }; return pending.count }

    private func hold(_ d: Detection, key: String, path: String, isPlist: Bool, at date: Date) {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        let due = max(date, now).addingTimeInterval(updateGrace)
        if var p = pending[key] {   // keep the first detection, extend the window, but never past firstSeen + maxHold
            p.due = min(max(p.due, due), p.firstSeen.addingTimeInterval(max(maxHold, updateGrace))); pending[key] = p
        } else if pending.count < 256 {
            pending[key] = Pending(detection: d, path: path, isPlist: isPlist, due: due, firstSeen: now)
        } else {
            overflow.append(d)   // hx5: a flood of distinct held keys must not drop a real tamper silently
        }
    }
    private var overflow: [Detection] = []

    /// Decides held changes whose grace period is over (all of them with `force`). Returns the ones that are tampering.
    public func flushPending(now: Date = Date(), force: Bool = false) -> [Detection] {
        lock.lock()
        // hx5: a clock moved backwards would leave `due` far in the future; anything due later than the longest
        // possible hold is treated as due now.
        let horizon = now.addingTimeInterval(max(maxHold, updateGrace) + 1)
        let ready = pending.filter { force || $0.value.due <= now || $0.value.due > horizon }
        for k in ready.keys { pending[k] = nil }
        let spilled = overflow; overflow = []
        lock.unlock()
        return spilled + flushUnloads(now: now, force: force) + ready.values.sorted { $0.detection.date < $1.detection.date }.compactMap { p in
            if p.isPlist {
                return FileManager.default.fileExists(atPath: p.path) && plistValidator(p.path) ? nil : p.detection
            }
            return bundleValidator(paths.appBundle) && serviceAlive() ? nil : p.detection
        }
    }

    public static let launchctlReloadVerbs: Set<String> = ["bootstrap", "load", "kickstart"]
    public static let userDaemonLabel = Product.bundlePrefix + ".userdaemon"
    static func sessionJobLabels(_ paths: GuardPaths) -> [String] { [paths.agentLabel, userDaemonLabel] }
    private var reloaded: [String: Date] = [:]
    private struct HeldUnload { let detection: Detection; let label: String; let firstSeen: Date; let due: Date }
    private var heldUnloads: [String: HeldUnload] = [:]

    private func holdUnload(_ d: Detection, label: String, at date: Date) {
        lock.lock(); defer { lock.unlock() }
        // wms-o7: bootout, bootstrap, bootout again used to leave the FIRST hold in place; the bootstrap in between then
        // counted as "reloaded" and the final bootout (the job really gone) was never reported. A hold that has already
        // been answered by a reload is replaced by the new unload.
        if let h = heldUnloads[label], let r = reloaded[label], r >= h.firstSeen { heldUnloads[label] = nil }
        if heldUnloads[label] == nil, heldUnloads.count < 16 {
            heldUnloads[label] = HeldUnload(detection: d, label: label, firstSeen: date, due: max(date, Date()).addingTimeInterval(updateGrace))
        }
    }

    /// Held session-job unloads whose grace period is over: reported unless the same job was loaded again since.
    private func flushUnloads(now: Date, force: Bool) -> [Detection] {
        lock.lock(); defer { lock.unlock() }
        let horizon = now.addingTimeInterval(max(maxHold, updateGrace) + 1)
        var out: [Detection] = []
        for (k, h) in heldUnloads {
            let back = reloaded[h.label].map { $0 >= h.firstSeen } ?? false
            if back { heldUnloads[k] = nil; continue }
            if force || h.due <= now || h.due > horizon { heldUnloads[k] = nil; out.append(h.detection) }
        }
        return out
    }

    public static let launchctlUnloadVerbs: Set<String> = ["bootout", "unload", "disable", "remove", "kill", "stop", "bsexec", "asuser", "submit", "attach", "debug"]
    public static let killers: Set<String> = ["kill", "pkill", "killall"]
    /// hx5: Apple signing identifiers of the tools, so a renamed copy (`cp /bin/launchctl /tmp/lc`) is still recognised.
    public static let signingIDToTool: [String: String] = ["com.apple.xpc.launchctl": "launchctl", "com.apple.kill": "kill", "com.apple.pkill": "pkill",
                                                           "com.apple.killall": "killall", "com.apple.rm": "rm", "com.apple.mv": "mv", "com.apple.cp": "cp",
                                                           "com.apple.chflags": "chflags", "com.apple.plutil": "plutil", "com.apple.defaults": "defaults",
                                                           "com.apple.tccutil": "tccutil", "com.apple.profiles": "profiles",
                                                           "com.apple.systemsetup": "systemsetup", "com.apple.sntp": "sntp", "com.apple.date": "date"]
    public static let fileMutators: Set<String> = ["rm", "mv", "cp", "chflags", "chmod", "chown", "plutil", "defaults", "truncate", "tee", "install", "ln"]
    /// Tools that reset system state we depend on (TCC grants such as Full Disk Access, configuration profiles).
    public static let resetters: Set<String> = ["tccutil", "profiles"]
    public static let clockTools: Set<String> = ["systemsetup", "sntp", "date", "ntpdate"]

    private func isSelf(_ p: ProcessInfoLite?) -> Bool {
        guard let p else { return false }
        let own = ownPIDs()
        if own.contains(p.pid) { return true }
        // hx5: a child the daemon spawned itself (ditto/mv during an update, the CLI) is ours too.
        if p.ppid > 1, own.contains(p.ppid) { return true }
        if let t = p.teamID, !t.isEmpty, trustedTeamIDs.contains(t) { return true }
        if trustUnverifiedSigningIDs, let s = p.signingID, s.hasPrefix(Product.bundlePrefix) { return true }
        // hx5: the path rule only covers root-owned install locations. /Applications/RamPart.app is usually writable by
        // the admin user, so a binary dropped into it is ours only when it matches the sealed manifest.
        if paths.isInAppBundle(p.path) {
            guard let m = manifestProvider?(), let expected = m.entries[p.path] else { return false }
            return InstallManifest.sha256(ofFile: p.path) == expected
        }
        if paths.isProtected(p.path) { return true }
        return false
    }

    /// The installed plist of a per-user session job: the menu bar agent's in /Library/LaunchAgents, the user helper's inside
    /// the app bundle (SMAppService). Symlinks resolved; anything elsewhere is a look-alike.
    func isOwnSessionPlist(_ arg: String, label: String) -> Bool {
        guard arg.hasPrefix("/"), arg.count < 4096 else { return false }
        let cands = label == paths.agentLabel ? [paths.agentPlist] : [paths.appBundle + "/Contents/Library/LaunchAgents/\(label).plist"]
        let a = GuardPaths.normalize((arg as NSString).resolvingSymlinksInPath).lowercased()
        let raw = GuardPaths.normalize(arg).lowercased()
        return cands.map { GuardPaths.normalize($0).lowercased() }.contains { $0 == a || $0 == raw }
    }

    /// Resolves symlinks in a path-like argument so `launchctl unload /tmp/link.plist` (link -> our plist) counts.
    private func isProtectedArg(_ a: String) -> Bool {
        if paths.isProtected(a) { return true }
        guard a.hasPrefix("/"), a.count < 4096 else { return false }
        let r = (a as NSString).resolvingSymlinksInPath
        return r != a && paths.isProtected(r)
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
        var out: [Detection] = flushPending()
        if isSelf(ev.process) { return out }
        switch ev.kind {
        case .exec:
            out += inspectExec(ev)
        case .fileWrite, .fileCreate, .fileClose, .fileDelete, .fileRename, .xattrDelete:
            for p in [ev.path, ev.destPath].compactMap({ $0 }) where paths.isProtected(p) {
                if ev.kind == .fileClose, ev.detail["modified"] == "0" { continue }
                let isPlist = paths.isPlist(p)
                // A plist rewritten with RamPart's own job definition (e.g. by our installer) is not tampering.
                if isPlist, ev.kind != .fileDelete, ev.kind != .xattrDelete, p != ev.path || ev.kind != .fileRename,
                   FileManager.default.fileExists(atPath: p), plistValidator(p) { continue }
                let kind: TamperKind = isPlist ? .plistTamper : (paths.isCritical(p) ? .configTamper : .fileTamper)
                let sev: Severity = isPlist || paths.isCritical(p) ? .critical : .high
                guard dedupe("\(kind.rawValue):\(p):\(ev.process?.pid ?? 0)", at: ev.date) else { continue }
                let d = detection(kind, severity: sev, score: sev == .critical ? 92 : 80, title: "\(ev.kind.rawValue) on a protected \(Product.name) file",
                                  detail: p, ev: ev, path: p)
                // App-bundle changes may be an update in progress: decide once the bundle has settled.
                if !isPlist, !paths.isCritical(p), paths.isInAppBundle(p) { hold(d, key: "bundle", path: p, isPlist: false, at: ev.date); continue }
                out.append(d)
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
                // Only the service matters: quitting or killing the app's UI process is not tampering.
                if (targetPID.map { ownPIDs().contains($0) } ?? false) || paths.isServiceBinary(targetPath),
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
        var tool = ((args.first ?? p.path) as NSString).lastPathComponent
        if let sid = p.signingID, let t = Self.signingIDToTool[sid] { tool = t }   // renamed copy of an Apple tool
        else if !Self.killers.contains(tool), !Self.fileMutators.contains(tool), tool != "launchctl" {
            let real = (p.path as NSString).lastPathComponent
            if Self.killers.contains(real) || real == "launchctl" || Self.fileMutators.contains(real) { tool = real }
        }
        let joined = args.joined(separator: " ")
        let lower = joined.lowercased()
        if Self.killers.contains(tool) {
            guard killTargetsService(tool: tool, args: Array(args.dropFirst())), dedupe("kill:\(p.pid)", at: ev.date) else { return [] }
            return [detection(.killAttempt, severity: .critical, score: 90, title: "\(tool) aimed at \(Product.name)", detail: joined, ev: ev, path: nil)]
        }
        let mentionsUs = paths.isOurLabel(joined) || lower.contains("rampartd") || lower.contains("rampart")
            || args.contains(where: { isProtectedArg($0) })
        // hx5/X4.8: `tccutil reset SystemPolicyAllFiles` with no bundle id strips every app's Full Disk Access, ours included.
        if tool == "tccutil", args.dropFirst().first?.lowercased() == "reset" {
            let service = args.dropFirst(2).first ?? ""
            let global = ["SystemPolicyAllFiles", "All", "Accessibility", "ScreenCapture", "kTCCServiceSystemPolicyAllFiles"].contains(service)
            let bundleOperand = args.dropFirst(3).first
            if global, bundleOperand == nil || paths.isOurLabel(bundleOperand ?? "") {
                guard dedupe("tccreset:\(p.pid)", at: ev.date) else { return [] }
                return [detection(.fileTamper, severity: bundleOperand == nil ? .high : .critical, score: bundleOperand == nil ? 80 : 90,
                                  title: "tccutil reset would strip \(Product.name)'s Full Disk Access",
                                  detail: joined + (bundleOperand == nil ? " (resets every app, \(Product.name) included)" : ""), ev: ev, path: nil)]
            }
        }
        // hx5/X4.9: clock changes. macOS lets admins set the clock, so this is detect-and-explain.
        if Self.clockTools.contains(tool) {
            let flags = args.dropFirst().filter { $0.hasPrefix("-") }
            let sets: Bool
            switch tool {
            case "systemsetup": sets = lower.contains("-setdate") || lower.contains("-settime") || lower.contains("-setusingnetworktime")
                || lower.contains("-setnetworktimeserver") || lower.contains("-settimezone")
            case "date": sets = args.dropFirst().contains { !$0.hasPrefix("-") && !$0.hasPrefix("+") && $0.rangeOfCharacter(from: .decimalDigits) != nil }
            case "sntp": sets = flags.contains { !$0.hasPrefix("--") && ($0.contains("s") || $0.contains("S")) }
            default: sets = true   // ntpdate, timed control tools
            }
            if sets, dedupe("clock:\(p.pid)", at: ev.date) {
                return [detection(.clockTamper, severity: .medium, score: 55, title: "System clock is being changed",
                                  detail: joined + ": this can expire \(Product.name) allowances and definition freshness", ev: ev, path: nil)]
            }
        }
        // A tool we don't recognise whose arguments still read like "launchctl bootout system/app.rampart.daemon"
        // (a renamed launchctl copy without signing info) is treated as launchctl.
        if tool != "launchctl", !Self.killers.contains(tool), !Self.fileMutators.contains(tool),
           args.dropFirst().contains(where: { Self.launchctlUnloadVerbs.contains($0) }),
           args.dropFirst().contains(where: { a in paths.labels.contains { a.hasSuffix("/" + $0) || a == $0 } }) { tool = "launchctl" }
        guard mentionsUs else { return [] }

        // rampart-setup.sh install / install-from reloads the per-user jobs: `launchctl bootout gui/<uid>/app.rampart.agent`
        // then `launchctl bootstrap gui/<uid> /Library/LaunchAgents/app.rampart.agent.plist`. A reload is noted here.
        if tool == "launchctl", let verb = args.dropFirst().first(where: { Self.launchctlReloadVerbs.contains($0) }) {
            // wms-o7: only a bootstrap / load of OUR plist file brings the job back. `bootstrap gui/501 /tmp/x/app.rampart.agent.plist`
            // (a look-alike job under our label) and `kickstart` (which can't load an unloaded job) used to count as a reload.
            if verb != "kickstart" {
                for label in Self.sessionJobLabels(paths) where args.dropFirst().contains(where: { isOwnSessionPlist($0, label: label) }) {
                    lock.lock(); reloaded[label] = ev.date; lock.unlock()
                }
            }
        }
        if tool == "launchctl", args.dropFirst().contains(where: { Self.launchctlUnloadVerbs.contains($0) }), paths.isOurLabel(joined) || args.contains(where: isProtectedArg) {
            // wms-o7: a repeat of the same bootout after a reload is a new unload, not a duplicate.
            lock.lock(); let stamp = Self.sessionJobLabels(paths).compactMap { reloaded[$0]?.timeIntervalSince1970 }.max() ?? 0; lock.unlock()
            guard dedupe("unload:\(joined):\(stamp)", at: ev.date) else { return [] }
            let d = detection(.unloadAttempt, severity: .critical, score: 95, title: "launchctl used against \(Product.name)", detail: joined, ev: ev, path: nil)
            // Only the per-user session jobs (menu bar agent, user helper) are held: a bootout followed by a bootstrap of the
            // same job within the grace period is an install / upgrade reloading it, not tampering. The system service
            // labels are always reported at once.
            let targets = args.dropFirst().filter { a in paths.labels.contains { a.hasSuffix("/" + $0) } || a.hasSuffix("/" + Self.userDaemonLabel) }
            let session = Self.sessionJobLabels(paths)
            if !targets.isEmpty, targets.allSatisfy({ t in t.hasPrefix("gui/") && session.contains { t.hasSuffix("/" + $0) } }),
               let label = session.first(where: { l in targets.contains { $0.hasSuffix("/" + l) } }) {
                holdUnload(d, label: label, at: ev.date); return []
            }
            return [d]
        }
        if Self.fileMutators.contains(tool), let target = args.first(where: isProtectedArg) {
            guard dedupe("mutate:\(p.pid):\(target)", at: ev.date) else { return [] }
            let isPlist = paths.isPlist(target)
            let unlocking = tool == "chflags" && args.contains(where: { $0.contains("noschg") || $0.contains("nouchg") })
            let d = detection(isPlist || unlocking ? .plistTamper : .fileTamper, severity: isPlist || unlocking ? .critical : .high, score: isPlist || unlocking ? 92 : 80,
                              title: unlocking ? "Immutable flag being cleared on a \(Product.name) file" : "\(tool) run on a protected \(Product.name) path",
                              detail: joined, ev: ev, path: target)
            if !unlocking {
                // Plist edited by a tool (not removed): judge the content once the tool is done.
                if isPlist, tool != "rm" { hold(d, key: "plist:\(target)", path: target, isPlist: true, at: ev.date); return [] }
                // Anything aimed only at the app bundle may be an update (ditto / rm -rf / mv): decide once it settles.
                let targets = args.dropFirst().filter(paths.isProtected)
                if !targets.isEmpty, targets.allSatisfy({ paths.isInAppBundle($0) && !paths.isCritical($0) }) {
                    hold(d, key: "bundle", path: target, isPlist: false, at: ev.date); return []
                }
            }
            return [d]
        }
        if Self.resetters.contains(tool), paths.isOurLabel(joined) {
            guard dedupe("reset:\(p.pid)", at: ev.date) else { return [] }
            return [detection(.fileTamper, severity: .critical, score: 90, title: "\(tool) aimed at \(Product.name) (TCC/profile reset)", detail: joined, ev: ev, path: nil)]
        }
        if (lower.contains("exclu") || lower.contains("allow")) && args.contains(where: isProtectedArg) {
            guard dedupe("excl:\(p.pid)", at: ev.date) else { return [] }
            return [detection(.exclusionOfSelf, severity: .high, score: 85, title: "Attempt to exclude \(Product.name) from scanning", detail: joined, ev: ev, path: nil)]
        }
        return []
    }

    /// kill / pkill / killall: true only if the target is the RamPart service (daemon, watchdog, bundled helper),
    /// not the app's UI process. kill takes pids; pkill matches a pattern against the name (or, with -f, the
    /// full command line); killall matches exact process names.
    private func killTargetsService(tool: String, args: [String]) -> Bool {
        let flags = args.filter { $0.hasPrefix("-") }
        let operands = args.filter { !$0.hasPrefix("-") }
        if tool == "kill" {
            let own = ownPIDs()
            // hx5: `kill -9 -1` (every process the caller may signal) and `kill -- -PGID` used to be read as flags.
            var pids: [Int32] = []
            var i = 0, endOfOptions = false, sawSignal = false, zeroSignal = false
            while i < args.count {
                let a = args[i]
                if endOfOptions || !a.hasPrefix("-") { if let n = Int32(a) { pids.append(n) } }
                else if a == "--" { endOfOptions = true }
                else if a == "-s" || a == "-n" {
                    if i + 1 < args.count, ["0", "SIG0", "sig0"].contains(args[i + 1]) { zeroSignal = true }
                    i += 1; sawSignal = true
                }
                else if a == "-l" || a == "-L" { return false }
                // wms-o7: signal 0 only asks "is it running?" (`kill -0 pid`, `kill -s 0 pid`); nothing is delivered.
                else if !sawSignal, ["-0", "-SIG0", "-sig0"].contains(a) { sawSignal = true; zeroSignal = true }
                else if let n = Int32(a), sawSignal { pids.append(n) }   // negative pid / process group after the signal
                else { sawSignal = true }
                i += 1
            }
            if zeroSignal { return false }
            if pids.contains(-1) { return true }
            if pids.contains(where: { $0 < -1 }) {
                let groups = Set(own.map { getpgid($0) }.filter { $0 > 0 })
                if pids.contains(where: { $0 < -1 && groups.contains(-$0) }) { return true }
            }
            return pids.contains { own.contains($0) }
        }
        // hx5: user/group-wide kills with no pattern (`killall -u root`, `pkill -U 0`) hit the root service too.
        if let ui = args.firstIndex(where: { $0 == "-u" || $0 == "-U" || $0 == "-G" }), args.indices.contains(ui + 1) {
            let who = args[ui + 1]
            if who == "0" || who == "root" || who == "wheel" { return true }
        }
        if tool == "killall", flags.contains("-m") {   // regex mode
            return operands.contains { pat in
                guard pat.count < 512, let re = try? NSRegularExpression(pattern: pat, options: flags.contains("-I") ? [.caseInsensitive] : []) else { return false }
                return paths.serviceNames.contains { re.firstMatch(in: $0, range: NSRange($0.startIndex..., in: $0)) != nil }
            }
        }
        let ci = flags.contains { $0 == "-i" || $0 == "-I" } || tool == "killall" && flags.contains("-I")
        let full = tool == "pkill" && flags.contains { $0.hasPrefix("-") && !$0.hasPrefix("--") && $0.dropFirst().contains("f") }
        let norm: (String) -> String = { ci ? $0.lowercased() : $0 }
        if tool == "killall" {
            let names = paths.serviceNames.map(norm)
            return operands.contains { names.contains(norm($0)) }
        }
        let haystacks = (full ? paths.serviceCommandLines + paths.serviceNames : paths.serviceNames).map(norm)
        let exact = tool == "pkill" && flags.contains { $0.hasPrefix("-") && !$0.hasPrefix("--") && $0.dropFirst().contains("x") }
        return operands.contains { pat in
            let p = norm(pat).replacingOccurrences(of: "^", with: "").replacingOccurrences(of: "$", with: "")
            if !p.isEmpty && haystacks.contains(where: { exact ? $0 == p : $0.contains(p) }) { return true }
            // hx5: pkill patterns are extended regexes (`pkill 'r.mpartd'`, `pkill '[r]ampartd'`).
            guard pat.count < 512, let re = try? NSRegularExpression(pattern: exact ? "^(?:" + pat + ")$" : pat, options: ci ? [.caseInsensitive] : []) else { return false }
            return haystacks.contains { re.firstMatch(in: $0, range: NSRange($0.startIndex..., in: $0)) != nil }
        }
    }

    /// For the daemon's settings handler: refuse exclusions that cover our own install paths and raise a detection.
    /// Returns the offending entries. Call before persisting `RampartSettings.exclusions`.
    public func exclusionsCoveringSelf(_ exclusions: [String]) -> [String] {
        // Normalise the protected prefixes once (not once per exclusion) and drain temporaries per entry: 100k
        // exclusions used to create ~1M autoreleased NSStrings in one request.
        let prefixes = paths.protectedPrefixes.map(GuardPaths.normalize)
        return exclusions.filter { e in
            autoreleasepool {
                let n = GuardPaths.normalize(e)
                return n == "/" || n == "/Library" || n == "/Applications"
                    || prefixes.contains { n == $0 || n.hasPrefix($0 + "/") || $0.hasPrefix(n + "/") }
            }
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
    /// Sealed install manifest, used to check a restored plist/binary is the installed one.
    public var manifest: InstallManifest?
    public init(paths: GuardPaths = .standard, store: SealedStore?, manifest: InstallManifest? = nil) { self.paths = paths; self.store = store; self.manifest = manifest }

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
                    if paths.isPlist(p) || paths.binaries.contains(p) {
                        // hx5: plists are raw files on disk; restore the payload (or legacy envelope), never the JSON wrapper.
                        if store.restoreRawIfNeeded(p, expectedSHA: manifest?.entries[p], mode: 0o644, dryRun: dryRun) {
                            r.restoredFiles.append(p); r.notes.append("\(p): restored from sealed backup")
                        }
                    } else {
                        let (verdict, restored) = store.restoreIfNeeded(p, dryRun: dryRun)
                        if restored { r.restoredFiles.append(p); r.notes.append("\(p): \(String(describing: verdict)) -> restored from sealed backup") }
                    }
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
        case .clockTamper:
            r.notes.append("clock changed: time-limited allowances and sessions are also bounded by a monotonic clock, so a rollback cannot extend them")
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
    private var issued: [String: (uid: uid_t, expires: Date, monoExpires: TimeInterval, purposes: Set<Purpose>)] = [:]
    /// Active authenticated sessions (pause or uninstall) by uid; tamper responses exempt these actors.
    /// hx5: expiry is checked against both the wall clock and a monotonic clock, so setting the date back does not
    /// stretch a session or a token.
    private var sessions: [uid_t: (purpose: Purpose, until: Date, monoUntil: TimeInterval)] = [:]
    /// Longest pause/uninstall session the daemon will open, whatever the caller asks for.
    public var maxSessionSeconds: TimeInterval = 4 * 3600

    public enum Purpose: String, Codable, Sendable, CaseIterable { case pause, uninstall, settings }
    /// wms-o7: what a token from the generic "authenticate" request may be redeemed for (pause, or a settings session:
    /// lift lockdown, restore internet, Kill Switch, settings changes). Uninstall tokens come only from requestUninstall.
    public static let generalPurposes: Set<Purpose> = [.pause, .settings]

    public init(key: IntegrityKey, clock: GuardClock = .live) { self.key = key; self.clock = clock }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case notAdmin, authorizationMissing, authorizationDenied(String), tokenInvalid, tokenExpired, tokenForOtherUser, tokenWrongPurpose
        public var description: String {
            switch self {
            case .notAdmin: return "an administrator account is required to turn protection off"
            case .authorizationMissing: return "administrator authentication is required"
            case .authorizationDenied(let s): return "authorization denied: \(s)"
            case .tokenInvalid: return "disable token is invalid or already used"
            case .tokenExpired: return "disable token expired; authenticate again"
            case .tokenForOtherUser: return "disable token belongs to a different user"
            case .tokenWrongPurpose: return "this authorization was given for a different action; authenticate again for this one"
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
    /// wms-o7: `purposes` binds the token at issue time: `redeem` refuses (and burns) it for any other purpose, so an
    /// authorization the user gave to, say, pause protection can't be spent on an uninstall. The daemon always passes an
    /// explicit set; the default (every purpose) exists for callers that predate binding.
    public func issueToken(peerUID: uid_t, isAdmin: Bool, authorizationOK: Bool,
                           purposes: Set<Purpose> = Set(Purpose.allCases)) -> Result<String, Failure> {
        guard !purposes.isEmpty else { return .failure(.tokenWrongPurpose) }
        guard isAdmin else { return .failure(.notAdmin) }
        guard authorizationOK else { return .failure(.authorizationMissing) }
        var nonce = [UInt8](repeating: 0, count: 16)
        if SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) != errSecSuccess {
            // wms-fb: never hand out an all-zero nonce; SystemRandomNumberGenerator is also a CSPRNG.
            var g = SystemRandomNumberGenerator()
            for i in nonce.indices { nonce[i] = UInt8.random(in: 0...255, using: &g) }
        }
        let expires = clock.now().addingTimeInterval(tokenTTL)
        let body = "\(nonce.map { String(format: "%02x", $0) }.joined()).\(peerUID).\(Int(expires.timeIntervalSince1970))"
        let token = body + "." + key.mac(domain: "disable-token", Data(body.utf8))
        let mono = clock.monotonic()
        lock.lock()
        issued = issued.filter { clock.now() <= $0.value.expires && mono <= $0.value.monoExpires }   // bounded
        if issued.count >= 64 { issued.removeAll() }
        issued[token] = (peerUID, expires, mono + tokenTTL, purposes)
        lock.unlock()
        return .success(token)
    }

    /// Step 2. Single use; checks MAC, expiry and that the same uid redeems it. On success opens an authenticated
    /// session for `purpose` lasting `sessionSeconds` (a pause window, or the few minutes an uninstall takes), during
    /// which that uid's actions on our files are not treated as attacks.
    public func redeem(_ token: String, peerUID: uid_t, purpose: Purpose = .pause, sessionSeconds: TimeInterval = 600) -> Result<Void, Failure> {
        let parts = token.split(separator: ".").map(String.init)
        guard parts.count == 4, token.utf8.count < 512,
              IntegrityKey.constantTimeEqual(key.mac(domain: "disable-token", Data(parts[0...2].joined(separator: ".").utf8)), parts[3]) else { return .failure(.tokenInvalid) }
        lock.lock(); defer { lock.unlock() }
        guard let rec = issued[token] else { return .failure(.tokenInvalid) }
        guard rec.uid == peerUID else { return .failure(.tokenForOtherUser) }   // not consumed: the right user may still redeem
        issued[token] = nil
        // Wrong purpose: burned, not kept for later (a token is spent on the first attempt by its owner).
        guard rec.purposes.contains(purpose) else { return .failure(.tokenWrongPurpose) }
        let mono = clock.monotonic()
        guard clock.now() <= rec.expires, mono <= rec.monoExpires else { return .failure(.tokenExpired) }
        let secs = max(0, min(sessionSeconds.isFinite ? sessionSeconds : 0, maxSessionSeconds))
        sessions[peerUID] = (purpose, clock.now().addingTimeInterval(secs), mono + secs)
        return .success(())
    }

    public func hasActiveSession(uid: uid_t, purpose: Purpose? = nil) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let s = sessions[uid], clock.now() <= s.until, clock.monotonic() <= s.monoUntil else { return false }
        return purpose == nil || s.purpose == purpose
    }
    public func endSession(uid: uid_t) { lock.lock(); sessions[uid] = nil; lock.unlock() }

    /// Uninstall: the only sanctioned path. The app/CLI obtains a token (admin + Authorization), redeems it with
    /// purpose `.uninstall`, and the daemon then runs these in order. Anything else deleting our files is tampering.
    public func uninstallCommands(paths: GuardPaths) -> [GuardCommand] {
        let ring = GuardianRing(paths: paths)
        var c = ImmutableFlagsPlan.unlockCommands(paths)
        c += ring.plists.filter { p in !c.contains { $0.arguments == ["noschg", p] } }.map { GuardCommand(ImmutableFlagsPlan.chflags, ["noschg", $0]) }
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
        "macOS still lets a root process stop any background service, so \(Product.name) watches for what it can see, alerts you, and restarts itself. " +
        "A root process that acts quickly enough (unloading all three guardians at once, or freezing them together) can still stop it."
}

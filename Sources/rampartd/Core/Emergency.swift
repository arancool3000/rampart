import Foundation
import RampartShared
import RampartGuard
import RampartRemediation

/// Emergency Lockdown in the daemon. Decisions, plans and state live in RampartGuard/EmergencyLockdown.swift;
/// this file executes them. Commands (pfctl, tmutil, launchctl) and signals run for real only in the installed
/// root daemon (GuardService.enforce: root, /Library/PrivilegedHelperTools, no RAMPART_NO_PRIVILEGED_TOOLS);
/// everywhere else every step is recorded as a dry run. Every step is logged; undoable steps are undone on lift.
///
/// Hooks (added by the lead):
///   DaemonWiring after Protection is built:      Emergency.start(protection)
///   Protection.handle, right after store.add:    Emergency.consider(d, protection: self)
///   Router: see the IPC cases in the final report (all return `.emergency(Data)`).
enum Emergency {
    nonisolated(unsafe) private static var controller: EmergencyController?
    nonisolated(unsafe) private static var timer: DispatchSourceTimer?
    private static let lock = NSLock()
    private static let q = DispatchQueue(label: "app.rampart.emergency", qos: .userInitiated)
    static let firewall = EmergencyFirewall()

    static func ctl(_ p: Protection) -> EmergencyController {
        lock.lock(); defer { lock.unlock() }
        if let c = controller { return c }
        let c = EmergencyController(path: p.runtime.root.appendingPathComponent("emergency.json").path)
        controller = c
        return c
    }

    static func enforcing(_ p: Protection) -> Bool { p.services.guardian?.enforce ?? false }
    static func mode(_ p: Protection) -> String { enforcing(p) ? "enforcing" : "dry run (actions are recorded, not carried out)" }

    // MARK: lifecycle

    /// Daemon start: a persisted MANUAL lockdown is re-applied (it survives reboots). An automatic one comes back
    /// without its network block, and any leftover emergency anchor is removed. Then the watch timer starts.
    static func start(_ p: Protection) {
        let c = ctl(p)
        // User incident 2026-11-09: a stale automatic lockdown started by RamPart's own (reinstalled, now verified) files
        // survived the reinstall. Re-check it first; a false alarm is lifted, undone, logged and announced.
        if c.isActive, recheckOnStart(p, c) {
            q.async { unloadNetwork(p, c, why: "false alarm lifted at start") }
        } else {
            let reapplyNet = c.prepareForRestart()
            if c.isActive { q.async { reapply(p, c, network: reapplyNet) } }
            if !reapplyNet { q.async { unloadNetwork(p, c, why: "start: no network block wanted") } }
        }
        startWatch(p, c)
    }

    /// Daemon start with an active lockdown: an automatic one whose trigger was RamPart's own now-verified files, or
    /// that no longer qualifies under the current trigger policy, is lifted. A manual lockdown is never auto-lifted.
    /// Returns true when it was lifted.
    @discardableResult
    static func recheckOnStart(_ p: Protection, _ c: EmergencyController) -> Bool {
        let st = c.state
        let d = st.reason?.detectionID.flatMap { p.store.get($0) }
        guard let why = EmergencyFalseAlarm.reason(state: st, detection: d,
                                                   isVerifiedOwnFile: { OwnInstall.isVerifiedOwnFile($0, p) },
                                                   isOwnPath: { OwnInstall.isOwnPath($0, p) }),
              let undo = c.liftFalseAlarm(why: why) else { return false }
        undoActions(p, c, undo)
        restoreOwnQuarantined(p, c, st)
        if let id = st.reason?.detectionID { _ = p.store.update(id) { $0.resolved = true } }
        logWarn("emergency: lockdown lifted at start, false alarm: \(why)")
        p.activity.add(.system, "Emergency lockdown lifted: false alarm", detail: why, outcome: "lifted (false alarm)", severity: .medium,
                       detectionID: st.reason?.detectionID, event: .lockdownLifted, actor: .system,
                       reason: "Re-checked when the \(Product.name) service started", action: "Lifted lockdown and undid its steps")
        notify(p, c, .falseAlarm)
        return true
    }

    /// Our own files a false-alarm lockdown quarantined come back only if nothing (e.g. a reinstall) replaced them.
    private static func restoreOwnQuarantined(_ p: Protection, _ c: EmergencyController, _ st: EmergencyState) {
        let paths = Set(st.actions.filter { $0.kind == .quarantineFiles }.flatMap(\.paths).filter { OwnInstall.isOwnPath($0, p) })
        guard !paths.isEmpty else { return }
        for rec in p.services.quarantine.list() where paths.contains(rec.originalPath) {
            if FileManager.default.fileExists(atPath: rec.originalPath) {
                c.log("Kept \(rec.originalPath) as reinstalled; its quarantined copy stays in the vault")
                continue
            }
            // Only a copy pinned by the sealed install manifest goes back; anything else stays in the vault.
            guard let pinned = p.services.guardian?.manifest?.entries[rec.originalPath], pinned.lowercased() == rec.sha256.lowercased() else {
                c.log("Left \(rec.originalPath) in quarantine (not pinned by the install manifest); reinstalling \(Product.name) puts it back")
                continue
            }
            do { _ = try p.services.quarantine.restore(id: rec.id); c.log("Restored \(Product.name)'s own file \(rec.originalPath)") }
            catch { c.log("Couldn't restore \(rec.originalPath): \(error.localizedDescription)") }
        }
    }

    private static func startWatch(_ p: Protection, _ c: EmergencyController) {
        let t = DispatchSource.makeTimerSource(queue: q)
        t.schedule(deadline: .now() + 15, repeating: 15, leeway: .seconds(2))
        t.setEventHandler { watch(p, c) }
        t.resume()
        lock.lock(); timer = t; lock.unlock()
    }

    /// Called for every stored detection. Auto-triggers only per EmergencyTriggerPolicy.
    static func consider(_ d: Detection, protection p: Protection) {
        // Health problems (a telemetry source down / not permitted / missing Full Disk Access) are never a trigger.
        if EmergencyTriggerPolicy.isHealthIssue(d) { return }
        // RamPart's own verified files (an install / upgrade rewriting them) never trigger or feed a lockdown.
        if let path = d.path, OwnInstall.isVerifiedOwnFile(path, p) {
            logInfo("emergency: ignored \(d.name): \(path) is \(Product.name)'s own verified file"); return
        }
        let c = ctl(p)
        let allow: (Detection) -> Bool = { d in
            if let h = d.sha256, p.runtime.config.allowlist.contains(h) { return true }
            if let path = d.path, p.runtime.config.exclusions.contains(where: { path == $0 || path.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }) { return true }
            return false
        }
        let reason = EmergencyTriggerPolicy.evaluate(d, isAllowlisted: allow)
        if c.isActive {
            _ = c.noteDetection(d, isVerifiedOwnFile: { OwnInstall.isVerifiedOwnFile($0, p) })
            guard let reason else { return }
            let a = c.assess(reason)
            if a.containNetwork, !c.state.isNetworkBlocked {
                q.async { if c.upgradeToNetwork(why: a.why) { applyNetwork(c, enforce: enforcing(p) && !c.state.dryRun); notify(p, c, .networkBlocked) } }
            }
            return
        }
        guard let reason else { return }
        automatic(p, reason: reason, detection: d)
    }

    /// Every automatic trigger goes through the safety policy: corroboration, no network on a single signal.
    static func automatic(_ p: Protection, reason: EmergencyTriggerReason, detection: Detection?) {
        let c = ctl(p)
        let a = c.assess(reason)
        guard a.engage else {
            c.log("Signal recorded, no lockdown: \(reason.summary). \(a.why)")
            p.activity.add(.system, "Suspicious signal noted (no lockdown)", detail: reason.summary, outcome: "watching", severity: .medium,
                           detectionID: reason.detectionID, event: .detection, actor: .system, reason: a.why)
            return
        }
        q.async { engage(p, reason: reason, detection: detection, containNetwork: a.containNetwork, why: a.why) }
    }

    // MARK: IPC entry points (Router)

    static func status(_ p: Protection) throws -> Data { try JSONEncoder.rampart.encode(ctl(p).status(mode: mode(p))) }

    static func manual(_ p: Protection, peer: Peer, reason note: String) throws -> Data {
        q.sync { engage(p, reason: .manual(uid: peer.uid, note: note), detection: nil, containNetwork: true, why: "You turned on Emergency Lockdown.") }
        return try status(p)
    }

    /// Re-scan the involved locations plus a quick scan; updates readiness.
    static func rescan(_ p: Protection) throws -> Data {
        let c = ctl(p)
        guard c.isActive else { throw ServiceError.failed(EmergencyError.notActive.description) }
        let st = c.state
        let dirs = Set(([st.reason?.path].compactMap { $0 } + st.actions.flatMap { $0.kind == .quarantineFiles ? $0.paths : [] })
            .map { ($0 as NSString).deletingLastPathComponent }.filter { !$0.isEmpty && $0 != "/" })
        let out = p.scan(paths: Array(dirs), quick: dirs.isEmpty, actor: .system, progress: { _, _, _, _ in })
        let critical = out.detections.filter { $0.severity >= .high && !$0.resolved && !EmergencyTriggerPolicy.isTestArtifact($0) }
        let triggerGone: Bool = {
            guard let r = st.reason else { return true }
            if r.kind == .manual { return true }
            if let id = r.detectionID, p.store.get(id)?.resolved == true { return true }
            if let path = r.path { return !FileManager.default.fileExists(atPath: path) }
            return r.pid.map { ProcessKiller.info($0) == nil } ?? false
        }()
        c.noteRescan(clean: critical.isEmpty, triggerGone: triggerGone)
        return try status(p)
    }

    /// Lift: token from requestDisableProtection, redeemed for a settings session (admin auth); undo actions.
    /// The owner is authorized by a root peer (`sudo rampart emergency off`) or by redeeming an admin token.
    /// User incident 2026-11-07: lifting failed behind the readiness gate; an authorized lift now always succeeds.
    static func authorize(_ p: Protection, token: String?, peer: Peer) throws {
        if peer.uid == 0 { return }
        guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection") }
        guard let token, !token.isEmpty else { throw ServiceError.denied(EmergencyError.notAuthorized.description) }
        do { try g.redeem(token, peer: peer, purpose: .settings, minutes: 5) }
        catch { throw ServiceError.denied(EmergencyError.notAuthorized.description + " (\(error.localizedDescription))") }
    }

    static func lift(_ p: Protection, token: String, force: Bool, peer: Peer) throws -> Data {
        let c = ctl(p)
        guard c.isActive else {
            // Nothing recorded, but a stale anchor may still block: always clean up for the owner.
            try authorize(p, token: token, peer: peer)
            unloadNetwork(p, c, why: "lift while not active"); return try status(p)
        }
        try authorize(p, token: token, peer: peer)
        let ready = c.readiness()?.ready ?? true
        let undo: [EmergencyAction]
        do { undo = try c.lift(authorized: true, force: true) } catch let e as EmergencyError { throw ServiceError.failed(e.description) }
        undoActions(p, c, undo)
        let who = peer.uid == 0 ? "root (command line)" : "an administrator"
        p.activity.add(.system, "Emergency lockdown lifted", detail: "Lifted by \(who)" + (ready ? "; all checks passed" : "; lifted before every check passed"),
                       outcome: "lifted", severity: .medium, event: .lockdownLifted, actor: .user)
        notify(p, c, .lifted)
        return try status(p)
    }

    /// Undo: always unloads the network anchor (whatever the action's recorded state), resumes frozen processes,
    /// re-enables paused startup items. Every step is independent.
    static func undoActions(_ p: Protection, _ c: EmergencyController, _ undo: [EmergencyAction]) {
        let enforce = enforcing(p)
        unloadNetwork(p, c, why: "lift")
        for a in undo {
            switch a.kind {
            case .suspendProcesses:
                if enforce { for pid in a.pids where ProcessKiller.info(pid) != nil { _ = Darwin.kill(pid, SIGCONT) } }
            case .pauseLaunchItems:
                if enforce { _ = run(a.undoCommands) }
            default: break
            }
            c.log("Undone: \(a.title)\(enforce ? "" : " (dry run)")")
        }
    }

    /// "Restore internet now": the admin password (or root) ends the network block. No readiness gate.
    static func restoreNetwork(_ p: Protection, token: String?, peer: Peer) throws -> Data {
        let c = ctl(p)
        try authorize(p, token: token, peer: peer)
        if c.isActive { try? c.restoreNetwork(authorized: true, by: peer.uid == 0 ? "root (command line)" : "an administrator") }
        unloadNetwork(p, c, why: "restore internet")
        p.activity.add(.system, "Internet restored", detail: "The emergency network block was removed by \(peer.uid == 0 ? "root" : "an administrator").",
                       outcome: "restored", severity: .medium, event: .lockdownLifted, actor: .user)
        notify(p, c, .networkRestored)
        return try status(p)
    }

    /// "Keep blocking": the automatic network block no longer expires.
    static func keepBlocking(_ p: Protection) throws -> Data {
        ctl(p).keepBlocking()
        return try status(p)
    }

    /// Removes the emergency anchor (idempotent; only the enforcing root daemon runs pfctl).
    static func unloadNetwork(_ p: Protection, _ c: EmergencyController, why: String) {
        guard enforcing(p) else { return }
        _ = run(firewall.unloadCommands(token: c.state.pfToken))
        c.update { $0.pfToken = nil }
        logInfo("emergency: network anchor unloaded (\(why))")
    }

    /// SIGTERM / bootout / uninstall: the emergency anchor never outlives the daemon (like DNS on SIGTERM). A manual
    /// lockdown is re-applied by the next start; an automatic one is not.
    static func shutdown(_ p: Protection) {
        let c = ctl(p)
        lock.lock(); timer?.cancel(); timer = nil; lock.unlock()
        let cmds = EmergencyRecovery.onShutdown(c, firewall: firewall)
        if enforcing(p) { _ = run(cmds) }
        logInfo("emergency: network anchor unloaded (daemon stopping)")
    }

    /// `sudo rampart emergency off` when the daemon can't be reached: works on the state file directly. Root only.
    static func offline(stateRoot: URL, dryRun: Bool) -> [String] {
        EmergencyRecovery.offline(statePath: stateRoot.appendingPathComponent("emergency.json").path, firewall: firewall, dryRun: dryRun,
                                  run: { let s = runCapture($0).0; return s == 0 || $0.acceptableExitCodes.contains(s) },
                                  signal: { Darwin.kill($0, SIGCONT) == 0 })
    }

    /// The app reports what it did in the user session (vault locked, clipboard cleared, banner shown).
    static func ack(_ p: Protection, _ ids: [String]) throws -> Data {
        let c = ctl(p)
        for id in ids.prefix(16) {
            guard let k = EmergencyAction.Kind(rawValue: id) else { continue }
            c.updateAction(k, state: .done, result: "done in your session")
            c.update { if !$0.appActionsDone.contains(id) { $0.appActionsDone.append(id) } }
        }
        return try status(p)
    }

    // MARK: engage / execute

    private static func engage(_ p: Protection, reason: EmergencyTriggerReason, detection: Detection?, containNetwork: Bool, why: String) {
        let c = ctl(p)
        let enforce = enforcing(p)
        let ctx = context(p, reason: reason, detection: detection)
        let actions = EmergencyPlanner.plan(reason, context: ctx, firewall: firewall, containNetwork: containNetwork)
        guard c.engage(reason, actions: actions, dryRun: !enforce, networkWhy: why) else { return }
        logWarn("EMERGENCY LOCKDOWN: \(reason.summary)\(containNetwork ? "" : " (internet left on)")\(enforce ? "" : " (dry run)")")
        let what = [reason.pid.map { "process \($0)" }, reason.path.map { "file \($0)" }, reason.detectionName.map { "detection \($0)" }].compactMap { $0 }.joined(separator: ", ")
        p.activity.add(.system, "Emergency lockdown", detail: reason.summary + (what.isEmpty ? "" : " (\(what))"),
                       outcome: enforce ? (containNetwork ? "locked down, internet blocked" : "locked down, internet on") : "locked down (dry run)",
                       severity: .critical, detectionID: reason.detectionID,
                       event: .lockdownStarted, actor: reason.kind == .manual ? .user : .system, reason: why,
                       action: (enforce ? "" : "Practice run, nothing was changed: ") + actions.filter { $0.state == .planned }.map(\.title).prefix(8).joined(separator: "; "))
        execute(p, c, actions, enforce: enforce, detection: detection)
        notify(p, c, .engaged)
    }

    // MARK: user-facing notification (user incident 2026-11-07: lockdown engaged silently)

    enum NoticeKind: String { case engaged, networkBlocked, networkRestored, expired, lifted, falseAlarm }

    /// Root cause of the silent lockdown: the alert was an app-side action that ran only when the app happened to
    /// poll (Emergency screen or banner on screen); the root daemon has no GUI session to post from. Now the daemon
    /// pushes the status to every subscribed app at once, and launches the app (or its agent) in the console user's
    /// session so it can post the time-sensitive notification even when no window is open.
    static func notify(_ p: Protection, _ c: EmergencyController, _ kind: NoticeKind) {
        let st = c.status(mode: mode(p))
        if let d = try? JSONEncoder.rampart.encode(st) { p.broadcastEmergency(d) }
        logInfo("emergency notice: \(kind.rawValue) — \(EmergencyNotice.text(st, kind: kind.rawValue).title)")
        lastNotice = (kind.rawValue, Date())
        // wms-o7: the app used to be started only when nobody was subscribed. Any local program can subscribe to the
        // event feed (or keep a connection open), so a script that killed the app and held a subscription made every
        // lockdown notice silent. The decision no longer depends on who is listening: whenever the user must hear about
        // it, the agent is started (kickstart of a running job does nothing) and re-loaded if it was booted out.
        if getuid() == 0, !Privileged.noPrivilegedTools { launchAppForNotice(kind) }
    }
    nonisolated(unsafe) static var lastNotice: (kind: String, date: Date)?

    /// Commands that bring the menu bar agent up for a notice (empty: no console user).
    static func noticeLaunchCommands(kind: NoticeKind, uid: uid_t, agentPlist: String = GuardPaths.standard.agentPlist) -> [GuardCommand] {
        guard uid != 0 else { return [] }
        let job = "gui/\(uid)/\(Product.agentLabel)"
        return [GuardCommand("/bin/launchctl", ["kickstart", job], acceptableExitCodes: [3, 113], note: "start the app to show the lockdown notice"),
                GuardCommand("/bin/launchctl", ["bootstrap", "gui/\(uid)", agentPlist], acceptableExitCodes: [5, 17, 37], note: "re-load the agent if it was booted out"),
                GuardCommand("/bin/launchctl", ["kickstart", job], acceptableExitCodes: [3, 113], note: "start it")]
    }

    private static func launchAppForNotice(_ kind: NoticeKind) {
        let cmds = noticeLaunchCommands(kind: kind, uid: consoleUID())
        guard let first = cmds.first else { return }
        // Already loaded: one kickstart is enough. Not loaded (exit 113): bootstrap our plist, then kickstart.
        if runCapture(first).0 == 0 { return }
        _ = run(Array(cmds.dropFirst()))
    }


    private static func context(_ p: Protection, reason: EmergencyTriggerReason, detection: Detection?) -> EmergencyContext {
        var tree: [(pid: Int32, path: String)] = []
        if let pid = reason.pid, pid > 1, let info = ProcessKiller.info(pid) {
            let nodes = ProcessKiller().tree(of: ProcessIdentity(pid: pid, startTime: info.start))
            tree = nodes.map { ($0.identity.pid, $0.path) }
        }
        var files = [reason.path].compactMap { $0 }
        if let d = detection { files += d.evidence.compactMap { e in e.detail.hasPrefix("/") ? e.detail.components(separatedBy: " ").first : nil } }
        files = files.filter { FileManager.default.fileExists(atPath: $0) && !p.runtime.isOwnData($0) && !OwnInstall.isVerifiedOwnFile($0, p) }
        tree = tree.filter { !OwnInstall.isVerifiedOwnProcess(pid: $0.pid, p) }
        let base = Set(p.state.value.persistenceBaseline ?? [])
        let newItems = base.isEmpty ? [] : p.lastPersistence.filter { !base.contains($0.id) }
        return EmergencyContext(processTree: tree, files: files, newLaunchItems: newItems, uid: consoleUID(),
                                isPlatformBinary: { ProcessKiller.isPlatformBinary($0) })
    }

    private static func execute(_ p: Protection, _ c: EmergencyController, _ actions: [EmergencyAction], enforce: Bool, detection: Detection?) {
        for a in actions where a.runner == .daemon && a.state == .planned {
            switch a.kind {
            case .suspendProcesses:
                guard enforce else { c.updateAction(a.kind, state: .dryRun, result: "would SIGSTOP \(a.pids)"); continue }
                var stopped: [Int32] = []
                for pid in a.pids where !ProcessKiller.isPlatformBinary(pid) && !OwnInstall.isVerifiedOwnProcess(pid: pid, p) && Darwin.kill(pid, SIGSTOP) == 0 { stopped.append(pid) }
                for pid in stopped { p.services.deception?.markContained(pid: pid, quarantineID: nil) }
                c.updateAction(a.kind, state: stopped.isEmpty ? .failed : .done, result: "suspended \(stopped)") { $0.pids = stopped }
            case .quarantineFiles:
                var done: [String] = [], hashes: [String] = []
                for path in a.paths {
                    if OwnInstall.isVerifiedOwnFile(path, p) { c.log("Not quarantined: \(path) is \(Product.name)'s own verified file"); continue }
                    let d = detection ?? Detection(path: path, name: "Emergency lockdown", category: .suspicious, severity: .critical, confidence: 100, evidence: [])
                    if let rec = try? p.services.quarantine.quarantine(path: path, detection: d) {
                        done.append(path); hashes.append(rec.sha256); p.markDecoyCatchContained(d, quarantineID: rec.id)
                    }
                }
                if let id = detection?.id, !done.isEmpty { _ = p.store.update(id) { $0.resolved = true } }
                c.update { $0.quarantinedHashes += hashes; if !done.isEmpty, $0.reason?.path.map(done.contains) == true { $0.triggerResolved = true } }
                c.updateAction(a.kind, state: done.count == a.paths.count ? .done : .failed, result: "\(done.count) of \(a.paths.count) quarantined")
            case .networkContainment:
                applyNetwork(c, enforce: enforce)
            case .remoteLockdown:
                if let g = p.services.guardian {
                    g.setLockdown(true)
                    var pol = g.loadPolicy(); pol.lockdownEnabled = true; pol.enforceKill = true; pol.suspendInsteadOfKill = false
                    let plan = g.enforcer.plan(report: g.monitor.report(policy: pol), policy: pol, dryRun: !enforce)
                    c.updateAction(a.kind, state: enforce ? .done : .dryRun, result: plan.notes.isEmpty ? "lockdown on; no unapproved remote tool running" : plan.notes.joined(separator: "; "))
                } else { c.updateAction(a.kind, state: .skipped, result: "remote-access monitor not running") }
            case .snapshot:
                guard enforce else { c.updateAction(a.kind, state: .dryRun, result: a.commands.map(\.description).joined(separator: "; ")); continue }
                let r = run(a.commands)
                c.updateAction(a.kind, state: r.allSatisfy { $0 } ? .done : .failed, result: r.allSatisfy { $0 } ? "snapshot created" : "tmutil failed (Time Machine may be off)")
            case .pauseLaunchItems:
                guard enforce else { c.updateAction(a.kind, state: .dryRun, result: "would disable \(a.paths.count) item(s)"); continue }
                let r = run(a.commands)
                c.update { $0.pausedLaunchLabels += a.paths.map { (($0 as NSString).lastPathComponent as NSString).deletingPathExtension } }
                c.updateAction(a.kind, state: r.allSatisfy { $0 } ? .done : .failed, result: "\(r.filter { $0 }.count) of \(r.count) commands ok")
            case .alert, .lockVault, .clearClipboard: break
            }
        }
    }

    private static func applyNetwork(_ c: EmergencyController, enforce: Bool) {
        do {
            try FileManager.default.createDirectory(atPath: firewall.directory, withIntermediateDirectories: true)
            // Resolve Apple update hosts while DNS still works, then write the rules.
            let ips = enforce ? EmergencyFirewall.appleUpdateHosts.flatMap(resolve) : []
            try firewall.appleTable(ips).write(toFile: firewall.appleHostsTablePath, atomically: true, encoding: .utf8)
            try firewall.anchorRules().write(toFile: firewall.rulesPath, atomically: true, encoding: .utf8)
        } catch {
            c.updateAction(.networkContainment, state: .failed, result: "could not write rules: \(error.localizedDescription)"); return
        }
        guard enforce else { c.updateAction(.networkContainment, state: .dryRun, result: "rules written to \(firewall.rulesPath); pfctl not run"); return }
        var token: String?
        var ok = true
        for cmd in firewall.loadCommands() {
            let (status, out) = runCapture(cmd)
            if cmd.arguments == ["-E"] { token = out.components(separatedBy: CharacterSet.decimalDigits.inverted).filter { !$0.isEmpty }.last }
            ok = ok && status == 0
        }
        c.update { $0.pfToken = token }
        c.updateAction(.networkContainment, state: ok ? .done : .failed, result: ok ? "pf emergency anchor loaded" : "pfctl failed")
    }

    private static func reapply(_ p: Protection, _ c: EmergencyController, network: Bool) {
        let enforce = enforcing(p) && !c.state.dryRun
        if network { applyNetwork(c, enforce: enforce) }
        p.services.guardian?.setLockdown(true)
        if enforce, let a = c.state.actions.first(where: { $0.kind == .suspendProcesses }) {
            for pid in a.pids where ProcessKiller.info(pid) != nil && !ProcessKiller.isPlatformBinary(pid) { _ = Darwin.kill(pid, SIGSTOP) }
        }
    }

    /// Every 15 s while locked down: escalation checks.
    private static func watch(_ p: Protection, _ c: EmergencyController) {
        let st = c.state
        guard st.active else { return }
        // Automatic network containment ends by itself after 10 minutes unless the user chose "Keep blocking".
        if c.expireNetworkIfDue() {
            unloadNetwork(p, c, why: "automatic block expired")
            p.activity.add(.system, "Internet restored", detail: "The automatic network block ended after 10 minutes.", outcome: "restored",
                           severity: .medium, event: .lockdownLifted, actor: .system)
            notify(p, c, .expired)
        }
        // Process won't stop: a suspended pid is running again, or the quarantined payload runs under a new pid.
        if let a = st.actions.first(where: { $0.kind == .suspendProcesses }), a.state == .done {
            for pid in a.pids where isRunningNotStopped(pid) { c.noteSignal(.processWontStop); break }
        }
        if let path = st.reason?.path, st.actions.contains(where: { $0.kind == .quarantineFiles && $0.state == .done }) {
            // Escalate only if the file that came back is still malicious or unverified: RamPart's own file put back by
            // a reinstall (and verifying) is not a payload reappearing.
            if FileManager.default.fileExists(atPath: path), !OwnInstall.isVerifiedOwnFile(path, p) { c.noteSignal(.payloadReappeared) }
            if !OwnInstall.isVerifiedOwnFile(path, p), !ProcessKiller().processes(runningExecutable: path).isEmpty { c.noteSignal(.processWontStop) }
        }
        // Persistence re-appears: a paused launch item is loaded again (plist back on disk after removal is enough).
        if !st.pausedLaunchLabels.isEmpty {
            let back = p.lastPersistence.filter { i in st.pausedLaunchLabels.contains { i.location.hasSuffix("/\($0).plist") } }
            if !back.isEmpty, let a = st.actions.first(where: { $0.kind == .pauseLaunchItems }), a.paths.contains(where: { !FileManager.default.fileExists(atPath: $0) }) {
                c.noteSignal(.persistenceReappeared)
            }
        }
    }

    // MARK: helpers

    private static func isRunningNotStopped(_ pid: Int32) -> Bool {
        var kp = kinfo_proc(); var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &kp, &size, nil, 0) == 0, size > 0 else { return false }
        return kp.kp_proc.p_stat != 4 /* SSTOP */ && kp.kp_proc.p_stat != 5 /* SZOMB */
    }

    private static func consoleUID() -> uid_t {
        var st = stat()
        return stat("/dev/console", &st) == 0 ? st.st_uid : getuid()
    }

    private static func resolve(_ host: String) -> [String] {
        var hints = addrinfo(); hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, "443", &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(first) }
        var out: [String] = []
        var cur: UnsafeMutablePointer<addrinfo>? = first
        while let a = cur {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(a.pointee.ai_addr, a.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                out.append(String(cString: buf))
            }
            cur = a.pointee.ai_next
        }
        return out
    }

    @discardableResult
    private static func run(_ cmds: [GuardCommand]) -> [Bool] {
        cmds.map { let (s, _) = runCapture($0); return s == 0 || $0.acceptableExitCodes.contains(s) }
    }

    /// Runs one command through the ZERO POP-UPS gate (Privileged.refusal), with a 20 s timeout.
    private static func runCapture(_ c: GuardCommand) -> (Int32, String) {
        if let why = Privileged.refusal(c.executable) { logInfo("emergency: refused \(c): \(why)"); return (-1, why) }
        if c.requiresRoot && getuid() != 0 { return (-1, "needs root") }
        let proc = Process(); let pipe = Pipe()
        proc.executableURL = URL(fileURLWithPath: c.executable); proc.arguments = c.arguments
        proc.standardOutput = pipe; proc.standardError = pipe
        do { try proc.run() } catch { return (-1, error.localizedDescription) }
        let deadline = Date().addingTimeInterval(20)
        while proc.isRunning && Date() < deadline { usleep(50_000) }
        if proc.isRunning { proc.terminate(); return (-1, "timed out") }
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return (proc.terminationStatus, out)
    }
}

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

    /// Daemon start: a persisted lockdown is re-applied (it survives reboots) and the watch timer starts.
    static func start(_ p: Protection) {
        let c = ctl(p)
        if c.isActive {
            c.log("Daemon restarted: lockdown re-applied")
            q.async { reapply(p, c) }
        }
        let t = DispatchSource.makeTimerSource(queue: q)
        t.schedule(deadline: .now() + 15, repeating: 15, leeway: .seconds(2))
        t.setEventHandler { watch(p, c) }
        t.resume()
        lock.lock(); timer = t; lock.unlock()
    }

    /// Called for every stored detection. Auto-triggers only per EmergencyTriggerPolicy.
    static func consider(_ d: Detection, protection p: Protection) {
        let c = ctl(p)
        if c.isActive { _ = c.noteDetection(d); return }
        let allow: (Detection) -> Bool = { d in
            if let h = d.sha256, p.runtime.config.allowlist.contains(h) { return true }
            if let path = d.path, p.runtime.config.exclusions.contains(where: { path == $0 || path.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }) { return true }
            return false
        }
        guard let reason = EmergencyTriggerPolicy.evaluate(d, isAllowlisted: allow) else { return }
        q.async { engage(p, reason: reason, detection: d) }
    }

    // MARK: IPC entry points (Router)

    static func status(_ p: Protection) throws -> Data { try JSONEncoder.rampart.encode(ctl(p).status(mode: mode(p))) }

    static func manual(_ p: Protection, peer: Peer, reason note: String) throws -> Data {
        q.sync { engage(p, reason: .manual(uid: peer.uid, note: note), detection: nil) }
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
    static func lift(_ p: Protection, token: String, force: Bool, peer: Peer) throws -> Data {
        guard let g = p.services.guardian else { throw ServiceError.unavailable("tamper protection") }
        let c = ctl(p)
        guard c.isActive else { throw ServiceError.failed(EmergencyError.notActive.description) }
        if let r = c.readiness(), !r.ready, !force {
            throw ServiceError.failed(EmergencyError.notReady(r.items.filter { !$0.met }.map(\.title)).description)
        }
        var authorized = false
        do { try g.redeem(token, peer: peer, purpose: .settings, minutes: 5); authorized = true } catch { throw ServiceError.denied(EmergencyError.notAuthorized.description + " (\(error.localizedDescription))") }
        let undo: [EmergencyAction]
        do { undo = try c.lift(authorized: authorized, force: force) } catch let e as EmergencyError { throw ServiceError.failed(e.description) }
        let enforce = enforcing(p) && !c.state.dryRun
        for a in undo {
            switch a.kind {
            case .suspendProcesses:
                if enforce { for pid in a.pids where ProcessKiller.info(pid) != nil { _ = Darwin.kill(pid, SIGCONT) } }
            case .networkContainment:
                let cmds = firewall.unloadCommands(token: c.state.pfToken)
                if enforce { _ = run(cmds) }
            case .pauseLaunchItems:
                if enforce { _ = run(a.undoCommands) }
            default: break
            }
            c.log("Undone: \(a.title)\(enforce ? "" : " (dry run)")")
        }
        p.activity.add(.system, "Emergency lockdown lifted", detail: force ? "lifted before every check passed" : "all checks passed", outcome: "lifted", severity: .medium,
                       event: .lockdownLifted, actor: .user)
        return try status(p)
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

    private static func engage(_ p: Protection, reason: EmergencyTriggerReason, detection: Detection?) {
        let c = ctl(p)
        let enforce = enforcing(p)
        let ctx = context(p, reason: reason, detection: detection)
        let actions = EmergencyPlanner.plan(reason, context: ctx, firewall: firewall)
        guard c.engage(reason, actions: actions, dryRun: !enforce) else { return }
        logWarn("EMERGENCY LOCKDOWN: \(reason.summary)\(enforce ? "" : " (dry run)")")
        p.activity.add(.system, "Emergency lockdown", detail: reason.summary, outcome: enforce ? "locked down" : "locked down (dry run)", severity: .critical, detectionID: reason.detectionID,
                       event: .lockdownStarted, actor: reason.detectionID != nil ? .system : nil, reason: reason.summary,
                       action: (enforce ? "" : "Practice run, nothing was changed: ") + actions.map(\.title).prefix(8).joined(separator: "; "))
        execute(p, c, actions, enforce: enforce, detection: detection)
    }

    private static func context(_ p: Protection, reason: EmergencyTriggerReason, detection: Detection?) -> EmergencyContext {
        var tree: [(pid: Int32, path: String)] = []
        if let pid = reason.pid, pid > 1, let info = ProcessKiller.info(pid) {
            let nodes = ProcessKiller().tree(of: ProcessIdentity(pid: pid, startTime: info.start))
            tree = nodes.map { ($0.identity.pid, $0.path) }
        }
        var files = [reason.path].compactMap { $0 }
        if let d = detection { files += d.evidence.compactMap { e in e.detail.hasPrefix("/") ? e.detail.components(separatedBy: " ").first : nil } }
        files = files.filter { FileManager.default.fileExists(atPath: $0) && !p.runtime.isOwnData($0) }
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
                for pid in a.pids where !ProcessKiller.isPlatformBinary(pid) && Darwin.kill(pid, SIGSTOP) == 0 { stopped.append(pid) }
                c.updateAction(a.kind, state: stopped.isEmpty ? .failed : .done, result: "suspended \(stopped)") { $0.pids = stopped }
            case .quarantineFiles:
                var done: [String] = [], hashes: [String] = []
                for path in a.paths {
                    let d = detection ?? Detection(path: path, name: "Emergency lockdown", category: .suspicious, severity: .critical, confidence: 100, evidence: [])
                    if let rec = try? p.services.quarantine.quarantine(path: path, detection: d) { done.append(path); hashes.append(rec.sha256) }
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

    private static func reapply(_ p: Protection, _ c: EmergencyController) {
        let enforce = enforcing(p) && !c.state.dryRun
        applyNetwork(c, enforce: enforce)
        p.services.guardian?.setLockdown(true)
        if enforce, let a = c.state.actions.first(where: { $0.kind == .suspendProcesses }) {
            for pid in a.pids where ProcessKiller.info(pid) != nil && !ProcessKiller.isPlatformBinary(pid) { _ = Darwin.kill(pid, SIGSTOP) }
        }
    }

    /// Every 15 s while locked down: escalation checks.
    private static func watch(_ p: Protection, _ c: EmergencyController) {
        let st = c.state
        guard st.active else { return }
        // Process won't stop: a suspended pid is running again, or the quarantined payload runs under a new pid.
        if let a = st.actions.first(where: { $0.kind == .suspendProcesses }), a.state == .done {
            for pid in a.pids where isRunningNotStopped(pid) { c.noteSignal(.processWontStop); break }
        }
        if let path = st.reason?.path, st.actions.contains(where: { $0.kind == .quarantineFiles && $0.state == .done }) {
            if FileManager.default.fileExists(atPath: path) { c.noteSignal(.payloadReappeared) }
            if !ProcessKiller().processes(runningExecutable: path).isEmpty { c.noteSignal(.processWontStop) }
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

import Foundation
import RampartShared
import RampartGuard
import RampartRemediation

/// Super Kill Switch in the daemon (IPC path A) and in `sudo rampart killswitch`. Steps and isolation come from
/// RampartGuard/KillSwitch.swift; every step runs even when an earlier one fails. Commands run for real only as root
/// and never with RAMPART_NO_PRIVILEGED_TOOLS (then each command is reported as "would run").
enum KillSwitchExec {
    /// IPC: the verified app/CLI peer (IPCAuthz .adminClient) plus an admin token redeemed here (Touch ID / password
    /// in the app), or a root peer. Unauthenticated calls are refused before anything changes.
    static func authorizedRun(_ p: Protection, token: String?, peer: Peer) throws -> Data {
        try Emergency.authorize(p, token: token, peer: peer)
        let r = run(p, via: peer.uid == 0 ? "command line (root)" : "app (authenticated)")
        return try JSONEncoder.rampart.encode(r)
    }

    static var dryRun: Bool { Privileged.noPrivilegedTools || getuid() != 0 }

    static func run(_ p: Protection, via: String) -> KillSwitch.Report {
        let steps: [KillSwitch.Step] = [
            (.liftLockdown, {
                let c = Emergency.ctl(p)
                guard c.isActive else { Emergency.unloadNetwork(p, c, why: "kill switch"); return "No lockdown was on." }
                let undo = try c.lift(authorized: true, force: true)
                Emergency.undoActions(p, c, undo)
                Emergency.notify(p, c, .lifted)
                return "Lockdown lifted."
            }),
            (.unloadAnchors, { try unloadAllAnchors() }),
            (.restoreDNS, {
                var notes: [String] = []
                if let w = p.services.web { do { try w.setOn(false) } catch { notes.append("filter: \(error.localizedDescription)") } }
                (p.services.web as? WebProtection)?.restoreOnExit()
                p.runtime.updateConfig { $0.webProtection = false }
                notes.append(try dnsAutomatic())
                return notes.joined(separator: "; ")
            }),
            (.resumeProcesses, { resumeFrozen(stateRoot: p.runtime.root) }),
            (.stopGuards, {
                var notes: [String] = []
                if let d = p.services.deception { do { try d.setTarpit(false); notes.append("network lure stopped") } catch { notes.append("lure: \(error.localizedDescription)") } }
                if let g = p.services.guardian { g.setLockdown(false); notes.append("remote-access lockdown off") }
                notes.append("web protection off")
                notes.append("Wi-Fi auto-disconnect is turned off by the app")
                return notes.joined(separator: "; ")
            }),
            (.pauseRealtime, { p.setRealtime(false); return "Real-time protection paused until you turn it back on." }),
        ]
        let r = KillSwitch.run(steps, via: via)
        p.activity.add(.system, "Super Kill Switch", detail: r.summary, outcome: r.allOK ? "everything off" : "partly done", severity: .high,
                       event: .lockdownLifted, actor: .user, action: r.steps.map { "\($0.ok ? "ok" : "failed"): \($0.title)" }.joined(separator: "; "))
        return r
    }

    /// `sudo rampart killswitch` without a reachable daemon: the same steps with plain tools.
    static func runOffline(stateRoot: URL) -> KillSwitch.Report {
        KillSwitch.run([
            (.liftLockdown, { Emergency.offline(stateRoot: stateRoot, dryRun: dryRun).joined(separator: "; ") }),
            (.unloadAnchors, { try unloadAllAnchors() }),
            (.restoreDNS, { try dnsAutomatic() }),
            (.resumeProcesses, { resumeFrozen(stateRoot: stateRoot) }),
            (.stopGuards, {
                let jobs = ["app.rampart.sentinel", "app.rampart.watchdog", Product.daemonLabel]
                return jobs.map { l in exec(GuardCommand("/bin/launchctl", ["bootout", "system/\(l)"], acceptableExitCodes: [3, 113, 5])) }.joined(separator: "; ")
            }),
            (.pauseRealtime, { "The service is stopped, so real-time protection is paused until you turn \(Product.name) back on." }),
        ], via: "command line (root, service unreachable)")
    }

    // MARK: steps

    static func unloadAllAnchors() throws -> String {
        var listing = ""
        if !dryRun {
            listing = capture(GuardCommand("/sbin/pfctl", ["-s", "Anchors"])) + "\n" + capture(GuardCommand("/sbin/pfctl", ["-a", "com.apple", "-s", "Anchors"]))
        }
        let anchors = KillSwitch.rampartAnchors(listing: listing)
        return KillSwitch.anchorCommands(anchors).map(exec).joined(separator: "; ")
    }

    static func dnsAutomatic() throws -> String {
        let listing = dryRun ? "" : capture(GuardCommand("/usr/sbin/networksetup", ["-listallnetworkservices"]))
        let services = KillSwitch.networkServices(listing: listing)
        if !dryRun && services.isEmpty { throw ServiceError.failed("no network services listed") }
        return KillSwitch.dnsCommands(services).map(exec).joined(separator: "; ")
    }

    static func resumeFrozen(stateRoot: URL) -> String {
        let c = EmergencyController(path: stateRoot.appendingPathComponent("emergency.json").path)
        let pids = c.state.actions.filter { $0.kind == .suspendProcesses }.flatMap(\.pids).filter { $0 > 1 }
        if pids.isEmpty { return "No frozen program." }
        if dryRun { return "would SIGCONT \(pids)" }
        return pids.map { "SIGCONT \($0): \(Darwin.kill($0, SIGCONT) == 0 ? "ok" : "gone")" }.joined(separator: "; ")
    }

    // MARK: runner (dry run unless root and privileged tools allowed)

    @discardableResult
    static func exec(_ c: GuardCommand) -> String {
        if dryRun { return "would run: \(c)" }
        let (s, _) = runRaw(c)
        return "\(c.arguments.prefix(3).joined(separator: " ")): \(s == 0 || c.acceptableExitCodes.contains(s) ? "ok" : "exit \(s)")"
    }
    static func capture(_ c: GuardCommand) -> String { dryRun ? "" : runRaw(c).1 }

    private static func runRaw(_ c: GuardCommand) -> (Int32, String) {
        // Root + RAMPART_NO_PRIVILEGED_TOOLS unset: Privileged.refusal allows pfctl / networksetup.
        if let why = Privileged.refusal(c.executable) { return (-1, why) }
        let proc = Process(); let pipe = Pipe()
        proc.executableURL = URL(fileURLWithPath: c.executable); proc.arguments = c.arguments
        proc.standardOutput = pipe; proc.standardError = pipe
        do { try proc.run() } catch { return (-1, error.localizedDescription) }
        let deadline = Date().addingTimeInterval(15)
        while proc.isRunning && Date() < deadline { usleep(50_000) }
        if proc.isRunning { proc.terminate(); return (-1, "timed out") }
        return (proc.terminationStatus, String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
    }
}

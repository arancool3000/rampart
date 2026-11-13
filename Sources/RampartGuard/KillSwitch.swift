import Foundation
import RampartShared

// Super Kill Switch: the pure core. Steps, step isolation, anchor / network-service parsing and the plain-tool
// commands. rampartd/Core/KillSwitchExec.swift runs it in the daemon (IPC path A) and in `sudo rampart killswitch`;
// Packaging/killswitch.sh is path B (no RamPart binary involved).

public enum KillSwitch {
    public static let copy = "Super Kill Switch: instantly turns off everything \(Product.name) is doing to your network and gets you back online."
    public static let scriptName = "killswitch.sh"

    public enum StepID: String, Codable, Sendable, CaseIterable {
        case liftLockdown, unloadAnchors, restoreDNS, resumeProcesses, stopGuards, pauseRealtime
        public var title: String {
            switch self {
            case .liftLockdown: return "Lift emergency lockdown"
            case .unloadAnchors: return "Remove \(Product.name)'s firewall rules"
            case .restoreDNS: return "Set DNS back to automatic and stop the DNS filter"
            case .resumeProcesses: return "Resume frozen programs"
            case .stopGuards: return "Stop the network lure, web protection, remote-access lockdown and Wi-Fi auto-disconnect"
            case .pauseRealtime: return "Pause real-time protection until you turn it back on"
            }
        }
    }

    public struct StepResult: Codable, Hashable, Sendable {
        public var id: StepID
        public var title: String
        public var ok: Bool
        public var detail: String
    }

    public struct Report: Codable, Hashable, Sendable {
        public var date: Date
        public var steps: [StepResult]
        public var via: String
        public var allOK: Bool { steps.allSatisfy(\.ok) }
        public var summary: String {
            let bad = steps.filter { !$0.ok }
            return bad.isEmpty ? "Everything \(Product.name) did to your network is off. You should be back online."
                               : "Done, with \(bad.count) step(s) that didn't fully work: " + bad.map(\.title).joined(separator: "; ")
        }
    }

    public typealias Step = (id: StepID, run: () throws -> String)

    /// Runs every step in order. Each is isolated: a throw (or a crash-free failure) never stops the next one.
    public static func run(_ steps: [Step], via: String, now: Date = Date()) -> Report {
        var out: [StepResult] = []
        for s in steps {
            do { out.append(StepResult(id: s.id, title: s.id.title, ok: true, detail: try s.run())) }
            catch { out.append(StepResult(id: s.id, title: s.id.title, ok: false, detail: "\(error)")) }
        }
        return Report(date: now, steps: out, via: via)
    }

    /// Anchors RamPart may have loaded (always flushed, loaded or not).
    public static let knownAnchors = ["com.apple/249.RampartEmergency", "com.apple/250.Rampart", "com.apple/251.RampartRemote", "app.rampart/lure"]

    /// Anchor names from `pfctl -s Anchors` / `pfctl -a com.apple -s Anchors` output that belong to RamPart, plus the known ones.
    public static func rampartAnchors(listing: String) -> [String] {
        let found = listing.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.lowercased().contains("rampart") && $0.allSatisfy { $0.isLetter || $0.isNumber || "._/-".contains($0) } }
        return Array(Set(knownAnchors + found)).sorted()
    }

    /// Service names from `networksetup -listallnetworkservices` (first explanatory line dropped, "*" = disabled kept).
    public static func networkServices(listing: String) -> [String] {
        listing.split(whereSeparator: \.isNewline).map(String.init)
            .filter { !$0.lowercased().contains("asterisk") }
            .map { $0.hasPrefix("*") ? String($0.dropFirst()) : $0 }
            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    public static func anchorCommands(_ anchors: [String]) -> [GuardCommand] {
        anchors.map { GuardCommand("/sbin/pfctl", ["-a", $0, "-F", "all"], acceptableExitCodes: [1], note: "flush \($0)") }
    }
    public static func dnsCommands(_ services: [String]) -> [GuardCommand] {
        services.map { GuardCommand("/usr/sbin/networksetup", ["-setdnsservers", $0, "Empty"], note: "DNS automatic on \($0)") }
            + [GuardCommand("/usr/bin/dscacheutil", ["-flushcache"], note: "flush the DNS cache")]
    }

    /// Path B: the bundled script is accepted only from inside a verified app bundle's Resources (no symlinks, not
    /// writable by others). Returns the script path or nil.
    ///
    /// wms-o7: for the real (administrator-prompt) run the script and every folder up to and including the bundle must
    /// also be root-owned. The app checks the bundle's signature, then macOS shows the password prompt, then root runs
    /// the file by path: from a copy the user (or an admin attacker who swapped /Applications/RamPart.app) can write, the
    /// script could be replaced while the prompt is on screen and the owner's password would run attacker code as root.
    /// A copy that isn't root-owned falls back to `sudo rampart killswitch`; path A (the service) is unaffected.
    public static func bundledScript(inBundle bundlePath: String, requireRootOwned: Bool = true) -> String? {
        let p = bundlePath + "/Contents/Resources/" + scriptName
        let r = (p as NSString).resolvingSymlinksInPath
        guard r == p || r.hasPrefix((bundlePath as NSString).resolvingSymlinksInPath + "/Contents/Resources/") else { return nil }
        var st = stat()
        guard lstat(p, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_mode & 0o022 == 0 else { return nil }
        if requireRootOwned {
            var dirs: [String] = [p]
            var d = (p as NSString).deletingLastPathComponent
            let stop = (bundlePath as NSString).standardizingPath
            while dirs.count < 8 { dirs.append(d); if d == stop || d == "/" || d.isEmpty { break }; d = (d as NSString).deletingLastPathComponent }
            for x in dirs {
                var s2 = stat()
                guard lstat(x, &s2) == 0, s2.st_uid == 0, s2.st_mode & 0o022 == 0 else { return nil }
            }
        }
        return p
    }

    /// The button shows whenever there is something to switch off (lockdown or web protection) — and never hides
    /// while the network might be blocked.
    public static func buttonVisible(lockdownActive: Bool, networkBlocked: Bool, webProtectionOn: Bool, daemonReachable: Bool) -> Bool {
        lockdownActive || networkBlocked || webProtectionOn || !daemonReachable
    }
}

// MARK: - Lockdown notifications (user incident 2026-11-07: lockdown engaged with no notification at all)

/// The user-facing notice for a lockdown transition. The daemon pushes status changes; the app (or its agent) turns
/// each transition into one time-sensitive notification with "Restore internet" (Super Kill Switch) and "Details".
public struct EmergencyNotice: Hashable, Sendable {
    public enum Kind: String, Sendable { case engaged, networkBlocked, networkRestored, expired, lifted, falseAlarm }
    public var kind: Kind
    public var title: String
    public var body: String
    public var actions: [String]
    public var timeSensitive: Bool

    public static let restoreAction = "Restore internet"
    public static let detailsAction = "Details"

    /// Plain reason with what (process / file) triggered it.
    public static func plainReason(_ s: EmergencyState) -> String {
        guard let r = s.reason else { return "\(Product.name) isolated this Mac" }
        var t = r.summary
        if let path = r.path { t += " — \((path as NSString).lastPathComponent)" }
        else if let pid = r.pid { t += " — process \(pid)" }
        return t
    }

    public static func text(_ st: EmergencyStatus, kind: String) -> EmergencyNotice {
        let k = Kind(rawValue: kind) ?? .engaged
        let s = st.state
        let reason = plainReason(s)
        let mins = max(1, Int((Double(st.networkSecondsLeft ?? Int(EmergencyNetworkPolicy.autoNetworkLifetime)) / 60).rounded(.up)))
        switch k {
        case .engaged:
            let net = s.isNetworkBlocked
                ? (st.networkSecondsLeft != nil ? " Internet is blocked for \(mins) min." : " Internet is blocked until you lift it.")
                : " Your internet stays on."
            return EmergencyNotice(kind: k, title: "\(Product.name) turned on Emergency Lockdown",
                                   body: "\(Product.name) turned on Emergency Lockdown: \(reason).\(net)",
                                   actions: s.isNetworkBlocked ? [restoreAction, detailsAction] : [detailsAction], timeSensitive: true)
        case .networkBlocked:
            return EmergencyNotice(kind: k, title: "\(Product.name) blocked the internet",
                                   body: "\(Product.name) blocked the internet: \(reason).\(st.networkSecondsLeft != nil ? " Internet is blocked for \(mins) min." : "")",
                                   actions: [restoreAction, detailsAction], timeSensitive: true)
        case .falseAlarm:
            return EmergencyNotice(kind: k, title: "Emergency Lockdown lifted: false alarm",
                                   body: "\(Product.name) lifted Emergency Lockdown: false alarm. \(s.falseAlarm ?? "It was started by \(Product.name)'s own files.") Nothing needs doing.",
                                   actions: [], timeSensitive: true)
        case .networkRestored, .expired, .lifted:
            return EmergencyNotice(kind: k, title: "Internet restored",
                                   body: k == .lifted ? "Emergency Lockdown is off. Internet restored." : k == .expired ? "The automatic network block ended. Internet restored." : "Internet restored.",
                                   actions: [], timeSensitive: true)
        }
    }

    /// The notice for going from `old` to `new` (nil = nothing to tell). Used by the app for every pushed/polled status.
    public static func transition(from old: EmergencyStatus?, to new: EmergencyStatus) -> EmergencyNotice? {
        let wasActive = old?.state.active ?? false, isActive = new.state.active
        let wasBlocked = (old?.state.active ?? false) && (old?.state.isNetworkBlocked ?? false)
        let isBlocked = isActive && new.state.isNetworkBlocked
        if isActive && (!wasActive || old?.state.startedAt != new.state.startedAt) { return text(new, kind: Kind.engaged.rawValue) }
        if isActive && isBlocked && !wasBlocked { return text(new, kind: Kind.networkBlocked.rawValue) }
        if wasActive && !isActive { return text(new, kind: (new.state.falseAlarm != nil ? Kind.falseAlarm : Kind.lifted).rawValue) }
        // An app that starts after the daemon lifted a false alarm still tells the user once.
        if old == nil, !isActive, new.state.falseAlarm != nil, let l = new.state.liftedAt, Date().timeIntervalSince(l) < 600 {
            return text(new, kind: Kind.falseAlarm.rawValue)
        }
        if wasBlocked && !isBlocked {
            let expired = new.state.log.last?.text.contains("automatically") ?? false
            return text(new, kind: (expired ? Kind.expired : Kind.networkRestored).rawValue)
        }
        return nil
    }
}

// MARK: - Recovery without the app (sudo CLI) and on daemon stop

public enum EmergencyRecovery {
    /// `sudo rampart emergency off` with or without a reachable daemon: flush the emergency anchor, SIGCONT frozen
    /// processes, mark the lockdown lifted. `run` / `signal` are injected (tests record instead of acting).
    public static func offline(statePath: String, firewall: EmergencyFirewall = EmergencyFirewall(), dryRun: Bool,
                               run: (GuardCommand) -> Bool, signal: (Int32) -> Bool) -> [String] {
        let c = EmergencyController(path: statePath)
        var out: [String] = []
        for cmd in firewall.unloadCommands(token: c.state.pfToken) {
            out.append(dryRun ? "would run: \(cmd)" : "\(cmd): \(run(cmd) ? "ok" : "not loaded")")
        }
        let pids = c.state.actions.filter { $0.kind == .suspendProcesses }.flatMap(\.pids).filter { $0 > 1 }
        for pid in pids { out.append(dryRun ? "would SIGCONT \(pid)" : "SIGCONT \(pid): \(signal(pid) ? "ok" : "gone")") }
        if c.isActive {
            if dryRun { out.append("would mark the lockdown lifted") }
            else if (try? c.lift(authorized: true, force: true)) != nil { c.log("Lifted from the command line (root)"); out.append("lockdown marked lifted") }
        }
        return out
    }

    /// Daemon stop (SIGTERM, bootout, uninstall): the commands that always run, and the state change. The anchor
    /// never outlives the daemon; an automatic lockdown's network block is recorded as removed.
    public static func onShutdown(_ c: EmergencyController, firewall: EmergencyFirewall = EmergencyFirewall()) -> [GuardCommand] {
        if c.isActive, c.state.isAutomatic, c.state.isNetworkBlocked {
            c.update { $0.networkBlocked = false; $0.networkExpiresAt = nil }
            c.log("Service stopped: automatic network block removed")
        }
        let cmds = firewall.unloadCommands(token: c.state.pfToken)
        c.update { $0.pfToken = nil }
        return cmds
    }
}

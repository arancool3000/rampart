import Foundation
import RampartShared

// Emergency Lockdown and "Protect Everything": the pure, testable core. No process is spawned here and no pf
// rule is loaded; this file only decides (trigger policy), plans (commands, signals, rule text), and keeps state
// (persisted JSON with a log). rampartd/Core/Emergency.swift executes the plan, and only the installed root daemon
// runs any command for real. Everything else is a dry run.
//
// Honest limit (also shown in the UI): RamPart cannot encrypt other apps' outgoing traffic. That needs a VPN
// server or Apple's NetworkExtension entitlement, which RamPart does not have. Instead, lockdown blocks it.

// MARK: - Trigger policy

public struct EmergencyTriggerReason: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case manual, confirmedMalware, ransomware, credentialTheft, tampering, exfiltration, deception
    }
    public var kind: Kind
    public var summary: String
    public var detectionID: UUID?
    public var detectionName: String?
    public var path: String?
    public var pid: Int32?
    public var sha256: String?
    public var confidence: Int
    public init(kind: Kind, summary: String, detectionID: UUID? = nil, detectionName: String? = nil, path: String? = nil,
                pid: Int32? = nil, sha256: String? = nil, confidence: Int = 100) {
        self.kind = kind; self.summary = summary; self.detectionID = detectionID; self.detectionName = detectionName
        self.path = path; self.pid = pid; self.sha256 = sha256; self.confidence = confidence
    }
    public static func manual(uid: uid_t, note: String = "") -> EmergencyTriggerReason {
        EmergencyTriggerReason(kind: .manual, summary: "You pressed Emergency Lockdown" + (note.isEmpty ? "" : " (\(note.prefix(120)))") + " [uid \(uid)]")
    }
}

/// Decides whether a detection is serious and certain enough to lock the Mac down without asking.
/// Never fires on notes (info/low/medium), on test files (EICAR, com.rampart.test.*), on allow-listed items,
/// or on low-confidence heuristics.
public enum EmergencyTriggerPolicy {
    public static let fileConfidence = 95
    public static let behaviourConfidence = 90

    public static func isTestArtifact(_ d: Detection) -> Bool {
        if d.category == .test { return true }
        let hay = ([d.name, d.path ?? ""] + d.evidence.map(\.title)).joined(separator: " ").lowercased()
        return hay.contains("eicar") || hay.contains("com.rampart.test") || hay.contains("rampart-test")
    }

    /// Telemetry / service health problems (a source that is down, not permitted, never started or crashed, missing Full
    /// Disk Access). These are status notes, never tampering and never a lockdown trigger.
    public static func isHealthIssue(_ d: Detection) -> Bool {
        let hay = ([d.name] + d.evidence.flatMap { [$0.title, $0.detail] }).joined(separator: " ").lowercased()
        if hay.contains("lost its real-time event feed") || hay.contains("telemetry source") || hay.contains("real-time protection is blind") { return true }
        if hay.contains("eslogger") && (HealthNote.isPermissionError(hay) || hay.contains("is down") || hay.contains("stopped") || hay.contains("crash")) { return true }
        if hay.contains("es_new_client_result") || hay.contains("full disk access") { return true }
        return false
    }

    /// Tamper kinds that are real evidence of an external actor (kill signal from another process, our binary or plist
    /// modified, launchctl bootout / launch item removed by someone else). Anything else is not counted as tampering.
    public static let evidentTamperKinds: Set<String> = ["killAttempt", "unloadAttempt", "binaryTamper", "plistTamper", "launchItemRemoved", "fileTamper"]

    public static func evaluate(_ d: Detection, isAllowlisted: (Detection) -> Bool = { _ in false }) -> EmergencyTriggerReason? {
        guard d.severity >= .high, !isTestArtifact(d), !isAllowlisted(d), !isHealthIssue(d) else { return nil }
        let text = ([d.name] + d.evidence.map { $0.title + " " + $0.detail }).joined(separator: " ").lowercased()
        let behaviour = d.evidence.contains { $0.source == .behaviour && $0.score >= 60 }
        func reason(_ k: EmergencyTriggerReason.Kind, _ s: String) -> EmergencyTriggerReason {
            EmergencyTriggerReason(kind: k, summary: s, detectionID: d.id, detectionName: d.name, path: d.path, pid: d.pid,
                                   sha256: d.sha256, confidence: d.confidence)
        }
        // Tampering with RamPart itself (high severity from the tamper detector).
        if d.name.hasPrefix("Tampering with \(Product.name)") && d.confidence >= 80 {
            let kind = String(d.name.dropFirst("Tampering with \(Product.name): ".count))
            guard evidentTamperKinds.contains(kind) else { return nil }
            let who = d.evidence.first.map { $0.detail } ?? ""
            return reason(.tampering, "Another program tried to switch off or alter \(Product.name) (\(kind)\(who.isEmpty ? "" : ": " + who.prefix(160)))")
        }
        if d.category == .ransomware, d.confidence >= behaviourConfidence, behaviour || text.contains("canary") {
            return reason(.ransomware, "Ransomware-like activity (canary files touched or mass file changes)")
        }
        if d.category == .infostealer, d.confidence >= behaviourConfidence, behaviour {
            return reason(.credentialTheft, "A program read saved passwords, keychains, cookies or wallets")
        }
        if d.confidence >= behaviourConfidence, behaviour,
           ["exfiltrat", "mass mail", "mass-mail", "massmail", "bulk upload", "spam relay"].contains(where: text.contains) {
            return reason(.exfiltration, "A program appears to be sending your data out or mass-mailing")
        }
        let strongFile = d.evidence.contains { [.hash, .yara, .xprotect].contains($0.source) && $0.score >= 90 }
        if strongFile, d.confidence >= fileConfidence {
            // Already-contained file (quarantined, never ran): a threat, but no reason to cut the network.
            if d.resolved && d.pid == nil { return nil }
            return reason(.confirmedMalware, "Known malware confirmed by \(d.evidence.first { [.hash, .yara, .xprotect].contains($0.source) }!.source.rawValue)")
        }
        return nil
    }
}

// MARK: - Process protection

public enum EmergencyProcessGuard {
    public static let protectedPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/db/",
                                           "/Applications/Safari.app/", "/System/Applications/"]
    public static let neverSignal: Set<String> = ["rampartd", "rampart", "RampartApp", "RamPart", "loginwindow", "WindowServer", "launchd", "kernel_task"]
    /// True when RamPart must never SIGSTOP this process (Apple platform binary, launchd, or RamPart itself).
    public static func isProtected(pid: Int32, path: String, isPlatformBinary: (Int32) -> Bool) -> Bool {
        if pid <= 1 || pid == getpid() { return true }
        if path.isEmpty { return true }   // unknown executable: don't guess
        if protectedPrefixes.contains(where: { path.hasPrefix($0) }) { return true }
        if neverSignal.contains((path as NSString).lastPathComponent) { return true }
        if path.contains("/Rampart.app/") || path.hasPrefix("/Library/PrivilegedHelperTools/app.rampart") { return true }
        return isPlatformBinary(pid)
    }
}

// MARK: - Network containment (pf)

public struct EmergencyFirewall: Codable, Hashable, Sendable {
    public static let pfctl = "/sbin/pfctl"
    /// Evaluated before RamPart's other anchors (251 remote access, 252+ IP blocklist).
    public var anchor: String
    public var directory: String
    public init(anchor: String = "com.apple/249.RampartEmergency", directory: String = Paths.effectiveRoot.appendingPathComponent("pf").path) {
        self.anchor = anchor; self.directory = directory
    }
    public var rulesPath: String { directory + "/emergency.anchor" }
    public var appleHostsTablePath: String { directory + "/emergency-apple.table" }

    /// RamPart's DNS-over-HTTPS upstreams (security.cloudflare-dns.com and dns.quad9.net). Fixed IPs so no DNS is
    /// needed to reach them while everything else is blocked.
    public static let dohResolvers = ["1.1.1.2", "1.0.0.2", "9.9.9.9", "149.112.112.112",
                                      "2606:4700:4700::1112", "2606:4700:4700::1002", "2620:fe::fe", "2620:fe::9"]
    /// Apple software update hosts. The daemon resolves them through DoH when lockdown starts and writes the
    /// addresses into `appleHostsTablePath`, so updates keep working.
    public static let appleUpdateHosts = ["swscan.apple.com", "swdist.apple.com", "swcdn.apple.com", "updates.cdn-apple.com",
                                          "mesu.apple.com", "gdmf.apple.com", "xp.apple.com", "osrecovery.apple.com"]

    public static func isAddress(_ s: String) -> Bool {
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1
    }

    /// One address per line; anything that is not a literal IPv4/IPv6 address is dropped (no pf injection).
    public func appleTable(_ addresses: [String]) -> String {
        Array(Set(addresses.filter(Self.isAddress))).sorted().joined(separator: "\n") + "\n"
    }

    /// pf rules: everything inbound and outbound is blocked except loopback (local apps keep working), DHCP and
    /// IPv6 neighbour discovery (the Mac keeps its address), HTTPS to RamPart's DoH resolvers, and HTTPS/HTTP to
    /// Apple software update. `quick` makes the first match final, so the block rules come last.
    public func anchorRules() -> String {
        let doh = Self.dohResolvers.joined(separator: ", ")
        return """
        # \(Product.name) EMERGENCY LOCKDOWN (generated; pfctl -a \(anchor) -f \(rulesPath))
        # Blocks all inbound and outbound traffic except the allow-list below. Lift it from \(Product.name) with your admin password.
        table <rampart_doh> const { \(doh) }
        table <rampart_apple_update> persist file "\(appleHostsTablePath)"
        pass quick on lo0 all
        pass out quick inet proto udp from any port 68 to any port 67 keep state
        pass in quick inet proto udp from any port 67 to any port 68 keep state
        pass out quick inet6 proto udp from any port 546 to any port 547 keep state
        pass quick inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv, routersol, routeradv }
        pass out quick proto tcp from any to <rampart_doh> port 443 keep state
        pass out quick proto tcp from any to <rampart_apple_update> port { 80, 443 } keep state
        block return out quick log all
        block drop in quick log all

        """
    }

    public func loadCommands() -> [GuardCommand] {
        [GuardCommand(Self.pfctl, ["-E"], note: "enable pf (reference-counted; prints a token kept for undo)"),
         GuardCommand(Self.pfctl, ["-a", anchor, "-f", rulesPath], note: "load the emergency anchor")]
    }
    public func unloadCommands(token: String?) -> [GuardCommand] {
        var c = [GuardCommand(Self.pfctl, ["-a", anchor, "-F", "all"], note: "remove the emergency rules")]
        if let t = token, !t.isEmpty, t.allSatisfy(\.isNumber) { c.append(GuardCommand(Self.pfctl, ["-X", t], note: "release our pf enable reference")) }
        return c
    }
}

// MARK: - Action plan

public struct EmergencyAction: Codable, Hashable, Identifiable, Sendable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        case alert, suspendProcesses, quarantineFiles, networkContainment, lockVault, clearClipboard, remoteLockdown, snapshot, pauseLaunchItems
    }
    /// Who carries it out: the daemon, or the app in the user's session (vault, clipboard, banner).
    public enum Runner: String, Codable, Sendable { case daemon, app }
    public enum State: String, Codable, Sendable { case planned, done, dryRun, failed, skipped, undone }
    public var id: String { kind.rawValue }
    public var kind: Kind
    public var runner: Runner
    public var title: String
    public var detail: String
    public var commands: [GuardCommand]
    public var undoCommands: [GuardCommand]
    public var pids: [Int32]
    public var protectedPIDs: [Int32]
    public var paths: [String]
    public var undoable: Bool
    public var undoNote: String
    public var state: State
    public var result: String
    public init(kind: Kind, runner: Runner = .daemon, title: String, detail: String, commands: [GuardCommand] = [], undoCommands: [GuardCommand] = [],
                pids: [Int32] = [], protectedPIDs: [Int32] = [], paths: [String] = [], undoable: Bool, undoNote: String, state: State = .planned, result: String = "") {
        self.kind = kind; self.runner = runner; self.title = title; self.detail = detail; self.commands = commands
        self.undoCommands = undoCommands; self.pids = pids; self.protectedPIDs = protectedPIDs; self.paths = paths
        self.undoable = undoable; self.undoNote = undoNote; self.state = state; self.result = result
    }
}

/// What the daemon knows when it plans: the offending process tree, involved files, and launch items added since
/// the last persistence baseline.
public struct EmergencyContext: Sendable {
    public var processTree: [(pid: Int32, path: String)]
    public var files: [String]
    public var newLaunchItems: [PersistenceItem]
    public var uid: uid_t
    public var isPlatformBinary: @Sendable (Int32) -> Bool
    public init(processTree: [(pid: Int32, path: String)] = [], files: [String] = [], newLaunchItems: [PersistenceItem] = [],
                uid: uid_t = getuid(), isPlatformBinary: @escaping @Sendable (Int32) -> Bool = { _ in false }) {
        self.processTree = processTree; self.files = files; self.newLaunchItems = newLaunchItems; self.uid = uid; self.isPlatformBinary = isPlatformBinary
    }
}

public enum EmergencyPlanner {
    public static let tmutil = "/usr/bin/tmutil", launchctl = "/bin/launchctl", kill = "/bin/kill"

    /// `containNetwork` false (an automatic trigger without high-confidence active-attack evidence): only the
    /// non-disruptive steps run (alert, freeze, quarantine, snapshot, vault lock); network, clipboard, remote-access
    /// and startup-item steps are planned as skipped.
    public static func plan(_ reason: EmergencyTriggerReason, context c: EmergencyContext, firewall: EmergencyFirewall = EmergencyFirewall(),
                            containNetwork: Bool = true) -> [EmergencyAction] {
        var out = planAll(reason, context: c, firewall: firewall)
        guard !containNetwork else { return out }
        let disruptive: Set<EmergencyAction.Kind> = [.networkContainment, .clearClipboard, .remoteLockdown, .pauseLaunchItems]
        for i in out.indices where disruptive.contains(out[i].kind) {
            out[i].state = .skipped
            out[i].result = out[i].kind == .networkContainment
                ? "Internet left on: one automatic signal is not enough to cut the network."
                : "Not needed for an automatic response without a confirmed active attack."
        }
        return out
    }

    private static func planAll(_ reason: EmergencyTriggerReason, context c: EmergencyContext, firewall: EmergencyFirewall) -> [EmergencyAction] {
        var out: [EmergencyAction] = []
        out.append(EmergencyAction(kind: .alert, runner: .app, title: "Alert you right away",
                                   detail: "Critical notification and an in-app banner: \(reason.summary).", undoable: false, undoNote: "Nothing to undo."))
        // 2. Suspend (SIGSTOP), never Apple platform binaries or RamPart.
        var stop: [Int32] = [], spared: [Int32] = []
        for n in c.processTree {
            if EmergencyProcessGuard.isProtected(pid: n.pid, path: n.path, isPlatformBinary: c.isPlatformBinary) { spared.append(n.pid) } else { stop.append(n.pid) }
        }
        out.append(EmergencyAction(kind: .suspendProcesses, title: "Freeze the offending programs",
                                   detail: stop.isEmpty ? "No running program to freeze." : "Suspends \(stop.count) process(es) with SIGSTOP so they can't act, without losing evidence."
                                     + (spared.isEmpty ? "" : " \(spared.count) macOS or \(Product.name) process(es) are never touched."),
                                   commands: stop.map { GuardCommand(kill, ["-STOP", String($0)]) },
                                   undoCommands: stop.map { GuardCommand(kill, ["-CONT", String($0)]) },
                                   pids: stop, protectedPIDs: spared, undoable: !stop.isEmpty, undoNote: "Resumed with SIGCONT when you lift lockdown.",
                                   state: stop.isEmpty ? .skipped : .planned))
        let files = Array(Set(c.files.filter { $0.hasPrefix("/") && !$0.hasPrefix("/System/") })).sorted()
        out.append(EmergencyAction(kind: .quarantineFiles, title: "Quarantine the files involved",
                                   detail: files.isEmpty ? "No file to quarantine." : "Moves \(files.count) file(s) into the encrypted quarantine vault.",
                                   paths: files, undoable: !files.isEmpty, undoNote: "Restore from Threats & Quarantine if a file turns out to be safe.",
                                   state: files.isEmpty ? .skipped : .planned))
        out.append(EmergencyAction(kind: .networkContainment, title: "Cut this Mac off the network",
                                   detail: "Blocks all incoming and outgoing traffic except this Mac's own apps (loopback), DHCP, \(Product.name)'s encrypted DNS (Cloudflare and Quad9) and Apple software updates. Local apps keep working.",
                                   commands: firewall.loadCommands(), undoCommands: firewall.unloadCommands(token: nil), paths: [firewall.rulesPath],
                                   undoable: true, undoNote: "Rules removed when you lift lockdown."))
        out.append(EmergencyAction(kind: .lockVault, runner: .app, title: "Lock the password vault",
                                   detail: "Locks \(Product.name) Passwords so nothing can read them while this is sorted out.", undoable: true, undoNote: "Unlock it again yourself later."))
        out.append(EmergencyAction(kind: .clearClipboard, runner: .app, title: "Clear the clipboard",
                                   detail: "Removes anything you copied (a password, a code) so a program can't grab it.", undoable: false, undoNote: "The old clipboard is not kept."))
        out.append(EmergencyAction(kind: .remoteLockdown, title: "Block remote access",
                                   detail: "Turns remote-access lockdown on and stops remote-control apps you haven't approved.",
                                   undoable: true, undoNote: "Lockdown stays on afterwards (your choice to turn it off); approved tools are untouched."))
        out.append(EmergencyAction(kind: .snapshot, title: "Take a local APFS snapshot",
                                   detail: "Asks Time Machine for a local snapshot so files can be rolled back if something encrypts or deletes them.",
                                   commands: [GuardCommand(tmutil, ["localsnapshot"], note: "snapshot of the startup volume")],
                                   undoable: false, undoNote: "macOS deletes local snapshots on its own after about 24 hours."))
        var lc: [GuardCommand] = [], undo: [GuardCommand] = [], items: [String] = []
        for i in c.newLaunchItems where i.kind == .launchAgent || i.kind == .launchDaemon {
            let label = i.label.filter { $0.isLetter || $0.isNumber || ".-_".contains($0) }
            guard !label.isEmpty, !label.hasPrefix("com.apple."), !label.hasPrefix(Product.bundlePrefix) else { continue }
            let domain = i.kind == .launchDaemon ? "system" : "gui/\(c.uid)"
            lc.append(GuardCommand(launchctl, ["bootout", "\(domain)/\(label)"], requiresRoot: domain == "system", acceptableExitCodes: [3, 113]))
            lc.append(GuardCommand(launchctl, ["disable", "\(domain)/\(label)"], requiresRoot: domain == "system"))
            undo.append(GuardCommand(launchctl, ["enable", "\(domain)/\(label)"], requiresRoot: domain == "system"))
            undo.append(GuardCommand(launchctl, ["bootstrap", domain, i.location], requiresRoot: domain == "system", acceptableExitCodes: [5, 17, 37]))
            items.append(i.location)
        }
        out.append(EmergencyAction(kind: .pauseLaunchItems, title: "Pause newly added startup items",
                                   detail: items.isEmpty ? "No new startup item since the last check." : "Disables \(items.count) launch item(s) added recently, so nothing new starts at login.",
                                   commands: lc, undoCommands: undo, paths: items, undoable: !items.isEmpty,
                                   undoNote: "Re-enabled when you lift lockdown (unless you remove them).", state: items.isEmpty ? .skipped : .planned))
        return out
    }
}

// MARK: - State, readiness, escalation

public struct EmergencyLogEntry: Codable, Hashable, Sendable {
    public var date: Date
    public var text: String
    public init(date: Date, text: String) { self.date = date; self.text = text }
}

public struct EmergencyEscalation: Codable, Hashable, Sendable {
    public enum Signal: String, Codable, Sendable, CaseIterable { case processWontStop, payloadReappeared, persistenceReappeared, tamperingContinues }
    public var signals: [Signal]
    public var headline: String { "\(Product.name) couldn't fully stop this." }
    public var steps: [String] {
        ["Turn off Wi-Fi now.",
         "Save your work and shut down your Mac.",
         "Contact a professional (Apple Support or a trusted repair shop). Don't enter passwords on this Mac until it's checked."]
    }
    public static func describe(_ s: Signal) -> String {
        switch s {
        case .processWontStop: return "A harmful program kept running after it was frozen, or restarted."
        case .payloadReappeared: return "A quarantined file came back."
        case .persistenceReappeared: return "A startup item that was paused came back."
        case .tamperingContinues: return "Something keeps trying to switch \(Product.name) off."
        }
    }
}

public struct EmergencyState: Codable, Hashable, Sendable {
    public var active: Bool = false
    public var startedAt: Date?
    public var reason: EmergencyTriggerReason?
    public var actions: [EmergencyAction] = []
    public var dryRun: Bool = true
    public var lastCriticalAt: Date?
    public var rescanAt: Date?
    public var rescanClean: Bool = false
    public var triggerResolved: Bool = false
    public var quarantinedHashes: [String] = []
    public var pausedLaunchLabels: [String] = []
    public var tamperCount: Int = 0
    public var signals: [EmergencyEscalation.Signal] = []
    public var pfToken: String?
    public var appActionsDone: [String] = []
    public var log: [EmergencyLogEntry] = []
    public var liftedAt: Date?
    // Safety fields (optional so older emergency.json files still decode).
    /// true = started by an automatic trigger (never persists a network block across restarts).
    public var automatic: Bool?
    /// The pf emergency anchor is (meant to be) loaded right now.
    public var networkBlocked: Bool?
    /// Automatic network containment ends by itself at this time unless the user chose "Keep blocking".
    public var networkExpiresAt: Date?
    public var keepBlocking: Bool?
    /// Why the network was or wasn't cut, in plain words.
    public var networkWhy: String?
    public init() {}
    public var isAutomatic: Bool { automatic ?? (reason.map { $0.kind != .manual } ?? false) }
    public var isNetworkBlocked: Bool { networkBlocked ?? (active && actions.contains { $0.kind == .networkContainment && ($0.state == .done || $0.state == .dryRun || $0.state == .planned || $0.state == .failed) }) }
}

/// One strong automatic signal, kept for corroboration.
public struct EmergencySignal: Codable, Hashable, Sendable {
    public var kind: EmergencyTriggerReason.Kind
    public var key: String
    public var date: Date
    public init(kind: EmergencyTriggerReason.Kind, key: String, date: Date) { self.kind = kind; self.key = key; self.date = date }
}

/// What an automatic trigger may do.
public struct EmergencyAssessment: Hashable, Sendable {
    public var engage: Bool
    public var containNetwork: Bool
    public var why: String
}

/// Auto-lockdown safety rules (user incident 2026-11-07: a missing Full Disk Access grant was read as tampering and cut
/// the network with no way back). Automatic triggers may alert, freeze and quarantine. The network is cut only on
/// high-confidence active-attack evidence: a ransomware burst, exfiltration plus a malicious detection, or at least two
/// independent strong signals (different kinds) within `window`. A single tamper or deception signal never locks down.
public enum EmergencyNetworkPolicy {
    public static let window: TimeInterval = 600
    /// After an administrator lifts a lockdown, automatic triggers can't cut the network again for this long
    /// (ransomware excepted) and tamper / deception signals alone are ignored.
    public static let liftCooldown: TimeInterval = 1800
    /// Automatic network containment expires on its own after this long unless the user confirms "Keep blocking".
    public static let autoNetworkLifetime: TimeInterval = 600

    public static func assess(_ r: EmergencyTriggerReason, recent: [EmergencySignal], now: Date, liftedAt: Date? = nil) -> EmergencyAssessment {
        if r.kind == .manual { return EmergencyAssessment(engage: true, containNetwork: true, why: "You turned on Emergency Lockdown.") }
        let live = recent.filter { now.timeIntervalSince($0.date) <= window && $0.date <= now.addingTimeInterval(5) }
        let kinds = Set(live.map(\.kind) + [r.kind])
        let independent = kinds.count >= 2
        let cooling = liftedAt.map { now.timeIntervalSince($0) < liftCooldown && now >= $0 } ?? false
        switch r.kind {
        case .ransomware:
            return EmergencyAssessment(engage: true, containNetwork: true, why: "Ransomware-like burst of file changes: the network is cut to stop it spreading or phoning home.")
        case .tampering, .deception:
            if cooling || !independent {
                return EmergencyAssessment(engage: false, containNetwork: false, why: "A single \(r.kind == .tampering ? "tamper" : "decoy") signal is only reported; it needs a second, independent signal.")
            }
            return EmergencyAssessment(engage: true, containNetwork: true, why: "Two independent signals: \(kinds.map(\.rawValue).sorted().joined(separator: " + ")).")
        case .exfiltration:
            let malicious = live.contains { [.confirmedMalware, .credentialTheft, .ransomware].contains($0.kind) }
            let net = !cooling && (malicious || independent)
            return EmergencyAssessment(engage: true, containNetwork: net,
                                       why: net ? "Data is being sent out and a malicious program was found: the network is cut." : "Data may be leaving this Mac; the program is frozen, the internet stays on.")
        case .confirmedMalware, .credentialTheft:
            let net = !cooling && independent
            return EmergencyAssessment(engage: true, containNetwork: net,
                                       why: net ? "Two independent signals: \(kinds.map(\.rawValue).sorted().joined(separator: " + ")). The network is cut." : "The program is frozen and its files quarantined. The internet stays on: one signal isn't enough to cut it.")
        case .manual:
            return EmergencyAssessment(engage: true, containNetwork: true, why: "")
        }
    }
}

public struct EmergencyReadiness: Codable, Hashable, Sendable {
    public struct Item: Codable, Hashable, Sendable { public var title: String; public var met: Bool }
    public var items: [Item]
    public var ready: Bool { items.allSatisfy(\.met) }
    public var secondsUntilQuiet: Int
}

/// Sent as JSON in `IPCResponse.emergency(Data)`.
public struct EmergencyStatus: Codable, Hashable, Sendable {
    public var state: EmergencyState
    public var readiness: EmergencyReadiness?
    public var escalation: EmergencyEscalation?
    public var mode: String            // "enforcing" or "dry run"
    public var honestNote: String
    public var report: String
    /// Seconds left on an automatic network block (nil = none, or it doesn't expire).
    public var networkSecondsLeft: Int? = nil
    /// Works from Terminal even when the app or the service is broken.
    public static let sudoEscape = "sudo rampart emergency off"
    public init(state: EmergencyState, readiness: EmergencyReadiness?, escalation: EmergencyEscalation?, mode: String, honestNote: String, report: String) {
        self.state = state; self.readiness = readiness; self.escalation = escalation; self.mode = mode; self.honestNote = honestNote; self.report = report
    }
    public static let encryptionNote = "\(Product.name) can't encrypt other apps' traffic: that needs a VPN server or Apple's NetworkExtension entitlement, which \(Product.name) doesn't have. Instead, lockdown blocks everything going out except encrypted DNS and Apple updates."
}

public enum EmergencyError: Error, CustomStringConvertible, Equatable {
    case notActive, notReady([String]), notAuthorized
    public var description: String {
        switch self {
        case .notActive: return "Emergency lockdown isn't on."
        case .notReady(let r): return "Not safe to lift yet: " + r.joined(separator: "; ")
        case .notAuthorized: return "Lifting lockdown needs your administrator password."
        }
    }
}

/// Thread-safe state machine with JSON persistence (survives restarts: the daemon re-applies on start).
public final class EmergencyController: @unchecked Sendable {
    public static let quietPeriod: TimeInterval = 120
    public let path: String
    public let clock: GuardClock
    private let lock = NSLock()
    private var s: EmergencyState
    private var signals: [EmergencySignal] = []

    public init(path: String, clock: GuardClock = .live) {
        self.path = path; self.clock = clock
        if let d = FileManager.default.contents(atPath: path), let st = try? JSONDecoder.rampart.decode(EmergencyState.self, from: d) { s = st } else { s = EmergencyState() }
    }

    public var state: EmergencyState { lock.lock(); defer { lock.unlock() }; return s }
    public var isActive: Bool { state.active }

    private func save() {
        guard let d = try? JSONEncoder.rampart.encode(s) else { return }
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        if FileManager.default.createFile(atPath: path + ".tmp", contents: d, attributes: [.posixPermissions: 0o600]) {
            _ = rename(path + ".tmp", path)
        }
    }
    private func logLocked(_ t: String) { s.log.append(EmergencyLogEntry(date: clock.now(), text: t)); if s.log.count > 500 { s.log.removeFirst(100) } }

    public func log(_ t: String) { lock.lock(); logLocked(t); save(); lock.unlock() }

    /// Records an automatic trigger and decides what it may do (see EmergencyNetworkPolicy).
    public func assess(_ r: EmergencyTriggerReason) -> EmergencyAssessment {
        lock.lock(); defer { lock.unlock() }
        let now = clock.now()
        let a = EmergencyNetworkPolicy.assess(r, recent: signals, now: now, liftedAt: s.liftedAt)
        if r.kind != .manual {
            signals.append(EmergencySignal(kind: r.kind, key: r.detectionName ?? r.summary, date: now))
            signals = signals.filter { now.timeIntervalSince($0.date) <= EmergencyNetworkPolicy.window }.suffix(64)
        }
        return a
    }

    /// Starts lockdown (no-op returning false if already active; the new reason is logged).
    @discardableResult
    public func engage(_ reason: EmergencyTriggerReason, actions: [EmergencyAction], dryRun: Bool, networkWhy: String? = nil) -> Bool {
        lock.lock(); defer { save(); lock.unlock() }
        if s.active { logLocked("Another trigger while locked down: \(reason.summary)"); s.lastCriticalAt = clock.now(); return false }
        let keep = s.log.suffix(50)
        s = EmergencyState()
        s.log = Array(keep)
        s.active = true; s.startedAt = clock.now(); s.reason = reason; s.actions = actions; s.dryRun = dryRun
        s.lastCriticalAt = reason.kind == .manual ? nil : clock.now()
        s.triggerResolved = reason.kind == .manual
        s.automatic = reason.kind != .manual
        let net = actions.contains { $0.kind == .networkContainment && $0.state == .planned }
        s.networkBlocked = net
        s.keepBlocking = reason.kind == .manual
        s.networkExpiresAt = net && reason.kind != .manual ? clock.now().addingTimeInterval(EmergencyNetworkPolicy.autoNetworkLifetime) : nil
        s.networkWhy = networkWhy
        logLocked("EMERGENCY LOCKDOWN ON\(dryRun ? " (dry run)" : ""): \(reason.summary)\(net ? "" : " (internet left on)")")
        return true
    }

    /// An active automatic lockdown without a network block gets one (a second, independent signal arrived).
    @discardableResult
    public func upgradeToNetwork(why: String) -> Bool {
        lock.lock(); defer { save(); lock.unlock() }
        guard s.active, !s.isNetworkBlocked, let i = s.actions.firstIndex(where: { $0.kind == .networkContainment }) else { return false }
        s.actions[i].state = .planned; s.actions[i].result = ""
        s.networkBlocked = true; s.networkWhy = why
        s.networkExpiresAt = s.isAutomatic ? clock.now().addingTimeInterval(EmergencyNetworkPolicy.autoNetworkLifetime) : nil
        logLocked("Network cut: \(why)")
        return true
    }

    /// Seconds until an automatic network block ends by itself (nil = no block, or it was kept / manual).
    public func networkSecondsLeft() -> Int? {
        let st = state
        guard st.active, st.isNetworkBlocked, st.keepBlocking != true, let e = st.networkExpiresAt else { return nil }
        return max(0, Int(e.timeIntervalSince(clock.now()).rounded(.up)))
    }

    /// True once an automatic network block has expired: the block is marked off and the daemon must unload the anchor.
    public func expireNetworkIfDue() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard s.active, s.isNetworkBlocked, s.keepBlocking != true, let e = s.networkExpiresAt, clock.now() >= e else { return false }
        markNetworkOffLocked("Internet restored automatically after \(Int(EmergencyNetworkPolicy.autoNetworkLifetime / 60)) minutes (you didn't choose Keep blocking)")
        save()
        return true
    }

    /// "Keep blocking": the user confirms the automatic network block; it no longer expires.
    public func keepBlocking() {
        lock.lock(); defer { save(); lock.unlock() }
        guard s.active, s.isNetworkBlocked else { return }
        s.keepBlocking = true; s.networkExpiresAt = nil
        logLocked("You chose to keep the network blocked")
    }

    /// "Restore internet now": ends the network block only (lockdown stays on for the other steps). No readiness gate.
    public func restoreNetwork(authorized: Bool, by who: String = "an administrator") throws {
        guard authorized else { throw EmergencyError.notAuthorized }
        lock.lock(); defer { save(); lock.unlock() }
        guard s.active else { throw EmergencyError.notActive }
        markNetworkOffLocked("Internet restored by \(who)")
    }

    private func markNetworkOffLocked(_ note: String) {
        s.networkBlocked = false; s.networkExpiresAt = nil; s.keepBlocking = false
        if let i = s.actions.firstIndex(where: { $0.kind == .networkContainment }), s.actions[i].state != .skipped {
            s.actions[i].state = .undone; s.actions[i].result = note
        }
        logLocked(note)
    }

    /// Daemon start or reboot with a persisted lockdown. An automatic lockdown comes back WITHOUT its network block
    /// (it is never re-applied); only a manual lockdown keeps blocking. Returns true when the network block must be re-applied.
    public func prepareForRestart() -> Bool {
        lock.lock(); defer { save(); lock.unlock() }
        guard s.active else { return false }
        if s.isAutomatic {
            if s.isNetworkBlocked { markNetworkOffLocked("Daemon restarted: automatic network block not re-applied") }
            else { logLocked("Daemon restarted: lockdown kept, internet stays on") }
            return false
        }
        logLocked("Daemon restarted: manual lockdown re-applied")
        return s.isNetworkBlocked
    }

    public func updateAction(_ kind: EmergencyAction.Kind, state st: EmergencyAction.State, result: String, change: ((inout EmergencyAction) -> Void)? = nil) {
        lock.lock(); defer { save(); lock.unlock() }
        guard let i = s.actions.firstIndex(where: { $0.kind == kind }) else { return }
        s.actions[i].state = st; s.actions[i].result = result; change?(&s.actions[i])
        logLocked("\(s.actions[i].title): \(st.rawValue)\(result.isEmpty ? "" : " — \(result)")")
    }

    public func update(_ f: (inout EmergencyState) -> Void) { lock.lock(); f(&s); save(); lock.unlock() }

    /// Feed every detection seen while locked down. Returns new escalation signals.
    @discardableResult
    public func noteDetection(_ d: Detection) -> [EmergencyEscalation.Signal] {
        lock.lock(); defer { save(); lock.unlock() }
        guard s.active, !EmergencyTriggerPolicy.isHealthIssue(d) else { return [] }
        var new: [EmergencyEscalation.Signal] = []
        if d.severity >= .high && !EmergencyTriggerPolicy.isTestArtifact(d) { s.lastCriticalAt = clock.now(); s.rescanClean = false }
        if let h = d.sha256, s.quarantinedHashes.contains(h) { new.append(.payloadReappeared) }
        if d.name.hasPrefix("Tampering with \(Product.name)") { s.tamperCount += 1; if s.tamperCount >= 2 { new.append(.tamperingContinues) } }
        if d.category == .persistence, let p = d.path, s.pausedLaunchLabels.contains(where: { p.contains($0) }) { new.append(.persistenceReappeared) }
        for n in new where !s.signals.contains(n) { s.signals.append(n); logLocked("Escalation: \(EmergencyEscalation.describe(n))") }
        return new
    }

    public func noteSignal(_ sig: EmergencyEscalation.Signal) {
        lock.lock(); defer { save(); lock.unlock() }
        guard s.active, !s.signals.contains(sig) else { return }
        s.signals.append(sig); logLocked("Escalation: \(EmergencyEscalation.describe(sig))")
    }

    public func noteRescan(clean: Bool, triggerGone: Bool) {
        lock.lock(); defer { save(); lock.unlock() }
        guard s.active else { return }
        s.rescanAt = clock.now(); s.rescanClean = clean
        if triggerGone { s.triggerResolved = true }
        logLocked("Re-scan finished: \(clean ? "nothing critical found" : "threats still present")")
    }

    public func readiness() -> EmergencyReadiness? {
        let st = state; let now = clock.now()
        guard st.active, let start = st.startedAt else { return nil }
        let quietFor = now.timeIntervalSince(st.lastCriticalAt ?? start)
        let wait = max(0, Int((Self.quietPeriod - quietFor).rounded(.up)))
        return EmergencyReadiness(items: [
            .init(title: "Re-scan finished with nothing critical left", met: st.rescanAt.map { $0 >= start } == true && st.rescanClean),
            .init(title: "The threat that started this is quarantined or gone", met: st.triggerResolved),
            .init(title: "No new critical events for 2 minutes", met: quietFor >= Self.quietPeriod),
            .init(title: "No sign that it's coming back", met: st.signals.isEmpty),
        ], secondsUntilQuiet: wait)
    }

    public func escalation() -> EmergencyEscalation? {
        let st = state
        guard st.active, !st.signals.isEmpty else { return nil }
        return EmergencyEscalation(signals: st.signals)
    }

    /// Lifting needs the admin-authenticated token flow (or a root peer); `authorized` is that outcome. An authorized
    /// lift ALWAYS succeeds: the readiness checklist is advice, never a gate for the owner (`force` is kept for the log).
    /// Returns the actions to undo; the network block is always among them (the daemon always unloads the anchor).
    public func lift(authorized: Bool, force: Bool = false) throws -> [EmergencyAction] {
        guard authorized else { throw EmergencyError.notAuthorized }
        guard let r = readiness() else { throw EmergencyError.notActive }
        lock.lock(); defer { save(); lock.unlock() }
        let undo = s.actions.filter { $0.runner == .daemon && ($0.kind == .networkContainment || ($0.undoable && ($0.state == .done || $0.state == .dryRun || $0.state == .failed))) }
        s.active = false; s.liftedAt = clock.now(); s.networkBlocked = false; s.networkExpiresAt = nil
        for i in s.actions.indices where s.actions[i].undoable && s.actions[i].state == .done { s.actions[i].state = .undone }
        logLocked("Lockdown lifted by an administrator\(r.ready ? "" : " before every check passed")")
        return undo
    }

    public func status(mode: String) -> EmergencyStatus {
        var st = EmergencyStatus(state: state, readiness: readiness(), escalation: escalation(), mode: mode,
                                 honestNote: EmergencyStatus.encryptionNote, report: EmergencyReport.text(state, clock.now()))
        st.networkSecondsLeft = networkSecondsLeft()
        return st
    }
}

// MARK: - Evidence report (local only; nothing is sent anywhere)

public enum EmergencyReport {
    public static func text(_ s: EmergencyState, _ now: Date = Date()) -> String {
        let f = ISO8601DateFormatter()
        var o = "\(Product.name) incident report (local copy; nothing was sent anywhere)\n"
        o += "Generated: \(f.string(from: now))\n"
        o += "Lockdown: \(s.active ? "ON" : "off")\(s.dryRun ? " (dry run)" : "")\n"
        if let st = s.startedAt { o += "Started: \(f.string(from: st))\n" }
        if let r = s.reason {
            o += "Trigger: \(r.kind.rawValue) — \(r.summary)\n"
            if let n = r.detectionName { o += "Detection: \(n) (confidence \(r.confidence))\n" }
            if let p = r.path { o += "File: \(p)\n" }
            if let h = r.sha256 { o += "SHA-256: \(h)\n" }
            if let pid = r.pid { o += "Process ID: \(pid)\n" }
            o += "Started by: \(r.kind == .manual ? "you" : "an automatic trigger")\n"
        }
        o += "Internet: \(s.isNetworkBlocked ? "blocked" : "on")\(s.networkWhy.map { " (\($0))" } ?? "")\n"
        o += "If the app can't lift it: \(EmergencyStatus.sudoEscape)\n"
        if !s.signals.isEmpty { o += "Escalation: " + s.signals.map { EmergencyEscalation.describe($0) }.joined(separator: " ") + "\n" }
        o += "\nActions:\n"
        for a in s.actions { o += "- \(a.title): \(a.state.rawValue)\(a.result.isEmpty ? "" : " (\(a.result))")\n" }
        o += "\nLog:\n"
        for e in s.log.suffix(100) { o += "\(f.string(from: e.date))  \(e.text)\n" }
        return o
    }
}

// MARK: - Protect Everything

/// One protection the "Protect Everything" switch manages.
public struct ProtectStep: Codable, Hashable, Identifiable, Sendable {
    public enum ID: String, Codable, Sendable, CaseIterable {
        case realtime, webProtection, autoQuarantine, scanArchives, autoUpdate, ransomwareCanaries, remoteLockdown, pasteGuard,
             publicWiFiGuard, tamperProtection, firewall, stealthMode, breachChecks
    }
    public enum Status: String, Codable, Sendable {
        case alreadyOn, willTurnOn, turnedOn, needsPermission, needsAdmin, unavailable, failed
    }
    /// How the step is applied (the app runs these through the existing IPC calls).
    public enum Via: String, Codable, Sendable { case settings, setRealtime, setWebProtection, setRemoteLockdown, fixPosture, appLocal, none }
    public var id: ID
    public var title: String
    public var status: Status
    public var via: Via
    public var note: String
    public init(id: ID, title: String, status: Status, via: Via, note: String = "") {
        self.id = id; self.title = title; self.status = status; self.via = via; self.note = note
    }
    public var needsUser: Bool { status == .needsPermission || status == .needsAdmin }
}

/// What's on right now (gathered by the app from existing IPC replies and local hosts).
public struct ProtectSnapshot: Codable, Hashable, Sendable {
    public var settings: RampartSettings
    public var remoteLockdown: Bool?
    public var webProtectionAvailable: Bool       // false in user mode
    public var postureFailing: [String]           // posture check IDs currently failing
    public var pasteGuard: String                 // "active", "needsPermission", "denied", "stopped", "unavailable"
    public var publicWiFiGuardOn: Bool
    public var publicWiFiDisconnect: Bool
    public var tamperEnforcing: Bool
    public var breachChecksOn: Bool
    public var systemService: Bool                // root daemon installed
    public init(settings: RampartSettings, remoteLockdown: Bool?, webProtectionAvailable: Bool, postureFailing: [String], pasteGuard: String,
                publicWiFiGuardOn: Bool, publicWiFiDisconnect: Bool, tamperEnforcing: Bool, breachChecksOn: Bool, systemService: Bool) {
        self.settings = settings; self.remoteLockdown = remoteLockdown; self.webProtectionAvailable = webProtectionAvailable
        self.postureFailing = postureFailing; self.pasteGuard = pasteGuard; self.publicWiFiGuardOn = publicWiFiGuardOn
        self.publicWiFiDisconnect = publicWiFiDisconnect; self.tamperEnforcing = tamperEnforcing; self.breachChecksOn = breachChecksOn
        self.systemService = systemService
    }
}

public enum ProtectEverythingPlanner {
    /// The checklist for turning everything on, from the current snapshot.
    public static func plan(_ s: ProtectSnapshot) -> [ProtectStep] {
        func flag(_ id: ProtectStep.ID, _ t: String, _ on: Bool, via: ProtectStep.Via = .settings) -> ProtectStep {
            ProtectStep(id: id, title: t, status: on ? .alreadyOn : .willTurnOn, via: via)
        }
        let st = s.settings
        var out = [
            flag(.realtime, "Real-time protection", st.realtimeOn, via: .setRealtime),
            s.webProtectionAvailable ? flag(.webProtection, "Web protection (malicious sites blocked)", st.webProtection, via: .setWebProtection)
                : ProtectStep(id: .webProtection, title: "Web protection (malicious sites blocked)", status: st.webProtection ? .alreadyOn : .needsAdmin, via: .setWebProtection,
                              note: "Needs the \(Product.name) system service, which changes DNS settings. Install Full Protection with your admin password."),
            flag(.autoQuarantine, "Quarantine threats automatically", st.autoQuarantine),
            flag(.scanArchives, "Scan inside archives and disk images", st.scanArchives),
            flag(.autoUpdate, "Update threat definitions automatically", st.autoUpdate),
            flag(.ransomwareCanaries, "Ransomware early warning (canary files)", st.ransomwareCanaries),
            s.remoteLockdown == nil
                ? ProtectStep(id: .remoteLockdown, title: "Remote-access lockdown", status: .unavailable, via: .setRemoteLockdown, note: "Needs the \(Product.name) background service.")
                : flag(.remoteLockdown, "Remote-access lockdown", s.remoteLockdown == true, via: .setRemoteLockdown),
        ]
        switch s.pasteGuard {
        case "active": out.append(ProtectStep(id: .pasteGuard, title: "PasteGuard (risky Terminal pastes)", status: .alreadyOn, via: .appLocal))
        case "needsPermission", "denied":
            out.append(ProtectStep(id: .pasteGuard, title: "PasteGuard (risky Terminal pastes)", status: .needsPermission, via: .appLocal,
                                   note: "Needs a macOS permission you grant in System Settings; turned on only if you allow it."))
        case "unavailable": out.append(ProtectStep(id: .pasteGuard, title: "PasteGuard (risky Terminal pastes)", status: .unavailable, via: .appLocal))
        default: out.append(ProtectStep(id: .pasteGuard, title: "PasteGuard (risky Terminal pastes)", status: .willTurnOn, via: .appLocal))
        }
        out.append(ProtectStep(id: .publicWiFiGuard, title: "Public Wi-Fi guard (disconnect from unsafe networks)",
                               status: s.publicWiFiGuardOn && s.publicWiFiDisconnect ? .alreadyOn : .willTurnOn, via: .appLocal))
        out.append(ProtectStep(id: .tamperProtection, title: "Tamper protection", status: s.tamperEnforcing ? .alreadyOn : .needsAdmin, via: .none,
                               note: s.tamperEnforcing ? "" : "Always watching; it can actively defend \(Product.name) only as the installed system service."))
        for (id, check, title) in [(ProtectStep.ID.firewall, "firewall", "macOS firewall"), (.stealthMode, "stealthMode", "Firewall stealth mode")] {
            let failing = s.postureFailing.contains(check)
            out.append(ProtectStep(id: id, title: title, status: !failing ? .alreadyOn : s.systemService ? .willTurnOn : .needsAdmin, via: .fixPosture,
                                   note: failing && !s.systemService ? "Turn it on in System Settings → Network → Firewall, or install Full Protection so \(Product.name) can." : ""))
        }
        out.append(ProtectStep(id: .breachChecks, title: "Password breach checks", status: s.breachChecksOn ? .alreadyOn : .needsPermission, via: .appLocal,
                               note: s.breachChecksOn ? "" : "Runs when your password vault is unlocked (only a 5-character hash prefix leaves your Mac)."))
        return out
    }

    /// Settings with every daemon-side flag turned on.
    public static func everythingOn(_ s: RampartSettings, webAvailable: Bool) -> RampartSettings {
        var n = s
        n.realtimeOn = true; n.autoQuarantine = true; n.scanArchives = true; n.autoUpdate = true; n.ransomwareCanaries = true
        if webAvailable { n.webProtection = true }
        return n
    }

    /// Settings to restore when the user turns the switch back off: only flags Protect Everything changed go back.
    public static func revert(current: RampartSettings, previous: RampartSettings) -> RampartSettings {
        var n = current
        n.realtimeOn = previous.realtimeOn; n.autoQuarantine = previous.autoQuarantine; n.scanArchives = previous.scanArchives
        n.autoUpdate = previous.autoUpdate; n.ransomwareCanaries = previous.ransomwareCanaries; n.webProtection = previous.webProtection
        return n
    }
}

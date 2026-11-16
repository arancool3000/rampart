import Foundation
import RampartShared

// Remote-access lockdown: "blocked until you allow". Detects Apple sharing services and third-party
// remote-control tools, applies a default-deny policy with per-tool (optionally time-limited) allowances,
// and generates the privileged actions (kill via hook, launchctl, systemsetup, pf) for the daemon.

// MARK: - Catalogue

public struct RemoteTool: Codable, Hashable, Identifiable, Sendable {
    public var id: String
    public var name: String
    public var vendor: String
    /// Apple Team IDs. Those marked in `teamIDNote` as unverified only add a weak hint; bundle/signing IDs decide.
    public var teamIDs: [String]
    public var signingIDPrefixes: [String]   // also matched against bundle identifiers and launchd labels
    public var pathHints: [String]           // lowercase substrings of executable paths
    public var ports: [Int]                  // listening or outbound ports typical for the tool
    public var isAppleService: Bool
    public init(id: String, name: String, vendor: String, teamIDs: [String] = [], signingIDPrefixes: [String],
                pathHints: [String] = [], ports: [Int] = [], isAppleService: Bool = false) {
        self.id = id; self.name = name; self.vendor = vendor; self.teamIDs = teamIDs; self.signingIDPrefixes = signingIDPrefixes
        self.pathHints = pathHints; self.ports = ports; self.isAppleService = isAppleService
    }
}

public enum RemoteToolCatalogue {
    /// Apple services first, then third-party tools. Team IDs: Google's is well known; the others are best-effort
    /// and only count as a weak hint, so a wrong one cannot cause a false positive on its own.
    public static let all: [RemoteTool] = [
        RemoteTool(id: "apple.screensharing", name: "Screen Sharing", vendor: "Apple", signingIDPrefixes: ["com.apple.screensharing", "com.apple.ScreensharingAgent"],
                   pathHints: ["screensharingd", "screensharingagent"], ports: [5900], isAppleService: true),
        RemoteTool(id: "apple.ard", name: "Remote Management (ARD)", vendor: "Apple", signingIDPrefixes: ["com.apple.RemoteDesktop", "com.apple.ARDAgent"],
                   pathHints: ["/ardagent.app/", "/ardagent"], ports: [3283, 5900], isAppleService: true),
        RemoteTool(id: "apple.ssh", name: "Remote Login (SSH)", vendor: "Apple", signingIDPrefixes: ["com.openssh.sshd"],
                   pathHints: ["/usr/sbin/sshd", "sshd-keygen-wrapper", "sshd-session"], ports: [22], isAppleService: true),
        RemoteTool(id: "apple.aeserver", name: "Remote Apple Events", vendor: "Apple", signingIDPrefixes: ["com.apple.AEServer"],
                   pathHints: ["aeserver"], ports: [3031], isAppleService: true),
        RemoteTool(id: "teamviewer", name: "TeamViewer", vendor: "TeamViewer GmbH", teamIDs: ["H7UGFYMTCW"],
                   signingIDPrefixes: ["com.teamviewer"], pathHints: ["teamviewer"], ports: [5938]),
        RemoteTool(id: "anydesk", name: "AnyDesk", vendor: "AnyDesk Software GmbH", teamIDs: ["KU6W3B6JMZ"],
                   signingIDPrefixes: ["com.philandro.anydesk", "com.anydesk"], pathHints: ["anydesk"], ports: [7070, 6568]),
        RemoteTool(id: "rustdesk", name: "RustDesk", vendor: "Purslane Ltd", teamIDs: ["HZF9JMC8YN"],
                   signingIDPrefixes: ["com.carriez.rustdesk", "com.carriez.RustDesk"], pathHints: ["rustdesk"], ports: [21115, 21116, 21117, 21118, 21119]),
        RemoteTool(id: "splashtop", name: "Splashtop", vendor: "Splashtop Inc.", teamIDs: ["CPQQ3AW4C8"],
                   signingIDPrefixes: ["com.splashtop"], pathHints: ["splashtop"], ports: [6783, 6784, 6785]),
        RemoteTool(id: "screenconnect", name: "ConnectWise ScreenConnect", vendor: "ConnectWise", teamIDs: ["GKGQ8D7YL2"],
                   signingIDPrefixes: ["com.screenconnect", "com.connectwise", "screenconnect-"], pathHints: ["screenconnect", "connectwise"], ports: [8040, 8041]),
        RemoteTool(id: "logmein", name: "LogMeIn / GoTo", vendor: "GoTo", teamIDs: ["GFNPVD63B7"],
                   signingIDPrefixes: ["com.logmein", "com.goto"], pathHints: ["logmein", "gotoresolve", "gotoassist"], ports: []),
        RemoteTool(id: "chromeremotedesktop", name: "Chrome Remote Desktop", vendor: "Google", teamIDs: ["EQHXZ8M8AV"],
                   signingIDPrefixes: ["com.google.chrome.remote_desktop", "org.chromium.chromoting", "com.google.chromeremotedesktop"],
                   pathHints: ["chrome remote desktop", "chromoting", "remote_assistance_host"], ports: []),
        RemoteTool(id: "zohoassist", name: "Zoho Assist", vendor: "Zoho", teamIDs: ["TZ824L8Y37"],
                   signingIDPrefixes: ["com.zoho.assist", "com.zohocorp.assist", "com.zoho.ZA"], pathHints: ["zoho assist", "zohoassist", "zaservice"], ports: []),
        RemoteTool(id: "parsec", name: "Parsec", vendor: "Unity", teamIDs: ["UD7A9A5B2P"],
                   signingIDPrefixes: ["tv.parsec", "com.parsec"], pathHints: ["parsec"], ports: [8000, 8001, 8002, 8003, 8004]),
        RemoteTool(id: "anyviewer", name: "AnyViewer", vendor: "AOMEI", signingIDPrefixes: ["com.aomei.anyviewer", "com.anyviewer"], pathHints: ["anyviewer"], ports: [30192]),
        RemoteTool(id: "hoptodesk", name: "HopToDesk", vendor: "HopToDesk", signingIDPrefixes: ["com.hoptodesk"], pathHints: ["hoptodesk"], ports: [21116, 21117]),
    ]
    public static func tool(_ id: String) -> RemoteTool? { all.first { $0.id == id } }
    /// Ports the inbound firewall blocks while lockdown is on and nothing is allowed.
    public static var inboundPorts: [Int] { Array(Set(all.flatMap(\.ports))).sorted() }
    /// Well-known Team IDs (strong on their own).
    public static let strongTeamIDs: Set<String> = ["EQHXZ8M8AV"]

    /// Apple's MDM machinery (device management, single sign-on, configuration profiles). Not remote access:
    /// on organisation-managed Macs it is how the organisation applies settings and network filters. Never match it.
    public static let mdmPathPrefixes = ["/system/library/privateframeworks/remotemanagement.framework/",
                                         "/system/library/privateframeworks/managedconfiguration.framework/"]

    private static let lowPrefixes: [[String]] = all.map { $0.signingIDPrefixes.map { $0.lowercased() } }

    public static func identify(signingID: String?, teamID: String?, path: String?, bundleID: String? = nil, label: String? = nil) -> (RemoteTool, [String])? {
        let lowPath = (path ?? "").lowercased()
        if mdmPathPrefixes.contains(where: { lowPath.hasPrefix($0) }) { return nil }
        if let sid = (signingID ?? bundleID)?.lowercased(), sid.hasPrefix("com.apple.remotemanagement") || sid.hasPrefix("com.apple.managedclient") { return nil }
        let ids = [signingID, bundleID, label].compactMap { $0 }
        let lowIDs = ids.map { $0.lowercased() }
        for (ti, t) in all.enumerated() {
            var why: [String] = []
            let prefixes = lowPrefixes[ti]
            for (s, ls) in zip(ids, lowIDs) where prefixes.contains(where: { ls.hasPrefix($0) }) {
                why.append("identifier \(s)")
            }
            if let tid = teamID, t.teamIDs.contains(tid) { why.append(strongTeamIDs.contains(tid) ? "Team ID \(tid)" : "Team ID \(tid) (hint)") }
            if !lowPath.isEmpty, t.pathHints.contains(where: { lowPath.contains($0) }) { why.append("path") }
            // Path alone is weak unless it is an Apple service daemon; a hint-only team ID alone is weak.
            let strong = why.contains { $0.hasPrefix("identifier") } || why.contains { $0.hasPrefix("Team ID") && !$0.hasSuffix("(hint)") }
            if strong || (t.isAppleService && why.contains("path")) || why.count >= 2 { return (t, why) }
        }
        return nil
    }
}

// MARK: - Inputs (live probes, injectable fixtures)

public struct ListeningPort: Codable, Hashable, Sendable {
    public var port: Int
    public var proto: String
    public var pid: Int32?
    public var process: String
    /// Local bind address from lsof ("*", "127.0.0.1", "[::1]"...). Empty when unknown.
    public var address: String = ""
    public init(port: Int, proto: String = "TCP", pid: Int32? = nil, process: String = "", address: String = "") {
        self.port = port; self.proto = proto; self.pid = pid; self.process = process; self.address = address
    }
    /// Identity ignores the bind address (added by hx5) so existing comparisons keep their meaning.
    public static func == (a: ListeningPort, b: ListeningPort) -> Bool { a.port == b.port && a.proto == b.proto && a.pid == b.pid && a.process == b.process }
    public func hash(into h: inout Hasher) { h.combine(port); h.combine(proto); h.combine(pid); h.combine(process) }
    public var isLoopback: Bool {
        let a = address.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        return a.hasPrefix("127.") || a == "::1" || a == "localhost"
    }
}

public struct SharingServiceState: Codable, Hashable, Sendable {
    public var screenSharing: Bool?
    public var remoteManagement: Bool?
    public var remoteLogin: Bool?
    public var remoteAppleEvents: Bool?
    public init(screenSharing: Bool? = nil, remoteManagement: Bool? = nil, remoteLogin: Bool? = nil, remoteAppleEvents: Bool? = nil) {
        self.screenSharing = screenSharing; self.remoteManagement = remoteManagement; self.remoteLogin = remoteLogin; self.remoteAppleEvents = remoteAppleEvents
    }
}

/// Scam context: remote tools started while a browser is frontmost, or shortly after a support-scam page, are how
/// tech-support scammers get in ("let me connect to fix the virus"). RampartWeb feeds `lastScamPageAt`.
public struct ScamContext: Codable, Hashable, Sendable {
    public var frontmostBundleID: String?
    public var lastScamPageAt: Date?
    public var window: TimeInterval = 15 * 60
    public init(frontmostBundleID: String? = nil, lastScamPageAt: Date? = nil, window: TimeInterval = 15 * 60) {
        self.frontmostBundleID = frontmostBundleID; self.lastScamPageAt = lastScamPageAt; self.window = window
    }
    public static let browsers = ["com.apple.safari", "com.google.chrome", "com.brave.browser", "com.microsoft.edgemac", "org.mozilla.firefox", "company.thebrowser.browser", "com.operasoftware.opera", "com.vivaldi.vivaldi"]
    public func isSuspicious(at now: Date) -> (Bool, String) {
        if let f = frontmostBundleID?.lowercased(), Self.browsers.contains(where: { f.hasPrefix($0) }) { return (true, "started while a web browser was frontmost") }
        if let t = lastScamPageAt, now.timeIntervalSince(t) >= 0, now.timeIntervalSince(t) <= window { return (true, "started \(Int(now.timeIntervalSince(t) / 60)) min after a support-scam page") }
        return (false, "")
    }
}

public struct RemoteAccessProbe: @unchecked Sendable {
    public var processes: () -> [ProcessInfoLite]
    public var listeners: () -> [ListeningPort]
    public var launchItems: () -> [PersistenceItem]
    public var sharing: () -> SharingServiceState
    public var inbound: () -> [ConnectionInfo]
    public var scam: () -> ScamContext
    public var now: () -> Date
    public init(processes: @escaping () -> [ProcessInfoLite], listeners: @escaping () -> [ListeningPort], launchItems: @escaping () -> [PersistenceItem],
                sharing: @escaping () -> SharingServiceState, inbound: @escaping () -> [ConnectionInfo], scam: @escaping () -> ScamContext = { ScamContext() },
                now: @escaping () -> Date = { Date() }) {
        self.processes = processes; self.listeners = listeners; self.launchItems = launchItems; self.sharing = sharing; self.inbound = inbound; self.scam = scam; self.now = now
    }

    /// Read-only live probe: libproc for processes, `lsof` for listeners and inbound sessions, `launchctl print`
    /// for the Apple services (works unprivileged: "Could not find service" means off), plist folders for launch items.
    /// Under `RAMPART_NO_PRIVILEGED_TOOLS=1` (development) no external tool is spawned: listeners/inbound are empty and
    /// every sharing flag is nil ("unknown"), so nothing on the user's screen can be triggered.
    public static func live(runner: GuardCommandRunning = GuardProcessRunner(), scam: @escaping () -> ScamContext = { ScamContext() }) -> RemoteAccessProbe {
        if GuardProcessRunner.devSafeMode {
            return RemoteAccessProbe(processes: { GuardProc.processes() }, listeners: { [] },
                                     launchItems: { RemoteAccessParsers.launchItems(in: ["/Library/LaunchDaemons", "/Library/LaunchAgents", NSHomeDirectory() + "/Library/LaunchAgents"]) },
                                     sharing: { SharingServiceState() }, inbound: { [] }, scam: scam)
        }
        return RemoteAccessProbe(
            processes: { GuardProc.processes() },
            listeners: { RemoteAccessParsers.listeners(fromLsof: runner.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"], timeout: 8).stdout) },
            launchItems: { RemoteAccessParsers.launchItems(in: ["/Library/LaunchDaemons", "/Library/LaunchAgents", NSHomeDirectory() + "/Library/LaunchAgents"]) },
            sharing: {
                func loaded(_ label: String) -> Bool? {
                    let r = runner.run("/bin/launchctl", ["print", "system/\(label)"], timeout: 5)
                    if r.launchFailed { return nil }
                    return r.status == 0 && !r.stdout.isEmpty
                }
                return SharingServiceState(screenSharing: loaded("com.apple.screensharing"),
                                           remoteManagement: FileManager.default.fileExists(atPath: "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd"),
                                           remoteLogin: loaded("com.openssh.sshd"), remoteAppleEvents: loaded("com.apple.AEServer"))
            },
            inbound: { RemoteAccessParsers.inbound(fromLsof: runner.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn"], timeout: 8).stdout) },
            scam: scam)
    }
}

public enum RemoteAccessParsers {
    /// `lsof -F pcn` output: lines prefixed p(pid) c(command) n(name "host:port->host:port" or "*:port").
    public static func listeners(fromLsof text: String) -> [ListeningPort] {
        var out: [ListeningPort] = []; var pid: Int32? = nil; var cmd = ""
        for line in text.split(separator: "\n") {
            guard let k = line.first else { continue }
            let v = String(line.dropFirst())
            switch k {
            case "p": pid = Int32(v); case "c": cmd = v
            case "n":
                if !v.contains("->"), let i = v.lastIndex(of: ":"), let port = Int(v[v.index(after: i)...]), (0...65535).contains(port) {
                    out.append(ListeningPort(port: port, pid: pid, process: cmd, address: String(v[..<i])))
                }
            default: break
            }
        }
        return out
    }
    /// Established sessions where the local side is one of our watched ports (an inbound remote session).
    public static func inbound(fromLsof text: String, watched: Set<Int> = Set(RemoteToolCatalogue.inboundPorts)) -> [ConnectionInfo] {
        var out: [ConnectionInfo] = []; var pid: Int32 = 0; var cmd = ""
        for line in text.split(separator: "\n") {
            guard let k = line.first else { continue }
            let v = String(line.dropFirst())
            switch k {
            case "p": pid = Int32(v) ?? 0; case "c": cmd = v
            case "n":
                let ends = v.components(separatedBy: "->"); guard ends.count == 2 else { continue }
                func split(_ s: String) -> (String, Int) {
                    guard let i = s.lastIndex(of: ":") else { return (s, 0) }
                    return (String(s[..<i]), Int(s[s.index(after: i)...]) ?? 0)
                }
                let (lh, lp) = split(ends[0]); let (rh, rp) = split(ends[1])
                if watched.contains(lp) {
                    out.append(ConnectionInfo(pid: pid, processName: cmd, proto: "TCP", localPort: lp, remoteAddress: rh.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), remotePort: rp, state: "ESTABLISHED"))
                    _ = lh
                }
            default: break
            }
        }
        return out
    }
    public static func launchItems(in dirs: [String]) -> [PersistenceItem] {
        var out: [PersistenceItem] = []
        for d in dirs {
            for f in (try? FileManager.default.contentsOfDirectory(atPath: d)) ?? [] where f.hasSuffix(".plist") {
                let p = d + "/" + f
                guard let data = FileManager.default.contents(atPath: p),
                      let pl = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { continue }
                let label = pl["Label"] as? String ?? String(f.dropLast(6))
                let target = (pl["Program"] as? String) ?? (pl["ProgramArguments"] as? [String])?.first
                out.append(PersistenceItem(kind: d.contains("LaunchDaemons") ? .launchDaemon : .launchAgent, label: label, location: p, target: target))
            }
        }
        return out
    }
}

// MARK: - Findings and policy

public struct RemoteToolFinding: Codable, Hashable, Identifiable, Sendable {
    public var id: String { toolID }
    public var toolID: String
    public var name: String
    public var isAppleService: Bool
    public var pids: [Int32]
    public var paths: [String]
    public var launchItems: [String]      // plist paths
    public var listeningPorts: [Int]
    public var inboundSessions: Int
    public var matchedBy: [String]
    public var serviceEnabled: Bool?      // Apple services: sharing toggle state
    public var allowed: Bool
    public var allowedUntil: Date?
    public var scamContext: Bool
    public var scamReason: String
    public var severity: Severity
    public var active: Bool { !pids.isEmpty || !listeningPorts.isEmpty || serviceEnabled == true || inboundSessions > 0 }
}

public struct RemoteAllowance: Codable, Hashable, Identifiable, Sendable {
    public var id: String { toolID }
    public var toolID: String
    public var name: String
    public var created: Date
    public var expires: Date?
    /// hx5: Team IDs seen on the tool when the user allowed it. When set, a process claiming the tool's identifier
    /// but signed by anyone else (or ad-hoc) is not covered by the allowance: a look-alike can't ride on it.
    public var teamIDs: [String]?
    /// Longest time-limited allowance (a "1 hour" approval must not become a year through a bad request).
    public static let maxMinutes = 7 * 24 * 60
    /// Tolerated backwards clock drift before a time-limited allowance is treated as void.
    public static let clockSkew: TimeInterval = 300
    public init(toolID: String, name: String, created: Date = Date(), expires: Date? = nil, teamIDs: [String]? = nil) {
        self.toolID = toolID; self.name = name; self.created = created; self.expires = expires; self.teamIDs = teamIDs
    }
    /// hx5: a time-limited allowance is void if the clock reads earlier than when it was granted (clock rolled back to
    /// stretch it) or if its window is longer than `maxMinutes` (a forged or corrupt policy). Permanent allowances
    /// (`expires == nil`) are an explicit user choice and stay active until revoked.
    public func isActive(at now: Date) -> Bool {
        guard let e = expires else { return true }
        if now < created.addingTimeInterval(-Self.clockSkew) { return false }
        if e.timeIntervalSince(created) > Double(Self.maxMinutes) * 60 + 1 { return false }
        return now < e
    }
}

/// Default deny. Persisted by the daemon (sealed) at `GuardPaths.remotePolicyFile`.
public struct RemoteAccessPolicy: Codable, Hashable, Sendable {
    public var lockdownEnabled: Bool = true
    public var allowances: [RemoteAllowance] = []
    /// Kill/suspend unapproved third-party tools (not just alert). Apple services are only turned off, never killed.
    public var enforceKill: Bool = true
    public var suspendInsteadOfKill: Bool = true
    public init() {}

    public func allowance(for toolID: String, at now: Date) -> RemoteAllowance? {
        allowances.first { $0.toolID == toolID && $0.isActive(at: now) }
    }
    /// `minutes` nil = until revoked; otherwise clamped to 1...RemoteAllowance.maxMinutes (0 or negative is never
    /// "forever"). `pinTeamIDs`: the daemon passes the Team IDs of the running tool so the allowance covers only it.
    public mutating func allow(_ tool: RemoteTool, minutes: Int?, now: Date = Date(), pinTeamIDs: [String]? = nil) {
        allowances.removeAll { $0.toolID == tool.id }
        let m = minutes.map { min(max($0, 1), RemoteAllowance.maxMinutes) }
        let pins = pinTeamIDs.map { Array(Set($0.filter { !$0.isEmpty })).sorted() }.flatMap { $0.isEmpty ? nil : $0 }
        allowances.append(RemoteAllowance(toolID: tool.id, name: tool.name, created: now, expires: m.map { now.addingTimeInterval(Double($0) * 60) }, teamIDs: pins))
    }
    public mutating func revoke(_ toolID: String) { allowances.removeAll { $0.toolID == toolID } }
    public mutating func prune(now: Date = Date()) { allowances.removeAll { !$0.isActive(at: now) } }
}

public struct RemoteAccessReport: Codable, Hashable, Sendable {
    public var generatedAt: Date
    public var lockdownEnabled: Bool
    public var findings: [RemoteToolFinding]
    public var sharing: SharingServiceState
    public var inbound: [ConnectionInfo]
    public var unknownListeners: [ListeningPort]   // watched ports held by something we could not identify
    public var blockedPorts: [Int]
    public var note: String
    /// hx5: non-loopback listeners held by an unsigned or ad-hoc signed program (no Team ID). A renamed or re-signed
    /// remote tool on a non-default port lands here instead of disappearing. Only filled when the probe supplies
    /// signing info (the daemon enriches processes); weak signal, reported at low severity.
    public var unsignedListeners: [ListeningPort] = []
    public var activeUnapproved: [RemoteToolFinding] { findings.filter { $0.active && !$0.allowed } }
}

// MARK: - Monitor

public final class RemoteAccessMonitor: @unchecked Sendable {
    public let probe: RemoteAccessProbe
    public init(probe: RemoteAccessProbe) { self.probe = probe }

    public func report(policy: RemoteAccessPolicy) -> RemoteAccessReport {
        let now = probe.now()
        let procs = probe.processes(), listeners = probe.listeners(), items = probe.launchItems()
        let sharing = probe.sharing(), inbound = probe.inbound(), scam = probe.scam()
        let (scamHit, scamReason) = scam.isSuspicious(at: now)
        var byTool: [String: RemoteToolFinding] = [:]
        func slot(_ t: RemoteTool) -> RemoteToolFinding {
            byTool[t.id] ?? RemoteToolFinding(toolID: t.id, name: t.name, isAppleService: t.isAppleService, pids: [], paths: [], launchItems: [], listeningPorts: [],
                                             inboundSessions: 0, matchedBy: [], serviceEnabled: nil, allowed: false, allowedUntil: nil, scamContext: false, scamReason: "", severity: .info)
        }
        for p in procs {
            if let (t, why) = RemoteToolCatalogue.identify(signingID: p.signingID, teamID: p.teamID, path: p.path) {
                var f = slot(t); f.pids.append(p.pid); if !f.paths.contains(p.path) { f.paths.append(p.path) }
                f.matchedBy = Array(Set(f.matchedBy + why)).sorted(); byTool[t.id] = f
            }
        }
        for i in items {
            if let (t, why) = RemoteToolCatalogue.identify(signingID: i.signing?.signingID, teamID: i.signing?.teamID, path: i.target, label: i.label) {
                var f = slot(t); f.launchItems.append(i.location); f.matchedBy = Array(Set(f.matchedBy + why.map { "launch item " + $0 })).sorted(); byTool[t.id] = f
            }
        }
        var unknown: [ListeningPort] = []
        for l in listeners {
            let owner = l.pid.flatMap { pid in byTool.values.first { $0.pids.contains(pid) } }
            if let o = owner { var f = byTool[o.toolID]!; f.listeningPorts.append(l.port); byTool[o.toolID] = f; continue }
            if let t = RemoteToolCatalogue.all.first(where: { $0.ports.contains(l.port) }), t.isAppleService || !l.process.isEmpty && t.pathHints.contains(where: { l.process.lowercased().contains($0) }) {
                var f = slot(t); f.listeningPorts.append(l.port); f.matchedBy = Array(Set(f.matchedBy + ["port \(l.port)"])).sorted(); byTool[t.id] = f
            } else if RemoteToolCatalogue.inboundPorts.contains(l.port) { unknown.append(l) }
        }
        for c in inbound {
            if let t = RemoteToolCatalogue.all.first(where: { $0.ports.contains(c.localPort) }) { var f = slot(t); f.inboundSessions += 1; byTool[t.id] = f }
        }
        let serviceFlags: [(String, Bool?)] = [("apple.screensharing", sharing.screenSharing), ("apple.ard", sharing.remoteManagement), ("apple.ssh", sharing.remoteLogin), ("apple.aeserver", sharing.remoteAppleEvents)]
        for (id, on) in serviceFlags {
            guard let t = RemoteToolCatalogue.tool(id) else { continue }
            if on == true || byTool[id] != nil { var f = slot(t); f.serviceEnabled = on; byTool[id] = f }
        }
        let procByPID = Dictionary(procs.map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        let claimed = Set(byTool.values.flatMap(\.pids))
        var unsigned: [ListeningPort] = []
        for l in listeners where !l.isLoopback {
            guard let pid = l.pid, !claimed.contains(pid), let pr = procByPID[pid], pr.signingID != nil, !pr.isPlatformBinary,
                  (pr.teamID ?? "").isEmpty, !pr.path.hasPrefix("/System/"), !pr.path.hasPrefix("/usr/libexec/"), !pr.path.hasPrefix("/usr/sbin/") else { continue }
            if unsigned.count < 64, !unknown.contains(l) { unsigned.append(l) }
        }
        var findings = byTool.values.map { f -> RemoteToolFinding in
            var f = f
            if let a = policy.allowance(for: f.toolID, at: now) {
                // hx5: a pinned allowance covers only processes signed by the Team IDs seen when it was granted.
                let pinned = a.teamIDs ?? []
                var impostor = !pinned.isEmpty && f.pids.contains { pid in !pinned.contains(procByPID[pid]?.teamID ?? "") }
                // wms-o7: an allowance granted while the tool wasn't running has no pins, and used to cover anything that
                // matched the tool by name or path (`~/Downloads/teamviewer/x`, an ad-hoc `codesign -i com.teamviewer.x`).
                // When signing facts are known and not one of the tool's processes carries a Team ID, it is a look-alike.
                // Apple's own services carry no Team ID (platform binaries), so the rule is for third-party tools only.
                if pinned.isEmpty, !f.isAppleService, !f.pids.isEmpty {
                    let known = f.pids.compactMap { procByPID[$0] }.filter { $0.signingID != nil || $0.teamID != nil }
                    if !known.isEmpty, !f.pids.contains(where: { !(procByPID[$0]?.teamID ?? "").isEmpty }) { impostor = true }
                }
                if !impostor { f.allowed = true; f.allowedUntil = a.expires }
                else { f.matchedBy = Array(Set(f.matchedBy + ["signer differs from the approved one"])).sorted() }
            }
            if !f.isAppleService && !f.pids.isEmpty && scamHit { f.scamContext = true; f.scamReason = scamReason }
            f.severity = !f.active ? .info : f.allowed ? .low : f.scamContext ? .critical : f.isAppleService ? .medium : .high
            f.pids.sort(); f.listeningPorts = Array(Set(f.listeningPorts)).sorted()
            return f
        }
        findings.sort { ($0.severity, $0.name) > ($1.severity, $1.name) }
        let blocked = policy.lockdownEnabled ? RemoteToolCatalogue.inboundPorts.filter { port in
            !findings.contains { $0.allowed && (RemoteToolCatalogue.tool($0.toolID)?.ports.contains(port) ?? false) }
        } : []
        return RemoteAccessReport(generatedAt: now, lockdownEnabled: policy.lockdownEnabled, findings: findings, sharing: sharing, inbound: inbound,
                                  unknownListeners: unknown, blockedPorts: blocked,
                                  note: "Remote access is blocked until you allow a tool. Allowances can be time-limited. Apple services are turned off in System Settings rather than killed. " +
                                        "A remote tool that is renamed, re-signed and moved to another port may not be recognised; unsigned programs accepting outside connections are listed separately.",
                                  unsignedListeners: unsigned)
    }

    /// Detections for the daemon's feed: one per active unapproved tool (and one per unknown listener on a watched port).
    public func detections(from r: RemoteAccessReport) -> [Detection] {
        var out: [Detection] = []
        guard r.lockdownEnabled else { return out }
        for f in r.activeUnapproved {
            var ev = [Evidence(source: .behaviour, title: "\(f.name) is \(f.isAppleService ? "enabled" : "running") without your approval",
                               detail: "matched by " + f.matchedBy.joined(separator: ", ") + (f.pids.isEmpty ? "" : "; pids " + f.pids.map(String.init).joined(separator: ",")), score: f.isAppleService ? 55 : 75)]
            if f.inboundSessions > 0 { ev.append(Evidence(source: .network, title: "Active inbound session", detail: "\(f.inboundSessions) established connection(s) on its port", score: 70)) }
            if f.scamContext { ev.append(Evidence(source: .behaviour, title: "Tech-support scam pattern", detail: f.scamReason + ". Scammers ask victims to install remote-control tools.", score: 85)) }
            out.append(Detection(path: f.paths.first, pid: f.pids.first, name: "Unapproved remote access: \(f.name)", category: .backdoor,
                                 severity: f.severity, confidence: min(99, ev.map(\.score).max() ?? 60), evidence: ev))
        }
        for l in r.unsignedListeners {
            out.append(Detection(pid: l.pid, name: "Unsigned program accepting outside connections on port \(l.port)", category: .suspicious, severity: .low, confidence: 40,
                                 evidence: [Evidence(source: .network, title: "\(l.process.isEmpty ? "A program" : l.process) listens on \(l.address.isEmpty ? "*" : l.address):\(l.port)",
                                                     detail: "no Team ID signature; remote-control tools that are renamed or moved to other ports look like this", score: 40)]))
        }
        for l in r.unknownListeners {
            out.append(Detection(pid: l.pid, name: "Unknown listener on remote-access port \(l.port)", category: .suspicious, severity: .medium, confidence: 50,
                                 evidence: [Evidence(source: .network, title: "\(l.process.isEmpty ? "A process" : l.process) listens on \(l.port)", detail: "port used by remote-control software", score: 50)]))
        }
        return out
    }
}

// MARK: - Enforcement

public struct RemoteEnforcementPlan: Codable, Sendable {
    public var dryRun: Bool
    public var suspendPIDs: [Int32]
    public var killPIDs: [Int32]
    public var signalled: [Int32]
    public var commands: [GuardCommand]
    public var pfRules: String
    public var pfFile: String
    public var notes: [String]
}

/// Turns a report + policy into actions. Kills go through `KillHook` (the daemon injects ProcessKiller-backed logic
/// that refuses platform binaries and checks pid reuse). Everything else is a GuardCommand for the daemon.
public struct RemoteAccessEnforcer: Sendable {
    /// Resolves a pid to its executable path (injectable for tests).
    nonisolated(unsafe) public static var processPath: (Int32) -> String = { GuardProc.path(of: $0) }
    public static let launchctl = "/bin/launchctl", systemsetup = "/usr/sbin/systemsetup", kickstart = "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart", pfctl = "/sbin/pfctl"
    public let kill: KillHook
    public let firewall: RemoteAccessFirewall
    public init(kill: @escaping KillHook, firewall: RemoteAccessFirewall = RemoteAccessFirewall()) { self.kill = kill; self.firewall = firewall }

    public func plan(report r: RemoteAccessReport, policy: RemoteAccessPolicy, dryRun: Bool = true) -> RemoteEnforcementPlan {
        var p = RemoteEnforcementPlan(dryRun: dryRun, suspendPIDs: [], killPIDs: [], signalled: [], commands: [], pfRules: "", pfFile: firewall.rulesPath, notes: [])
        guard policy.lockdownEnabled else { p.notes.append("lockdown off: nothing enforced"); return p }
        for f in r.activeUnapproved {
            if f.isAppleService {
                switch f.toolID {
                case "apple.ssh": p.commands.append(GuardCommand(Self.systemsetup, ["-f", "-setremotelogin", "off"], note: "needs FDA on macOS 13+; open SSH sessions end"))
                case "apple.aeserver": p.commands.append(GuardCommand(Self.systemsetup, ["-setremoteappleevents", "off"]))
                case "apple.screensharing": p.commands.append(GuardCommand(Self.launchctl, ["bootout", "system/com.apple.screensharing"], acceptableExitCodes: [3, 113], note: "turns Screen Sharing off until re-enabled in System Settings"))
                case "apple.ard": p.commands.append(GuardCommand(Self.kickstart, ["-deactivate", "-stop"], note: "Remote Management off"))
                default: break
                }
                continue
            }
            if policy.enforceKill {
                if policy.suspendInsteadOfKill { p.suspendPIDs += f.pids } else { p.killPIDs += f.pids }
            }
            for item in f.launchItems {
                let label = (item as NSString).lastPathComponent.replacingOccurrences(of: ".plist", with: "")
                let domain = item.contains("LaunchDaemons") ? "system" : "gui/\(getuid())"
                p.commands.append(GuardCommand(Self.launchctl, ["bootout", "\(domain)/\(label)"], requiresRoot: domain == "system", acceptableExitCodes: [3, 113]))
                p.commands.append(GuardCommand(Self.launchctl, ["disable", "\(domain)/\(label)"], requiresRoot: domain == "system"))
            }
            p.notes.append("\(f.name): \(policy.suspendInsteadOfKill ? "suspend" : "kill") pids \(f.pids), disable \(f.launchItems.count) launch item(s)")
        }
        p.pfRules = firewall.anchorRules(blockedPorts: r.blockedPorts)
        p.commands += firewall.loadCommands()
        // Hard guard: never signal macOS system processes, whatever matched upstream.
        // hx5: "/usr/" used to cover /usr/local (Homebrew, user-writable): a remote tool installed there was never stopped.
        let protectedPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"]
        func isSystem(_ pid: Int32) -> Bool {
            let path = Self.processPath(pid)
            if path.hasPrefix("/usr/local/") { return pid <= 1 }
            return pid <= 1 || protectedPrefixes.contains { path.hasPrefix($0) }
        }
        p.suspendPIDs.removeAll(where: isSystem); p.killPIDs.removeAll(where: isSystem)
        if !dryRun {
            for pid in p.suspendPIDs where kill(pid, SIGSTOP) { p.signalled.append(pid) }
            for pid in p.killPIDs where kill(pid, SIGKILL) { p.signalled.append(pid) }
        }
        return p
    }

    /// Resume suspended processes after the user allows a tool.
    public func resume(_ pids: [Int32], dryRun: Bool = true) -> [Int32] {
        dryRun ? [] : pids.filter { kill($0, SIGCONT) }
    }
}

/// pf anchor for inbound remote-access ports. Separate anchor from RampartNetwork's IP table so either can be
/// loaded alone. Generates files and commands; never runs pfctl.
public struct RemoteAccessFirewall: Codable, Sendable {
    public var anchor: String
    public var directory: String
    public init(anchor: String = "com.apple/251.RampartRemote", directory: String = Paths.effectiveRoot.appendingPathComponent("pf").path) {
        self.anchor = anchor; self.directory = directory
    }
    public var rulesPath: String { directory + "/remote-access.anchor" }

    public func anchorRules(blockedPorts: [Int]) -> String {
        var s = "# \(Product.name) remote-access lockdown (generated; pfctl -a \(anchor) -f \(rulesPath))\n"
        s += "# Inbound connections to these ports are dropped until the user allows the matching tool.\n"
        if blockedPorts.isEmpty { s += "# nothing blocked\n"; return s }
        let ports = blockedPorts.sorted().map(String.init).joined(separator: ", ")
        s += "block drop in quick log proto tcp from any to any port { \(ports) }\n"
        s += "block drop in quick log proto udp from any to any port { \(ports) }\n"
        return s
    }
    public func writeRules(_ rules: String) throws {
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        try rules.write(toFile: rulesPath, atomically: true, encoding: .utf8)
    }
    public func loadCommands() -> [GuardCommand] {
        [GuardCommand(RemoteAccessEnforcer.pfctl, ["-E"], note: "enable pf (reference-counted)"),
         GuardCommand(RemoteAccessEnforcer.pfctl, ["-a", anchor, "-f", rulesPath], note: "load the anchor rules")]
    }
    public func unloadCommands() -> [GuardCommand] { [GuardCommand(RemoteAccessEnforcer.pfctl, ["-a", anchor, "-F", "all"])] }
}

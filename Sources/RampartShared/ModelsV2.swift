import Foundation

// v2 shared types: real data for every app screen. Owned by the lead.

/// One row in Protection Activity. Produced by the daemon (scans, detections, quarantine, blocks, tamper,
/// remote access, lockdown, settings, updates, service start/stop) and by the app for the features that run in
/// the app process (PasteGuard, Wi-Fi guard, vault, authenticator, Refresh, network scan).
/// The structured fields are optional so older `activity.jsonl` lines still decode; `ActivityPresenter` turns any
/// entry (old or new) into plain English. Never put secrets, passwords, vault contents or AI prompts here.
public struct ActivityEntry: Codable, Hashable, Identifiable, Sendable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        case scan, detection, quarantine, restore, persistence, webBlock, posture, update, settings, system
        case tamper, realtime, remoteAccess, pasteGuard, lockdown, wifi, vault, refresh, networkScan
    }
    public var id: UUID
    public var date: Date
    public var kind: Kind
    public var title: String
    public var detail: String
    public var outcome: String
    public var severity: Severity
    public var detectionID: UUID?
    /// Fine-grained decision type (nil on entries written before it existed: inferred by ActivityPresenter).
    public var event: ActivityEvent?
    /// Who caused it (settings changes, lockdown, clean-ups).
    public var actor: ActivityActor?
    /// The process involved, when known.
    public var process: ActivityProcess?
    /// The file path, URL or host involved.
    public var target: String?
    /// The rule, list or check that fired.
    public var rule: String?
    /// Why it fired, plain English.
    public var reason: String?
    /// 0...100 score or confidence.
    public var score: Int?
    /// What RamPart did, plain English.
    public var action: String?
    /// Files scanned, items cleaned, devices found...
    public var count: Int?
    /// Threats found, items failed...
    public var found: Int?
    public var sha256: String?
    /// Id of the related object (quarantine record, allow rule) for Undo.
    public var refID: String?
    /// Extra labelled facts (setting name, old/new value, network name...). Never secrets.
    public var facts: [String: String]?

    public init(id: UUID = UUID(), date: Date = Date(), kind: Kind, title: String, detail: String = "",
                outcome: String = "", severity: Severity = .info, detectionID: UUID? = nil,
                event: ActivityEvent? = nil, actor: ActivityActor? = nil, process: ActivityProcess? = nil,
                target: String? = nil, rule: String? = nil, reason: String? = nil, score: Int? = nil,
                action: String? = nil, count: Int? = nil, found: Int? = nil, sha256: String? = nil,
                refID: String? = nil, facts: [String: String]? = nil) {
        self.id = id; self.date = date; self.kind = kind; self.title = title; self.detail = detail
        self.outcome = outcome; self.severity = severity; self.detectionID = detectionID
        self.event = event; self.actor = actor; self.process = process; self.target = target; self.rule = rule
        self.reason = reason; self.score = score; self.action = action; self.count = count; self.found = found
        self.sha256 = sha256; self.refID = refID; self.facts = facts
    }

    private enum CodingKeys: String, CodingKey {
        case id, date, kind, title, detail, outcome, severity, detectionID, event, actor, process, target, rule, reason
        case score, action, count, found, sha256, refID, facts
    }
    /// Tolerant: an unknown kind/event/actor (written by a newer build) never drops the whole line.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        date = try c.decode(Date.self, forKey: .date)
        kind = Kind(rawValue: (try? c.decode(String.self, forKey: .kind)) ?? "") ?? .system
        title = (try? c.decode(String.self, forKey: .title)) ?? ""
        detail = (try? c.decode(String.self, forKey: .detail)) ?? ""
        outcome = (try? c.decode(String.self, forKey: .outcome)) ?? ""
        severity = (try? c.decode(Severity.self, forKey: .severity)) ?? .info
        detectionID = try? c.decodeIfPresent(UUID.self, forKey: .detectionID)
        event = ((try? c.decodeIfPresent(String.self, forKey: .event)) ?? nil).flatMap(ActivityEvent.init(rawValue:))
        actor = ((try? c.decodeIfPresent(String.self, forKey: .actor)) ?? nil).flatMap(ActivityActor.init(rawValue:))
        process = (try? c.decodeIfPresent(ActivityProcess.self, forKey: .process)) ?? nil
        target = (try? c.decodeIfPresent(String.self, forKey: .target)) ?? nil
        rule = (try? c.decodeIfPresent(String.self, forKey: .rule)) ?? nil
        reason = (try? c.decodeIfPresent(String.self, forKey: .reason)) ?? nil
        score = (try? c.decodeIfPresent(Int.self, forKey: .score)) ?? nil
        action = (try? c.decodeIfPresent(String.self, forKey: .action)) ?? nil
        count = (try? c.decodeIfPresent(Int.self, forKey: .count)) ?? nil
        found = (try? c.decodeIfPresent(Int.self, forKey: .found)) ?? nil
        sha256 = (try? c.decodeIfPresent(String.self, forKey: .sha256)) ?? nil
        refID = (try? c.decodeIfPresent(String.self, forKey: .refID)) ?? nil
        facts = (try? c.decodeIfPresent([String: String].self, forKey: .facts)) ?? nil
    }
}

/// Every protective decision or state change RamPart records. Adding a case without a mapping in
/// `ActivityPresenter` fails the `activity` selftest suite.
public enum ActivityEvent: String, Codable, Sendable, CaseIterable {
    // scans
    case scanStarted, scanFinished, scanCancelled, scanFailed, scanPaused, scanResumed
    // threats
    case detection, quarantined, quarantineFailed, restored, deleted, exported, sandboxRun, alertsResolved
    case realtimeBlock, processStopped
    // web / DNS / scam
    case webBlocked, dnsBlocked, scamBlocked, webWarning
    // other guards
    case pasteGuardBlocked, pasteGuardWarned
    case remoteAccessAttempt, remoteAccessAllowed, remoteAccessRevoked, remoteLockdownChanged
    case tamper
    case lockdownStarted, lockdownLifted
    case wifiWarning, wifiDisconnected, wifiStayedConnected, wifiTrustChanged
    // persistence and posture
    case persistenceAdded, persistenceRemoved, startupItemRemoved, startupItemRemoveFailed, postureFixed, postureFixFailed
    // settings
    case settingsChanged, protectionToggled, protectionPaused, protectionResumed, allowRuleAdded, allowRuleRemoved
    case adminSession, protectEverything
    // updates
    case definitionsUpdated, definitionsFailed
    // privacy features
    case vaultEvent, authenticatorEvent
    // maintenance
    case refreshCleanup, refreshUndo, networkScan
    // Cat & Mouse deception messages (decoys touched, tarpit visits)
    case deceptionEvent
    // service
    case serviceStarted, serviceStopped, uninstall
    /// Older free-text entries that match no known decision.
    case other
}

public enum ActivityActor: String, Codable, Sendable, CaseIterable {
    case user, ai, system, schedule, commandLine
}

/// The process behind an event. Name/path/signer are display strings; pid/parent are as observed at the time.
public struct ActivityProcess: Codable, Hashable, Sendable {
    public var name: String?
    public var path: String?
    public var signer: String?
    public var pid: Int32?
    public var parentPID: Int32?
    public var parentName: String?
    public init(name: String? = nil, path: String? = nil, signer: String? = nil, pid: Int32? = nil,
                parentPID: Int32? = nil, parentName: String? = nil) {
        self.name = name; self.path = path; self.signer = signer; self.pid = pid
        self.parentPID = parentPID; self.parentName = parentName
    }
    public var isEmpty: Bool { name == nil && path == nil && pid == nil }
}

/// A live network connection attributed to a process.
public struct ConnectionInfo: Codable, Hashable, Identifiable, Sendable {
    public var id: String { "\(pid)-\(proto)-\(remoteAddress):\(remotePort)-\(localPort)" }
    public var pid: Int32
    public var processName: String
    public var processPath: String?
    public var proto: String          // "TCP" / "UDP"
    public var localPort: Int
    public var remoteAddress: String
    public var remotePort: Int
    public var remoteHost: String?    // reverse-mapped from the DNS log when known
    public var state: String?
    public var signing: SigningInfo.Status?
    public var flagged: Bool          // matches a blocklist or a behaviour rule
    public init(pid: Int32, processName: String, processPath: String? = nil, proto: String, localPort: Int,
                remoteAddress: String, remotePort: Int, remoteHost: String? = nil, state: String? = nil,
                signing: SigningInfo.Status? = nil, flagged: Bool = false) {
        self.pid = pid; self.processName = processName; self.processPath = processPath; self.proto = proto
        self.localPort = localPort; self.remoteAddress = remoteAddress; self.remotePort = remotePort
        self.remoteHost = remoteHost; self.state = state; self.signing = signing; self.flagged = flagged
    }
}

public struct WiFiStatus: Codable, Hashable, Sendable {
    public var connected: Bool
    public var ssid: String?          // nil without Location permission
    public var security: String?
    public var weakSecurity: Bool
    public var gatewayIP: String?
    public var gatewayMACChanged: Bool
    public var note: String?
    public init(connected: Bool, ssid: String? = nil, security: String? = nil, weakSecurity: Bool = false,
                gatewayIP: String? = nil, gatewayMACChanged: Bool = false, note: String? = nil) {
        self.connected = connected; self.ssid = ssid; self.security = security; self.weakSecurity = weakSecurity
        self.gatewayIP = gatewayIP; self.gatewayMACChanged = gatewayMACChanged; self.note = note
    }
}

public struct NetworkStats: Codable, Hashable, Sendable {
    public var webProtectionOn: Bool
    public var webProtectionAvailable: Bool   // false in user mode (needs the root daemon to switch DNS)
    public var blockedToday: Int
    public var blockedThisMonth: Int
    public var blockedByDay: [Int]            // last 14 days, oldest first
    public var blocklistDomains: Int
    public var blocklistsUpdated: Date?
    public var recentBlocks: [String]         // most recent blocked domains, newest first
    public init(webProtectionOn: Bool = false, webProtectionAvailable: Bool = false, blockedToday: Int = 0,
                blockedThisMonth: Int = 0, blockedByDay: [Int] = [], blocklistDomains: Int = 0,
                blocklistsUpdated: Date? = nil, recentBlocks: [String] = []) {
        self.webProtectionOn = webProtectionOn; self.webProtectionAvailable = webProtectionAvailable
        self.blockedToday = blockedToday; self.blockedThisMonth = blockedThisMonth; self.blockedByDay = blockedByDay
        self.blocklistDomains = blocklistDomains; self.blocklistsUpdated = blocklistsUpdated; self.recentBlocks = recentBlocks
    }
}

/// User-facing settings, owned and persisted by the daemon (single source of truth).
public struct RampartSettings: Codable, Hashable, Sendable {
    public var realtimeOn: Bool = true
    public var autoQuarantine: Bool = true
    public var scanArchives: Bool = true
    public var scheduledQuickScan: Bool = true
    public var scheduledScanHour: Int = 12
    public var exclusions: [String] = []
    public var notifyThreats: Bool = true
    public var notifyInfo: Bool = false
    public var learningMode: Bool = true
    public var developerMode: Bool = false
    public var ransomwareCanaries: Bool = false
    public var autoUpdate: Bool = true
    public var webProtection: Bool = false
    public var blockTrackers: Bool = false
    public init() {}
}

/// What a persistence cleanup would do, shown before the user confirms.
public struct RemediationPreview: Codable, Hashable, Sendable {
    public var persistenceID: String
    public var title: String
    public var steps: [String]       // human-readable steps
    public var commands: [String]    // exact commands (for the "details" disclosure)
    public var undoable: Bool
    public var requiresRoot: Bool
    public init(persistenceID: String, title: String, steps: [String], commands: [String], undoable: Bool, requiresRoot: Bool) {
        self.persistenceID = persistenceID; self.title = title; self.steps = steps
        self.commands = commands; self.undoable = undoable; self.requiresRoot = requiresRoot
    }
}

public struct AllowRuleSpec: Codable, Hashable, Identifiable, Sendable {
    public enum Scope: String, Codable, Sendable { case fileHash, developer, folder, signingID }
    public var id: UUID
    public var scope: Scope
    public var value: String
    public var name: String
    public var created: Date
    public var expires: Date?
    public init(id: UUID = UUID(), scope: Scope, value: String, name: String, created: Date = Date(), expires: Date? = nil) {
        self.id = id; self.scope = scope; self.value = value; self.name = name; self.created = created; self.expires = expires
    }
}

public struct HealthReport: Codable, Hashable, Sendable {
    public var mode: String            // "root" or "user"
    public var version: String
    public var uptimeSeconds: Double
    public var cpuPercent: Double
    public var residentMB: Double
    public var sources: [String: Bool]
    public var lastErrors: [String]
    public var sourceCPUSeconds: [String: Double]
    /// `IPC.version` of the daemon; nil = older than v6.
    public var ipcVersion: Int? = nil
    public init(mode: String, version: String, uptimeSeconds: Double, cpuPercent: Double, residentMB: Double,
                sources: [String: Bool], lastErrors: [String], sourceCPUSeconds: [String: Double] = [:]) {
        self.mode = mode; self.version = version; self.uptimeSeconds = uptimeSeconds; self.cpuPercent = cpuPercent
        self.residentMB = residentMB; self.sources = sources; self.lastErrors = lastErrors; self.sourceCPUSeconds = sourceCPUSeconds
    }
}

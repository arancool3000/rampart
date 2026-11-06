import Foundation

// v2 shared types: real data for every app screen. Owned by the lead.

/// One row in Protection Activity. Produced by the daemon for scans, detections, quarantine,
/// persistence changes, web blocks, posture fixes, updates and settings changes.
public struct ActivityEntry: Codable, Hashable, Identifiable, Sendable {
    public enum Kind: String, Codable, Sendable { case scan, detection, quarantine, restore, persistence, webBlock, posture, update, settings, system }
    public var id: UUID
    public var date: Date
    public var kind: Kind
    public var title: String
    public var detail: String
    public var outcome: String
    public var severity: Severity
    public var detectionID: UUID?
    public init(id: UUID = UUID(), date: Date = Date(), kind: Kind, title: String, detail: String = "",
                outcome: String = "", severity: Severity = .info, detectionID: UUID? = nil) {
        self.id = id; self.date = date; self.kind = kind; self.title = title; self.detail = detail
        self.outcome = outcome; self.severity = severity; self.detectionID = detectionID
    }
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
    public init(mode: String, version: String, uptimeSeconds: Double, cpuPercent: Double, residentMB: Double,
                sources: [String: Bool], lastErrors: [String], sourceCPUSeconds: [String: Double] = [:]) {
        self.mode = mode; self.version = version; self.uptimeSeconds = uptimeSeconds; self.cpuPercent = cpuPercent
        self.residentMB = residentMB; self.sources = sources; self.lastErrors = lastErrors; self.sourceCPUSeconds = sourceCPUSeconds
    }
}

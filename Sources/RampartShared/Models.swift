import Foundation

// Shared contract for every Rampart module. Owned by the lead; change only by coordinating.

public enum Product {
    /// Display name. Change only here (and Info.plist via scripts/build.sh) if the product is renamed.
    public static let name = "RamPart"
    public static let bundlePrefix = "app.rampart"
    public static let daemonLabel = "app.rampart.daemon"
    public static let agentLabel = "app.rampart.agent"
    public static let xpcService = "app.rampart.daemon.xpc"
    public static let version = "0.1.0"
}

public enum Paths {
    public static let supportRoot = URL(fileURLWithPath: "/Library/Application Support/Rampart")
    public static let quarantineDir = supportRoot.appendingPathComponent("Quarantine")
    public static let databaseDir = supportRoot.appendingPathComponent("DB")
    public static let rulesDir = supportRoot.appendingPathComponent("Rules")
    public static let blocklistDir = supportRoot.appendingPathComponent("Blocklists")
    public static let journalDir = supportRoot.appendingPathComponent("Journal")
    public static let logDir = URL(fileURLWithPath: "/Library/Logs/Rampart")
    /// Per-user state for non-root runs (CLI, tests).
    public static var userRoot: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Rampart")
    }
    /// Root-owned when running as root, otherwise the per-user folder.
    public static var effectiveRoot: URL { getuid() == 0 ? supportRoot : userRoot }
    public static let xprotectBundles = [
        "/var/protected/xprotect/XProtect.bundle/Contents/Resources",
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources",
    ]
}

public enum Severity: Int, Codable, Comparable, Sendable, CaseIterable {
    case info = 0, low = 1, medium = 2, high = 3, critical = 4
    public static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }
    public var label: String { ["Info", "Low", "Medium", "High", "Critical"][rawValue] }
}

public enum ThreatCategory: String, Codable, Sendable {
    case malware, infostealer, adware, pua, ransomware, backdoor, miner, persistence, phishing, test, suspicious
}

/// Which engine produced a finding.
public enum DetectionSource: String, Codable, Sendable {
    case hash, yara, xprotect, signing, heuristic, behaviour, network, persistence, posture
}

/// One piece of evidence. Every alert shows these in the "Why was this flagged?" panel.
public struct Evidence: Codable, Hashable, Sendable {
    public var source: DetectionSource
    public var title: String
    public var detail: String
    public var score: Int // 0...100 contribution
    public init(source: DetectionSource, title: String, detail: String, score: Int) {
        self.source = source; self.title = title; self.detail = detail; self.score = score
    }
}

public struct Detection: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var date: Date
    public var path: String?
    public var pid: Int32?
    public var sha256: String?
    public var name: String            // e.g. "EICAR-Test-File", "Unsigned LaunchAgent"
    public var category: ThreatCategory
    public var severity: Severity
    public var confidence: Int         // 0...100
    public var evidence: [Evidence]
    public var resolved: Bool
    public init(id: UUID = UUID(), date: Date = Date(), path: String? = nil, pid: Int32? = nil,
                sha256: String? = nil, name: String, category: ThreatCategory, severity: Severity,
                confidence: Int, evidence: [Evidence], resolved: Bool = false) {
        self.id = id; self.date = date; self.path = path; self.pid = pid; self.sha256 = sha256
        self.name = name; self.category = category; self.severity = severity
        self.confidence = confidence; self.evidence = evidence; self.resolved = resolved
    }
}

/// Facts about a file that any engine may fill in; passed along the scan pipeline.
public struct FileFacts: Codable, Sendable {
    public var path: String
    public var size: UInt64
    public var sha256: String?
    public var kind: FileKind
    public var isExecutable: Bool
    public var signing: SigningInfo?
    public var quarantineOrigin: String?   // from com.apple.quarantine / kMDItemWhereFroms
    public init(path: String, size: UInt64, sha256: String? = nil, kind: FileKind = .other,
                isExecutable: Bool = false, signing: SigningInfo? = nil, quarantineOrigin: String? = nil) {
        self.path = path; self.size = size; self.sha256 = sha256; self.kind = kind
        self.isExecutable = isExecutable; self.signing = signing; self.quarantineOrigin = quarantineOrigin
    }
}

public enum FileKind: String, Codable, Sendable {
    case machO, fatMachO, script, appBundle, dmg, pkg, zip, archive, plist, document, other
}

public struct SigningInfo: Codable, Hashable, Sendable {
    public enum Status: String, Codable, Sendable { case apple, developerID, appStore, adHoc, unsigned, invalid, revoked, unknown }
    public var status: Status
    public var teamID: String?
    public var signingID: String?
    public var notarized: Bool?
    public var hardenedRuntime: Bool?
    public var entitlements: [String]
    public init(status: Status, teamID: String? = nil, signingID: String? = nil, notarized: Bool? = nil,
                hardenedRuntime: Bool? = nil, entitlements: [String] = []) {
        self.status = status; self.teamID = teamID; self.signingID = signingID
        self.notarized = notarized; self.hardenedRuntime = hardenedRuntime; self.entitlements = entitlements
    }
}

/// A file-level detector (hash DB, YARA, heuristics). Must be thread-safe.
public protocol FileDetector: Sendable {
    var name: String { get }
    func inspect(_ facts: FileFacts) -> [Evidence]
}

// MARK: - Real-time events

public struct ProcessInfoLite: Codable, Hashable, Sendable {
    public var pid: Int32
    public var ppid: Int32
    public var path: String
    public var args: [String]
    public var uid: UInt32
    public var signingID: String?
    public var teamID: String?
    public var isPlatformBinary: Bool
    public init(pid: Int32, ppid: Int32, path: String, args: [String] = [], uid: UInt32 = 0,
                signingID: String? = nil, teamID: String? = nil, isPlatformBinary: Bool = false) {
        self.pid = pid; self.ppid = ppid; self.path = path; self.args = args; self.uid = uid
        self.signingID = signingID; self.teamID = teamID; self.isPlatformBinary = isPlatformBinary
    }
}

public enum SecurityEventKind: String, Codable, Sendable {
    case exec, fileCreate, fileWrite, fileRename, fileClose, fileDelete, xattrDelete,
         persistenceAdded, persistenceRemoved, tccRequest, xprotectDetection, networkConnect, dnsQuery, other
}

public struct SecurityEvent: Codable, Sendable {
    public var date: Date
    public var kind: SecurityEventKind
    public var process: ProcessInfoLite?
    public var path: String?
    public var destPath: String?
    public var detail: [String: String]
    public var source: String   // "eslogger", "fsevents", "procsweep", "unifiedlog", "dns", ...
    public init(date: Date = Date(), kind: SecurityEventKind, process: ProcessInfoLite? = nil, path: String? = nil,
                destPath: String? = nil, detail: [String: String] = [:], source: String) {
        self.date = date; self.kind = kind; self.process = process; self.path = path
        self.destPath = destPath; self.detail = detail; self.source = source
    }
}

/// Anything that produces real-time events (eslogger, FSEvents, process sweep, log stream).
public protocol EventSource: AnyObject {
    var name: String { get }
    var isAvailable: Bool { get }
    func start(handler: @escaping @Sendable (SecurityEvent) -> Void) throws
    func stop()
}

// MARK: - Persistence, posture, quarantine

public struct PersistenceItem: Codable, Hashable, Identifiable, Sendable {
    public enum Kind: String, Codable, Sendable { case launchAgent, launchDaemon, loginItem, btm, cron, periodic, shellRC, profile, browserExtension, systemExtension, sshKey, other }
    public var id: String { kind.rawValue + ":" + location }
    public var kind: Kind
    public var label: String
    public var location: String   // plist or file path
    public var target: String?    // executable it launches
    public var signing: SigningInfo?
    public init(kind: Kind, label: String, location: String, target: String? = nil, signing: SigningInfo? = nil) {
        self.kind = kind; self.label = label; self.location = location; self.target = target; self.signing = signing
    }
}

public struct PostureCheck: Codable, Hashable, Identifiable, Sendable {
    public enum State: String, Codable, Sendable { case pass, fail, unknown, notApplicable }
    public var id: String
    public var title: String
    public var state: State
    public var weight: Int
    public var detail: String
    public var fixable: Bool        // one-click fix available
    public var fixHint: String
    public init(id: String, title: String, state: State, weight: Int, detail: String, fixable: Bool, fixHint: String) {
        self.id = id; self.title = title; self.state = state; self.weight = weight
        self.detail = detail; self.fixable = fixable; self.fixHint = fixHint
    }
}

public struct QuarantineRecord: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var date: Date
    public var originalPath: String
    public var sha256: String
    public var size: UInt64
    public var detectionName: String
    public var ownerUID: UInt32
    public var mode: UInt16
    public init(id: UUID = UUID(), date: Date = Date(), originalPath: String, sha256: String, size: UInt64,
                detectionName: String, ownerUID: UInt32, mode: UInt16) {
        self.id = id; self.date = date; self.originalPath = originalPath; self.sha256 = sha256
        self.size = size; self.detectionName = detectionName; self.ownerUID = ownerUID; self.mode = mode
    }
}

public struct ProtectionStatus: Codable, Sendable {
    public var realtimeOn: Bool
    public var sources: [String: Bool]     // event source name -> running
    public var webProtectionOn: Bool
    public var fullDiskAccess: Bool
    public var lastScan: Date?
    public var signatureVersion: String
    public var xprotectVersion: String?
    public var securityScore: Int?
    public var openDetections: Int
    /// When definitions (hash feeds, blocklists, rules) last updated successfully; nil = never.
    public var definitionsUpdated: Date? = nil
    /// `IPC.version` of the daemon that answered; nil = a daemon older than v6.
    public var ipcVersion: Int? = nil
    /// Health problems of the real-time feed (missing Full Disk Access, a source that stopped), one entry per
    /// problem with a repeat count. These are status notes, never detections and never a lockdown trigger.
    public var healthNotes: [HealthNote]? = nil
    public init(realtimeOn: Bool = false, sources: [String: Bool] = [:], webProtectionOn: Bool = false,
                fullDiskAccess: Bool = false, lastScan: Date? = nil, signatureVersion: String = "0",
                xprotectVersion: String? = nil, securityScore: Int? = nil, openDetections: Int = 0) {
        self.realtimeOn = realtimeOn; self.sources = sources; self.webProtectionOn = webProtectionOn
        self.fullDiskAccess = fullDiskAccess; self.lastScan = lastScan; self.signatureVersion = signatureVersion
        self.xprotectVersion = xprotectVersion; self.securityScore = securityScore; self.openDetections = openDetections
    }
}

/// One deduplicated health problem ("Real-time monitoring needs Full Disk Access"), shown as a status note.
public struct HealthNote: Codable, Hashable, Sendable, Identifiable {
    public enum Fix: String, Codable, Sendable { case fullDiskAccess, restartService, none }
    public var id: String            // stable key, e.g. "source:eslogger"
    public var source: String
    public var message: String
    public var detail: String
    public var fix: Fix
    public var count: Int
    public var firstSeen: Date
    public var lastSeen: Date
    public init(id: String, source: String, message: String, detail: String, fix: Fix, count: Int = 1, firstSeen: Date = Date(), lastSeen: Date = Date()) {
        self.id = id; self.source = source; self.message = message; self.detail = detail; self.fix = fix
        self.count = count; self.firstSeen = firstSeen; self.lastSeen = lastSeen
    }

    /// Permission (TCC / Full Disk Access) failures of a telemetry source: eslogger's ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED etc.
    public static func isPermissionError(_ s: String?) -> Bool {
        guard let l = s?.lowercased() else { return false }
        return ["not permitted", "not_permitted", "full disk access", "tcc", "eperm", "operation not permitted", "not authorized", "err_not_privileged"].contains { l.contains($0) }
    }

    /// The note for a telemetry source that is down.
    public static func sourceDown(_ name: String, lastError: String?, at date: Date = Date()) -> HealthNote {
        if isPermissionError(lastError) {
            return HealthNote(id: "source:\(name)", source: name, message: "Real-time monitoring needs Full Disk Access",
                              detail: "macOS didn't allow \(Product.name)'s event feed (\(name)) to start. Turn on Full Disk Access for \(Product.name), then it starts by itself.",
                              fix: .fullDiskAccess, firstSeen: date, lastSeen: date)
        }
        return HealthNote(id: "source:\(name)", source: name, message: "Real-time monitoring paused (\(name) stopped)",
                          detail: (lastError.map { "\($0). " } ?? "") + "\(Product.name) keeps restarting it. This is a health issue, not an attack.",
                          fix: .restartService, firstSeen: date, lastSeen: date)
    }
}

// MARK: - IPC (daemon <-> app/CLI). JSON over a root-owned Unix socket; see IPC.swift.

public enum IPCRequest: Codable, Sendable {
    case status
    case scan(paths: [String], quick: Bool)
    case listDetections
    case listQuarantine
    case quarantine(detectionID: UUID)
    case restore(id: UUID, allow: Bool)
    case deleteQuarantined(id: UUID)
    case allow(sha256: String)
    case posture
    case fixPosture(checkID: String)
    case persistence
    case setWebProtection(on: Bool)
    case updateSignatures
    case subscribeEvents
    // v2 (added for the app to show real data instead of demo data)
    case activity(limit: Int)
    case connections
    case wifi
    case networkStats
    case getSettings
    case setSettings(RampartSettings)
    case pauseScan(paused: Bool)
    case cancelScan
    case setRealtime(on: Bool)
    case previewRemediation(persistenceID: String)
    case remediate(persistenceID: String)
    case listAllowRules
    case addAllowRule(AllowRuleSpec)
    case removeAllowRule(id: UUID)
    case health
    // v3: tamper protection and remote-access lockdown (RampartGuard). Privileged ones need an admin peer.
    case remoteAccessReport
    case allowRemoteTool(id: String, minutes: Int?)
    case revokeRemoteTool(id: String)
    case setRemoteLockdown(on: Bool)
    case tamperStatus
    case requestDisableProtection(authorization: Data?, reason: String)
    case disableProtection(token: String, minutes: Int)
    case requestUninstall(authorization: Data?)
    case uninstall(token: String)
    // v3: forward per-user events (PasteGuard/clipboard) from the user session to the root daemon
    case forwardEvents([SecurityEvent])
    // v4: web protection for rampart-nmh / extensions / browser (payloads are RampartWeb JSON)
    case checkURL(url: String)
    case scamCheck(text: String, kind: String)
    case webLookup(host: String)
    case webVerdict(url: String, verdict: String, score: Int, headline: String)
    // v5: quarantine manager (restore elsewhere, encrypted export, best-effort sandbox run)
    case restoreQuarantinedTo(id: UUID, path: String, allow: Bool)
    case exportQuarantined(id: UUID, path: String)
    case sandboxRun(id: UUID, confirmation: String)
    // v6: Emergency Lockdown (RampartGuard/EmergencyLockdown.swift); all answered with `.emergency(Data)`
    case emergencyStatus
    case emergencyLockdown(reason: String)
    case emergencyRescan
    case liftEmergencyLockdown(token: String, force: Bool)
    case emergencyAck(actionIDs: [String])
    // v8: lockdown safety. keep=true: "Keep blocking" (no token needed); keep=false: "Restore internet now" (admin token,
    // or a root peer). Both answered with `.emergency(Data)`.
    case emergencyNetwork(keep: Bool, token: String?)
    // v8: Super Kill Switch; token from requestDisableProtection after Touch ID / password (root peer: none needed).
    // Answered with `.killSwitch(Data)` (JSON of RampartGuard.KillSwitch.Report).
    case killSwitch(token: String?)
    // v6: deep URL chain check (redirect chain + page signals), served off the IPC thread
    case checkURLChain(url: String)   // -> .urlVerdict(Data) with JSON of RampartWeb.ChainReport
    // v7: Cat & Mouse (RampartGuard Deception*); answered with `.deception(Data)` (JSON of DeceptionStatus)
    case deceptionStatus
    case deceptionSetDecoys(on: Bool)
    case deceptionSetMaze(on: Bool)
    case deceptionRemoveAll
    case deceptionSetTarpit(on: Bool, port: UInt16, scope: String)
    case deceptionSetTone(serious: Bool)
    case deceptionEvidence(catchID: UUID)            // -> .deceptionEvidence(Data)
    // v7 (added later in v7; an older v7 daemon answers "unknown request", which the app treats as unsupported)
    case deceptionSetDecoysVisible(visible: Bool)    // -> .deception(Data)
}

public enum IPCResponse: Codable, Sendable {
    case ok
    case error(String)
    case status(ProtectionStatus)
    case detections([Detection])
    case quarantine([QuarantineRecord])
    case posture([PostureCheck])
    case persistence([PersistenceItem])
    /// walkFinished: the file walk is done, so `total` is final. timedOut: files whose deep checks hit their time
    /// limit so far. secondsSinceLastCompletion: time since any file finished (large = a big file is being checked).
    /// Optional so replies from older daemons (without these keys) still decode (SE-0295 decodeIfPresent).
    case scanProgress(scanned: Int, total: Int, current: String, walkFinished: Bool? = nil, timedOut: Int? = nil, secondsSinceLastCompletion: Double? = nil)
    case scanFinished(scanned: Int, detections: [Detection], seconds: Double)
    case event(Detection)
    // v2
    case activity([ActivityEntry])
    case connections([ConnectionInfo])
    case wifi(WiFiStatus)
    case networkStats(NetworkStats)
    case settings(RampartSettings)
    case remediationPreview(RemediationPreview)
    case allowRules([AllowRuleSpec])
    case health(HealthReport)
    // v3
    case remoteAccess(Data)   // JSON of RampartGuard.RemoteAccessReport
    case tamper(Data)         // JSON of the tamper status struct
    case disableToken(String)
    // v4
    case urlVerdict(Data)     // JSON of RampartWeb.URLReport
    case scamReport(Data)     // JSON of RampartWeb.ScamReport
    case webLookup(Data?)     // JSON of RampartWeb.BlocklistHit, nil when not listed
    // v5
    case exported(path: String, password: String)
    case sandboxReport(Data)  // JSON of rampartd SandboxReport (mirrored in the app's QuarantineManager.swift)
    // v6
    case emergency(Data)      // JSON of RampartGuard.EmergencyStatus
    case killSwitch(Data)     // JSON of RampartGuard.KillSwitch.Report
    // v7
    case deception(Data)          // JSON of RampartGuard.DeceptionStatus
    case deceptionEvidence(Data)  // JSON of RampartGuard.DeceptionEvidence
}

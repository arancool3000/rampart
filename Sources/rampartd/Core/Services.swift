import Foundation
import RampartShared
import RampartGuard
import RampartBehaviour

// The plug-in layer. Each protocol is implemented either by a module adapter (Integrations.swift)
// or by a built-in fallback (Builtin.swift) so the daemon always runs.

struct ScanOutcome {
    var scanned: Int
    var detections: [Detection]
    var seconds: Double
    var errors: Int = 0
}

/// Extra scan state for the app: walk finished (total is final), files abandoned at the deadline, stall time.
struct ScanTick { var walkFinished = false; var timedOut = 0; var secondsSinceLastCompletion: Double = 0 }
typealias ScanProgress = (_ scanned: Int, _ total: Int, _ current: String, _ tick: ScanTick) -> Void

protocol ScanService: AnyObject {
    var engineNames: [String] { get }
    var signatureVersion: String { get }
    /// Scans files/folders. `progress` is called from any thread. `cancelled` is polled.
    func scan(paths: [String], progress: @escaping ScanProgress, cancelled: @escaping () -> Bool) -> ScanOutcome
    /// Single-file scan used by real-time on-write scanning. Returns a detection only at >= 30 confidence.
    func scanFile(_ path: String) -> Detection?
}

protocol QuarantineService: AnyObject {
    func list() -> [QuarantineRecord]
    func quarantine(path: String, detection: Detection) throws -> QuarantineRecord
    /// Returns the restored path.
    func restore(id: UUID) throws -> String
    func delete(id: UUID) throws
    func purgeExpired()
}

protocol ProcessResponder: AnyObject {
    /// Stops and kills a process tree rooted at pid. Returns a human description.
    func terminate(pid: Int32, expectedPath: String?) -> String
}

protocol PostureService: AnyObject {
    func checks() -> [PostureCheck]
    func score(_ checks: [PostureCheck]) -> Int?
    /// Executes a safe fix (daemon only). Returns a description of what was done.
    func fix(checkID: String, dryRun: Bool) throws -> String
}

/// A persistence item plus the scanner's raw attributes (browser, extensionID, cron line, ...).
struct PersistenceLookup {
    var item: PersistenceItem
    var attributes: [String: String]
}

protocol NetworkInfoService: AnyObject {
    func connections() -> [ConnectionInfo]
    func wifi() -> WiFiStatus
    func stats(available: Bool) -> NetworkStats
}

protocol PersistenceRemediationService: AnyObject {
    func preview(_ r: PersistenceLookup) throws -> RemediationPreview
    /// Applies the cleanup (journaled, undoable where possible). Returns a summary.
    func remediate(_ r: PersistenceLookup) throws -> String
}

/// Live controls of the behaviour engine (settings + allow rules + ransomware canaries).
protocol BehaviourControl: AnyObject {
    func apply(learningMode: Bool, developerMode: Bool)
    func setAllowRules(_ rules: [AllowRuleSpec])
    /// The ransomware detector (canary paths are planted by RampartGuard.RansomCanaryRegistry, then registered here).
    var ransomware: RansomwareDetector { get }
}

protocol PersistenceService: AnyObject {
    /// Last-scanned item with this id (scans again if unknown).
    func lookup(id: String) -> PersistenceLookup?
    /// Enumerates persistence and returns risky findings for items that are new or changed since the
    /// previous scan (on the very first scan: for everything).
    func scan() -> (items: [PersistenceItem], findings: [Detection])
}

protocol UpdateService: AnyObject {
    /// Downloads/refreshes signatures/rules/blocklists. Returns a short summary.
    func update() -> String
}

protocol RealtimeService: AnyObject {
    var sources: [String: Bool] { get }
    var isRunning: Bool { get }
    func start(onEvent: @escaping (SecurityEvent) -> Void, onDetection: @escaping (Detection) -> Void)
    func stop()
}

protocol WebProtectionService: AnyObject {
    var isOn: Bool { get }
    func setOn(_ on: Bool) throws
}

enum ServiceError: LocalizedError {
    case unavailable(String), notFound(String), denied(String), failed(String)
    var errorDescription: String? {
        switch self {
        case .unavailable(let s): return "\(s) is not available in this build"
        case .notFound(let s): return "not found: \(s)"
        case .denied(let s): return "permission denied: \(s)"
        case .failed(let s): return s
        }
    }
}

/// Container of every service; built by `Services.make`.
final class Services {
    var scanner: ScanService
    var quarantine: QuarantineService
    var processes: ProcessResponder?
    var posture: PostureService?
    var persistence: PersistenceService?
    var updater: UpdateService?
    var realtime: RealtimeService?
    var web: WebProtectionService?
    var network: NetworkInfoService?
    var guardian: GuardService?
    var webCheck: WebCheckService?
    /// Deep content inspection, Apple impersonation and link-chain checks (DeepWiring.swift).
    var deep: DeepProtectionService?
    /// Cat & Mouse decoys, maze and tarpit (RampartGuard Deception*), user-session daemon only.
    var deception: DeceptionService?
    /// EventHub.cpuBySource (daemon only).
    var sourceCPU: (() -> [String: Double])?
    /// DNS query-log events (.dnsQuery, detail["name"]) for the behaviour engine; set by the daemon wiring.
    var onDNSEvent: ((SecurityEvent) -> Void)?
    /// Set by Protection: (domain, list) for every DNS block (rate-limited by the network adapter).
    var onWebBlock: ((String, String?) -> Void)?
    var persistenceRemediation: PersistenceRemediationService?
    var behaviour: BehaviourControl?
    /// Signing summary for a file (cached), used by developer/signing-ID allow rules.
    var signingLookup: ((String) -> SigningInfo?)?
    /// Called with a lowercase SHA-256 when the user trusts a file (engine allowlist, etc.).
    var allowHooks: [(String) -> Void] = []
    /// Called after the daemon finishes wiring, e.g. to load rules in the background.
    var warmups: [() -> Void] = []
    /// Human-readable list of what got wired ("engine: RampartEngine.ScanCoordinator", ...).
    var wiring: [String] = []

    init(scanner: ScanService, quarantine: QuarantineService) {
        self.scanner = scanner; self.quarantine = quarantine
    }

    /// Builds services from the modules that are available; falls back to built-ins.
    static func make(runtime: Runtime, daemon: Bool) -> Services {
        let s = Services(scanner: BuiltinScanner(runtime: runtime, detectors: [BuiltinEicarDetector()]),
                         quarantine: BuiltinQuarantine(dir: runtime.quarantineDir))
        s.persistence = BuiltinPersistence()
        s.wiring = ["scanner: builtin (EICAR only)", "quarantine: builtin vault", "persistence: builtin launchd enumeration"]
        Integrations.wire(s, runtime: runtime, daemon: daemon)
        return s
    }
}

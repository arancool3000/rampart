import Foundation
import RampartShared

/// Daemon/CLI configuration (`<root>/config.json`). Every field is optional on disk; missing keys get defaults.
struct RampartConfig: Codable, Equatable {
    var autoQuarantine = true           // quarantine detections with confidence >= 90
    var killMaliciousProcesses = true   // behaviour detections >= 90 with a pid
    var realtime = true
    var webProtection = false           // DNS filter; OFF by default
    var dnsPort: Int? = nil             // nil = 53 as root, 5353 in user mode
    var scheduledQuickScanHours = 24.0  // 0 disables
    var signatureUpdateHours = 6.0      // 0 disables
    var persistenceCheckMinutes = 30.0  // 0 disables
    var postureCheckHours = 12.0        // 0 disables
    var maxFileSizeMB = 512
    var exclusions: [String] = []
    var quickScanPaths: [String]? = nil
    var watchPaths: [String]? = nil
    var allowlist: [String] = []        // sha256 values the user chose to trust
    var scanArchives = true
    // v2 user-facing settings (RampartSettings is a view of these).
    var scheduledQuickScan = true
    var scheduledScanHour = 12
    var notifyThreats = true
    var notifyInfo = false
    var learningMode = true
    var developerMode = false
    var ransomwareCanaries = false
    var autoUpdate = true
    var blockTrackers = false

    init() {}

    var settings: RampartSettings {
        var s = RampartSettings()
        s.realtimeOn = realtime; s.autoQuarantine = autoQuarantine; s.scanArchives = scanArchives
        s.scheduledQuickScan = scheduledQuickScan; s.scheduledScanHour = scheduledScanHour; s.exclusions = exclusions
        s.notifyThreats = notifyThreats; s.notifyInfo = notifyInfo; s.learningMode = learningMode
        s.developerMode = developerMode; s.ransomwareCanaries = ransomwareCanaries; s.autoUpdate = autoUpdate
        s.webProtection = webProtection; s.blockTrackers = blockTrackers
        return s
    }

    mutating func apply(_ s: RampartSettings) {
        realtime = s.realtimeOn; autoQuarantine = s.autoQuarantine; scanArchives = s.scanArchives
        scheduledQuickScan = s.scheduledQuickScan; scheduledScanHour = max(0, min(23, s.scheduledScanHour))
        exclusions = s.exclusions.map { ($0 as NSString).expandingTildeInPath }.filter { $0.hasPrefix("/") }
        notifyThreats = s.notifyThreats; notifyInfo = s.notifyInfo; learningMode = s.learningMode
        developerMode = s.developerMode; ransomwareCanaries = s.ransomwareCanaries; autoUpdate = s.autoUpdate
        webProtection = s.webProtection; blockTrackers = s.blockTrackers
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = RampartConfig()
        autoQuarantine = (try? c.decodeIfPresent(Bool.self, forKey: .autoQuarantine)) ?? d.autoQuarantine
        killMaliciousProcesses = (try? c.decodeIfPresent(Bool.self, forKey: .killMaliciousProcesses)) ?? d.killMaliciousProcesses
        realtime = (try? c.decodeIfPresent(Bool.self, forKey: .realtime)) ?? d.realtime
        webProtection = (try? c.decodeIfPresent(Bool.self, forKey: .webProtection)) ?? d.webProtection
        dnsPort = (try? c.decodeIfPresent(Int.self, forKey: .dnsPort)) ?? nil
        scheduledQuickScanHours = (try? c.decodeIfPresent(Double.self, forKey: .scheduledQuickScanHours)) ?? d.scheduledQuickScanHours
        signatureUpdateHours = (try? c.decodeIfPresent(Double.self, forKey: .signatureUpdateHours)) ?? d.signatureUpdateHours
        persistenceCheckMinutes = (try? c.decodeIfPresent(Double.self, forKey: .persistenceCheckMinutes)) ?? d.persistenceCheckMinutes
        postureCheckHours = (try? c.decodeIfPresent(Double.self, forKey: .postureCheckHours)) ?? d.postureCheckHours
        maxFileSizeMB = (try? c.decodeIfPresent(Int.self, forKey: .maxFileSizeMB)) ?? d.maxFileSizeMB
        exclusions = (try? c.decodeIfPresent([String].self, forKey: .exclusions)) ?? []
        quickScanPaths = (try? c.decodeIfPresent([String].self, forKey: .quickScanPaths)) ?? nil
        watchPaths = (try? c.decodeIfPresent([String].self, forKey: .watchPaths)) ?? nil
        allowlist = (try? c.decodeIfPresent([String].self, forKey: .allowlist)) ?? []
        scanArchives = (try? c.decodeIfPresent(Bool.self, forKey: .scanArchives)) ?? d.scanArchives
        scheduledQuickScan = (try? c.decodeIfPresent(Bool.self, forKey: .scheduledQuickScan)) ?? d.scheduledQuickScan
        scheduledScanHour = (try? c.decodeIfPresent(Int.self, forKey: .scheduledScanHour)) ?? d.scheduledScanHour
        notifyThreats = (try? c.decodeIfPresent(Bool.self, forKey: .notifyThreats)) ?? d.notifyThreats
        notifyInfo = (try? c.decodeIfPresent(Bool.self, forKey: .notifyInfo)) ?? d.notifyInfo
        learningMode = (try? c.decodeIfPresent(Bool.self, forKey: .learningMode)) ?? d.learningMode
        developerMode = (try? c.decodeIfPresent(Bool.self, forKey: .developerMode)) ?? d.developerMode
        ransomwareCanaries = (try? c.decodeIfPresent(Bool.self, forKey: .ransomwareCanaries)) ?? d.ransomwareCanaries
        autoUpdate = (try? c.decodeIfPresent(Bool.self, forKey: .autoUpdate)) ?? d.autoUpdate
        blockTrackers = (try? c.decodeIfPresent(Bool.self, forKey: .blockTrackers)) ?? d.blockTrackers
    }
}

/// Where everything lives for this run (root daemon, --user dev daemon, CLI --local, or a test root).
final class Runtime {
    let root: URL
    let userMode: Bool
    let socketPath: String
    private let lock = NSLock()
    private var _config: RampartConfig

    var configURL: URL { root.appendingPathComponent("config.json") }
    var detectionsURL: URL { root.appendingPathComponent("detections.json") }
    var stateURL: URL { root.appendingPathComponent("state.json") }
    var quarantineDir: URL { root.appendingPathComponent("Quarantine") }
    var databaseDir: URL { root.appendingPathComponent("DB") }
    var rulesDir: URL { root.appendingPathComponent("Rules") }
    var blocklistDir: URL { root.appendingPathComponent("Blocklists") }
    var journalDir: URL { root.appendingPathComponent("Journal") }
    var logFile: URL {
        (getuid() == 0 && !userMode && root == Paths.supportRoot)
            ? Paths.logDir.appendingPathComponent("rampartd.log")
            : root.appendingPathComponent("Logs/rampartd.log")
    }

    var config: RampartConfig {
        get { lock.lock(); defer { lock.unlock() }; return _config }
    }

    init(root: URL? = nil, userMode: Bool, socketPath: String? = nil) {
        self.userMode = userMode
        self.root = root ?? (userMode ? Paths.userRoot : Paths.effectiveRoot)
        self.socketPath = socketPath ?? (userMode || getuid() != 0 ? IPC.userSocketPath : IPC.socketPath)
        self._config = RampartConfig()
        for d in [self.root, quarantineDir, databaseDir, rulesDir, blocklistDir, journalDir] { Util.ensureDir(d) }
        reloadConfig()
    }

    @discardableResult
    func reloadConfig() -> Bool {
        guard let data = try? Data(contentsOf: configURL) else {
            try? Util.writeJSON(RampartConfig(), to: configURL, mode: 0o644)
            return false
        }
        do {
            let c = try JSONDecoder.rampart.decode(RampartConfig.self, from: data)
            lock.lock(); _config = c; lock.unlock()
            return true
        } catch {
            logWarn("config.json unreadable (\(error)); keeping previous settings")
            return false
        }
    }

    func updateConfig(_ change: (inout RampartConfig) -> Void) {
        lock.lock(); change(&_config); let c = _config; lock.unlock()
        do { try Util.writeJSON(c, to: configURL, mode: 0o644) } catch { logError("config save failed: \(error)") }
    }

    /// Folder allow rules (set by Protection) — never scanned.
    private var _allowFolders: [String] = []
    var allowFolders: [String] {
        get { lock.lock(); defer { lock.unlock() }; return _allowFolders }
        set { lock.lock(); _allowFolders = newValue; lock.unlock() }
    }

    var dnsPort: Int { config.dnsPort ?? ((getuid() == 0 && !userMode) ? 53 : 5353) }

    /// Paths scanned by a quick scan.
    var quickScanPaths: [String] {
        if let p = config.quickScanPaths, !p.isEmpty { return p }
        var paths = ["/Applications", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Library/Application Support",
                     "/Users/Shared", "/private/tmp", "/private/var/tmp"]
        for home in Util.homeDirectories() {
            paths += ["Downloads", "Desktop", "Documents", "Applications", "Library/LaunchAgents",
                      "Library/Application Support", ".local/bin"].map { home + "/" + $0 }
        }
        return paths.filter { FileManager.default.fileExists(atPath: $0) }
    }

    /// Paths watched for on-write scanning.
    var watchPaths: [String] {
        if let p = config.watchPaths, !p.isEmpty { return p }
        var paths = ["/Applications", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Users/Shared", "/private/tmp", "/private/var/tmp"]
        for home in Util.homeDirectories() {
            paths += ["Downloads", "Desktop", "Documents", "Applications", "Library/LaunchAgents"].map { home + "/" + $0 }
        }
        return paths.filter { FileManager.default.fileExists(atPath: $0) }
    }

    /// Never scan into these (prefix match), plus user exclusions.
    var exclusions: [String] {
        ["/System", "/dev", "/private/var/vm", "/private/var/db/uuidtext", "/private/var/db/diagnostics",
         "/Volumes", "/cores", "/.Spotlight-V100", "/.fseventsd", "/System/Volumes",
         quarantineDir.path, root.path] + config.exclusions + allowFolders
    }
}

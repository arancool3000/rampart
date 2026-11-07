import Foundation
import Darwin
import RampartShared

// Defence in depth: three cooperating root launchd jobs with different labels and binary names
// (daemon `app.rampart.daemon`, watchdog `app.rampart.watchdog`, sentinel `app.rampart.sentinel`).
// Each runs `GuardianLoop` once a second: for every partner it verifies the binary and plist hashes
// against the sealed manifest, restores a missing/edited plist or binary from the sealed backup,
// re-bootstraps the job, and kickstarts it if it is not running. launchd KeepAlive covers plain kills;
// the ring covers bootout/disable/file deletion. Back-off applies only after repeated failures of the
// same partner so a flapping job cannot make the ring spin.
//
// What it cannot do: stop a root process that deletes all three binaries and all backups in the same
// second, or anything done from Recovery Mode. That is true for every antivirus without a kernel presence.

public enum GuardianRole: String, Codable, Sendable, CaseIterable {
    case daemon, watchdog, sentinel
}

public struct GuardianJob: Codable, Hashable, Sendable {
    public var role: GuardianRole
    public var label: String
    public var binary: String
    public var plist: String
    public init(role: GuardianRole, label: String, binary: String, plist: String) {
        self.role = role; self.label = label; self.binary = binary; self.plist = plist
    }
}

public struct GuardianRing: Codable, Hashable, Sendable {
    public var jobs: [GuardianJob]
    public init(paths: GuardPaths) {
        let prefix = Product.bundlePrefix
        jobs = [
            GuardianJob(role: .daemon, label: paths.daemonLabel, binary: paths.daemonBinary, plist: paths.daemonPlist),
            GuardianJob(role: .watchdog, label: paths.watchdogLabel, binary: paths.watchdogBinary, plist: paths.watchdogPlist),
            GuardianJob(role: .sentinel, label: prefix + ".sentinel",
                        binary: (paths.watchdogBinary as NSString).deletingLastPathComponent + "/" + prefix + ".sentinel",
                        plist: (paths.watchdogPlist as NSString).deletingLastPathComponent + "/" + prefix + ".sentinel.plist"),
        ]
    }
    public func job(_ r: GuardianRole) -> GuardianJob { jobs.first { $0.role == r }! }
    public func partners(of r: GuardianRole) -> [GuardianJob] { jobs.filter { $0.role != r } }
    public var labels: [String] { jobs.map(\.label) }
    public var binaries: [String] { jobs.map(\.binary) }
    public var plists: [String] { jobs.map(\.plist) }

    /// LaunchDaemon plist for a helper role. Watchdog and sentinel are the same binary logic under different
    /// names; `--role` tells them which partner set to guard. KeepAlive + ThrottleInterval 1 so launchd itself
    /// restarts them within a second.
    public func plistXML(for role: GuardianRole, logDir: String = Paths.logDir.path) -> String {
        let j = job(role)
        let args = role == .daemon ? [j.binary] : [j.binary, "--role", role.rawValue]
        let argXML = args.map { "        <string>\($0)</string>" }.joined(separator: "\n")
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key><string>\(j.label)</string>
            <key>ProgramArguments</key>
            <array>
        \(argXML)
            </array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            <key>ThrottleInterval</key><integer>1</integer>
            <key>ProcessType</key><string>Background</string>
            <key>Nice</key><integer>5</integer>
            <key>StandardOutPath</key><string>\(logDir)/\(j.label).log</string>
            <key>StandardErrorPath</key><string>\(logDir)/\(j.label).log</string>
        </dict>
        </plist>

        """
    }
}

/// One partner's state as seen by a guardian tick.
public struct GuardianCheck: Codable, Hashable, Sendable {
    public var label: String
    public var running: Bool
    public var binaryIntact: Bool?     // nil: no manifest entry
    public var plistIntact: Bool?
    public var restoredFiles: [String]
    public var commands: [GuardCommand]
    public var notes: [String]
    public var healthy: Bool { running && binaryIntact != false && plistIntact != false }
}

public struct GuardianTick: Codable, Sendable {
    public var role: GuardianRole
    public var at: Date
    public var checks: [GuardianCheck]
    public var backoffSeconds: Double
    public var dryRun: Bool
}

/// The loop body every guardian runs. Pure decision logic with injected probes so it is testable without launchd.
public final class GuardianLoop: @unchecked Sendable {
    public static let launchctl = "/bin/launchctl"
    public let role: GuardianRole
    public let ring: GuardianRing
    public let store: SealedStore?
    public let manifest: InstallManifest?
    public let clock: GuardClock
    /// Is the job with this label running? Default: `launchctl print system/<label>` contains "pid = ".
    public let isRunning: @Sendable (String) -> Bool
    /// Reads a sealed backup of a file (binary or plist) when the live copy is bad. Default: SealedStore backup.
    public var interval: TimeInterval = 1
    /// hx5: was 60 s. An attacker who re-boots-out a partner every time it comes back pushed the ring into minute-long
    /// gaps; 8 s keeps the worst-case gap short while still stopping a flapping job from spinning the CPU.
    public var maxBackoff: TimeInterval = 8
    private let lock = NSLock()
    private var failures: [String: Int] = [:]
    private var nextAllowed: [String: Date] = [:]
    private let log = RLog.logger("guard.ring")

    public init(role: GuardianRole, ring: GuardianRing, store: SealedStore?, manifest: InstallManifest?,
                clock: GuardClock = .live, runner: GuardCommandRunning = GuardProcessRunner(),
                isRunning: (@Sendable (String) -> Bool)? = nil) {
        self.role = role; self.ring = ring; self.store = store; self.manifest = manifest; self.clock = clock
        self.isRunning = isRunning ?? { label in
            Self.isLive(printOutput: runner.run(Self.launchctl, ["print", "system/\(label)"], timeout: 3).stdout)
        }
    }

    /// hx5: "pid = N" alone is not liveness. A job frozen with SIGSTOP (or `launchctl kill SIGSTOP`) still has a pid,
    /// launchd never restarts it, and the old check reported it healthy forever. A stopped or zombie process now
    /// counts as not running, so the partner gets `kickstart -k` (SIGKILL works on a stopped process).
    public static func isLive(printOutput: String, state: (Int32) -> UInt32? = GuardianLoop.processStatus) -> Bool {
        guard let pid = parsePID(printOutput), pid > 1 else { return false }
        guard let st = state(pid) else { return false }
        return st != UInt32(SSTOP) && st != UInt32(SZOMB)
    }
    public static func parsePID(_ printOutput: String) -> Int32? {
        for line in printOutput.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("pid = "), let n = Int32(t.dropFirst(6).trimmingCharacters(in: .whitespaces)) { return n }
        }
        return nil
    }
    /// BSD process status (SRUN, SSTOP, SZOMB...), nil if the pid does not exist.
    public static let processStatus: (Int32) -> UInt32? = { pid in
        var bi = proc_bsdinfo()
        let sz = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sz) == sz else { return nil }
        return bi.pbi_status
    }

    public static func rebootstrap(_ j: GuardianJob) -> [GuardCommand] {
        [GuardCommand(launchctl, ["enable", "system/\(j.label)"], note: "undo disable"),
         GuardCommand(launchctl, ["bootstrap", "system", j.plist], acceptableExitCodes: [5, 17, 37], note: "already loaded is fine"),
         GuardCommand(launchctl, ["kickstart", "-k", "system/\(j.label)"], note: "start now")]
    }

    private func fileIntact(_ path: String) -> Bool? {
        guard let m = manifest, let expected = m.entries[path] else { return nil }
        return InstallManifest.sha256(ofFile: path) == expected
    }

    /// One tick: checks every partner; returns what was (or would be, in dryRun) done.
    /// `GuardCommand`s are for the caller to run (root). File restores from sealed backups happen here when !dryRun.
    public func tick(dryRun: Bool = true) -> GuardianTick {
        let now = clock.now()
        var checks: [GuardianCheck] = []
        var backoff: Double = 0
        for j in ring.partners(of: role) {
            var c = GuardianCheck(label: j.label, running: isRunning(j.label), binaryIntact: fileIntact(j.binary),
                                  plistIntact: fileIntact(j.plist), restoredFiles: [], commands: [], notes: [])
            if c.healthy { lock.lock(); failures[j.label] = 0; nextAllowed[j.label] = nil; lock.unlock(); checks.append(c); continue }
            lock.lock()
            // hx5: a clock moved backwards would otherwise stretch the back-off for as long as the jump.
            if let na = nextAllowed[j.label], now < na, na.timeIntervalSince(now) <= maxBackoff {
                lock.unlock(); c.notes.append("in back-off until \(na)"); checks.append(c); continue
            }
            let n = (failures[j.label] ?? 0) + 1
            failures[j.label] = n
            let delay = min(maxBackoff, pow(2, Double(min(n, 10) - 1)))   // 1,2,4,8 s
            nextAllowed[j.label] = now.addingTimeInterval(delay)
            backoff = max(backoff, delay)
            lock.unlock()

            for (path, intact) in [(j.plist, c.plistIntact), (j.binary, c.binaryIntact)] where intact == false || !FileManager.default.fileExists(atPath: path) {
                if let store, store.hasBackup(for: path) {
                    // hx5: binaries and plists are raw files: restore the payload whose hash matches the manifest,
                    // not the JSON envelope (which launchd cannot run).
                    let restored = store.restoreRawIfNeeded(path, expectedSHA: manifest?.entries[path],
                                                            mode: path == j.binary ? 0o755 : 0o644, dryRun: dryRun)
                    if restored {
                        c.restoredFiles.append(path)
                        if path == j.binary { c.commands.append(GuardCommand("/bin/chmod", ["755", path], note: "binary must be executable")) }
                    }
                } else { c.notes.append("\(path): no sealed backup (reinstall required)") }
            }
            if c.binaryIntact == false && c.restoredFiles.contains(j.binary) == false && store?.hasBackup(for: j.binary) != true {
                c.notes.append("\(j.label): binary hash mismatch and no backup; NOT restarting a replaced binary as root")
                checks.append(c); continue
            }
            c.commands += Self.rebootstrap(j)
            c.notes.append("\(j.label) unhealthy (running=\(c.running)); re-bootstrap attempt \(n), next retry in \(Int(delay)) s")
            log.warning("\(j.label, privacy: .public) unhealthy; restore attempt \(n)")
            checks.append(c)
        }
        return GuardianTick(role: role, at: now, checks: checks, backoffSeconds: backoff, dryRun: dryRun)
    }

    /// Runs `tick` every `interval` seconds on a background thread until `stop`. Commands go to `execute`.
    private var timer: DispatchSourceTimer?
    public func start(dryRun: Bool, execute: @escaping @Sendable ([GuardCommand]) -> Void, onTick: (@Sendable (GuardianTick) -> Void)? = nil) {
        let q = DispatchQueue(label: Product.bundlePrefix + ".guardian." + role.rawValue, qos: .utility)
        let t = DispatchSource.makeTimerSource(queue: q)
        t.schedule(deadline: .now() + interval, repeating: interval)
        t.setEventHandler { [weak self] in
            guard let self else { return }
            let tk = self.tick(dryRun: dryRun)
            let cmds = tk.checks.flatMap(\.commands)
            if !cmds.isEmpty && !dryRun { execute(cmds) }
            onTick?(tk)
        }
        t.resume(); timer = t
    }
    public func stop() { timer?.cancel(); timer = nil }
}

/// Entry point for the helper binaries (watchdog/sentinel). The lead adds an executable target whose main is:
///     import RampartGuard; GuardianMain.run(arguments: CommandLine.arguments)
/// Runs as root under launchd; dry-run unless `RAMPART_GUARDIAN_LIVE=1` so development never touches launchd.
public enum GuardianMain {
    public static func run(arguments: [String], paths: GuardPaths = .standard) -> Never {
        let roleName = arguments.firstIndex(of: "--role").flatMap { arguments.indices.contains($0 + 1) ? arguments[$0 + 1] : nil } ?? "watchdog"
        let role = GuardianRole(rawValue: roleName) ?? .watchdog
        let live = ProcessInfo.processInfo.environment["RAMPART_GUARDIAN_LIVE"] == "1" && getuid() == 0
        let key = try? IntegrityKey.loadOrCreate(at: paths.keyFile)
        let store = key.map { SealedStore(key: $0, backupDir: paths.backupDir) }
        let manifest = store.flatMap { InstallManifest.load(from: $0, path: paths.manifestFile) }
        let loop = GuardianLoop(role: role, ring: GuardianRing(paths: paths), store: store, manifest: manifest)
        let runner = GuardProcessRunner()
        loop.start(dryRun: !live, execute: { cmds in
            for c in cmds { _ = runner.run(c.executable, c.arguments, timeout: 10) }
        })
        signal(SIGTERM) { _ in }   // ignore polite stops; launchd KeepAlive and the ring handle the rest
        dispatchMain()
    }
}

// MARK: - Attacker response

/// What to do the moment a tamper detection fires: stop the attacking process tree first (unless it belongs to
/// an authenticated uninstall/disable session), then run the self-defence policy. Kills go through `KillHook`
/// (the daemon injects ProcessKiller logic with pid-reuse and platform-binary checks); dryRun records only.
public struct TamperResponder: Sendable {
    public let policy: SelfDefencePolicy
    public let kill: KillHook
    public let flow: ProtectionDisableFlow?
    public let processTree: @Sendable (Int32) -> [Int32]
    public init(policy: SelfDefencePolicy, flow: ProtectionDisableFlow?, kill: @escaping KillHook,
                processTree: @escaping @Sendable (Int32) -> [Int32] = TamperResponder.liveTree) {
        self.policy = policy; self.flow = flow; self.kill = kill; self.processTree = processTree
    }

    /// Descendants of `pid` (leaves first) plus `pid`; never pid 0/1 or ourselves.
    public static let liveTree: @Sendable (Int32) -> [Int32] = { root in
        guard root > 1, root != getpid() else { return [] }
        var children: [Int32: [Int32]] = [:]
        for pid in GuardProc.allPIDs() { if let i = GuardProc.info(pid) { children[i.ppid, default: []].append(pid) } }
        var order: [Int32] = [], queue = [root], seen: Set<Int32> = []
        while !queue.isEmpty {
            let p = queue.removeFirst(); guard seen.insert(p).inserted else { continue }
            order.append(p); queue += children[p] ?? []
        }
        return order.reversed()
    }

    public struct Outcome: Codable, Sendable {
        public var dryRun: Bool
        public var attackerPIDs: [Int32]
        public var stopped: [Int32]
        public var exempt: Bool
        public var response: SelfDefenceResponse
    }

    public func respond(to detection: Detection, kind: TamperKind, actorPID: Int32?, actorUID: uid_t?, dryRun: Bool = true) -> Outcome {
        let exempt = actorUID.flatMap { flow?.hasActiveSession(uid: $0) } ?? false
        var tree: [Int32] = []
        var stopped: [Int32] = []
        if !exempt, let pid = actorPID, pid > 1, pid != getpid() {
            tree = processTree(pid)
            if !dryRun {
                for p in tree where kill(p, SIGSTOP) { stopped.append(p) }   // freeze first, so the restore wins the race
                for p in tree { _ = kill(p, SIGKILL) }
            }
        }
        let r = policy.respond(to: kind, path: detection.path, dryRun: dryRun)
        return Outcome(dryRun: dryRun, attackerPIDs: tree, stopped: stopped, exempt: exempt, response: r)
    }
}

/// UI copy, kept in one place so the app and the CLI say the same true thing.
public enum TamperCopy {
    public static let whatItDoes =
        "Scripts and malware running as your user can't turn \(Product.name) off: protection can only be paused or removed " +
        "with your administrator password through \(Product.name) itself. Attempts to stop, unload, delete or edit it that " +
        "\(Product.name) can see are detected, undone from sealed backups where possible, and reported to you."
    public static let limit =
        "No antivirus can stop a person who deliberately restarts into Recovery Mode and removes it, and macOS lets a " +
        "root process stop any background service. A root process can also read the sealing key, clear immutable flags, " +
        "or unload all three guardians at once; \(Product.name) makes most of that loud and short-lived, but it cannot " +
        "make it impossible."
}

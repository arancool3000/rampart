import Foundation
import Darwin
import RampartShared

// RampartGuard: tamper protection (self-defence) and remote-access lockdown.
// Depends only on RampartShared. Nothing in this module executes privileged commands itself:
// every action is a `GuardCommand` returned for rampartd to run, and every entry point has `dryRun`.
//
// HONEST LIMIT (read this before promising anything in the UI):
// RamPart has no Endpoint Security entitlement and no kernel presence. A process running as root
// can always defeat it: `launchctl bootout`, `kill -9`, `chflags noschg`, `rm -rf`. What this module
// does is make every such attempt (1) detectable, (2) loud, and (3) automatically undone where macOS
// allows it: launchd KeepAlive + a watchdog pair, HMAC-sealed config, hash manifest for binaries,
// immutable flags on installed files, and an admin-authenticated path for a *legitimate* disable so
// that anything else stands out as tampering.

/// A typed command for the daemon to run: absolute executable + argument array, never a shell string.
public struct GuardCommand: Codable, Hashable, Sendable, CustomStringConvertible {
    public var executable: String
    public var arguments: [String]
    public var requiresRoot: Bool
    /// Exit codes treated as success besides 0 (e.g. bootout of a job that is not loaded).
    public var acceptableExitCodes: [Int32]
    public var note: String
    public init(_ executable: String, _ arguments: [String], requiresRoot: Bool = true,
                acceptableExitCodes: [Int32] = [], note: String = "") {
        self.executable = executable; self.arguments = arguments; self.requiresRoot = requiresRoot
        self.acceptableExitCodes = acceptableExitCodes; self.note = note
    }
    public var description: String {
        let quoted = arguments.map { a -> String in
            a.isEmpty || a.contains(where: { " \"'$\\{}<>".contains($0) })
                ? "'" + a.replacingOccurrences(of: "'", with: "'\\''") + "'" : a
        }
        return ([executable] + quoted).joined(separator: " ")
    }
}

/// Result of a command the daemon ran on our behalf (or a fake in tests).
public struct GuardCommandResult: Sendable, Equatable {
    public var status: Int32
    public var stdout: String
    public var stderr: String
    public var launchFailed: Bool
    public var succeeded: Bool { !launchFailed && status == 0 }
    public init(status: Int32 = 0, stdout: String = "", stderr: String = "", launchFailed: Bool = false) {
        self.status = status; self.stdout = stdout; self.stderr = stderr; self.launchFailed = launchFailed
    }
    public static let failedToLaunch = GuardCommandResult(status: -1, launchFailed: true)
}

/// Runs read-only probes (launchctl print, lsof). Injectable; tests use `FakeGuardRunner`.
public protocol GuardCommandRunning: Sendable {
    func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> GuardCommandResult
}

/// Real runner based on `Process` (argument arrays only, with a timeout). Same shape as RampartPosture's.
public struct GuardProcessRunner: GuardCommandRunning {
    public init() {}
    private final class Box: @unchecked Sendable { let lock = NSLock(); var out = Data(); var err = Data() }

    /// Tools that can raise a dialog or change system state. Refused outright while `RAMPART_NO_PRIVILEGED_TOOLS=1`
    /// (ARCHITECTURE.md "ZERO POP-UPS RULE"); the daemon sets that in development.
    public static let privilegedTools: Set<String> = ["launchctl", "systemsetup", "tccutil", "sfltool", "profiles", "osascript", "security",
                                                      "pfctl", "chflags", "kickstart", "systemextensionsctl", "sudo", "lsof", "networksetup"]
    public static var devSafeMode: Bool { ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] == "1" }

    public func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> GuardCommandResult {
        if Self.devSafeMode, Self.privilegedTools.contains((executable as NSString).lastPathComponent) {
            return GuardCommandResult(status: -1, stderr: "refused: RAMPART_NO_PRIVILEGED_TOOLS=1 (\(executable))", launchFailed: true)
        }
        guard FileManager.default.isExecutableFile(atPath: executable) else { return .failedToLaunch }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = arguments
        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe; p.standardError = errPipe; p.standardInput = FileHandle.nullDevice
        let finished = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in finished.signal() }
        do { try p.run() } catch { return .failedToLaunch }
        let box = Box(); let readers = DispatchGroup()
        readers.enter(); DispatchQueue.global(qos: .utility).async {
            let d = outPipe.fileHandleForReading.readDataToEndOfFile(); box.lock.lock(); box.out = d; box.lock.unlock(); readers.leave()
        }
        readers.enter(); DispatchQueue.global(qos: .utility).async {
            let d = errPipe.fileHandleForReading.readDataToEndOfFile(); box.lock.lock(); box.err = d; box.lock.unlock(); readers.leave()
        }
        if finished.wait(timeout: .now() + timeout) == .timedOut {
            p.terminate()
            if finished.wait(timeout: .now() + 0.5) == .timedOut { kill(p.processIdentifier, SIGKILL); _ = finished.wait(timeout: .now() + 0.5) }
        }
        _ = readers.wait(timeout: .now() + 1)
        box.lock.lock(); let out = box.out, err = box.err; box.lock.unlock()
        return GuardCommandResult(status: p.isRunning ? -1 : p.terminationStatus,
                                  stdout: String(decoding: out, as: UTF8.self), stderr: String(decoding: err, as: UTF8.self))
    }
}

/// Scripted runner for self-tests: maps "executable arg1 arg2" to canned output.
public final class FakeGuardRunner: GuardCommandRunning, @unchecked Sendable {
    private let lock = NSLock()
    public var responses: [String: GuardCommandResult]
    public private(set) var calls: [String] = []
    public init(_ responses: [String: GuardCommandResult] = [:]) { self.responses = responses }
    public func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> GuardCommandResult {
        let key = ([executable] + arguments).joined(separator: " ")
        lock.lock(); calls.append(key); lock.unlock()
        return responses[key] ?? GuardCommandResult(status: 1, stderr: "no fixture for \(key)")
    }
}

/// Where RamPart lives once installed. Everything in `TamperDetector` keys off these paths and labels.
public struct GuardPaths: Codable, Hashable, Sendable {
    public var daemonLabel: String
    public var watchdogLabel: String
    public var agentLabel: String
    public var daemonBinary: String
    public var watchdogBinary: String
    public var daemonPlist: String
    public var watchdogPlist: String
    public var agentPlist: String
    public var appBundle: String
    public var supportRoot: String
    public var guardDir: String
    public var keyFile: String
    public var backupDir: String
    public var manifestFile: String
    public var configFile: String
    public var allowRulesFile: String
    public var remotePolicyFile: String

    public init(supportRoot: String = Paths.supportRoot.path, appBundle: String = "/Applications/\(Product.name).app") {
        daemonLabel = Product.daemonLabel
        watchdogLabel = Product.bundlePrefix + ".watchdog"
        agentLabel = Product.agentLabel
        daemonBinary = "/Library/PrivilegedHelperTools/\(Product.daemonLabel)"
        watchdogBinary = "/Library/PrivilegedHelperTools/\(Product.bundlePrefix).watchdog"
        daemonPlist = "/Library/LaunchDaemons/\(Product.daemonLabel).plist"
        watchdogPlist = "/Library/LaunchDaemons/\(Product.bundlePrefix).watchdog.plist"
        agentPlist = "/Library/LaunchAgents/\(Product.agentLabel).plist"
        self.appBundle = appBundle
        self.supportRoot = supportRoot
        guardDir = supportRoot + "/Guard"
        keyFile = guardDir + "/integrity.key"
        backupDir = guardDir + "/Backup"
        manifestFile = guardDir + "/manifest.json"
        configFile = supportRoot + "/config.json"
        allowRulesFile = supportRoot + "/allow-rules.json"
        remotePolicyFile = guardDir + "/remote-access-policy.json"
    }

    public static let standard = GuardPaths()

    /// Dev/test layout under a scratch folder (nothing under /Library).
    public static func scratch(_ root: String) -> GuardPaths {
        var p = GuardPaths(supportRoot: root + "/support", appBundle: root + "/RamPart.app")
        p.daemonBinary = root + "/bin/app.rampart.daemon"
        p.watchdogBinary = root + "/bin/app.rampart.watchdog"
        p.daemonPlist = root + "/LaunchDaemons/app.rampart.daemon.plist"
        p.watchdogPlist = root + "/LaunchDaemons/app.rampart.watchdog.plist"
        p.agentPlist = root + "/LaunchAgents/app.rampart.agent.plist"
        return p
    }

    public var labels: [String] { [daemonLabel, watchdogLabel, agentLabel] }
    public var plists: [String] { [daemonPlist, watchdogPlist, agentPlist] }
    public var binaries: [String] { [daemonBinary, watchdogBinary] }
    /// Prefixes under which any write/delete/rename by a foreign process is tampering.
    public var protectedPrefixes: [String] { [daemonBinary, watchdogBinary, daemonPlist, watchdogPlist, agentPlist, appBundle, supportRoot] }
    /// Files whose edit is treated as critical (they decide whether we run at all).
    public var criticalFiles: [String] { plists + binaries + [configFile, allowRulesFile, keyFile, manifestFile] }

    public func isProtected(_ path: String) -> Bool {
        let p = Self.normalize(path)
        return protectedPrefixes.map(Self.normalize).contains { p == $0 || p.hasPrefix($0 + "/") }
    }
    public func isCritical(_ path: String) -> Bool { criticalFiles.map(Self.normalize).contains(Self.normalize(path)) }
    public func isPlist(_ path: String) -> Bool { plists.map(Self.normalize).contains(Self.normalize(path)) }
    public func isOurLabel(_ s: String) -> Bool {
        let l = s.lowercased()
        return labels.contains { l.contains($0.lowercased()) } || l.contains("app.rampart")
    }

    static func normalize(_ p: String) -> String {
        var s = (p as NSString).standardizingPath
        if s.hasPrefix("/private/var/") { s = String(s.dropFirst("/private".count)) }
        if s.hasPrefix("/private/tmp/") { s = String(s.dropFirst("/private".count)) }
        return s
    }
}

/// Admin check by group membership (gid 80 = admin). Same rule the daemon's IPC layer uses.
public enum AdminCheck {
    public static func isAdmin(uid: uid_t) -> Bool {
        if uid == 0 { return true }
        guard let pw = getpwuid(uid) else { return false }
        var groups = [Int32](repeating: 0, count: 64); var n: Int32 = 64
        if getgrouplist(pw.pointee.pw_name, Int32(bitPattern: pw.pointee.pw_gid), &groups, &n) == -1 { return false }
        return groups.prefix(Int(n)).contains(80)
    }
}

/// Minimal libproc helpers so this module needs no RampartRemediation dependency.
public enum GuardProc {
    public static func allPIDs() -> [Int32] {
        var cap = Int(proc_listallpids(nil, 0)) + 64
        while true {
            var pids = [Int32](repeating: 0, count: cap)
            let n = pids.withUnsafeMutableBytes { Int(proc_listallpids($0.baseAddress, Int32($0.count))) }
            if n < 0 { return [] }
            if n < cap { return Array(pids.prefix(n)).filter { $0 > 0 } }
            cap *= 2
        }
    }
    public static func path(of pid: Int32) -> String {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : ""
    }
    public struct Info { public var pid: Int32; public var ppid: Int32; public var uid: UInt32; public var start: UInt64 }
    public static func info(_ pid: Int32) -> Info? {
        var bi = proc_bsdinfo()
        let sz = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sz) == sz else { return nil }
        return Info(pid: Int32(bi.pbi_pid), ppid: Int32(bi.pbi_ppid), uid: bi.pbi_uid,
                    start: UInt64(bi.pbi_start_tvsec) * 1_000_000 + UInt64(bi.pbi_start_tvusec))
    }
    /// Live process list without signing info (the daemon enriches via RampartSigning when it has it).
    public static func processes() -> [ProcessInfoLite] {
        allPIDs().compactMap { pid in
            guard let i = info(pid) else { return nil }
            let p = path(of: pid)
            guard !p.isEmpty else { return nil }
            return ProcessInfoLite(pid: pid, ppid: i.ppid, path: p, uid: i.uid)
        }
    }
}

/// Kill hook: `(pid, signal) -> success`. The daemon injects RampartRemediation.ProcessKiller-backed
/// logic (pid-reuse checks, platform-binary protection); tests inject a recorder.
public typealias KillHook = @Sendable (Int32, Int32) -> Bool

/// Rough-and-ready clock injection for back-off and token expiry tests.
public struct GuardClock: Sendable {
    public var now: @Sendable () -> Date
    public init(now: @escaping @Sendable () -> Date = { Date() }) { self.now = now }
    public static let live = GuardClock()
}

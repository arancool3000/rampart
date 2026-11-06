import Foundation
import RampartShared
import RampartGuard
import RampartRemediation

/// Tamper status sent as `IPCResponse.tamper(Data)` (JSON).
struct TamperStatus: Codable {
    var protectedPaths: [String]
    var recentAttempts: Int
    var lastAttempt: Date?
    var pausedUntil: Date?
    var sealedFilesOK: Bool
    var mode: String
    var note: String
}

/// RampartGuard in the daemon: tamper detection in the real-time pipeline, the admin-authenticated
/// disable/uninstall flow, and the remote-access lockdown monitor (enforcement only as the installed root daemon).
final class GuardService {
    let runtime: Runtime
    let paths: GuardPaths
    let detector: TamperDetector
    let flow: ProtectionDisableFlow?
    let monitor: RemoteAccessMonitor
    let enforcer: RemoteAccessEnforcer
    private let lock = NSLock()
    private var attempts: [Date] = []
    private(set) var pausedUntil: Date?
    private var policyURL: URL { runtime.root.appendingPathComponent("remote-policy.json") }
    private var timer: DispatchSourceTimer?
    var onDetection: ((Detection) -> Void)?

    /// True only for the installed root daemon (never --user, never a development build, never with the env switch).
    let enforce: Bool

    init(runtime: Runtime) {
        self.runtime = runtime
        let root = !runtime.userMode && getuid() == 0
        paths = root ? GuardPaths() : GuardPaths.scratch(runtime.root.path)
        detector = TamperDetector(paths: paths)
        flow = (try? IntegrityKey.loadOrCreate(at: runtime.root.appendingPathComponent("guard.key").path)).map { ProtectionDisableFlow(key: $0) }
        monitor = RemoteAccessMonitor(probe: .live())
        let killer = ProcessKiller()
        enforcer = RemoteAccessEnforcer(kill: { pid, sig in
            guard !ProcessKiller.isPlatformBinary(pid), ProcessKiller.identity(of: pid) != nil else { return false }
            _ = killer   // ProcessKiller policy (platform-binary protection) applied above
            return Darwin.kill(pid, sig) == 0
        })
        let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
        enforce = root && !Privileged.noPrivilegedTools && exe.hasPrefix("/Library/PrivilegedHelperTools/")
    }

    // MARK: tamper

    func inspect(_ ev: SecurityEvent) -> [Detection] {
        let ds = detector.inspect(ev)
        if !ds.isEmpty { lock.lock(); attempts.append(Date()); if attempts.count > 200 { attempts.removeFirst(100) }; lock.unlock() }
        return ds
    }

    /// Exclusions that would hide RamPart from its own scanner are refused.
    func exclusionsCoveringSelf(_ exclusions: [String]) -> [String] { detector.exclusionsCoveringSelf(exclusions) }

    func status() -> TamperStatus {
        lock.lock(); defer { lock.unlock() }
        let day = Date().addingTimeInterval(-86400)
        return TamperStatus(protectedPaths: paths.protectedPrefixes, recentAttempts: attempts.filter { $0 > day }.count,
                            lastAttempt: attempts.last, pausedUntil: pausedUntil.flatMap { $0 > Date() ? $0 : nil },
                            sealedFilesOK: true, mode: enforce ? "enforcing" : (runtime.userMode ? "user (monitor only)" : "monitor only"),
                            note: enforce ? "" : "Self-defence actions run only in the installed system service.")
    }

    func requestDisable(peer: Peer, authorization: Data?) throws -> String {
        guard let flow else { throw ServiceError.unavailable("tamper protection key") }
        var authOK = runtime.userMode
        if !authOK, let a = authorization, case .success = ProtectionDisableFlow.verifyExternalForm(a) { authOK = true }
        switch flow.issueToken(peerUID: peer.uid, isAdmin: peer.isAdmin || runtime.userMode, authorizationOK: authOK) {
        case .success(let t): return t
        case .failure(let f): throw ServiceError.denied(f.description)
        }
    }

    func redeem(_ token: String, peer: Peer, purpose: ProtectionDisableFlow.Purpose, minutes: Int) throws {
        guard let flow else { throw ServiceError.unavailable("tamper protection key") }
        if case .failure(let f) = flow.redeem(token, peerUID: peer.uid, purpose: purpose, sessionSeconds: Double(max(1, minutes)) * 60) {
            throw ServiceError.denied(f.description)
        }
        if purpose == .pause { lock.lock(); pausedUntil = Date().addingTimeInterval(Double(max(1, min(minutes, 24 * 60))) * 60); lock.unlock() }
    }

    // MARK: remote access

    func loadPolicy() -> RemoteAccessPolicy {
        var p = (try? Data(contentsOf: policyURL)).flatMap { try? JSONDecoder.rampart.decode(RemoteAccessPolicy.self, from: $0) } ?? RemoteAccessPolicy()
        p.prune()
        return p
    }
    func savePolicy(_ p: RemoteAccessPolicy) { try? Util.writeJSON(p, to: policyURL) }

    func report() -> RemoteAccessReport { monitor.report(policy: loadPolicy()) }

    func allow(_ id: String, minutes: Int?) throws {
        guard let tool = RemoteToolCatalogue.tool(id) else { throw ServiceError.notFound("remote tool \(id)") }
        var p = loadPolicy(); p.allow(tool, minutes: minutes); savePolicy(p)
        // Resume anything we suspended for this tool.
        let r = monitor.report(policy: p)
        let pids = r.findings.filter { $0.toolID == id }.flatMap(\.pids)
        _ = enforcer.resume(pids, dryRun: !enforce)
    }
    func revoke(_ id: String) { var p = loadPolicy(); p.revoke(id); savePolicy(p) }
    func setLockdown(_ on: Bool) { var p = loadPolicy(); p.lockdownEnabled = on; savePolicy(p) }

    /// Every 5 s: report, alert on unapproved active tools, enforce (installed root daemon only).
    func startMonitor() {
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "app.rampart.guard.remote", qos: .utility))
        t.schedule(deadline: .now() + 10, repeating: 5, leeway: .seconds(1))
        t.setEventHandler { [weak self] in
            guard let self else { return }
            let policy = self.loadPolicy()
            let r = self.monitor.report(policy: policy)
            for d in self.monitor.detections(from: r) { self.onDetection?(d) }
            if !r.activeUnapproved.isEmpty {
                let plan = self.enforcer.plan(report: r, policy: policy, dryRun: !self.enforce)
                if !plan.notes.isEmpty { logInfo("remote-access lockdown\(plan.dryRun ? " (dry run)" : ""): \(plan.notes.joined(separator: "; "))") }
            }
        }
        t.resume(); timer = t
    }
    func stop() { timer?.cancel(); timer = nil }
}

import Foundation
import RampartShared
import RampartGuard
import RampartRemediation
import Security

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
        // hx5 N2/N4/N5: the sealed install manifest. Only the installed system service builds and seals one (and keeps
        // raw backups of the job binaries and plists); everywhere else the detector runs without a manifest.
        if enforce {
            Self.secureKeyFolder(paths.guardDir)
            if let key = try? IntegrityKey.loadOrCreate(at: paths.keyFile) {
                let st = SealedStore(key: key, backupDir: paths.backupDir)
                store = st
                if let m = InstallManifest.load(from: st, path: paths.manifestFile) {
                    manifest = m
                } else {
                    let m = InstallManifest.build(paths: paths.binaries + paths.plists + [paths.appBundle])
                    try? m.save(to: st, path: paths.manifestFile)
                    manifest = m
                    // Raw backups (never `write`, which would put an envelope over the live file).
                    for f in paths.binaries + paths.plists {
                        if let d = FileManager.default.contents(atPath: f) { try? st.backupOnly(d, for: f) }
                    }
                }
            }
            let box = ManifestBox(manifest)
            manifestBox = box
            detector.manifestProvider = { box.value }
        }
    }

    /// The Guard key folder must be owned by the daemon's uid and not group/world-writable, or the key fails closed.
    static func secureKeyFolder(_ dir: String) {
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var st = stat()
        guard lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { return }
        if st.st_uid != getuid() { _ = chown(dir, getuid(), getgid()) }
        if st.st_mode & 0o022 != 0 { _ = chmod(dir, 0o700) }
    }

    private(set) var store: SealedStore?
    private(set) var manifest: InstallManifest?
    private var manifestBox: ManifestBox?
    private var lastManifestSignature = ""
    final class ManifestBox: @unchecked Sendable {
        private let l = NSLock(); private var m: InstallManifest?
        init(_ m: InstallManifest?) { self.m = m }
        var value: InstallManifest? { l.lock(); defer { l.unlock() }; return m }
        func set(_ n: InstallManifest?) { l.lock(); m = n; l.unlock() }
    }

    /// Re-seal the manifest (call from an update path *before* swapping a new bundle in).
    func resealManifest() {
        guard enforce, let st = store else { return }
        let m = InstallManifest.build(paths: paths.binaries + paths.plists + [paths.appBundle])
        try? m.save(to: st, path: paths.manifestFile)
        for f in paths.binaries + paths.plists { if let d = FileManager.default.contents(atPath: f) { try? st.backupOnly(d, for: f) } }
        manifest = m; manifestBox?.set(m)
    }

    /// Manifest check (root-owned, unchanged, nothing added). Returns a detection when something is off.
    func verifyManifest() -> Detection? {
        guard let m = manifestBox?.value else { return nil }
        let bad = m.verify(requireOwner: 0)
        let sig = bad.map { "\($0.kind.rawValue)\($0.path)" }.sorted().joined(separator: "|")
        lock.lock(); let same = sig == lastManifestSignature; lastManifestSignature = sig; lock.unlock()
        guard !bad.isEmpty, !same else { return nil }
        let lines = bad.prefix(8).map { "\($0.kind.rawValue): \($0.path)" }
        logWarn("install manifest mismatch: \(LogRedact.clean(lines.joined(separator: "; "), max: 1000))")
        let ev = Evidence(source: .heuristic, title: "\(Product.name)'s installed files changed",
                          detail: lines.joined(separator: "\n"), score: 80)
        return Detection(path: bad.first?.path, name: "Tamper: installed files changed", category: .suspicious,
                         severity: .high, confidence: 80, evidence: [ev])
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

    /// Process that redeemed each uid's session (pid + pidversion from its audit token): a session authorises only
    /// that process, not every program the same user runs during the window (hx10).
    private var sessionOwner: [uid_t: (pid: pid_t, version: UInt32?)] = [:]

    /// True while `peer` holds an admin-authenticated *settings* session opened by this same process; needed for broad
    /// exclusions / folder rules and for protection-weakening calls from the CLI. A pause or uninstall session does not count.
    func hasAuthenticatedSession(_ peer: Peer) -> Bool {
        guard flow?.hasActiveSession(uid: peer.uid, purpose: .settings) ?? false else { return false }
        lock.lock(); defer { lock.unlock() }
        guard let o = sessionOwner[peer.uid] else { return false }
        return Self.sameProcess(owner: o, peer: peer)
    }

    static func sameProcess(owner o: (pid: pid_t, version: UInt32?), peer: Peer) -> Bool {
        IPCAuthz.sameProcess(ownerPID: o.pid, ownerVersion: o.version, pid: peer.pid, version: peer.pidVersion)
    }

    func redeem(_ token: String, peer: Peer, purpose: ProtectionDisableFlow.Purpose, minutes: Int) throws {
        guard let flow else { throw ServiceError.unavailable("tamper protection key") }
        let m = max(1, min(minutes, 24 * 60))
        if case .failure(let f) = flow.redeem(token, peerUID: peer.uid, purpose: purpose, sessionSeconds: Double(m) * 60) {
            throw ServiceError.denied(f.description)
        }
        lock.lock(); sessionOwner[peer.uid] = (peer.pid, peer.pidVersion); lock.unlock()
        if purpose == .pause { lock.lock(); pausedUntil = Date().addingTimeInterval(Double(m) * 60); lock.unlock() }
    }

    // MARK: remote access

    func loadPolicy() -> RemoteAccessPolicy {
        var p = (try? Data(contentsOf: policyURL)).flatMap { try? JSONDecoder.rampart.decode(RemoteAccessPolicy.self, from: $0) } ?? RemoteAccessPolicy()
        p.prune()
        return p
    }
    func savePolicy(_ p: RemoteAccessPolicy) { try? SecureStore.writeJSON(p, to: policyURL) }

    func report() -> RemoteAccessReport { monitor.report(policy: loadPolicy()) }

    /// Team ID of a running process (read-only Security.framework query; never prompts).
    static func teamID(pid: Int32) -> String? {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary, [], &code) == errSecSuccess,
              let code, let id = ClientIdentity.of(code: code), id.valid else { return nil }
        return id.teamID
    }

    /// hx5 N3: `pinCurrentSigners` pins the allowance to the Team IDs of the tool's running processes, so a
    /// look-alike signed by someone else is not covered by it.
    func allow(_ id: String, minutes: Int?, pinCurrentSigners: Bool = false) throws {
        guard let tool = RemoteToolCatalogue.tool(id) else { throw ServiceError.notFound("remote tool \(id)") }
        var pins: [String]? = nil
        if pinCurrentSigners {
            let current = monitor.report(policy: loadPolicy()).findings.filter { $0.toolID == id }.flatMap(\.pids)
            let teams = current.prefix(32).compactMap { Self.teamID(pid: $0) }
            if !teams.isEmpty { pins = teams }
        }
        var p = loadPolicy(); p.allow(tool, minutes: minutes, pinTeamIDs: pins); savePolicy(p)
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
        // At start: anything held from before is decided now, and the install is checked once.
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            for d in self.detector.flushPending(force: true) { self.onDetection?(d) }
            if let d = self.verifyManifest() { self.onDetection?(d) }
        }
        var tick = 0
        t.setEventHandler { [weak self] in
            guard let self else { return }
            tick += 1
            // Update awareness: decide held bundle / plist changes whose grace period is over.
            for d in self.detector.flushPending() { self.onDetection?(d) }
            // Every minute: re-verify the install manifest. (Held changes are decided by flushPending above, which
            // also treats anything past the hold horizon as due; forcing here would cut a legitimate update's grace.)
            if tick % 12 == 0, let d = self.verifyManifest() { self.onDetection?(d) }
            let policy = self.loadPolicy()
            let r = self.monitor.report(policy: policy)
            for d in self.monitor.detections(from: r) { self.onDetection?(d) }
            if !r.activeUnapproved.isEmpty {
                let plan = self.enforcer.plan(report: r, policy: policy, dryRun: !self.enforce)
                if !plan.notes.isEmpty { logInfo("remote-access lockdown\(plan.dryRun ? " (dry run)" : ""): \(LogRedact.clean(plan.notes.joined(separator: "; "), max: 1000))") }
            }
        }
        t.resume(); timer = t
    }
    func stop() { timer?.cancel(); timer = nil }
}

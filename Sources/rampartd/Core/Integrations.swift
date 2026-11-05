import Foundation
import RampartShared
import RampartEngine
import RampartSigning
import RampartRemediation
import RampartNetwork
import RampartPosture

// Wires the library modules into Services. Daemon-only modules (RampartTelemetry: event sources)
// are wired from Sources/rampartd/DaemonWiring.swift through `daemonHook`, because the CLI target
// doesn't link them.

/// Runs an async function to completion from synchronous code (daemon worker threads only).
func runBlocking<T>(_ f: @escaping () async -> T) -> T {
    let sem = DispatchSemaphore(value: 0)
    var out: T?
    Task.detached { out = await f(); sem.signal() }
    sem.wait()
    return out!
}

enum Integrations {
    /// Set by rampartd before `Services.make` to add daemon-only wiring (event sources, behaviour engine).
    static var daemonHook: ((Services, Runtime) -> Void)?
    /// The YARA engine, if wired (for warm-up and status).
    static var lastYara: AnyObject?

    static func wire(_ s: Services, runtime: Runtime, daemon: Bool) {
        var updaters: [(String, () -> String)] = []

        // Engine: hash DB + scan coordinator (+ signing heuristics, YARA).
        var db: HashDatabase?
        do { db = try HashDatabase(url: runtime.databaseDir.appendingPathComponent("rampart.sqlite")) }
        catch { logWarn("hash database unavailable: \(error)") }
        let coord = ScanCoordinator(database: db)
        coord.register(SigningEnricher())
        coord.register(SigningHeuristicDetector())
        var engineNotes = ["eicar", db != nil ? "hash-db" : "no-hash-db", "signing-heuristics"]
        engineNotes += wireYara(coord, runtime: runtime, updaters: &updaters)
        s.warmups += YaraWiring.warmups()
        let engine = EngineScanService(coord: coord, db: db, runtime: runtime)
        s.scanner = engine
        s.wiring = ["scanner: RampartEngine.ScanCoordinator [\(coord.detectorNames.joined(separator: ", "))]"]
        if let db {
            s.allowHooks.append { h in try? db.allow(sha256: h, note: "user allowed") }
            let updater = HashFeedUpdater(database: db)
            updaters.append(("hashes", {
                let r = runBlocking { () -> String in
                    do { let r = try await updater.update(); return "\(r.feed): \(r.stored) stored, \(r.pruned) pruned (sig \(r.signatureVersion))" }
                    catch { return "hash feed failed: \(error)" }
                }
                return r
            }))
        }
        _ = engineNotes

        // Remediation: encrypted vault + process killer.
        do {
            let vault = try QuarantineVault(root: runtime.quarantineDir)
            s.quarantine = VaultQuarantine(vault: vault)
            s.wiring.append("quarantine: RampartRemediation.QuarantineVault (AES-GCM)")
        } catch {
            s.wiring.append("quarantine: builtin vault (QuarantineVault failed: \(error))")
        }
        s.processes = KillerResponder()
        s.wiring.append("process response: RampartRemediation.ProcessKiller")

        // Posture.
        s.posture = PostureAdapter(runtime: runtime)
        s.wiring.append("posture: RampartPosture.PostureScanner + PostureFixer")

        // Persistence (RampartBehaviour.PersistenceScanner when available).
        wireBehaviourPersistence(s, runtime: runtime)

        // Network: DNS filter (off by default) + blocklist updates.
        let lists = BlocklistUpdater(directory: runtime.blocklistDir)
        let web = WebProtection(runtime: runtime, lists: lists)
        s.web = web
        s.wiring.append("web protection: RampartNetwork.DNSFilterServer on 127.0.0.1:\(runtime.dnsPort) (\(runtime.config.webProtection ? "on" : "off"))")
        updaters.append(("blocklists", {
            let r = runBlocking { await lists.updateAll() }
            web.reloadBlocklist()
            return r.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: ", ")
        }))

        s.updater = CompositeUpdater(updaters)
        if daemon { daemonHook?(s, runtime) }
    }

    // MARK: modules that may still be placeholders

    static func wireYara(_ coord: ScanCoordinator, runtime: Runtime, updaters: inout [(String, () -> String)]) -> [String] {
        YaraWiring.wire(coord, runtime: runtime, updaters: &updaters)
    }

    static func wireBehaviourPersistence(_ s: Services, runtime: Runtime) {
        if let p = BehaviourWiring.persistence(runtime: runtime) {
            s.persistence = p
            s.wiring.append("persistence: RampartBehaviour.PersistenceScanner")
        } else {
            s.wiring.append("persistence: builtin launchd enumeration")
        }
    }
}

// MARK: - Adapters

/// Adds signing + provenance facts for executables so the engine's trust prior and detectors can use them.
struct SigningEnricher: FileFactsEnricher {
    func enrich(_ facts: inout FileFacts) {
        guard facts.signing == nil else { return }
        switch facts.kind {
        case .machO, .fatMachO, .appBundle:
            facts.signing = SigningInspector.inspectCached(path: facts.path).info
        default:
            guard facts.isExecutable, facts.kind == .script else { return }
        }
        if facts.quarantineOrigin == nil {
            let prov = Provenance.read(path: facts.path)
            facts.quarantineOrigin = prov.whereFroms.first ?? prov.quarantine?.agentName
        }
    }
}

final class EngineScanService: ScanService {
    let coord: ScanCoordinator
    let db: HashDatabase?
    let runtime: Runtime
    init(coord: ScanCoordinator, db: HashDatabase?, runtime: Runtime) { self.coord = coord; self.db = db; self.runtime = runtime }

    var engineNames: [String] { coord.detectorNames }
    var signatureVersion: String { "\(EngineInfo.version)/\(db?.signatureVersion ?? "nodb")" }

    private func options(for roots: [String]) -> ScanOptions {
        var o = coord.options
        func under(_ p: String, _ prefix: String) -> Bool { p == prefix || p.hasPrefix(prefix.hasSuffix("/") ? prefix : prefix + "/") }
        // Our exclusions, minus those that contain an explicitly requested root (the vault is always excluded).
        let ours = runtime.exclusions.filter { ex in !roots.contains { under($0, ex) } }
        o.walk.excludedPrefixes = Array(Set(WalkOptions.defaultExcludedPrefixes + ours + [runtime.quarantineDir.path]))
        o.walk.maxFileSize = UInt64(runtime.config.maxFileSizeMB) << 20
        o.unpackArchives = runtime.config.scanArchives
        return o
    }

    func scan(paths: [String], progress: @escaping ScanProgress, cancelled: @escaping () -> Bool) -> ScanOutcome {
        let cancel = ScanCancellation()
        let report = coord.scan(paths: paths, options: options(for: paths), cancel: cancel) { p in
            if cancelled() { cancel.cancel() }
            progress(p.scanned, max(p.discovered, p.scanned), p.current)
        }
        return ScanOutcome(scanned: report.scanned, detections: report.detections, seconds: report.seconds, errors: report.errors)
    }

    func scanFile(_ path: String) -> Detection? {
        var o = options(for: [path]); o.unpackDiskImages = false
        guard let d = coord.scanFile(at: path, options: o).detection, d.confidence >= 30 else { return nil }
        return d
    }
}

final class VaultQuarantine: QuarantineService {
    let vault: QuarantineVault
    init(vault: QuarantineVault) { self.vault = vault }
    func list() -> [QuarantineRecord] { vault.list() }
    func quarantine(path: String, detection: Detection) throws -> QuarantineRecord {
        try vault.quarantine(path: path, detectionName: detection.name)
    }
    func restore(id: UUID) throws -> String {
        try vault.restore(id: id, options: QuarantineVault.RestoreOptions(allowlist: false))
    }
    func delete(id: UUID) throws { try vault.delete(id: id) }
    func purgeExpired() { _ = vault.purge(olderThanDays: 30) }
}

final class KillerResponder: ProcessResponder {
    let killer = ProcessKiller()
    func terminate(pid: Int32, expectedPath: String?) -> String {
        guard let ident = ProcessKiller.identity(of: pid) else { return "pid \(pid) already gone" }
        if let exp = expectedPath {
            let actual = ProcessKiller.path(of: pid)
            if !actual.isEmpty && actual != exp && !exp.hasPrefix(actual) && !actual.hasPrefix(exp) {
                return "pid \(pid) now runs \(actual), not \(exp); not killed (pid reuse)"
            }
        }
        let r = killer.killTree(ident, dryRun: false)
        return "killed \(r.killed.count) process(es)\(r.skipped.isEmpty ? "" : "; skipped: \(r.skipped.joined(separator: ", "))")"
    }
}

final class PostureAdapter: PostureService {
    let runtime: Runtime
    init(runtime: Runtime) { self.runtime = runtime }
    func checks() -> [PostureCheck] { PostureScanner().checks() }
    func score(_ checks: [PostureCheck]) -> Int? { SecurityScore.compute(checks).value }
    func fix(checkID: String, dryRun: Bool) throws -> String {
        guard let fix = PostureFixer.fix(for: checkID, dryRun: dryRun) else {
            throw ServiceError.failed("'\(checkID)' has no one-click fix\(PostureFixer.settingsLink(for: checkID).map { "; open \($0)" } ?? "")")
        }
        if dryRun || (fix.requiresRoot && getuid() != 0) {
            throw ServiceError.failed("not running as root; the fix would run:\n\(fix.preview)")
        }
        var out: [String] = []
        for cmd in fix.commands {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: cmd[0]); p.arguments = Array(cmd.dropFirst())
            p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
            try p.run(); p.waitUntilExit()
            out.append("\(cmd.joined(separator: " ")) -> \(p.terminationStatus)")
            if p.terminationStatus != 0 { throw ServiceError.failed("fix failed: \(out.joined(separator: "; "))") }
        }
        // Re-scan to verify the fix took effect.
        let after = PostureScanner().checks().first { $0.id == checkID }
        out.append("re-check: \(after?.state.rawValue ?? "unknown")")
        if after?.state == .fail { throw ServiceError.failed("fix ran but the check still fails: \(out.joined(separator: "; "))") }
        return out.joined(separator: "; ")
    }
}

final class WebProtection: WebProtectionService {
    let runtime: Runtime
    let lists: BlocklistUpdater
    private var server: DNSFilterServer?
    private var switcher: DNSSwitcher?
    private let lock = NSLock()
    init(runtime: Runtime, lists: BlocklistUpdater) { self.runtime = runtime; self.lists = lists }

    var isOn: Bool { lock.lock(); defer { lock.unlock() }; return server?.isRunning ?? false }

    func setOn(_ on: Bool) throws {
        lock.lock(); defer { lock.unlock() }
        if on {
            if server?.isRunning == true { return }
            let srv = DNSFilterServer(config: DNSFilterConfig(port: UInt16(runtime.dnsPort)), blocklist: lists.buildBlocklist())
            srv.queryLog = { e in if e.verdict.rawValue.hasPrefix("block") { logInfo("dns blocked \(e.name) (\(e.listSource ?? "?"))") } }
            try srv.start()
            server = srv
            // Point the system resolver at us only as the real root daemon (never in --user/dev runs).
            if getuid() == 0 && !runtime.userMode {
                let sw = DNSSwitcher(snapshotURL: runtime.root.appendingPathComponent("dns-original.json"), dryRun: false)
                do { _ = try sw.apply(); switcher = sw } catch { logWarn("DNS switch failed: \(error)") }
            }
            logInfo("web protection on (DNS filter 127.0.0.1:\(runtime.dnsPort))")
        } else {
            if let sw = switcher { _ = sw.restore(); switcher = nil }
            server?.stop(); server = nil
            logInfo("web protection off")
        }
    }

    func reloadBlocklist() {
        lock.lock(); defer { lock.unlock() }
        server?.blocklist = lists.buildBlocklist()
    }
}

final class CompositeUpdater: UpdateService {
    let parts: [(String, () -> String)]
    init(_ parts: [(String, () -> String)]) { self.parts = parts }
    func update() -> String { parts.map { "\($0.0): \($0.1())" }.joined(separator: "; ") }
}

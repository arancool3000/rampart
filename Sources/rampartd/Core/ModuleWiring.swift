import Foundation
import RampartShared
import RampartEngine
import RampartYara
import RampartBehaviour
import RampartSigning

// Wiring for RampartYara and RampartBehaviour.

enum YaraWiring {
    /// Registers the YARA engine (Apple XProtect rules compiled in place + Rules/rampart-generic.yar).
    /// Rules compile lazily on first use; the daemon warms them up in the background at start.
    static func wire(_ coord: ScanCoordinator, runtime: Runtime, updaters: inout [(String, () -> String)]) -> [String] {
        let local = runtime.rulesDir.appendingPathComponent("rampart-generic.yar").path
        let yara = YaraEngine(genericRulesPaths: [local] + YaraEngine.defaultGenericPathsPublic)
        coord.register(yara)
        Integrations.lastYara = yara
        updaters.append(("yara", {
            _ = yara.reloadIfNeeded(force: true)
            let st = yara.currentStatus
            return "\(st.stats?.compiled ?? 0) rules (XProtect \(st.xprotectVersion ?? "not found"))"
        }))
        return ["yara"]
    }
    static func warmups() -> [() -> Void] {
        guard let y = Integrations.lastYara as? YaraEngine else { return [] }
        return [{
            let t = Date(); _ = y.reloadIfNeeded()
            let st = y.currentStatus
            logInfo("YARA ready: \(st.stats?.compiled ?? 0) rules compiled, \(st.stats?.skipped ?? 0) skipped, XProtect \(st.xprotectVersion ?? "not found"), \(String(format: "%.1f", Date().timeIntervalSince(t))) s")
        }]
    }
}

extension YaraEngine {
    /// Same candidates YaraEngine uses by default (app Resources/Rules, support folder, source tree).
    static var defaultGenericPathsPublic: [String] {
        var c = [Paths.rulesDir.appendingPathComponent("rampart-generic.yar").path,
                 Paths.effectiveRoot.appendingPathComponent("Rules/rampart-generic.yar").path]
        let exe = URL(fileURLWithPath: CommandLine.arguments.first ?? "").resolvingSymlinksInPath().deletingLastPathComponent()
        c.append(exe.appendingPathComponent("../Resources/Rules/rampart-generic.yar").standardized.path)
        c.append(exe.appendingPathComponent("Rules/rampart-generic.yar").path)
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        c.append(repo.appendingPathComponent("Rules/rampart-generic.yar").path)
        return c
    }
}

enum BehaviourWiring {
    /// One behaviour engine per process, shared by persistence assessment and the real-time pipeline.
    static var engine: BehaviourEngine?

    static func persistence(runtime: Runtime) -> PersistenceService? {
        let signing: SigningProvider = { path in SigningInspector.inspectCached(path: path).info }
        var cfg = BehaviourConfig()
        cfg.learningMode = runtime.config.learningMode
        cfg.developerMode = runtime.config.developerMode
        let e = BehaviourEngine(config: cfg, signing: signing)
        engine = e
        return BehaviourPersistence(runtime: runtime, engine: e, signing: signing)
    }
}

/// Live behaviour-engine controls.
final class BehaviourControlAdapter: BehaviourControl {
    let engine: BehaviourEngine
    init(engine: BehaviourEngine) { self.engine = engine }
    func apply(learningMode: Bool, developerMode: Bool) {
        engine.config.developerMode = developerMode
        if learningMode { engine.config.learningMode = true } else { engine.endLearning() }
    }
    func setAllowRules(_ rules: [AllowRuleSpec]) {
        let entries: [AllowEntry] = rules.compactMap { r in
            switch r.scope {
            case .developer: return AllowEntry(teamID: r.value, note: r.name)
            case .signingID: return AllowEntry(signingID: r.value, note: r.name)
            case .folder: return AllowEntry(pathPrefix: r.value, note: r.name)
            case .fileHash: return nil
            }
        }
        engine.config.allowlist = BehaviourConfig.defaultAllowlist + entries
    }
    // Canary documents are covered by R01 (with atomic-save handling); they are not credential honeytokens.
    var ransomware: RansomwareDetector { engine.ransomware }
}

/// RampartBehaviour.PersistenceScanner + snapshot differ + BehaviourEngine.evaluatePersistence.
final class BehaviourPersistence: PersistenceService {
    let runtime: Runtime
    let engine: BehaviourEngine
    let signing: SigningProvider
    private let lock = NSLock()
    var snapshotURL: URL { runtime.root.appendingPathComponent("persistence-snapshot.json") }
    private var last: [String: PersistenceRecord] = [:]
    private var lastScan = Date.distantPast

    func lookup(id: String) -> PersistenceLookup? {
        lock.lock(); var r = last[id]; let age = Date().timeIntervalSince(lastScan); lock.unlock()
        if r == nil && age > 5 { _ = scan(); lock.lock(); r = last[id]; lock.unlock() }
        return r.map { PersistenceLookup(item: $0.item, attributes: $0.attributes) }
    }

    init(runtime: Runtime, engine: BehaviourEngine, signing: @escaping SigningProvider) {
        self.runtime = runtime; self.engine = engine; self.signing = signing
    }

    func scan() -> (items: [PersistenceItem], findings: [Detection]) {
        lock.lock(); defer { lock.unlock() }
        var records: [PersistenceRecord] = []
        var seen = Set<String>()
        var incomplete = Set<PersistenceItem.Kind>()
        // As root, enumerate every user's home; otherwise just ours. snapshot() records kinds whose
        // enumeration timed out (e.g. a slow `sfltool dumpbtm`) so the differ doesn't report them removed.
        for (i, home) in Util.homeDirectories().enumerated() {
            var c = PersistenceScanConfig(home: home, includeSystemLaunchd: false)
            // Never run anything that can show an authorization dialog without root: `sfltool dumpbtm`
            // asks for an administrator password when not root. BTM items are enumerated by the root daemon.
            // Without root (or with RAMPART_NO_PRIVILEGED_TOOLS) run no external tools at all:
            // sfltool / profiles / systemextensionsctl can show dialogs. Files are still enumerated.
            if getuid() != 0 || Privileged.noPrivilegedTools {
                c.runCommands = false
                c.kinds.subtract([.btm, .loginItem])
                // Not enumerated, so never reported "removed" by the differ.
                incomplete.formUnion([.btm, .loginItem, .profile, .systemExtension, .cron])
            }
            if i > 0 { c.launchDaemonDirs = []; c.launchAgentDirs = [home + "/Library/LaunchAgents"] }  // system dirs once
            let snap = PersistenceScanner(config: c, signing: signing).snapshot()
            incomplete.formUnion(snap.incompleteKinds ?? [])
            for r in snap.records where seen.insert(r.id).inserted { records.append(r) }
        }
        var current = PersistenceSnapshot(records: records)
        current.incompleteKinds = incomplete.isEmpty ? nil : Array(incomplete).sorted { $0.rawValue < $1.rawValue }
        var findings: [Detection] = []
        if let old = try? PersistenceSnapshot.load(from: snapshotURL) {
            let diff = PersistenceDiffer.diff(baseline: old, current: current)
            if !diff.isEmpty {
                findings = PersistenceWiringPolicy.apply(engine.evaluatePersistence(added: diff.added, changed: diff.changed),
                                                      records: diff.added + diff.changed.map(\.new), root: runtime.root)
                logInfo("persistence diff: +\(diff.added.count) ~\(diff.changed.count) -\(diff.removed.count), \(findings.count) finding(s)")
            }
        } else {
            // First run: everything already present is the trusted baseline. Never alert on it; only log
            // an informational review list (items that would have been flagged as new).
            let review = engine.reviewPersistence(records)
            for x in review.prefix(50) { logInfo("persistence baseline review: \(x.finding.ruleID) \(x.record.item.location) (not alerted)") }
            logInfo("persistence baseline: \(records.count) items trusted, \(review.count) listed for optional review")
            findings = []
        }
        last = Dictionary(records.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a }); lastScan = Date()
        do { try current.save(to: snapshotURL) } catch { logWarn("persistence snapshot save failed: \(error)") }
        return (records.map(\.item), findings)
    }
}

extension BehaviourWiring {
    /// Hooks the behaviour engine into the real-time pipeline. Returns a note for the wiring log.
    static func attach(_ pipeline: RealtimePipeline, services: Services, runtime: Runtime) -> String {
        guard let e = engine else { return "" }
        // Never flag Rampart's own binaries (dev builds live in hidden .build folders).
        let own = [URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent().path + "/",
                   "/Applications/Rampart.app/", "/Library/PrivilegedHelperTools/app.rampart."]
        let root = runtime.root
        pipeline.behaviour = { ev in
            e.process(ev).filter { d in !own.contains { p in d.path?.hasPrefix(p) == true } }.compactMap { d in
                // Launch-item findings in real time get the same policy as the persistence scan.
                guard let p = d.path, p.hasSuffix(".plist"), p.contains("/LaunchAgents/") || p.contains("/LaunchDaemons/") else { return d }
                let kind: PersistenceItem.Kind = p.contains("/LaunchDaemons/") ? .launchDaemon : .launchAgent
                guard let r = PersistenceScanner.parseLaunchdPlist(path: p, kind: kind) else { return d }
                return PersistenceWiringPolicy.apply([d], records: [r], root: root).first
            }
        }
        return " + RampartBehaviour.BehaviourEngine"
    }
}

enum PersistenceWiringPolicy {
    /// Own plists pointing at our verified binary are dropped; benign user agents become notes (LaunchItemPolicy).
    static func apply(_ ds: [Detection], records: [PersistenceRecord], root: URL) -> [Detection] {
        guard !ds.isEmpty else { return ds }
        let pins = LaunchItemPolicy.trustedCDHashes(root: root)
        var byPath: [String: PersistenceRecord] = [:]
        for r in records { byPath[r.item.location] = r; if let t = r.item.target { byPath[t] = byPath[t] ?? r } }
        return ds.compactMap { d in
            // Login items: resolve `btm:<uid>:<uuid>` to the real program and signer; only real indicators are threats.
            if let p = d.path, let r = byPath[p], [.btm, .loginItem].contains(r.item.kind) {
                let home = Util.homeDirectories().first { r.item.target?.hasPrefix($0 + "/") == true } ?? Util.homeDirectories().first ?? "/nonexistent"
                return LaunchItemPolicy.applyLoginItem(d, record: r, home: home, signing: r.item.signing)
            }
            guard let p = d.path, let r = byPath[p], [.launchAgent, .launchDaemon].contains(r.item.kind) else { return d }
            if LaunchItemPolicy.isGenuineOwnPlist(r.item.location, trustedCDHashes: pins, ownTeamID: nil) { return nil }
            let home = Util.homeDirectories().first { r.item.location.hasPrefix($0 + "/") } ?? "/nonexistent"
            if LaunchItemPolicy.isBenignUserAgent(plist: r.item.location, target: r.item.target, arguments: r.arguments, home: home) {
                return LaunchItemPolicy.asNote(d)
            }
            return d
        }
    }
}

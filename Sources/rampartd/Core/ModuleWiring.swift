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
        let e = BehaviourEngine(signing: signing)
        engine = e
        return BehaviourPersistence(runtime: runtime, engine: e, signing: signing)
    }
}

/// RampartBehaviour.PersistenceScanner + snapshot differ + BehaviourEngine.evaluatePersistence.
final class BehaviourPersistence: PersistenceService {
    let runtime: Runtime
    let engine: BehaviourEngine
    let signing: SigningProvider
    private let lock = NSLock()
    var snapshotURL: URL { runtime.root.appendingPathComponent("persistence-snapshot.json") }

    init(runtime: Runtime, engine: BehaviourEngine, signing: @escaping SigningProvider) {
        self.runtime = runtime; self.engine = engine; self.signing = signing
    }

    func scan() -> (items: [PersistenceItem], findings: [Detection]) {
        lock.lock(); defer { lock.unlock() }
        var records: [PersistenceRecord] = []
        var seen = Set<String>()
        // As root, enumerate every user's home; otherwise just ours.
        for (i, home) in Util.homeDirectories().enumerated() {
            let cfg = PersistenceScanConfig(home: home, includeSystemLaunchd: false)
            var c = cfg
            if i > 0 { c.launchDaemonDirs = []; c.launchAgentDirs = [home + "/Library/LaunchAgents"] }  // system dirs once
            for r in PersistenceScanner(config: c, signing: signing).scanRecords() where seen.insert(r.id).inserted { records.append(r) }
        }
        let current = PersistenceSnapshot(records: records)
        var findings: [Detection] = []
        if let old = try? PersistenceSnapshot.load(from: snapshotURL) {
            let diff = PersistenceDiffer.diff(baseline: old, current: current)
            if !diff.isEmpty {
                findings = engine.evaluatePersistence(added: diff.added, changed: diff.changed)
                logInfo("persistence diff: +\(diff.added.count) ~\(diff.changed.count) -\(diff.removed.count), \(findings.count) finding(s)")
            }
        } else {
            // First run: assess everything once so pre-existing risky items surface.
            findings = engine.evaluatePersistence(added: records)
            logInfo("persistence baseline: \(records.count) items, \(findings.count) finding(s)")
        }
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
        pipeline.behaviour = { ev in
            e.process(ev).filter { d in !own.contains { p in d.path?.hasPrefix(p) == true } }
        }
        return " + RampartBehaviour.BehaviourEngine"
    }
}

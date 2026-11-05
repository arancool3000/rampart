import Foundation
import RampartShared

/// `FileDetector` that runs Apple's XProtect YARA rules (read in place, never copied) plus
/// Rampart's generic rules through the native Swift YARA engine.
public final class YaraEngine: FileDetector, @unchecked Sendable {
    public let name = "yara"

    public struct Status: Sendable {
        public var xprotectPath: String?
        public var xprotectVersion: String?
        public var genericRulesPath: String?
        public var stats: YaraCompileStats?
        public var loadedAt: Date?
    }

    /// Externals the generic rules may reference; set per file from `FileFacts`.
    public static let externalDefaults: [String: YaraExternal] = [
        "filepath": .string(""), "filename": .string(""), "extension": .string(""),
        "is_executable": .bool(false), "sig_state": .string("unknown"),
    ]

    public let options: YaraScanOptions
    private let xprotectRoots: [String]
    private let genericCandidates: [String]
    private let lock = NSLock()
    private var rules: YaraRules?
    private var status = Status()
    private var lastVersionCheck = Date.distantPast
    public var versionCheckInterval: TimeInterval = 300
    private let log = RLog.logger("yara")

    public init(xprotectRoots: [String] = Paths.xprotectBundles, genericRulesPaths: [String]? = nil,
                options: YaraScanOptions = .init()) {
        self.xprotectRoots = xprotectRoots
        self.options = options
        self.genericCandidates = genericRulesPaths ?? YaraEngine.defaultGenericPaths()
    }

    static func defaultGenericPaths() -> [String] {
        var c = [
            Paths.rulesDir.appendingPathComponent("rampart-generic.yar").path,
            Paths.effectiveRoot.appendingPathComponent("Rules/rampart-generic.yar").path,
        ]
        let exe = URL(fileURLWithPath: CommandLine.arguments.first ?? "").resolvingSymlinksInPath().deletingLastPathComponent()
        c.append(exe.appendingPathComponent("../Resources/Rules/rampart-generic.yar").standardized.path)
        c.append(exe.appendingPathComponent("Rules/rampart-generic.yar").path)
        // Development fallback: the source tree this file was compiled from.
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        c.append(repo.appendingPathComponent("Rules/rampart-generic.yar").path)
        return c
    }

    // MARK: Loading

    /// Picks the XProtect bundle with the highest version that has a readable XProtect.yara.
    public static func locateXProtect(_ roots: [String]) -> (path: String, version: String)? {
        var best: (String, String, Int)?
        for r in roots {
            guard FileManager.default.isReadableFile(atPath: r + "/XProtect.yara") else { continue }
            let v = bundleVersion(r) ?? "0"
            let num = Int(v) ?? 0
            if best == nil || num > best!.2 { best = (r, v, num) }
        }
        return best.map { ($0.0, $0.1) }
    }

    static func bundleVersion(_ resources: String) -> String? {
        let plist = URL(fileURLWithPath: resources).deletingLastPathComponent().appendingPathComponent("Info.plist")
        guard let d = try? Data(contentsOf: plist),
              let p = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] else { return nil }
        return (p["CFBundleShortVersionString"] as? String) ?? (p["CFBundleVersion"] as? String)
    }

    /// Compiles (or recompiles) all rule sources. Safe to call concurrently with scans.
    @discardableResult
    public func load() -> Status {
        var sources: [YaraSource] = []
        var st = Status()
        if let xp = YaraEngine.locateXProtect(xprotectRoots) {
            st.xprotectPath = xp.path; st.xprotectVersion = xp.version
            for file in ["XProtect.yara", "XPScripts.yr"] {
                if let t = try? String(contentsOfFile: xp.path + "/" + file, encoding: .utf8) {
                    sources.append(YaraSource(namespace: "xprotect:" + file, text: t))
                }
            }
        }
        for g in genericCandidates where FileManager.default.isReadableFile(atPath: g) {
            if let t = try? String(contentsOfFile: g, encoding: .utf8) {
                sources.append(YaraSource(namespace: "rampart", text: t)); st.genericRulesPath = g
                break
            }
        }
        let compiled = YaraRules.compile(sources, externals: YaraEngine.externalDefaults)
        st.stats = compiled.stats; st.loadedAt = Date()
        lock.lock(); rules = compiled; status = st; lastVersionCheck = Date(); lock.unlock()
        log.info("YARA loaded: \(compiled.stats.compiled) rules, \(compiled.stats.skipped) skipped, XProtect \(st.xprotectVersion ?? "none")")
        return st
    }

    /// Recompiles when the XProtect bundle version changed. Returns true if it reloaded.
    @discardableResult
    public func reloadIfNeeded(force: Bool = false) -> Bool {
        lock.lock()
        let loaded = rules != nil
        let due = force || Date().timeIntervalSince(lastVersionCheck) > versionCheckInterval
        let current = status.xprotectVersion
        if due { lastVersionCheck = Date() }
        lock.unlock()
        if !loaded { load(); return true }
        guard due else { return false }
        let now = YaraEngine.locateXProtect(xprotectRoots)?.version
        if now != current { load(); return true }
        return false
    }

    public var currentStatus: Status { lock.lock(); defer { lock.unlock() }; return status }
    public var compiledRules: YaraRules? { lock.lock(); defer { lock.unlock() }; return rules }

    // MARK: Scanning

    public func scan(path: String, facts: FileFacts? = nil) -> YaraScanResult {
        reloadIfNeeded()
        guard let r = compiledRules else { return YaraScanResult(matches: [], timedOut: false, skippedReason: "no rules", bytesScanned: 0, seconds: 0) }
        return r.scanFile(atPath: path, options: options, externals: YaraEngine.externals(for: facts, path: path))
    }

    static func externals(for facts: FileFacts?, path: String) -> [String: YaraExternal] {
        let url = URL(fileURLWithPath: path)
        var e: [String: YaraExternal] = [
            "filepath": .string(path), "filename": .string(url.lastPathComponent), "extension": .string(url.pathExtension.lowercased()),
        ]
        if let f = facts {
            e["is_executable"] = .bool(f.isExecutable)
            if let s = f.signing { e["sig_state"] = .string(s.status.rawValue) }
        }
        return e
    }

    public func inspect(_ facts: FileFacts) -> [Evidence] {
        let res = scan(path: facts.path, facts: facts)
        let version = currentStatus.xprotectVersion ?? "?"
        return res.matches.map { YaraEngine.evidence(for: $0, xprotectVersion: version) }
    }

    // MARK: Naming

    public struct Classification: Sendable {
        public var detectionName: String
        public var category: ThreatCategory
        public var severity: Severity
        public var score: Int
        public var source: DetectionSource
    }

    /// Maps a rule match to a Detection name/category/score.
    public static func classify(_ m: YaraMatch) -> Classification {
        if m.namespace.hasPrefix("xprotect") {
            // Prefer Apple's description ("MACOS.ADLOAD.D"), else the rule name minus the XProtect_ prefix.
            var base = m.meta["description"] ?? m.rule
            for p in ["XProtect_", "XPROTECT_", "Xprotect_"] where base.hasPrefix(p) { base = String(base.dropFirst(p.count)) }
            base = base.replacingOccurrences(of: "_", with: ".")
            let upper = base.uppercased()
            let hunt = upper.hasPrefix("HUNT.") || m.rule.uppercased().contains("HUNT")
            let cat = category(for: upper)
            let name = "XProtect." + base
            if hunt { return Classification(detectionName: name, category: .suspicious, severity: .medium, score: 75, source: .xprotect) }
            let sev: Severity = (cat == .adware || cat == .pua) ? .high : .critical
            return Classification(detectionName: name, category: cat, severity: sev, score: 97, source: .xprotect)
        }
        let score = Int(m.meta["score"] ?? "") ?? 50
        let cat = ThreatCategory(rawValue: m.meta["category"] ?? "") ?? .suspicious
        let name = m.meta["detection"] ?? m.rule.replacingOccurrences(of: "_", with: "-")
        let sev: Severity = cat == .test ? .low : (score >= 90 ? .critical : score >= 60 ? .high : score >= 30 ? .medium : .low)
        return Classification(detectionName: name, category: cat, severity: sev, score: score, source: .yara)
    }

    static func category(for upper: String) -> ThreatCategory {
        let table: [(ThreatCategory, [String])] = [
            (.ransomware, ["RANSOM", "EVILQUEST", "LOCKBIT", "KEROBEROS"]),
            (.miner, ["MINING", "MINER", "HMINING", "XMRIG", "COINMINER"]),
            (.infostealer, ["STEAL", "AMOS", "ATOMIC", "POSEIDON", "BANSHEE", "CUTHWULF", "METASTEALER", "CUCKOO", "SOMA",
                            "REALST", "KEYSTEAL", "RODRIGO", "CALISTO", "ODYSSEY", "MACSYNC", "PHEXIA", "FROST"]),
            (.adware, ["ADLOAD", "PIRRIT", "BUNDLORE", "ADPLUGIN", "GENIEO", "MAXOFFERS", "VSEARCH", "SHLAYER", "SLEEPYSTEGOSAURUS",
                       "CRAPYRATOR", "ADWARE", "SURFBUDDY", "DOLITTLE", "TUBEFUSE", "SPIGOT"]),
            (.backdoor, ["BACKDOOR", "RAT", "DOK", "KEYRANGER", "XAGENT", "WINDTAIL", "CREATIVEUPDATE", "GOLDDIGGER", "RUSTBUCKET",
                         "SMOOTHOPERATOR", "COLDROOT", "OCEANLOTUS", "LAZARUS", "NUKESPED", "KANDYKORN", "SNOWDRIFT", "NIMBLERAT"]),
        ]
        let words = Set(upper.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init))
        for (cat, keys) in table {
            for k in keys where words.contains(k) || (k.count >= 5 && upper.contains(k)) { return cat }
        }
        return .malware
    }

    public static func evidence(for m: YaraMatch, xprotectVersion: String) -> Evidence {
        let c = classify(m)
        let strs = m.strings.prefix(6).map { "\($0.identifier)@0x\(String($0.offset, radix: 16))" }.joined(separator: ", ")
        let detail: String
        if c.source == .xprotect {
            detail = "Matched Apple XProtect rule \(m.rule) (XProtect \(xprotectVersion))" + (strs.isEmpty ? "" : "; strings: \(strs)")
        } else {
            detail = "Matched Rampart rule \(m.rule)" + (m.meta["description"].map { ": \($0)" } ?? "") + (strs.isEmpty ? "" : "; strings: \(strs)")
        }
        return Evidence(source: c.source, title: c.detectionName, detail: detail, score: c.score)
    }
}

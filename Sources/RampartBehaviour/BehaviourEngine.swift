import Foundation
import RampartShared

public struct BehaviourConfig: Sendable {
    /// Learning mode (doc 05 §12.4): rules not marked alwaysActive only record observations and build a
    /// per-machine baseline; after learning, baselined (rule, identity) pairs are scored ×0.25.
    public var learningMode = false
    public var developerMode = true
    public var allowlist: [AllowEntry] = BehaviourConfig.defaultAllowlist
    public var dedupeWindow: TimeInterval = 600
    public var storyTTL: TimeInterval = 1800
    public var chainWindow: TimeInterval = 600
    public var logThreshold = 30
    public var alertThreshold = 60
    public var criticalThreshold = 90
    /// Decoy credential files (R39).
    public var honeytokens: Set<String> = []
    /// Team IDs already present (from the persistence baseline) for R26.
    public var knownTeamIDs: Set<String> = []
    /// Apply the first-seen ×1.2 multiplier once the engine has watched this long.
    public var firstSeenWarmup: TimeInterval = 3600
    /// How long a risky browser clipboard copy stays armed for R31 token matching.
    public var clipboardWindow: TimeInterval = 600
    /// Salt for clipboard token hashes; must match the producer (default: per-boot salt).
    public var clipboardSalt: String = ClipboardFingerprint.bootSalt
    public var beaconMinSamples = 6
    public var beaconMinSpan: TimeInterval = 1800
    public var beaconMaxCV = 0.1
    /// Names that end a story walk: the story root is the child of the first of these in the chain.
    public var sessionRoots: [String] = ["launchd", "kernel_task", "Finder", "Dock", "loginwindow", "WindowServer", "login",
                                        "Terminal", "iTerm2", "iTerm", "Warp", "WezTerm", "wezterm-gui", "Alacritty", "kitty",
                                        "Ghostty", "Hyper", "tmux", "screen", "sshd", "sshd-session"]

    public static let defaultAllowlist: [AllowEntry] = [
        AllowEntry(pathPrefix: "/opt/homebrew/", weakOnly: true, note: "Homebrew toolchain"),
        AllowEntry(pathPrefix: "/usr/local/Homebrew/", weakOnly: true, note: "Homebrew toolchain (Intel)"),
        AllowEntry(pathPrefix: "/Library/Developer/CommandLineTools/", weakOnly: true, note: "Command Line Tools"),
    ]
    public init() {}
}

/// A rule hit recorded while in learning mode (telemetry only).
public struct BehaviourObservation: Codable, Sendable {
    public var date: Date
    public var ruleID: String
    public var identity: String
    public var detail: String
}

/// Read-only view of one story (scored process lineage).
public struct StorySnapshot: Sendable {
    public var key: String
    public var score: Int
    public var ruleIDs: [String]
    public var detectionID: UUID
}

/// Behavioural engine: consumes SecurityEvents, keeps process lineage, evaluates the data-driven rule set and
/// built-in detectors, scores per story (doc 05 §12) and returns Detections with explanatory Evidence.
public final class BehaviourEngine: @unchecked Sendable {
    public let rules: RuleSet
    public var config: BehaviourConfig
    public let tracker = ProcessTracker()
    public let ransomware: RansomwareDetector
    public private(set) var observations: [BehaviourObservation] = []
    public var onObservation: (@Sendable (BehaviourObservation) -> Void)?

    private let trustEval: TrustEvaluator
    private let ruleByID: [String: Rule]
    private let matchRules: [Rule]
    /// Decoys each pid has touched (R39 calm path for a user opening one decoy).
    var honeyTouches: [Int32: Set<String>] = [:]
    private var stories: [String: Story] = [:]
    private var marks: [String: [Mark]] = [:]
    private var thresholds: [String: [(Date, String)]] = [:]
    private var firstSeenKeys: Set<String> = []
    private var imageFirstSeen: [String: Date] = [:]
    private var connected: Set<String> = []
    private var beacons: [String: [Date]] = [:]
    private var beaconFired: Set<String> = []
    private var rcCache: [String: Set<String>] = [:]
    private var clipboards: [(date: Date, tokens: Set<String>, source: String, verdict: String?)] = []
    private var learned: Set<String> = []
    private var startDate: Date?
    private let lock = NSRecursiveLock()

    public init(rules: RuleSet = .default, config: BehaviourConfig = BehaviourConfig(), signing: SigningProvider? = nil,
                ransomware: RansomwareDetector = RansomwareDetector()) {
        self.rules = rules; self.config = config; self.ransomware = ransomware
        self.trustEval = TrustEvaluator(provider: signing)
        self.ruleByID = Dictionary(rules.rules.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        self.matchRules = rules.rules.filter { $0.isEnabled && !($0.matchers ?? []).isEmpty }
        for p in PersistenceScanner.rcFiles(home: PathUtil.home) { seedShellRC(p) }
    }

    // MARK: public API

    /// Feeds one event. Returns new or escalated detections (same `id` for one story as it escalates).
    public func process(_ e: SecurityEvent) -> [Detection] {
        lock.lock(); defer { lock.unlock() }
        if startDate == nil { startDate = e.date }
        let node = tracker.observe(e)
        if ProcessTracker.isExit(e) { return [] }
        let ctx = Context(engine: self, event: e, node: node)
        var hits: [PendingHit] = []
        recordClipboard(e)

        for rule in matchRules {
            for m in rule.matchers ?? [] where matches(m, rule: rule, ctx) {
                if let s = m.setMark { setMark(s, ctx) }
                if rule.type != .marker { hits.append(PendingHit(rule: rule, ctx: ctx, facts: matchFacts(m, ctx))) }
                break
            }
        }
        hits += builtins(ctx)
        var out: [Detection] = []
        for h in hits { if let d = apply(h) { out.append(d) } }
        expireStories(now: e.date)
        capState(now: e.date)
        return dedupe(out)
    }

    /// wms-o6: every per-key table is bounded, so an event flood with endless distinct pids, paths or stories can't
    /// grow the engine's memory without limit (the tables are caches; losing old entries only loses old context).
    public static let maxTableEntries = 20_000
    func capState(now: Date) {
        let cap = Self.maxTableEntries
        if thresholds.count > cap {
            let maxWin = 3600.0
            thresholds = thresholds.filter { !$0.value.isEmpty && now.timeIntervalSince($0.value.last!.0) < maxWin }
            if thresholds.count > cap { thresholds.removeAll(keepingCapacity: true) }
        }
        if firstSeenKeys.count > cap * 5 { firstSeenKeys.removeAll(keepingCapacity: true) }
        if imageFirstSeen.count > cap * 2 { imageFirstSeen.removeAll(keepingCapacity: true) }
        if connected.count > cap * 2 { connected.removeAll(keepingCapacity: true) }
        if beacons.count > cap { beacons.removeAll(keepingCapacity: true); beaconFired.removeAll(keepingCapacity: true) }
        if beaconFired.count > cap { beaconFired.removeAll(keepingCapacity: true) }
        if marks.count > cap { marks = marks.filter { !$0.value.isEmpty } }
        if stories.count > cap {
            stories = stories.filter { now.timeIntervalSince($0.value.lastActivity) < config.storyTTL }
            if stories.count > cap {
                let keep = stories.values.sorted { $0.lastActivity > $1.lastActivity }.prefix(cap * 3 / 4)
                stories = Dictionary(uniqueKeysWithValues: keep.map { ($0.key, $0) })
            }
        }
    }

    /// Sizes of the internal tables (tests / diagnostics).
    public var stateSizes: [String: Int] {
        lock.lock(); defer { lock.unlock() }
        return ["thresholds": thresholds.count, "stories": stories.count, "firstSeenKeys": firstSeenKeys.count,
                "imageFirstSeen": imageFirstSeen.count, "connected": connected.count, "beacons": beacons.count]
    }

    /// Assesses records without scoring or touching story state (baseline review lists).
    public func reviewPersistence(_ records: [PersistenceRecord]) -> [(record: PersistenceRecord, finding: PersistenceFinding)] {
        lock.lock(); defer { lock.unlock() }
        let assessor = PersistenceAssessor(trust: { [trustEval] in trustEval.trust(path: $0) }, knownTeamIDs: config.knownTeamIDs)
        return records.flatMap { r in assessor.assess(r).map { (r, $0) } }
    }

    /// Scores persistence records found by a scheduled scan (added and changed items from the differ).
    public func evaluatePersistence(added: [PersistenceRecord], changed: [PersistenceChange] = [], date: Date = Date()) -> [Detection] {
        lock.lock(); defer { lock.unlock() }
        var out: [Detection] = []
        let assessor = PersistenceAssessor(trust: { [trustEval] in trustEval.trust(path: $0) }, knownTeamIDs: config.knownTeamIDs)
        let items = added.map { ($0, nil as PersistenceRecord?) } + changed.map { ($0.new, Optional($0.old)) }
        for (r, prev) in items {
            let ev = PersistenceDiffer.event(for: r, kind: .persistenceAdded, date: date, changed: prev != nil)
            let ctx = Context(engine: self, event: ev, node: nil)
            for f in assessor.assess(r, previous: prev) {
                guard let rule = ruleByID[f.ruleID], rule.isEnabled else { continue }
                var h = PendingHit(rule: rule, ctx: ctx, facts: f.detail)
                h.storyKey = "persist:" + r.id; h.targetPath = f.targetPath; h.subjectLabel = r.item.location
                h.source = .persistence
                if let d = apply(h) { out.append(d) }
            }
        }
        return dedupe(out)
    }

    /// Adds a scoped exception (e.g. from a user "allow" decision).
    public func allow(_ entry: AllowEntry) { lock.lock(); config.allowlist.append(entry); lock.unlock() }

    /// Remembers the current lines of a shell startup file so later additions can be diffed (R12).
    public func seedShellRC(_ path: String) {
        guard let s = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        lock.lock(); rcCache[PathUtil.canonical(path)] = Set(s.components(separatedBy: "\n")); lock.unlock()
    }

    public func stories(now: Date = Date()) -> [StorySnapshot] {
        lock.lock(); defer { lock.unlock() }
        return stories.values.map { StorySnapshot(key: $0.key, score: score($0, now: now).0, ruleIDs: Array($0.hits.keys).sorted(), detectionID: $0.detectionID) }
    }

    /// Ends learning mode; baselined pairs keep a ×0.25 weight.
    public func endLearning() { lock.lock(); config.learningMode = false; lock.unlock() }

    // MARK: context

    struct Context {
        let event: SecurityEvent
        let node: ProcessNode?
        let chain: [ProcessNode]          // ancestors, nearest first
        let argv: String
        let storyKey: String
        let imagePath: String?
        init(engine: BehaviourEngine, event: SecurityEvent, node: ProcessNode?) {
            self.event = event; self.node = node
            let chain = node.map { engine.tracker.ancestors(of: $0) } ?? []
            self.chain = chain
            self.argv = node?.argvText ?? (event.process.map { ArgvText.normalise($0.args) } ?? "")
            self.imagePath = node?.path ?? event.process?.path
            self.storyKey = engine.storyKey(node: node, chain: chain, event: event)
        }
        var names: [String] { ([node].compactMap { $0 } + chain).map(\.name) }
    }

    func storyKey(node: ProcessNode?, chain: [ProcessNode], event: SecurityEvent) -> String {
        guard let node else {
            if event.kind == .persistenceAdded || event.kind == .persistenceRemoved { return "persist:" + (event.path ?? "?") }
            return "fs"
        }
        let all = [node] + chain
        for (i, n) in all.enumerated() where nameIn(n.name, config.sessionRoots) || nameIn(n.name, rules.lists["browsers"] ?? []) {
            return "p:" + (i == 0 ? n.key : all[i - 1].key).description
        }
        return "p:" + (all.last ?? node).key.description
    }

    // MARK: clipboard

    func recordClipboard(_ e: SecurityEvent) {
        guard e.kind == .other, e.detail["type"] == "clipboard", e.detail["class"] == "risky",
              let tok = e.detail["clip_tokens"], !tok.isEmpty else { return }
        let src = e.detail["source_app"] ?? ""
        // PasteGuard-rated copies (detail["paste_verdict"]) arm R31 whatever app they came from.
        let verdict = e.detail["paste_verdict"].flatMap { ["suspicious", "malicious"].contains($0) ? $0 : nil }
        guard verdict != nil || anyRegex(["@browserRegex"], src) else { return }
        clipboards = clipboards.filter { e.date.timeIntervalSince($0.date) <= config.clipboardWindow }
        clipboards.append((e.date, ClipboardFingerprint.parse(tok), src.isEmpty ? "an app" : src, verdict))
    }

    /// Best overlap between the current command and an armed clipboard copy.
    func clipboardMatch(_ ctx: Context, min: Double) -> (Double, Int, String, String?)? {
        let now = ctx.event.date
        var best: (Double, Int, String, String?)?
        // Telemetry's ClipboardMemory (keyed HMAC, daemon-private key) already matched this exec to a recent copy.
        if ctx.event.detail["clipboard_match"] == "1", let o = Double(ctx.event.detail["clipboard_overlap"] ?? ""), o >= min,
           let cls = ctx.event.detail["clipboard_class"], cls == "risky",
           let app = ctx.event.detail["clipboard_source_app"], anyRegex(["@browserRegex"], app) {
            best = (o, 2, app, nil)
        }
        for c in clipboards where now.timeIntervalSince(c.date) <= config.clipboardWindow && now >= c.date {
            let o = ClipboardFingerprint.overlap(command: ctx.argv, clip: c.tokens, salt: config.clipboardSalt)
            if o.fraction >= min && o.shared >= 2 && o.distinctive >= 1 && o.fraction > (best?.0 ?? -1) { best = (o.fraction, o.shared, c.source, c.verdict) }
        }
        return best
    }

    // MARK: matching

    func nameIn(_ name: String, _ patterns: [String]) -> Bool {
        let pats = rules.expand(patterns) ?? []
        return pats.contains { RegexCache.shared.fullMatch($0, name) }
    }

    func anyRegex(_ patterns: [String]?, _ s: String) -> Bool {
        (rules.expand(patterns) ?? []).contains { RegexCache.shared.matches($0, s) }
    }

    func trustOf(_ n: ProcessNode) -> TrustClass {
        if let t = n.trust { return t }
        let t = trustEval.trust(path: n.path, platformHint: n.isPlatformBinary, teamID: n.teamID, tierHint: n.tierHint)
        n.trust = t
        return t
    }

    func isUntrusted(_ n: ProcessNode) -> Bool {
        if isAllowlisted(node: n, rule: nil) { return false }
        let t = trustOf(n)
        return t.isUntrusted || (t == .unknown && PathClass.classify(n.path).isSuspiciousLocation)
    }

    func activeMarks(_ name: String, window: TimeInterval?, now: Date) -> [Mark] {
        (marks[name] ?? []).filter { now.timeIntervalSince($0.date) <= (window ?? $0.window) && now >= $0.date.addingTimeInterval(-1) }
    }

    func lineageUntrusted(_ ctx: Context) -> Bool {
        let nodes = [ctx.node].compactMap { $0 } + ctx.chain
        if nodes.contains(where: isUntrusted) { return true }
        let now = ctx.event.date
        if activeMarks("entry", window: nil, now: now).contains(where: { $0.story == ctx.storyKey }) { return true }
        return !activeMarks("pasteEntry", window: nil, now: now).isEmpty && ctx.chain.contains { nameIn($0.name, ["@terminals"]) }
    }

    /// Positive name match on a node: its file name, or the name its Apple signature was shipped under (renamed copies).
    func nodeNameIn(_ n: ProcessNode, _ patterns: [String]) -> Bool {
        nameIn(n.name, patterns) || (n.shippedName.map { nameIn($0, patterns) } ?? false)
    }

    func matches(_ m: Matcher, rule: Rule, _ ctx: Context) -> Bool {
        let e = ctx.event
        if let k = m.kinds, !k.contains(e.kind) { return false }
        let pname = ctx.node?.name ?? e.process.map { PathUtil.basename($0.path) }
        let shipped = ctx.node?.shippedName ?? e.process.flatMap { ProcessNode.shippedName(path: $0.path, signingID: $0.signingID, isPlatformBinary: $0.isPlatformBinary) }
        if let p = m.process {
            guard let pname, nameIn(pname, p) || (shipped.map { nameIn($0, p) } ?? false) else { return false }
        }
        // Exclusions use the real file name only: a shipped-name alias must never make something exempt.
        if let p = m.processNot, let pname, nameIn(pname, p) { return false }
        if let p = m.processPath { guard let ip = ctx.imagePath, anyRegex(p, ip) else { return false } }
        if let a = m.args { for p in rules.expand(a) ?? [] where !RegexCache.shared.matches(p, ctx.argv) { return false } }
        if let a = m.argsAny, !anyRegex(a, ctx.argv) { return false }
        if let a = m.argsNot, anyRegex(a, ctx.argv) { return false }
        let paths = [e.path, e.destPath].compactMap { $0 }
        if let p = m.path { guard paths.contains(where: { anyRegex(p, $0) }) else { return false } }
        if let p = m.pathNot, paths.contains(where: { anyRegex(p, $0) }) { return false }
        if let pc = m.pathClass {
            let subject = e.kind == .exec ? (ctx.imagePath ?? e.path) : e.path
            guard let s = subject, pc.contains(PathClass.classify(s)) else { return false }
        }
        if let d = m.detail {
            for (k, p) in d { guard let v = e.detail[k], RegexCache.shared.matches(p, v) else { return false } }
        }
        if let d = m.detailNot {
            for (k, p) in d { if let v = e.detail[k], RegexCache.shared.matches(p, v) { return false } }
        }
        if let p = m.parent { guard let par = ctx.chain.first, nodeNameIn(par, p) else { return false } }
        if let a = m.ancestor { guard ctx.chain.contains(where: { nodeNameIn($0, a) }) else { return false } }
        if let a = m.ancestorNot, ctx.chain.contains(where: { nameIn($0.name, a) }) { return false }
        if let s = m.sibling {
            guard let n = ctx.node else { return false }
            let sibs = tracker.siblings(of: n, within: m.siblingWindow ?? 3).filter { nodeNameIn($0, s) }
            let ok = sibs.contains { sib in !(m.siblingArgsNot.map { anyRegex($0, sib.argvText) } ?? false) }
            if !ok { return false }
        }
        if let t = m.trust {
            guard let n = ctx.node else { return false }
            switch t {
            case .untrusted: if !isUntrusted(n) { return false }
            case .nonApple: if trustOf(n) == .apple { return false }
            }
        }
        if m.lineageUntrusted == true && !lineageUntrusted(ctx) { return false }
        if let r = m.requireMark, !markSatisfied(r, ctx) { return false }
        if m.quarantined == true {
            guard let ip = ctx.imagePath else { return false }
            let q = e.detail["quarantined"] == "1" || getxattr(ip, "com.apple.quarantine", nil, 0, 0, 0) >= 0
            if !q { return false }
        }
        if let min = m.storyMinScore {
            guard let st = stories[ctx.storyKey], score(st, now: e.date).0 >= min else { return false }
        }
        if let f = m.clipboardOverlap, clipboardMatch(ctx, min: f) == nil { return false }
        if m.firstSeen == true {
            let k = rule.id + "|" + (ctx.imagePath ?? "")
            if firstSeenKeys.contains(k) { return false }
            firstSeenKeys.insert(k)
        }
        if let th = m.threshold {
            let group: String
            switch th.groupBy ?? .story {
            case .story: group = ctx.storyKey
            case .actor: group = ctx.imagePath ?? ctx.storyKey
            case .global: group = "*"
            }
            let key = rule.id + "|" + group
            let value: String
            switch th.distinct {
            case "path": value = e.path ?? ""
            case "dir": value = PathUtil.dirname(e.path ?? "")
            case "process": value = pname ?? ""
            case "args": value = ctx.argv
            case let s? where s.hasPrefix("detail:"): value = e.detail[String(s.dropFirst(7))] ?? ""
            default: value = UUID().uuidString
            }
            var list = (thresholds[key] ?? []).filter { e.date.timeIntervalSince($0.0) <= th.window }
            list.append((e.date, value))
            thresholds[key] = list
            if Set(list.map(\.1)).count < th.count { return false }
            thresholds[key] = []
        }
        return true
    }

    struct Mark { var value: String; var story: String; var date: Date; var window: TimeInterval }

    func setMark(_ s: MarkSpec, _ ctx: Context) {
        let w = s.window ?? 600
        var values: [String] = []
        switch s.from {
        case .args: values = PathUtil.pathArgs(ctx.node?.args ?? ctx.event.process?.args ?? [], cwd: ctx.node?.cwd ?? ctx.event.detail["cwd"])
        case .path: values = [ctx.event.path].compactMap { $0 }.map(PathUtil.canonical)
        case .actorPath: values = [ctx.imagePath].compactMap { $0 }
        case .story: values = [ctx.storyKey]
        case .global: values = ["*"]
        }
        let tooBroad: Set<String> = ["/", "/Users", "/Applications", "/tmp", "/private/tmp", "/var/folders", PathUtil.home, "/Library"]
        for v in values where v == "*" || (!tooBroad.contains(v) && v.count >= 2) {
            var list = (marks[s.name] ?? []).filter { ctx.event.date.timeIntervalSince($0.date) <= $0.window }
            list.append(Mark(value: v, story: ctx.storyKey, date: ctx.event.date, window: w))
            if list.count > 500 { list.removeFirst(list.count - 500) }
            marks[s.name] = list
        }
    }

    func markSatisfied(_ r: MarkRequirement, _ ctx: Context) -> Bool {
        let ms = activeMarks(r.name, window: r.window, now: ctx.event.date)
        guard !ms.isEmpty else { return false }
        func under(_ p: String, _ v: String) -> Bool { p == v || p.hasPrefix(v.hasSuffix("/") ? v : v + "/") }
        switch r.scope {
        case .global: return true
        case .story: return ms.contains { $0.story == ctx.storyKey }
        case .execPath:
            guard ctx.event.kind == .exec, let p = ctx.imagePath.map(PathUtil.canonical) else { return false }
            return ms.contains { under(p, $0.value) }
        case .eventPath:
            guard let p = ctx.event.path.map(PathUtil.canonical) else { return false }
            return ms.contains { under(p, $0.value) }
        case .argPath:
            let args = PathUtil.pathArgs(ctx.node?.args ?? [], cwd: ctx.node?.cwd)
            return ms.contains { m in ctx.argv.contains(m.value) || args.contains { under($0, m.value) } }
        }
    }

    func matchFacts(_ m: Matcher, _ ctx: Context) -> String {
        var f: [String] = []
        if let r = m.requireMark { f.append("follows earlier '\(r.name)' activity") }
        if let t = m.threshold { f.append("\(t.count)+ distinct events within \(Int(t.window)) s") }
        if let s = m.sibling, !s.isEmpty { f.append("piped from a sibling downloader") }
        if let o = m.clipboardOverlap, let c = clipboardMatch(ctx, min: o) {
            f.append("\(Int((c.0 * 100).rounded()))% of the command's tokens (\(c.1)) match a risky command copied from \(c.2)")
        }
        if m.quarantined == true { f.append("binary still carries the download quarantine flag") }
        if let s = m.storyMinScore { f.append("story already scored \(s)+ from other rules") }
        return f.joined(separator: "; ")
    }

    // MARK: built-ins

    /// The user's own signed GUI app (an .app bundle, not root, not unsigned/ad-hoc).
    func isTrustedGUIActor(_ ctx: Context) -> Bool {
        guard let ip = ctx.imagePath, ip.contains(".app/Contents/MacOS/") else { return false }
        if let uid = ctx.event.process?.uid, uid < 500 { return false }
        let t = trustEval.trust(path: ip, platformHint: ctx.event.process?.isPlatformBinary ?? false,
                                teamID: ctx.event.process?.teamID, tierHint: ctx.event.detail["signing"])
        return !t.isUntrusted
    }

    func builtins(_ ctx: Context) -> [PendingHit] {
        let e = ctx.event
        var out: [PendingHit] = []
        func hit(_ id: String, _ facts: String, story: String? = nil, target: String? = nil, label: String? = nil,
                 source: DetectionSource = .behaviour) {
            guard let r = ruleByID[id], r.isEnabled else { return }
            var h = PendingHit(rule: r, ctx: ctx, facts: facts)
            if let story { h.storyKey = story }
            h.targetPath = target; h.subjectLabel = label; h.source = source
            out.append(h)
        }
        let paths = [e.path, e.destPath].compactMap { $0 }.map(PathUtil.canonical)

        // Ransomware family (file events).
        if [.fileWrite, .fileCreate, .fileClose, .fileRename, .fileDelete].contains(e.kind) {
            let key = ctx.node != nil ? ctx.storyKey : "fs"
            for r in ransomware.observe(e, actorKey: key, trustedGUIActor: isTrustedGUIActor(ctx)) { hit(r.ruleID, r.detail, target: r.path, label: r.path) }
        }
        let atomicSave = e.kind == .fileRename && paths.contains(where: RansomwareDetector.isAtomicSaveTemp)
            && (isTrustedGUIActor(ctx) || e.process == nil)
        // R39 honeytokens.
        if !config.honeytokens.isEmpty {
            let tokens = Set(config.honeytokens.map(PathUtil.canonical))
            if let t = paths.first(where: { tokens.contains($0) }), e.kind != .exec, !atomicSave {
                // The user opening one decoy in a trusted GUI app (TextEdit, Preview) is not an infostealer: no alarm
                // here; the Cat & Mouse service records a calm note (mirrors DeceptionUserOpen.isCalm).
                let pid = e.process?.pid ?? 0
                if pid > 0 { var set = honeyTouches[pid] ?? []; set.insert(t); honeyTouches[pid] = set; if honeyTouches.count > 512 { honeyTouches.removeAll() } }
                let isRead = (e.kind == .fileClose && e.detail["modified"] == "0") || e.detail["es_event"] == "open"
                if !(isRead && isTrustedGUIActor(ctx) && (honeyTouches[pid]?.count ?? 0) <= 1) {
                    hit("R39", "Decoy \(PathUtil.basename(t)) touched (\(e.kind.rawValue)).", label: t)
                }
            } else if e.kind == .exec, let t = tokens.first(where: { ctx.argv.contains($0) }) {
                hit("R39", "Command line references decoy \(PathUtil.basename(t)).", label: t)
            }
        }
        // Persistence additions (event-driven).
        if e.kind == .persistenceAdded, let r = PersistenceDiffer.record(from: e) {
            let assessor = PersistenceAssessor(trust: { [trustEval] in trustEval.trust(path: $0) }, knownTeamIDs: config.knownTeamIDs)
            for f in assessor.assess(r) where !(f.ruleID == "R11" && e.detail["persistence_kind"] == nil) {
                hit(f.ruleID, f.detail, story: ctx.node == nil ? "persist:" + r.id : nil, target: f.targetPath, label: r.item.location,
                    source: .persistence)
            }
        }
        if [.fileCreate, .fileWrite, .fileRename, .fileClose].contains(e.kind), e.kind != .fileClose || e.detail["modified"] != "0" {
            let p = PathUtil.canonical(e.destPath ?? e.path ?? "")
            let assessor = PersistenceAssessor(trust: { [trustEval] in trustEval.trust(path: $0) }, knownTeamIDs: config.knownTeamIDs)
            if p.hasSuffix(".plist"), p.contains("/LaunchAgents/") || p.contains("/LaunchDaemons/"),
               let r = PersistenceScanner.parseLaunchdPlist(path: p, kind: p.contains("/LaunchDaemons/") ? .launchDaemon : .launchAgent) {
                for f in assessor.assess(r) { hit(f.ruleID, f.detail, target: f.targetPath, label: p, source: .persistence) }
            }
            if p.hasSuffix(".json"), p.contains("/NativeMessagingHosts/"), let r = PersistenceScanner.parseNativeHost(path: p) {
                for f in assessor.assess(r) { hit(f.ruleID, f.detail, target: f.targetPath, label: p, source: .persistence) }
            }
            // R12 shell rc additions.
            let base = PathUtil.basename(p)
            if [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".bash_profile", ".bashrc", ".bash_login", ".profile"].contains(base)
                || ["/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/profile", "/etc/bashrc"].contains(p)
                || (p.contains("/fish/") && base.hasSuffix(".fish") && (base == "config.fish" || p.contains("/conf.d/"))) {  // wms-o10
                var added: [String] = []
                if let a = e.detail["added_lines"] { added = a.components(separatedBy: "\n") }
                else if let s = try? String(contentsOfFile: p, encoding: .utf8) {
                    let lines = s.components(separatedBy: "\n")
                    if let prev = rcCache[p] { added = lines.filter { !prev.contains($0) } }
                    rcCache[p] = Set(lines)
                }
                for l in added {
                    let line = l.trimmingCharacters(in: .whitespaces)
                    guard !line.hasPrefix("#"), let why = PersistenceScanner.shellLineReason(line) else { continue }
                    hit("R12", "\(p) gained a line that \(why): \(line.prefix(200))", label: p, source: .persistence)
                    break
                }
            }
        }
        // R58 self-deleting binary.
        if e.kind == .fileDelete, let p = e.path {
            for n in tracker.liveNodes(image: p) where isUntrusted(n) {
                let c = Context(engine: self, event: SecurityEvent(date: e.date, kind: .other, process: nil, path: p, source: e.source), node: n)
                if let r = ruleByID["R58"] {
                    var h = PendingHit(rule: r, ctx: c, facts: "pid \(n.pid) is still running from \(p), which was just deleted.")
                    h.targetPath = p
                    out.append(h)
                }
                break
            }
        }
        // EV1 / EV3 (wms-o6): renamed or relocated Apple tools, and programs dressed up as system processes.
        if e.kind == .exec, let n = ctx.node {
            let appleSigned = trustEval.isAppleSigned(path: n.path, platformHint: n.isPlatformBinary)
            if appleSigned, PathClass.isRelocatedAppleToolPath(n.path), !isAllowlisted(node: n, rule: ruleByID["EV1"]) {
                let shipped = n.shippedName.map { " (it ships as \($0))" } ?? ""
                hit("EV1", "An Apple-signed tool runs from \(n.path)\(shipped), outside the system folders.", label: n.path)
            }
            if !appleSigned, let why = Self.systemNameDisguise(path: n.path, argv0: n.args.first) {
                hit("EV3", why, label: n.path)
            }
        }
        // R41 first connection / R46 beaconing.
        if e.kind == .networkConnect, let n = ctx.node, e.detail["listen"] != "1" {
            let ip = e.detail["remote_ip"] ?? e.detail["remote"] ?? ""
            if !ip.isEmpty && !Self.isPrivateIP(ip) && isUntrusted(n) {
                if connected.insert(n.path).inserted {
                    hit("R41", "\(n.path) connected to \(ip)\(e.detail["remote_port"].map { ":" + $0 } ?? "") for the first time.")
                }
                let key = n.path + "|" + ip
                var times = (beacons[key] ?? []) + [e.date]
                if times.count > 64 { times.removeFirst(times.count - 64) }
                beacons[key] = times
                if times.count >= config.beaconMinSamples, let f = times.first, let l = times.last,
                   l.timeIntervalSince(f) >= config.beaconMinSpan, !beaconFired.contains(key) {
                    let gaps = zip(times.dropFirst(), times).map { $0.timeIntervalSince($1) }
                    let mean = gaps.reduce(0, +) / Double(gaps.count)
                    let sd = sqrt(gaps.map { pow($0 - mean, 2) }.reduce(0, +) / Double(gaps.count))
                    if mean > 0 && sd / mean <= config.beaconMaxCV {
                        beaconFired.insert(key)
                        hit("R46", "\(times.count) connections to \(ip) every \(Int(mean)) s (jitter \(String(format: "%.0f", 100 * sd / mean))%) over \(Int(l.timeIntervalSince(f) / 60)) min.")
                    }
                }
            }
        }
        return out
    }

    /// Names of macOS system processes that malware borrows to hide in process lists (T1036.004/.005).
    static let systemProcessNames: Set<String> = [
        "launchd", "kernel_task", "windowserver", "loginwindow", "mds", "mds_stores", "mdworker", "mdworker_shared",
        "softwareupdated", "softwareupdate", "syspolicyd", "trustd", "cfprefsd", "distnoted", "coreaudiod", "bluetoothd",
        "airportd", "xprotect", "xprotectservice", "coreservicesd", "securityd", "syslogd", "logd", "notifyd",
        "configd", "sharingd", "systemuiserver", "controlcenter", "coreservicesuiagent", "nsurlsessiond", "rapportd",
        "usernoted", "usereventagent", "diskarbitrationd", "fseventsd", "opendirectoryd", "powerd", "tccd", "amfid",
        "apsd", "cloudd", "accountsd", "sysmond", "kextd", "spindump", "secd", "runningboardd",
        "xpcproxy", "launchservicesd",
    ]

    /// Why a non-Apple program looks disguised as a system process, or nil.
    static func systemNameDisguise(path: String, argv0: String?) -> String? {
        let base = PathUtil.basename(path)
        let lower = base.lowercased()
        let sysDir = PathClass.classify(path) == .system
        if !sysDir, systemProcessNames.contains(lower) || (lower.hasPrefix("com.apple.") && !path.contains(".app/Contents/")) {
            // A same-named app bundle in /Applications (e.g. a third-party "Dock" utility) is not a disguise.
            if !(path.hasPrefix("/Applications/") && path.contains(".app/Contents/MacOS/")) {
                return "A non-Apple program named \"\(base)\" runs from \(path), outside the system folders, under a macOS process name."
            }
        }
        if let a0 = argv0, !a0.isEmpty {
            let raw = a0.hasPrefix("-") ? String(a0.dropFirst()) : a0
            let n0 = PathUtil.basename(raw)
            let l0 = n0.lowercased()
            if l0 != lower, systemProcessNames.contains(l0) || (l0.hasPrefix("com.apple.") && l0.count > 10) {
                return "\(path) started with argv[0] \"\(String(n0.prefix(80)))\", the name of a macOS system process, so it shows up as that in process lists."
            }
        }
        return nil
    }

    static func isPrivateIP(_ ip: String) -> Bool {
        if ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("127.") || ip.hasPrefix("169.254.") || ip == "::1"
            || ip.lowercased().hasPrefix("fe80") || ip.lowercased().hasPrefix("fd") || ip.hasPrefix("0.") { return true }
        if ip.hasPrefix("172."), let s = ip.split(separator: ".").dropFirst().first.flatMap({ Int($0) }), (16...31).contains(s) { return true }
        if ip.hasPrefix("100."), let s = ip.split(separator: ".").dropFirst().first.flatMap({ Int($0) }), (64...127).contains(s) { return true }
        return false
    }

    // MARK: scoring

    struct PendingHit {
        var rule: Rule
        var ctx: Context
        var facts: String
        var storyKey: String
        var targetPath: String?
        var subjectLabel: String?
        var source: DetectionSource = .behaviour
        init(rule: Rule, ctx: Context, facts: String) {
            self.rule = rule; self.ctx = ctx; self.facts = facts; self.storyKey = ctx.storyKey
        }
    }

    struct Hit {
        var rule: Rule
        var score: Int
        var first: Date
        var last: Date
        var evidence: Evidence
    }

    final class Story {
        let key: String
        let detectionID = UUID()
        var hits: [String: Hit] = [:]
        var lastActivity: Date
        var emittedLevel = 0
        var emittedRules: Set<String> = []
        var pid: Int32?
        var path: String?
        init(key: String, date: Date) { self.key = key; self.lastActivity = date }
    }

    /// Credential-theft and exfiltration rules that the built-in toolchain allows (Homebrew, Command Line Tools)
    /// never hide: a compromised npm/pip/brew package runs under those interpreters (X6 B-X6-1).
    static let toolchainNeverHides: Set<String> = ["R30", "R36", "R37", "R37b", "R37S", "R38", "R39", "R42", "R42D", "R43", "R43C",
                                                   "R44", "R45", "R59", "R59R", "R60", "R60W", "R62", "L11"]

    /// A path allow broader than one user-owned subfolder (e.g. "/", "/Users/", "~", "~/Downloads/", "/Applications/").
    public static func isBroadPrefix(_ prefix: String) -> Bool {
        let comps = prefix.split(separator: "/").filter { !$0.isEmpty }
        if comps.isEmpty { return true }
        if comps.first == "Users" || comps.first == "private" { return comps.count <= 3 }
        return comps.count <= 1
    }

    func isAllowlisted(node: ProcessNode?, rule: Rule?, path: String? = nil) -> Bool {
        for a in config.allowlist {
            if let ids = a.ruleIDs, let r = rule, !ids.contains(r.id) { continue }
            if a.ruleIDs != nil && rule == nil { continue }
            if a.weakOnly == true, let r = rule, r.type == .strong { continue }
            let builtinToolchain = BehaviourConfig.defaultAllowlist.contains(a)
            // Built-in toolchain allows only quiet build/dev noise, never credential theft or exfiltration.
            if builtinToolchain, let r = rule, Self.toolchainNeverHides.contains(r.id) { continue }
            if let p = a.pathPrefix, !builtinToolchain, a.ruleIDs == nil {
                // A broad folder allow (home, a top-level folder) is never honoured, whatever it says.
                if Self.isBroadPrefix(p) { continue }
                // User folder allows are weak-only unless they explicitly opt out (weakOnly: false).
                if a.teamID == nil, a.signingID == nil, a.weakOnly == nil, let r = rule, r.type == .strong { continue }
            }
            // Always-on strong rules (password-dialog lures, keychain/credential theft, kill chains…) can't be
            // silenced by a broad Team-ID, signing-ID or folder allow. Only an allow that names the rule ID can.
            if let r = rule, r.alwaysActive == true, r.type == .strong, a.ruleIDs == nil { continue }
            var ok = a.teamID != nil || a.signingID != nil || a.pathPrefix != nil
            if let t = a.teamID { ok = ok && node?.teamID == t }
            if let s = a.signingID { ok = ok && node?.signingID == s }
            if let p = a.pathPrefix { ok = ok && ((node?.path ?? path)?.hasPrefix(p) ?? false) }
            if ok { return true }
        }
        return false
    }

    /// Returns (multiplier, explanation, identity used for learning).
    func multiplier(_ h: PendingHit) -> (Double, [String], String) {
        let rule = h.rule
        var m = 1.0
        var why: [String] = []
        var identity = h.ctx.imagePath ?? h.targetPath ?? h.subjectLabel ?? "?"
        func apply(trust t: TrustClass, path: String, label: String) {
            if t != .unknown && t.multiplier != 1.0 { m *= t.multiplier; why.append("\(label) \(t.rawValue) ×\(t.multiplier)") }
            if PathClass.classify(path).isSuspiciousLocation { m *= 1.3; why.append("\(label) in \(PathClass.classify(path).rawValue) folder ×1.3") }
        }
        switch rule.subject ?? .actor {
        case .actor:
            if let n = h.ctx.node { apply(trust: trustOf(n), path: n.path, label: "program"); identity = n.teamID ?? n.signingID ?? n.path }
        case .target:
            if let t = h.targetPath, t.hasPrefix("/") {
                // R07 on an Apple target only fires for inline downloaded/encoded code: the interpreter's signature
                // says nothing about that code, so it earns no "Apple" discount.
                let tt = trustEval.trust(path: t)
                if !(rule.id == "R07" && tt == .apple) { apply(trust: tt, path: t, label: "target") }
                identity = t
            }
        case .none:
            break
        case .lineage:
            let nodes = [h.ctx.node].compactMap { $0 } + h.ctx.chain
            if let n = h.ctx.node, trustOf(n) != .apple, !isAllowlisted(node: n, rule: nil) {
                apply(trust: trustOf(n), path: n.path, label: "program"); identity = n.teamID ?? n.path
            } else if let worst = nodes.filter({ isUntrusted($0) }).max(by: { trustOf($0).multiplier < trustOf($1).multiplier }) {
                apply(trust: trustOf(worst), path: worst.path, label: "ancestor \(worst.name)"); identity = worst.teamID ?? worst.path
            }
        }
        if let n = h.ctx.node, let start = startDate, h.ctx.event.date.timeIntervalSince(start) > config.firstSeenWarmup {
            let first = imageFirstSeen[n.path] ?? h.ctx.event.date
            imageFirstSeen[n.path] = first
            if h.ctx.event.date.timeIntervalSince(first) < 3600 && trustOf(n) != .apple { m *= 1.2; why.append("first seen < 1 h ×1.2") }
        }
        let names = h.ctx.names
        // "Typed by hand" discount: not when the session shows a paste from the web (pasteEntry), and not while a
        // risky command copied from a browser is armed (riskyClipboard): then the terminal activity may be pasted.
        if let f = rule.interactiveFactor, h.ctx.chain.contains(where: { nameIn($0.name, ["@terminals"]) }),
           activeMarks("pasteEntry", window: nil, now: h.ctx.event.date).isEmpty,
           activeMarks("riskyClipboard", window: nil, now: h.ctx.event.date).isEmpty {
            m *= f; why.append("typed in an interactive terminal ×\(f)")
        }
        if rule.devSensitive == true && config.developerMode && names.dropFirst().contains(where: { nameIn($0, ["@devtools"]) }) {
            m *= 0.5; why.append("developer toolchain in lineage ×0.5")
        }
        if rule.id == "R31", let v = clipboardMatch(h.ctx, min: 0.6)?.3 {
            m *= 1.3; why.append("PasteGuard rated the copied command \(v) ×1.3")
        }
        if learned.contains(rule.id + "|" + identity) { m *= 0.25; why.append("seen during learning ×0.25") }
        return (m, why, identity)
    }

    func apply(_ h: PendingHit) -> Detection? {
        let rule = h.rule
        let nodes = [h.ctx.node].compactMap { $0 } + (rule.subject == .lineage ? h.ctx.chain : [])
        if nodes.contains(where: { isAllowlisted(node: $0, rule: rule) }) { return nil }
        if h.ctx.node == nil, isAllowlisted(node: nil, rule: rule, path: h.targetPath ?? h.subjectLabel) { return nil }
        let (mult, multWhy, identity) = multiplier(h)
        var eff = Int(min(100, (Double(rule.score) * mult).rounded()))
        if rule.id == "R07L" { eff = min(eff, 25) }   // log-only by design: never escalated by context multipliers
        guard eff > 0 else { return nil }
        let evidence = Evidence(source: h.source, title: "\(rule.id) \(rule.name)", detail: explain(h, multWhy: multWhy), score: eff)
        let now = h.ctx.event.date

        if config.learningMode && rule.alwaysActive != true {
            learned.insert(rule.id + "|" + identity)
            let o = BehaviourObservation(date: now, ruleID: rule.id, identity: identity, detail: evidence.detail)
            observations.append(o)
            if observations.count > 5000 { observations.removeFirst(1000) }
            onObservation?(o)
            return nil
        }

        let story = stories[h.storyKey] ?? Story(key: h.storyKey, date: now)
        stories[h.storyKey] = story
        story.lastActivity = max(story.lastActivity, now)
        if story.pid == nil { story.pid = h.ctx.node?.pid }
        if story.path == nil || h.source == .persistence { story.path = h.subjectLabel ?? h.targetPath ?? h.ctx.imagePath }
        if let old = story.hits[rule.id], now.timeIntervalSince(old.last) < config.dedupeWindow {
            // Count each rule once per story per window; keep the stronger evidence.
            if eff > old.score { story.hits[rule.id] = Hit(rule: rule, score: eff, first: old.first, last: now, evidence: evidence) }
        } else {
            story.hits[rule.id] = Hit(rule: rule, score: eff, first: now, last: now, evidence: evidence)
        }

        // R40 stealer chain: ≥3 distinct kill-chain stages within the chain window.
        let stages = Set(story.hits.values.filter { now.timeIntervalSince($0.last) <= config.chainWindow }.compactMap { $0.rule.stage?.chainOrder })
        if stages.count >= 3, story.hits["R40"] == nil, let r40 = ruleByID["R40"], r40.isEnabled {
            let names = story.hits.values.filter { $0.rule.stage?.chainOrder != nil }.sorted { $0.first < $1.first }
                .map { "\($0.rule.id) (\($0.rule.stage!.rawValue))" }
            let ev = Evidence(source: .behaviour, title: "R40 \(r40.name)",
                              detail: r40.why + " Stages seen: " + names.joined(separator: " → ") + ".", score: r40.score)
            story.hits["R40"] = Hit(rule: r40, score: r40.score, first: now, last: now, evidence: ev)
        }
        return emitIfNeeded(story, now: now)
    }

    func explain(_ h: PendingHit, multWhy: [String]) -> String {
        var parts = [h.rule.why]
        if !h.facts.isEmpty { parts.append(h.facts) }
        if let n = h.ctx.node {
            var s = "Process: \(n.path) (pid \(n.pid), \(trustOf(n).rawValue))"
            let a = n.argvText
            if a.count > 0 && a != n.path { s += ", command: \(a.prefix(300))" }
            parts.append(s)
            if !h.ctx.chain.isEmpty {
                parts.append("Started by: " + h.ctx.chain.prefix(6).map { "\($0.name) (\($0.pid))" }.joined(separator: " ← "))
            }
        }
        if let p = h.ctx.event.path, h.ctx.event.kind != .exec { parts.append("File: \(p)" + (h.ctx.event.destPath.map { " → \($0)" } ?? "")) }
        if !multWhy.isEmpty { parts.append("Weighting: " + multWhy.joined(separator: ", ")) }
        return parts.joined(separator: ". ").replacingOccurrences(of: "..", with: ".")
    }

    func score(_ s: Story, now: Date) -> (Int, Bool) {
        var prod = 1.0
        for h in s.hits.values {
            var v = Double(h.score)
            if let hl = h.rule.effectiveHalfLife { v *= pow(0.5, max(0, now.timeIntervalSince(h.last)) / hl) }
            prod *= (1 - min(100, v) / 100)
        }
        var total = 100 * (1 - prod)
        // Sequence bonus: longest run of kill-chain stages in time order, +15 per consecutive stage.
        let staged = s.hits.values.filter { $0.rule.stage?.chainOrder != nil && now.timeIntervalSince($0.last) <= config.chainWindow }
            .sorted { $0.first < $1.first }.compactMap { $0.rule.stage?.chainOrder }
        var best = [Int](repeating: 1, count: staged.count)
        for i in staged.indices { for j in 0..<i where staged[j] < staged[i] { best[i] = max(best[i], best[j] + 1) } }
        let run = best.max() ?? 0
        if run >= 2 { total += Double(15 * (run - 1)) }
        // One weak signal alone never alerts.
        let onlyWeak = s.hits.count == 1 && s.hits.values.first!.rule.type == .weak
        if onlyWeak { total = min(total, Double(config.alertThreshold - 1)) }
        return (Int(min(100, total.rounded())), onlyWeak)
    }

    func level(_ score: Int) -> Int {
        score >= config.criticalThreshold ? 3 : score >= config.alertThreshold ? 2 : score >= config.logThreshold ? 1 : 0
    }

    func emitIfNeeded(_ s: Story, now: Date) -> Detection? {
        let (sc, _) = score(s, now: now)
        let lv = level(sc)
        let newRules = Set(s.hits.keys).subtracting(s.emittedRules)
        guard lv > s.emittedLevel || (lv >= 2 && !newRules.isEmpty) else { return nil }
        s.emittedLevel = max(s.emittedLevel, lv); s.emittedRules = Set(s.hits.keys)
        let ordered = s.hits.values.sorted { $0.score > $1.score }
        let top = s.hits["R40"] ?? ordered.first!
        let severity: Severity = sc >= config.criticalThreshold ? .critical : sc >= 75 ? .high : sc >= config.alertThreshold ? .medium : sc >= config.logThreshold ? .low : .info
        return Detection(id: s.detectionID, date: now, path: s.path, pid: s.pid, name: top.rule.name, category: top.rule.category,
                         severity: severity, confidence: sc, evidence: ordered.map(\.evidence))
    }

    func expireStories(now: Date) {
        guard stories.count > 64 || Int(now.timeIntervalSince1970) % 30 == 0 else { return }
        stories = stories.filter { now.timeIntervalSince($0.value.lastActivity) < config.storyTTL }
    }

    func dedupe(_ ds: [Detection]) -> [Detection] {
        var seen: [UUID: Int] = [:]
        var out: [Detection] = []
        for d in ds {
            if let i = seen[d.id] { if d.confidence >= out[i].confidence { out[i] = d } } else { seen[d.id] = out.count; out.append(d) }
        }
        return out
    }
}

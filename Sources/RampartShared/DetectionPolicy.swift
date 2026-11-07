import Foundation

// Signal-to-noise policy (user complaint 2026-11-07: "too overconfident, reports way too much; I will miss something").
// One pure, shared policy decides how sure RamPart is about a finding, where it is shown, and whether it may be acted
// on automatically. The daemon applies it before storing (and when re-evaluating an upgraded store); the app applies the
// same functions for display, so an older store renders correctly too.
//
//  - Confirmed: definitive evidence only: known-bad hash, an Apple XProtect match, one of our vetted YARA rules on a
//    non-test file, an Apple-revoked signature, or the confirmed stealer chain (R40).
//  - Likely: two or more independent signals, or one strong behaviour/persistence rule. No heuristic exceeds 89 %,
//    and an uncorroborated one never exceeds 70 %.
//  - Possible: a single heuristic (content, signing, one rule), or anything in a developer / own / test context.
//  - Informational: below the log threshold.
//
// Tiers: "Needs you" = Likely or Confirmed and still open; "Handled automatically" = quarantined or resolved;
// "FYI" = everything else (Possible, Informational, test files, health conditions, unresolvable login items).
// Only Confirmed, or Likely with corroboration, may be remediated automatically (quarantine, kill, emergency).

public enum ConfidenceLevel: Int, Codable, Comparable, Sendable, CaseIterable {
    case informational = 0, possible, likely, confirmed
    public static func < (a: ConfidenceLevel, b: ConfidenceLevel) -> Bool { a.rawValue < b.rawValue }
    public var label: String { ["Informational", "Possible", "Likely", "Confirmed"][rawValue] }
    public var explanation: String {
        switch self {
        case .confirmed: return "Confirmed: matched a known threat (signature, Apple XProtect or a confirmed attack chain)."
        case .likely: return "Likely: more than one independent warning sign, or one strong one. Review it."
        case .possible: return "Possible: a single warning sign with nothing to confirm it. Often harmless."
        case .informational: return "Informational: logged for reference, no action needed."
        }
    }
}

public enum DetectionTier: String, Codable, Sendable, CaseIterable {
    case needsYou, handled, fyi
    public var title: String {
        switch self { case .needsYou: return "Needs you"; case .handled: return "Handled automatically"; case .fyi: return "FYI" }
    }
}

public struct DetectionAssessment: Equatable, Sendable {
    public var level: ConfidenceLevel
    /// Calibrated confidence (what is stored and shown).
    public var confidence: Int
    /// The engine's confidence before calibration.
    public var rawConfidence: Int
    public var definitive: Bool
    /// Independent signal families (e.g. "content", "signature", "rule:R07", "network").
    public var signalFamilies: Set<String>
    /// Why the finding is discounted (developer build, RamPart's own component, user opened a bait file...).
    public var benignContext: String?
    /// Why the finding is never a decision (test file, health condition, unresolvable login item).
    public var fyiReason: String?
    public var corroborated: Bool { signalFamilies.count >= 2 }
    /// Confirmed, or Likely with an independent second signal and a strong raw score.
    public var autoRemediate: Bool
}

public enum DetectionPolicy {
    /// Bump when these rules change so stored detections are re-evaluated.
    public static let version = 1
    /// A single uncorroborated heuristic never shows more than this.
    public static let heuristicCap = 70
    /// Corroborated heuristics stay below "Confirmed".
    public static let corroboratedCap = 89
    /// Developer builds, RamPart's own components, a bait file the user opened.
    public static let benignContextCap = 45
    public static let likelyThreshold = 60
    public static let logThreshold = 30
    /// Raw score a corroborated (not definitive) finding needs before anything is done automatically.
    public static let autoRemediateRaw = 90
    /// One behaviour / persistence rule this strong (raw) is "Likely" even alone (still capped at 70 %).
    public static let strongSingleRule = 85
    public static let calibrationTitle = "How sure RamPart is"
    public static let recheckedReason = "Re-checked with improved rules: not a threat"

    // MARK: evidence

    /// Behaviour / persistence rule id from an evidence title ("R07 New launch item..." -> "R07").
    public static func ruleID(_ e: Evidence) -> String? {
        guard let first = e.title.split(separator: " ").first.map(String.init), (2...5).contains(first.count),
              first.first?.isUppercase == true, first.contains(where: \.isNumber),
              first.allSatisfy({ $0.isUppercase || $0.isNumber }) else { return nil }
        return first
    }

    /// Explanatory evidence that carries no weight.
    public static func isContextOnly(_ e: Evidence) -> Bool {
        e.score <= 0 || e.title == "Note" || e.title == "Why this matters" || e.title == calibrationTitle
    }

    public static func isRevoked(_ e: Evidence) -> Bool {
        guard e.source == .signing else { return false }
        let t = (e.title + " " + e.detail).lowercased()
        guard t.contains("revoked") else { return false }
        return !(t.contains("not revoked") || t.contains("no revoked") || t.contains("isn't revoked") || t.contains("unrevoked"))
    }

    static func isTestEvidence(_ e: Evidence) -> Bool {
        let t = (e.title + " " + e.detail).lowercased()
        return t.contains("eicar") || t.contains("com.rampart.test")
    }

    /// Definitive evidence: known-bad hash, Apple XProtect, a vetted YARA rule (not a test signature), an Apple-revoked
    /// signature, or the confirmed stealer chain.
    public static func isDefinitive(_ e: Evidence) -> Bool {
        guard !isContextOnly(e), e.score >= 90, !isTestEvidence(e) else { return false }
        switch e.source {
        case .hash, .xprotect, .yara: return true
        case .signing: return isRevoked(e)
        case .behaviour, .persistence: return ruleID(e) == "R40"
        default: return false
        }
    }

    /// The independent signal family a piece of evidence belongs to, or nil if it is only context.
    /// All content heuristics of one file are one family; weak signing facts (ad-hoc, unsigned, broken) are context,
    /// never corroboration; each behaviour / persistence rule is its own observation.
    public static func family(_ e: Evidence) -> String? {
        guard !isContextOnly(e), e.score >= 20 else { return nil }
        switch e.source {
        case .hash, .xprotect, .yara: return "signature"
        case .signing: return isRevoked(e) || e.score >= 60 ? "signing" : nil
        case .heuristic: return "content"
        case .behaviour, .persistence: return "rule:" + (ruleID(e) ?? e.title)
        case .network: return "network"
        case .posture: return nil
        }
    }

    // MARK: context

    static let devMarkers = ["/.build/", "/.build-", "/DerivedData/", "/node_modules/", "/target/debug/", "/target/release/",
                             "/.cargo/", "/go/pkg/", "/.rustup/", "/.swiftpm/", "/Library/Developer/"]
    static let devRoots = ["Rampart", "Code", "Developer", "Projects", "src", "dev", "repos", "git", "go", "GitHub", "workspace"]

    /// Paths of RamPart's own installed components (root-owned or inside our bundle).
    public static func isOwnComponentPath(_ p: String) -> Bool {
        ["/Applications/RamPart.app/", "/Applications/Rampart.app/", "/Library/PrivilegedHelperTools/app.rampart.",
         "/Library/Application Support/Rampart/"].contains { p.hasPrefix($0) }
            || p.range(of: #"^/Users/[^/]+/Library/Application Support/Rampart/"#, options: .regularExpression) != nil
    }

    /// Developer build output, agent workspaces and the user's code folders.
    public static func developerContext(_ p: String) -> String? {
        let p = p.hasPrefix("/tmp/") ? "/private" + p : p
        if let m = devMarkers.first(where: { p.contains($0) }) { return "developer build folder (\(m.trimmingCharacters(in: CharacterSet(charactersIn: "/"))))" }
        if p.hasPrefix("/private/tmp/claude-") || (p.hasPrefix("/private/var/folders/") && p.contains("/claude-")) { return "agent workspace" }
        let roots = devRoots.joined(separator: "|")
        if p.range(of: "^/Users/[^/]+/(\(roots))/", options: .regularExpression) != nil { return "your code folder" }
        return nil
    }

    static let guiOpener = try! NSRegularExpression(pattern: #"Process: (/\S*\.app/Contents/MacOS/[^(]*) \(pid \d+, (apple|appStore|notarized|developerID)\)"#)

    /// The user opened one of RamPart's bait files with a normal signed app (TextEdit, Preview, Finder Quick Look).
    public static func isUserOpenedBait(_ d: Detection) -> Bool {
        let decoyRules: Set<String> = ["R01", "R39"]
        let hits = d.evidence.filter { !isContextOnly($0) }
        guard !hits.isEmpty, hits.allSatisfy({ ruleID($0).map(decoyRules.contains) == true }) else { return false }
        return hits.allSatisfy { e in guiOpener.firstMatch(in: e.detail, range: NSRange(location: 0, length: (e.detail as NSString).length)) != nil }
    }

    public static func benignContext(_ d: Detection) -> String? {
        if isUserOpenedBait(d) { return "a bait file opened with a normal app" }
        guard let p = d.path, p.hasPrefix("/") else { return nil }
        if isOwnComponentPath(p) { return "part of \(Product.name)" }
        return developerContext(p)
    }

    /// An exact EICAR test-signature match (the industry test file): quarantined like malware, shown only as handled.
    public static func isTestSignature(_ d: Detection) -> Bool {
        d.category == .test && d.evidence.contains { $0.title == "EICAR-Test-File" && $0.score >= 90 }
    }

    public static func isTestArtifact(_ d: Detection) -> Bool {
        if d.category == .test { return true }
        let hay = ([d.name, d.path ?? ""] + d.evidence.map(\.title)).joined(separator: " ").lowercased()
        return hay.contains("eicar") || hay.contains("com.rampart.test") || hay.contains("rampart-test")
    }

    /// Health / status conditions (a telemetry source down, missing Full Disk Access). Status notes, never threats.
    public static func isHealthCondition(_ d: Detection) -> Bool {
        let hay = ([d.name] + d.evidence.flatMap { [$0.title, $0.detail] }).joined(separator: " ").lowercased()
        if hay.contains("lost its real-time event feed") || hay.contains("telemetry source") || hay.contains("real-time protection is blind") { return true }
        if hay.contains("eslogger") && (HealthNote.isPermissionError(hay) || hay.contains("is down") || hay.contains("stopped") || hay.contains("crash")) { return true }
        return hay.contains("es_new_client_result") || hay.contains("full disk access")
    }

    /// A login item whose program couldn't be identified (`btm:<uid>:<uuid>` with no path).
    public static func isUnresolvedLoginItem(_ d: Detection) -> Bool { d.path?.hasPrefix("btm:") == true }

    public static func fyiReason(_ d: Detection) -> String? {
        if isTestArtifact(d) { return "test file" }
        if isHealthCondition(d) { return "status condition, shown under Protection health" }
        if isUnresolvedLoginItem(d) { return "login item whose program couldn't be identified" }
        return nil
    }

    // MARK: assessment

    public static func assess(_ d: Detection) -> DetectionAssessment {
        let raw = d.confidence
        let definitive = d.evidence.contains(where: isDefinitive)
        let families = Set(d.evidence.compactMap(family))
        let fyi = fyiReason(d)
        let benign = definitive ? nil : benignContext(d)
        var level: ConfidenceLevel
        var conf = raw
        if d.category == .test {
            level = .informational
        } else if definitive {
            level = .confirmed
        } else {
            let cap = benign != nil ? benignContextCap : families.count >= 2 ? corroboratedCap : heuristicCap
            conf = min(raw, cap)
            let strongSingleRule = families.count == 1 && families.first!.hasPrefix("rule:") && raw >= strongSingleRule
            if conf < logThreshold { level = .informational }
            else if benign != nil { level = .possible }
            else if conf >= likelyThreshold && (families.count >= 2 || strongSingleRule) { level = .likely }
            else { level = .possible }
        }
        if fyi != nil && level > .possible { level = .possible }
        // The EICAR test signature may be quarantined automatically (that is what it is for); it lands in "Handled".
        let auto = isTestSignature(d) || (fyi == nil && (level == .confirmed
            || (level == .likely && families.count >= 2 && raw >= autoRemediateRaw && benign == nil)))
        return DetectionAssessment(level: level, confidence: conf, rawConfidence: raw, definitive: definitive,
                                   signalFamilies: families, benignContext: benign, fyiReason: fyi, autoRemediate: auto)
    }

    public static func level(_ d: Detection) -> ConfidenceLevel { assess(d).level }
    public static func mayAutoRemediate(_ d: Detection) -> Bool { assess(d).autoRemediate }

    static func severity(confidence c: Int) -> Severity {
        c >= 90 ? .critical : c >= 75 ? .high : c >= 60 ? .medium : c >= 30 ? .low : .info
    }

    /// Applies the calibration: confidence capped, severity no higher than the calibrated confidence supports, and a
    /// plain note saying why when the score was lowered. Idempotent.
    public static func calibrate(_ d: Detection) -> Detection {
        let a = assess(d)
        var n = d
        n.confidence = a.confidence
        if d.category != .test && a.level != .confirmed {
            n.severity = min(d.severity, severity(confidence: a.confidence))
            if a.level <= .possible { n.severity = min(n.severity, .low) }
        }
        if a.confidence < a.rawConfidence || a.fyiReason != nil, !n.evidence.contains(where: { $0.title == calibrationTitle }) {
            let why: String
            if let f = a.fyiReason { why = "Shown for information only: \(f)." }
            else if let b = a.benignContext { why = "Lowered to \(a.confidence)%: \(b), with no definitive evidence." }
            else if a.corroborated { why = "Lowered to \(a.confidence)%: several warning signs, but no known-threat match." }
            else { why = "Lowered to \(a.confidence)%: a single warning sign with no independent confirmation." }
            n.evidence.append(Evidence(source: d.evidence.first?.source ?? .heuristic, title: calibrationTitle, detail: why, score: 0))
        }
        return n
    }

    // MARK: tiers

    /// Already stopped by RamPart when it happened (e.g. "Dangerous pasted command blocked").
    public static func isBlocked(_ d: Detection) -> Bool { d.name.lowercased().hasSuffix(" blocked") }

    public static func tier(_ d: Detection, quarantined: Bool = false) -> DetectionTier {
        if quarantined || d.resolved || isBlocked(d) { return .handled }
        let a = assess(d)
        if a.fyiReason != nil { return .fyi }
        return a.level >= .likely ? .needsYou : .fyi
    }

    /// Severity × confidence, for sorting "Needs you".
    public static func priority(_ d: Detection) -> Int { (d.severity.rawValue + 1) * max(0, min(100, d.confidence)) }

    // MARK: dedupe and grouping

    /// One file, process or login item.
    public static func subjectKey(_ d: Detection) -> String {
        if isHealthCondition(d) { return "health:" + d.name.lowercased() }
        if let p = d.path, !p.isEmpty { return "path:" + p }
        if let pid = d.pid { return "pid:\(pid)" }
        return "name:" + d.name.lowercased()
    }

    /// Same rule + same subject (or the same health / status condition).
    public static func dedupeKey(_ d: Detection) -> String {
        if isHealthCondition(d) { return subjectKey(d) }
        let rules = Set(d.evidence.filter { !isContextOnly($0) }.compactMap(ruleID)).sorted().joined(separator: ",")
        return subjectKey(d) + "|" + d.name + "|" + rules
    }

    /// Folds `new` into `old` (same dedupe key): one row with a count and first/last seen; the stronger evidence wins.
    public static func merge(_ old: Detection, _ new: Detection) -> Detection {
        var m = new.confidence >= old.confidence ? new : old
        m.id = old.id
        m.resolution = old.resolution ?? new.resolution
        m.resolved = old.resolved && new.resolved
        m.count = (old.count ?? 1) + (new.count ?? 1)
        m.firstSeen = min(old.firstSeen ?? old.date, new.firstSeen ?? new.date)
        m.lastSeen = max(old.lastSeen ?? old.date, new.lastSeen ?? new.date)
        m.date = max(old.date, new.date)
        if m.sha256 == nil { m.sha256 = new.sha256 ?? old.sha256 }
        if m.pid == nil { m.pid = new.pid ?? old.pid }
        return m
    }

    /// Merges duplicates: open ones with open ones, resolved history with resolved history (never across). Order is kept.
    public static func mergeDuplicates(_ ds: [Detection]) -> (items: [Detection], merged: Int) {
        var out: [Detection] = []
        var index: [String: Int] = [:]
        var merged = 0
        for d in ds {
            let k = (d.resolved ? "resolved|" + (d.resolution ?? "") + "|" : "open|") + dedupeKey(d)
            if let i = index[k] { out[i] = merge(out[i], d); merged += 1 }
            else { index[k] = out.count; out.append(d) }
        }
        return (out, merged)
    }

    // MARK: re-evaluation

    public struct Reevaluation: Sendable {
        public var items: [Detection]
        public var resolved: Int
        public var merged: Int
        public var downgraded: Int
    }

    /// Re-checks a stored list with this policy: calibrates every open detection, resolves the ones that are no longer
    /// threats (test files, health conditions, RamPart's own components, a bait file the user opened, informational ones)
    /// with a reason, and merges duplicates. Possible findings stay open in FYI. Quarantine is never touched.
    public static func reevaluate(_ ds: [Detection]) -> Reevaluation {
        var resolved = 0, downgraded = 0
        let items = ds.map { d -> Detection in
            guard !d.resolved else { return d }
            let before = tier(d)
            var n = calibrate(d)
            let a = assess(n)
            // Unresolvable login items stay open in FYI (the user may still want to look); the rest are closed.
            let noLongerThreat = (a.fyiReason != nil && !isUnresolvedLoginItem(n)) || a.level == .informational
                || (a.benignContext.map { $0.hasPrefix("part of") || $0.hasPrefix("a bait file") } ?? false)
            if noLongerThreat {
                n.resolved = true
                n.resolution = recheckedReason + ((a.fyiReason ?? a.benignContext).map { " (\($0))" } ?? "")
                resolved += 1
            } else if before == .needsYou && tier(n) != .needsYou {
                downgraded += 1
            }
            return n
        }
        let m = mergeDuplicates(items)
        return Reevaluation(items: m.items, resolved: resolved, merged: m.merged, downgraded: downgraded)
    }
}

/// One row in the Threats list: every signal about one file, process or login item.
public struct DetectionGroup: Identifiable, Sendable {
    public var id: String
    public var tier: DetectionTier
    /// The strongest member (severity × confidence).
    public var primary: Detection
    public var members: [Detection]
    /// Occurrences, counting merged duplicates.
    public var count: Int { members.reduce(0) { $0 + ($1.count ?? 1) } }
    public var firstSeen: Date { members.map { $0.firstSeen ?? $0.date }.min() ?? primary.date }
    public var lastSeen: Date { members.map { $0.lastSeen ?? $0.date }.max() ?? primary.date }
    public var level: ConfidenceLevel { members.map(DetectionPolicy.level).max() ?? .informational }
    public init(id: String, tier: DetectionTier, primary: Detection, members: [Detection]) {
        self.id = id; self.tier = tier; self.primary = primary; self.members = members
    }
}

extension DetectionPolicy {
    /// Groups detections by tier and subject. "Needs you" is sorted by severity × confidence, the others by recency.
    public static func groups(_ ds: [Detection], quarantined: (Detection) -> Bool = { _ in false }) -> [DetectionTier: [DetectionGroup]] {
        var buckets: [DetectionTier: [String: [Detection]]] = [:]
        var order: [DetectionTier: [String]] = [:]
        for d in ds {
            let t = tier(d, quarantined: quarantined(d))
            let k = subjectKey(d)
            if buckets[t]?[k] == nil { order[t, default: []].append(k) }
            buckets[t, default: [:]][k, default: []].append(d)
        }
        var out: [DetectionTier: [DetectionGroup]] = [:]
        for t in DetectionTier.allCases {
            var gs = (order[t] ?? []).map { k -> DetectionGroup in
                let ms = buckets[t]![k]!.sorted { priority($0) != priority($1) ? priority($0) > priority($1) : $0.date > $1.date }
                return DetectionGroup(id: t.rawValue + "|" + k, tier: t, primary: ms[0], members: ms)
            }
            if t == .needsYou {
                gs.sort { priority($0.primary) != priority($1.primary) ? priority($0.primary) > priority($1.primary) : $0.lastSeen > $1.lastSeen }
            } else {
                gs.sort { $0.lastSeen > $1.lastSeen }
            }
            out[t] = gs
        }
        return out
    }

    /// The number shown on the sidebar badge and in the "Needs attention" footer: "Needs you" rows only.
    public static func needsYouCount(_ ds: [Detection], quarantined: (Detection) -> Bool = { _ in false }) -> Int {
        Set(ds.filter { tier($0, quarantined: quarantined($0)) == .needsYou }.map(subjectKey)).count
    }
}

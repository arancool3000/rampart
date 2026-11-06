import Foundation
import RampartShared

/// Doc 05 §12.2 confidence classes.
public enum RuleType: String, Codable, Sendable {
    case strong      // atomic-strong: may alert alone
    case weak        // atomic-weak: context only, needs corroboration
    case sequence    // fires on ordered combinations
    case marker      // never scores; only records marks for sequence rules
}

/// Kill-chain stage used for sequence bonuses and the stealer-chain rule (R40).
public enum Stage: String, Codable, Sendable {
    case entry, execution, credential, collection, exfil, persistence, evasion, impact, recon, surveillance
    /// Order for the "consecutive stage" bonus (doc 05 §12.2). Nil = not part of the stealer kill chain.
    var chainOrder: Int? {
        switch self {
        case .entry: return 0
        case .execution: return 1
        case .credential: return 2
        case .collection: return 3
        case .exfil: return 4
        default: return nil
        }
    }
}

/// Whose signature drives the context multiplier.
public enum TrustSubject: String, Codable, Sendable {
    case actor     // the acting process image
    case lineage   // least-trusted non-Apple process in the chain (LOLBins scored through their ancestor)
    case target    // the file/executable the event points at (persistence targets)
    case none      // no signing multiplier (the behaviour is bad whoever signed the code, e.g. Dock hijack)
}

public enum TrustRequirement: String, Codable, Sendable {
    case untrusted   // subject is unsigned / ad-hoc / invalid, or unknown in a temp/hidden location
    case nonApple    // subject is not an Apple platform binary
}

public struct MarkRequirement: Codable, Sendable, Hashable {
    public enum Scope: String, Codable, Sendable {
        case execPath   // the exec'd image lies at/under a marked path
        case argPath    // some argument contains a marked path
        case eventPath  // the event path lies at/under a marked path
        case story      // the mark was set in the same story
        case global     // the mark was set anywhere
    }
    public var name: String
    public var scope: Scope
    public var window: TimeInterval?
}

public struct MarkSpec: Codable, Sendable, Hashable {
    public enum From: String, Codable, Sendable { case args, path, actorPath, story, global }
    public var name: String
    public var from: From
    public var window: TimeInterval?   // default 600
}

public struct Threshold: Codable, Sendable, Hashable {
    public enum Group: String, Codable, Sendable { case story, actor, global }
    public var count: Int
    public var window: TimeInterval
    /// What makes two events distinct: "path", "dir", "process", "args", "detail:<key>"; nil counts every event.
    public var distinct: String?
    public var groupBy: Group?
}

/// Declarative match condition. All present fields must hold (AND). Regex lists are OR within the list
/// unless stated. Name lists (process/parent/ancestor/sibling) are full-match, case-insensitive regexes and
/// may reference shared lists as "@name".
public struct Matcher: Codable, Sendable {
    public var kinds: [SecurityEventKind]?
    public var process: [String]?
    public var processNot: [String]?
    public var processPath: [String]?
    public var args: [String]?          // ALL must match the normalised argv
    public var argsAny: [String]?       // at least one must match
    public var argsNot: [String]?       // none may match
    public var path: [String]?          // event path or destPath matches any
    public var pathNot: [String]?
    public var pathClass: [PathClass]?  // event path (file events) / image path (exec)
    public var detail: [String: String]? // every key must exist and match its regex
    public var detailNot: [String: String]?
    public var parent: [String]?
    public var ancestor: [String]?
    public var ancestorNot: [String]?
    public var sibling: [String]?
    public var siblingArgsNot: [String]?
    public var siblingWindow: TimeInterval?
    public var trust: TrustRequirement?
    public var lineageUntrusted: Bool?
    public var requireMark: MarkRequirement?
    public var setMark: MarkSpec?
    public var threshold: Threshold?
    public var firstSeen: Bool?          // only the first time this image path matches this rule
    /// Exec'd image carries com.apple.quarantine (or the event says detail["quarantined"] == "1").
    public var quarantined: Bool?
    /// The story already scores at least this much (corroboration from other rules).
    public var storyMinScore: Int?
    /// A risky clipboard copied from a browser (with `clip_tokens`) within the clipboard window shares at least
    /// this fraction (and ≥2) of the command's token hashes. See `ClipboardFingerprint`.
    public var clipboardOverlap: Double?
}

public struct Rule: Codable, Sendable {
    public var id: String
    public var name: String
    public var type: RuleType
    public var category: ThreatCategory
    public var score: Int
    public var stage: Stage?
    public var subject: TrustSubject?
    public var why: String
    /// Weak rules decay with this half-life (seconds). Default 900 for weak, none for strong/sequence.
    public var halfLife: TimeInterval?
    /// Multiplier when the lineage contains an interactive terminal / ssh session (admin doing it by hand).
    public var interactiveFactor: Double?
    /// Down-weighted ×0.5 in developer mode when a dev toolchain is in the lineage.
    public var devSensitive: Bool?
    /// Fires even in learning mode (the doc 05 v1 strong set).
    public var alwaysActive: Bool?
    public var enabled: Bool?
    /// Implemented in Swift (ransomware, persistence, honeytokens, beaconing...). Matchers are ignored.
    public var builtin: Bool?
    public var matchers: [Matcher]?

    public var effectiveHalfLife: TimeInterval? { halfLife ?? (type == .weak ? 900 : nil) }
    public var isEnabled: Bool { enabled ?? true }
}

/// A versioned, data-driven rule file (JSON). See `DefaultRules.json`.
public struct RuleSet: Codable, Sendable {
    public var version: String
    public var lists: [String: [String]]
    public var rules: [Rule]

    public static func decode(_ data: Data) throws -> RuleSet {
        try JSONDecoder().decode(RuleSet.self, from: data)
    }
    public static func load(from url: URL) throws -> RuleSet { try decode(Data(contentsOf: url)) }

    /// Built-in default rule set.
    public static var `default`: RuleSet {
        // The embedded JSON is validated by the self-test; a decode failure here is a programming error.
        try! decode(Data(DefaultRules.json.utf8))
    }

    public func rule(_ id: String) -> Rule? { rules.first { $0.id == id } }

    /// Expands "@list" references.
    func expand(_ names: [String]?) -> [String]? {
        guard let names else { return nil }
        var out: [String] = []
        for n in names {
            if n.hasPrefix("@"), let l = lists[String(n.dropFirst())] { out += l } else { out.append(n) }
        }
        return out
    }

    /// Returns problems: unknown lists, bad regexes, duplicate IDs.
    public func validate() -> [String] {
        var problems: [String] = []
        var ids = Set<String>()
        for r in rules {
            if !ids.insert(r.id).inserted { problems.append("duplicate id \(r.id)") }
            for m in r.matchers ?? [] {
                let nameLists = [m.process, m.processNot, m.parent, m.ancestor, m.ancestorNot, m.sibling]
                for l in nameLists {
                    for n in l ?? [] where n.hasPrefix("@") && lists[String(n.dropFirst())] == nil {
                        problems.append("\(r.id): unknown list \(n)")
                    }
                    for n in expand(l) ?? [] where RegexCache.shared.regex("^(?:" + n + ")$") == nil {
                        problems.append("\(r.id): bad name regex \(n)")
                    }
                }
                let rx = [m.processPath, m.args, m.argsAny, m.argsNot, m.path, m.pathNot, m.siblingArgsNot].compactMap { $0 }.flatMap { $0 }
                    + Array((m.detail ?? [:]).values) + Array((m.detailNot ?? [:]).values)
                for p in rx {
                    let ex = p.hasPrefix("@") ? (lists[String(p.dropFirst())] ?? ["("]) : [p]
                    for e in ex where RegexCache.shared.regex(e) == nil { problems.append("\(r.id): bad regex \(e)") }
                }
            }
            if r.builtin != true && r.type != .marker && (r.matchers ?? []).isEmpty { problems.append("\(r.id): no matchers") }
        }
        return problems
    }
}

/// Scoped exception. Matches when every present field matches. `ruleIDs == nil` means all rules.
/// `weakOnly` exceptions suppress weak/sequence rules but never strong ones (used for dev-tool defaults).
public struct AllowEntry: Codable, Hashable, Sendable {
    public var teamID: String?
    public var signingID: String?
    public var pathPrefix: String?
    public var ruleIDs: [String]?
    public var weakOnly: Bool?
    public var note: String?
    public init(teamID: String? = nil, signingID: String? = nil, pathPrefix: String? = nil,
                ruleIDs: [String]? = nil, weakOnly: Bool? = nil, note: String? = nil) {
        self.teamID = teamID; self.signingID = signingID; self.pathPrefix = pathPrefix
        self.ruleIDs = ruleIDs; self.weakOnly = weakOnly; self.note = note
    }
}

import Foundation
import RampartShared

// RampartWeb: Scam Check engine, URL / website risk analysis and the browser-extension contract.
// Offline-first and explainable: every verdict carries the signals that produced it, with the
// matched evidence so the UI can highlight it. Nothing here talks to the network by itself;
// reputation and AI are pluggable through protocols at the bottom of this file.

// MARK: - Verdicts

public enum ScamVerdict: String, Codable, Sendable, CaseIterable {
    case likelySafe, suspicious, likelyScam

    public var title: String {
        switch self {
        case .likelySafe: return "Likely safe"
        case .suspicious: return "Suspicious"
        case .likelyScam: return "Likely scam"
        }
    }
    /// What the browser extension should do: nothing, a banner, or a full-page interstitial.
    public var action: ScamAction {
        switch self {
        case .likelySafe: return .allow
        case .suspicious: return .warn
        case .likelyScam: return .block
        }
    }
    /// Score thresholds (0–100). Tuned against the synthetic corpus in rampart-selftest.
    public static func from(score: Int) -> ScamVerdict {
        if score >= ScamScoring.scamThreshold { return .likelyScam }
        if score >= ScamScoring.suspiciousThreshold { return .suspicious }
        return .likelySafe
    }
}

public enum ScamAction: String, Codable, Sendable { case allow, warn, block }

public enum ScamScoring {
    public static let scamThreshold = 70
    public static let suspiciousThreshold = 35
    /// Noisy-OR combination, same shape as the file-scan scoring in ARCHITECTURE.md:
    /// 100·(1 − Π(1 − s/100)). Signals in the same category are first collapsed to
    /// their strongest member plus a small bonus per extra hit, so ten urgency phrases
    /// never outweigh one "send gift cards" request.
    public static func combine(_ signals: [ScamSignal]) -> Int {
        var byCategory: [ScamSignal.Category: [Int]] = [:]
        for s in signals where s.score > 0 { byCategory[s.category, default: []].append(min(100, s.score)) }
        var product = 1.0
        for (_, scores) in byCategory {
            let sorted = scores.sorted(by: >)
            var effective = Double(sorted[0])
            for extra in sorted.dropFirst().prefix(3) { effective += Double(extra) * 0.15 }
            effective = min(effective, 97)
            product *= (1 - effective / 100)
        }
        return Int((100 * (1 - product)).rounded())
    }
}

// MARK: - Signals and evidence

/// A span of the analysed input, in UTF-16 offsets of the text that was analysed, so the
/// app can highlight it with AttributedString and the extension can match it in the DOM.
public struct ScamHighlight: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable { case phrase, link, header, domain, script }
    public var text: String
    public var kind: Kind
    public var start: Int?
    public var end: Int?
    public init(text: String, kind: Kind, start: Int? = nil, end: Int? = nil) {
        self.text = text; self.kind = kind; self.start = start; self.end = end
    }
}

public struct ScamSignal: Codable, Hashable, Identifiable, Sendable {
    public enum Category: String, Codable, Sendable, CaseIterable {
        case urgency, payment, credentials, techSupport, remoteAccess, smishing, lure,
             sender, authentication, link, urlStructure, lookalike, domainReputation,
             pageClickFix, pageClipboard, pageDrainer, pageScareware, pageCredentialForm,
             blocklist, ai, benign
    }
    public var id: String               // stable rule id, e.g. "text.payment.giftcard"
    public var category: Category
    public var title: String            // short, plain language ("Asks for gift cards")
    public var explanation: String      // one or two sentences the user can act on
    public var score: Int               // 0...100; negative scores are allowed for benign evidence
    public var evidence: [ScamHighlight]
    public init(id: String, category: Category, title: String, explanation: String, score: Int, evidence: [ScamHighlight] = []) {
        self.id = id; self.category = category; self.title = title; self.explanation = explanation
        self.score = score; self.evidence = evidence
    }
}

// MARK: - Input and report

public enum ScamInputKind: String, Codable, Sendable { case message, url, email, page }

public struct ScamReport: Codable, Hashable, Sendable {
    public var kind: ScamInputKind
    public var verdict: ScamVerdict
    public var score: Int
    public var headline: String          // "This message asks for gift cards and pressures you to act now."
    public var signals: [ScamSignal]     // strongest first
    public var urls: [URLReport]         // every link found in the input, analysed
    public var language: String          // BCP-47 of the lexicon used ("en")
    public var tips: [String]
    public var aiOpinion: ScamAIOpinion?
    public var analysedText: String      // the text highlights refer to (plain text of the message)
    public init(kind: ScamInputKind, verdict: ScamVerdict, score: Int, headline: String, signals: [ScamSignal],
                urls: [URLReport], language: String, tips: [String], aiOpinion: ScamAIOpinion? = nil, analysedText: String) {
        self.kind = kind; self.verdict = verdict; self.score = score; self.headline = headline; self.signals = signals
        self.urls = urls; self.language = language; self.tips = tips; self.aiOpinion = aiOpinion; self.analysedText = analysedText
    }
    public var highlights: [ScamHighlight] { signals.flatMap(\.evidence) }
}

/// Result of analysing one URL.
public struct URLReport: Codable, Hashable, Sendable {
    public var original: String
    public var host: String?             // lowercased, punycode-decoded for display
    public var asciiHost: String?        // as the browser sends it (xn-- form)
    public var registrableDomain: String?
    public var verdict: ScamVerdict
    public var score: Int
    public var signals: [ScamSignal]
    public var brandMatch: String?       // brand this host impersonates, if any
    public init(original: String, host: String?, asciiHost: String?, registrableDomain: String?, verdict: ScamVerdict,
                score: Int, signals: [ScamSignal], brandMatch: String?) {
        self.original = original; self.host = host; self.asciiHost = asciiHost; self.registrableDomain = registrableDomain
        self.verdict = verdict; self.score = score; self.signals = signals; self.brandMatch = brandMatch
    }
}

/// Structured facts the browser extension collects from a page (cheap for it, expensive for us to re-derive).
public struct PageSignals: Codable, Hashable, Sendable {
    public struct Form: Codable, Hashable, Sendable {
        public var action: String?           // resolved absolute URL
        public var hasPassword: Bool
        public var hasEmailOrUser: Bool
        public var hasCardNumber: Bool
        public var hasOTP: Bool
        public init(action: String? = nil, hasPassword: Bool = false, hasEmailOrUser: Bool = false, hasCardNumber: Bool = false, hasOTP: Bool = false) {
            self.action = action; self.hasPassword = hasPassword; self.hasEmailOrUser = hasEmailOrUser; self.hasCardNumber = hasCardNumber; self.hasOTP = hasOTP
        }
    }
    public var title: String = ""
    public var forms: [Form] = []
    public var usesClipboardWrite: Bool = false     // navigator.clipboard.writeText / execCommand("copy") seen in scripts
    public var overlayText: String = ""             // visible text of fixed/absolute full-viewport overlays
    public var visibleText: String = ""             // truncated innerText
    public var scriptSnippets: [String] = []        // inline script excerpts the content script found suspicious
    public var imageAlts: [String] = []             // alt / src basename of logos
    public var externalScriptHosts: [String] = []
    public var hasWalletConnect: Bool = false
    public var isTopFrame: Bool = true
    public var isHTTPS: Bool = true
    /// First `<h1>` (≤200 chars), sent by newer extensions. Optional so older senders still decode.
    public var h1: String? = nil
    /// Absolute hrefs ending in .dmg/.pkg/.mpkg/.zip/.app/.iso (≤30), sent by newer extensions.
    public var downloadLinks: [String]? = nil
    public init() {}
}

// MARK: - Pluggable providers

/// Optional AI second opinion. RampartAI implements this; RampartWeb never imports RampartAI.
public struct ScamAIOpinion: Codable, Hashable, Sendable {
    public var verdict: ScamVerdict
    public var confidence: Int           // 0...100
    public var summary: String
    public var reasons: [String]
    public var provider: String          // "Gemini", ...
    public init(verdict: ScamVerdict, confidence: Int, summary: String, reasons: [String], provider: String) {
        self.verdict = verdict; self.confidence = confidence; self.summary = summary; self.reasons = reasons; self.provider = provider
    }
}

public protocol ScamAIAssessor: Sendable {
    var providerName: String { get }
    var isConfigured: Bool { get }
    /// Given the raw input and our offline report, return an independent opinion.
    func assess(input: String, kind: ScamInputKind, offlineReport: ScamReport) async throws -> ScamAIOpinion
}

/// Reputation lookups (local blocklists, daemon, remote feeds) behind one protocol.
public struct BlocklistHit: Codable, Hashable, Sendable {
    public var rule: String
    public var source: String
    public var category: String?         // "phishing", "malware", "scam"...
    public init(rule: String, source: String, category: String? = nil) { self.rule = rule; self.source = source; self.category = category }
}

public protocol WebBlocklistProvider: Sendable {
    var name: String { get }
    func lookup(host: String) -> BlocklistHit?
    func lookup(url: String) -> BlocklistHit?
}

public extension WebBlocklistProvider {
    func lookup(url: String) -> BlocklistHit? {
        guard let host = URLAnalyzer.parse(url)?.asciiHost else { return nil }
        return lookup(host: host)
    }
}

/// Tracks domains this Mac has visited so "never seen before" can be a (weak) signal.
public protocol SeenDomainStore: Sendable {
    /// Returns when this registrable domain was first seen, recording it now if new.
    func firstSeen(_ registrableDomain: String) -> Date
    var count: Int { get }
}

/// Allowlist of hosts the user chose to trust ("Continue anyway" / "Don't warn again").
public protocol WebAllowlist: Sendable {
    func isAllowed(host: String) -> Bool
}

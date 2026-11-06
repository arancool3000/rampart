import Foundation
import RampartWeb

// Pure navigation policy for RamPart Secure Browser. No WebKit, no I/O: everything here is
// deterministic so `--selftest` can exercise it headlessly.

/// Why a navigation was flagged. Each reason maps to one interstitial and one plain sentence.
public enum NavigationRisk: String, Codable, Hashable, Sendable, CaseIterable {
    case blocklisted          // RamPart blocklist (phishing/malware feeds) hit
    case likelyScam           // RampartWeb URL verdict: likely scam
    case suspiciousURL        // RampartWeb URL verdict: suspicious
    case lookalikeDomain      // confusable/punycode/typo of a known brand
    case plainHTTP            // not encrypted and no HTTPS upgrade possible (upgrade failed earlier)
    case dangerousScheme      // javascript:, data:, file:, blob: at top level
    case rawIPHost            // http(s)://1.2.3.4/
    case credentialBait       // login keywords on a shared-hosting / free-TLD domain

    public var title: String {
        switch self {
        case .blocklisted: return "This site is on RamPart's block list"
        case .likelyScam: return "This looks like a scam site"
        case .suspiciousURL: return "This address looks suspicious"
        case .lookalikeDomain: return "This domain imitates a well-known site"
        case .plainHTTP: return "This connection isn't private"
        case .dangerousScheme: return "This kind of link can't be opened here"
        case .rawIPHost: return "This site uses a bare IP address"
        case .credentialBait: return "This sign-in page is on a throwaway domain"
        }
    }
}

/// What the browser should do with a navigation request.
public enum NavigationDecision: Equatable, Sendable {
    case allow
    /// Load `url` instead (https upgrade of an http request).
    case upgrade(URL)
    /// Show a calm interstitial; the user may continue.
    case warn([NavigationRisk], score: Int)
    /// Show a firm interstitial; "Go back" only, "visit anyway" hidden unless developer mode.
    case block([NavigationRisk], score: Int)

    public var isAllowed: Bool { if case .allow = self { return true }; return false }
    public var risks: [NavigationRisk] {
        switch self {
        case .warn(let r, _), .block(let r, _): return r
        default: return []
        }
    }
}

/// Facts the policy needs that come from engines (RampartWeb, the daemon's blocklists).
public struct URLFacts: Equatable, Sendable {
    public var blocklistHit: String?          // name of the list that matched
    public var scamScore: Int                 // 0...100 from RampartWeb (0 if unavailable)
    public var scamVerdict: ScamVerdict
    public var brandMatch: String?            // brand the host imitates, if any
    public var allowlisted: Bool              // user chose "Continue anyway" before
    public init(blocklistHit: String? = nil, scamScore: Int = 0, scamVerdict: ScamVerdict = .likelySafe,
                brandMatch: String? = nil, allowlisted: Bool = false) {
        self.blocklistHit = blocklistHit; self.scamScore = scamScore; self.scamVerdict = scamVerdict
        self.brandMatch = brandMatch; self.allowlisted = allowlisted
    }
}

public struct URLDecisionPolicy: Sendable {
    public var httpsOnly = true
    /// Hosts the user explicitly allowed plain HTTP for in this session (after an upgrade failed).
    public var httpAllowedHosts: Set<String> = []
    public init() {}

    public static let dangerousSchemes: Set<String> = ["javascript", "data", "file", "blob", "ftp", "vbscript", "ms-msdt", "search-ms"]
    public static let localSchemes: Set<String> = ["about", "rampart"]

    /// Decide a top-level navigation. `isMainFrame == false` requests (subresources/iframes) are only
    /// subject to the blocklist and scheme checks; the content rule list handles trackers.
    public func decide(url: URL, facts: URLFacts, isMainFrame: Bool = true, httpUpgradeFailed: Bool = false) -> NavigationDecision {
        let scheme = (url.scheme ?? "").lowercased()
        if Self.localSchemes.contains(scheme) { return .allow }
        if Self.dangerousSchemes.contains(scheme) || scheme.isEmpty {
            return .block([.dangerousScheme], score: 100)
        }
        guard scheme == "http" || scheme == "https" else { return .block([.dangerousScheme], score: 100) }
        let host = (url.host ?? "").lowercased()

        var risks: [NavigationRisk] = []
        var score = facts.scamScore
        if facts.blocklistHit != nil { risks.append(.blocklisted); score = max(score, 95) }

        if !facts.allowlisted {
            switch facts.scamVerdict {
            case .likelyScam: risks.append(.likelyScam)
            case .suspicious: if isMainFrame { risks.append(.suspiciousURL) }
            case .likelySafe: break
            }
            if facts.brandMatch != nil, isMainFrame, !risks.contains(.likelyScam) { risks.append(.lookalikeDomain); score = max(score, 70) }
            if isMainFrame, Self.isRawIP(host) { risks.append(.rawIPHost); score = max(score, 40) }
        }

        // HTTPS-only: upgrade first, warn only if the upgrade already failed.
        if scheme == "http", isMainFrame, httpsOnly, !Self.isLoopback(host) {
            if !httpUpgradeFailed && !httpAllowedHosts.contains(host) {
                var comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
                comps?.scheme = "https"
                if comps?.port == 80 { comps?.port = nil }
                if let up = comps?.url, risks.isEmpty { return .upgrade(up) }
            } else if !httpAllowedHosts.contains(host) {
                risks.append(.plainHTTP); score = max(score, 35)
            }
        }

        if risks.isEmpty { return .allow }
        let blocking = risks.contains(.blocklisted) || risks.contains(.likelyScam)
        return blocking ? .block(risks, score: score) : .warn(risks, score: score)
    }

    public static func isRawIP(_ host: String) -> Bool {
        if host.hasPrefix("[") { return true }                       // IPv6 literal
        let parts = host.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in p.allSatisfy(\.isNumber) && Int(p).map { $0 <= 255 } == true }
    }
    public static func isLoopback(_ host: String) -> Bool {
        host == "localhost" || host.hasPrefix("127.") || host == "::1" || host == "[::1]"
    }

    /// Turn what the user typed into something navigable. Search goes to DuckDuckGo (no tracking).
    public static func resolveTyped(_ input: String) -> URL? {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        if text == "about:blank" || text.hasPrefix("rampart:") { return URL(string: text) }
        if let u = URL(string: text), let s = u.scheme?.lowercased(), !s.isEmpty, u.host != nil || s == "about" {
            return u
        }
        let looksLikeHost = !text.contains(" ") && (text.contains(".") || text.hasPrefix("localhost")) && !text.hasSuffix(".")
        if looksLikeHost, let u = URL(string: "https://" + text), u.host != nil { return u }
        var comps = URLComponents(string: "https://duckduckgo.com/")!
        comps.queryItems = [URLQueryItem(name: "q", value: text)]
        return comps.url
    }
}

// MARK: - Interstitial selection

/// Which full-page interstitial to show, and with what copy. Pure so it can be unit-tested.
public struct Interstitial: Equatable, Sendable {
    public enum Tone: String, Sendable { case danger, caution }
    public var tone: Tone
    public var symbol: String
    public var title: String
    public var body: String
    public var reasons: [String]
    public var primaryLabel: String       // always the safe option, and the default button
    public var secondaryLabel: String?    // "Visit anyway" when allowed
    public var showsContinue: Bool

    public static func select(for decision: NavigationDecision, host: String, developerMode: Bool = false) -> Interstitial? {
        switch decision {
        case .allow, .upgrade: return nil
        case .block(let risks, _):
            let primary = risks.first ?? .likelyScam
            return Interstitial(tone: .danger, symbol: "hand.raised.fill", title: primary.title,
                                body: blockBody(primary, host: host), reasons: risks.map(\.title),
                                primaryLabel: "Go back", secondaryLabel: developerMode ? "Visit anyway (unsafe)" : nil,
                                showsContinue: developerMode)
        case .warn(let risks, _):
            let primary = risks.first ?? .suspiciousURL
            return Interstitial(tone: .caution, symbol: "exclamationmark.shield.fill", title: primary.title,
                                body: warnBody(primary, host: host), reasons: risks.map(\.title),
                                primaryLabel: "Go back", secondaryLabel: "Continue anyway", showsContinue: true)
        }
    }

    static func blockBody(_ r: NavigationRisk, host: String) -> String {
        switch r {
        case .blocklisted: return "RamPart's block lists mark \(host) as a phishing or malware site. Nothing from it has been loaded."
        case .likelyScam: return "\(host) has the hallmarks of a scam page: the address is built to look like a trusted site or to pressure you. Nothing from it has been loaded."
        case .dangerousScheme: return "Links of this type can run code or open local files, so the secure browser never follows them."
        default: return "RamPart stopped this page before it loaded."
        }
    }
    static func warnBody(_ r: NavigationRisk, host: String) -> String {
        switch r {
        case .lookalikeDomain: return "\(host) looks like a well-known site's address but isn't that site. If you were expecting your bank or a shop, go back and type the address yourself."
        case .plainHTTP: return "\(host) doesn't offer a secure (HTTPS) connection, so anything you type here could be read or changed on the way."
        case .rawIPHost: return "Legitimate shops and banks use names, not numbers. Pages served from a bare IP address are often temporary or malicious."
        case .credentialBait: return "This sign-in form lives on a free hosting domain, which is where most phishing pages are built."
        case .suspiciousURL: return "The address of \(host) has features that scam sites use. Take a moment before entering anything personal."
        default: return "Take a moment before continuing."
        }
    }
}

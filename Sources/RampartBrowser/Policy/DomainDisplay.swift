import Foundation
import RampartWeb

/// What the address bar shows: the registrable domain prominently, the rest dimmed, with an
/// identity state that drives the lock symbol and the punycode / look-alike highlight.
public struct DomainDisplay: Equatable, Sendable {
    public enum Identity: Equatable, Sendable {
        case secure                 // https, no warnings
        case insecure               // http
        case local                  // about:, rampart:
        case punycode(decoded: String)   // xn-- host; shows the decoded form with a warning
        case lookalike(brand: String)    // host imitates a brand
        case mixedScript            // Latin + other script in a label
    }
    public var scheme: String
    public var prefix: String           // "https://sub." part shown dimmed (empty for root hosts)
    public var domain: String           // registrable domain shown prominently (punycode-decoded)
    public var suffixPath: String       // path/query shown dimmed
    public var identity: Identity
    public var fullText: String         // what ⌘L edits
    public var asciiHost: String = ""   // xn-- form when the host uses punycode, else empty

    public var lockSymbol: String {
        switch identity {
        case .secure: return "lock.fill"
        case .insecure: return "lock.open.trianglebadge.exclamationmark"
        case .local: return "shield.lefthalf.filled"
        case .punycode, .lookalike, .mixedScript: return "exclamationmark.triangle.fill"
        }
    }
    public var isWarning: Bool {
        switch identity {
        case .secure, .local: return false
        default: return true
        }
    }
    public var identityLabel: String {
        switch identity {
        case .secure: return "Encrypted connection"
        case .insecure: return "Not encrypted"
        case .local: return "RamPart page"
        case .punycode(let d): return "International characters: \(d)"
        case .lookalike(let b): return "Not \(b)"
        case .mixedScript: return "Mixed alphabets in the address"
        }
    }

    public static func make(url: URL?, brandMatch: String? = nil) -> DomainDisplay {
        guard let url else { return DomainDisplay(scheme: "", prefix: "", domain: "", suffixPath: "", identity: .local, fullText: "") }
        let scheme = (url.scheme ?? "").lowercased()
        let full = url.absoluteString
        if URLDecisionPolicy.localSchemes.contains(scheme) {
            // hx6: never echo page-chosen text (a fragment, a query, an unknown about:/rampart: page) next to
            // the "RamPart page" identity. Inert blank documents read "New tab"; anything else is shown plainly.
            if scheme == "about", URLDecisionPolicy.isInertAbout(url, isMainFrame: false) {
                return DomainDisplay(scheme: scheme, prefix: "", domain: "New tab", suffixPath: "", identity: .local, fullText: "")
            }
            return DomainDisplay(scheme: scheme, prefix: "", domain: String(sanitized(full).prefix(60)), suffixPath: "", identity: .insecure, fullText: full)
        }
        let asciiHost = (url.host ?? "").lowercased()
        let unicodeHost = Punycode.decodeHost(asciiHost)
        let split = PublicSuffix.split(asciiHost)
        let registrableASCII = split?.registrable ?? asciiHost
        let registrable = Punycode.decodeHost(registrableASCII)
        let sub = asciiHost.hasSuffix(registrableASCII) && asciiHost.count > registrableASCII.count
            ? String(unicodeHost.dropLast(registrable.count)) : ""
        // hx6: show the path as sent (still percent-encoded) and strip bidi/control characters, so
        // "%E2%80%AE" (right-to-left override) or "%2F" can't reorder or fake what the dimmed part says.
        var pathPart = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedPath ?? url.path
        if pathPart == "/" { pathPart = "" }
        if let q = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedQuery, !q.isEmpty { pathPart += "?" + q }
        if let port = url.port { pathPart = ":\(port)" + pathPart }
        pathPart = sanitized(pathPart)
        if pathPart.count > 120 { pathPart = String(pathPart.prefix(120)) + "…" }

        let identity: Identity
        if let b = brandMatch {
            identity = .lookalike(brand: b)
        } else if asciiHost.contains("xn--") {
            identity = .punycode(decoded: unicodeHost)
        } else if Confusables.isMixedScript(unicodeHost) {
            identity = .mixedScript
        } else if scheme == "https" {
            identity = .secure
        } else {
            identity = .insecure
        }
        return DomainDisplay(scheme: scheme, prefix: sanitized(scheme + "://" + sub), domain: sanitized(registrable), suffixPath: pathPart, identity: identity, fullText: full,
                             asciiHost: asciiHost.contains("xn--") ? asciiHost : "")
    }

    /// Removes characters that change how surrounding text renders (bidi overrides/isolates, zero-width
    /// joiners, other format and control characters). Used for every page-supplied string RamPart shows.
    public static func sanitized(_ s: String, keepNewlines: Bool = false) -> String {
        String(String.UnicodeScalarView(s.unicodeScalars.filter { u in
            if keepNewlines, u == "\n" { return true }
            switch u.properties.generalCategory {
            case .format, .control, .lineSeparator, .paragraphSeparator, .privateUse, .unassigned, .surrogate: return false
            default: return true
            }
        }))
    }
}

/// Text RamPart shows about a page's origin in its own prompts (camera/mic, JS dialogs). Page-chosen
/// characters are stripped, punycode is shown decoded with its ASCII form, and an empty or opaque origin
/// (data:, sandboxed frames) is named plainly instead of leaving a blank where the site should be.
public enum PromptText {
    public static func origin(_ host: String) -> String {
        let h = DomainDisplay.sanitized(host.lowercased()).trimmingCharacters(in: .whitespacesAndNewlines)
        if h.isEmpty { return "A page with no web address" }
        if h.contains("xn--") { return "\(Punycode.decodeHost(h)) (\(h))" }
        return String(h.prefix(253))
    }
    /// Page-supplied dialog text: sanitized, capped at 1,000 characters.
    public static func message(_ s: String) -> String {
        let t = DomainDisplay.sanitized(s, keepNewlines: true)
        return t.count > 1000 ? String(t.prefix(1000)) + "…" : t
    }
}

/// A small, honest certificate summary for the identity sheet. Built from `SecTrust` on the WebKit side;
/// here only the data shape and the sentence that describes it, so it is testable.
public struct IdentitySummary: Equatable, Sendable {
    public var host: String
    public var encrypted: Bool
    public var subject: String?        // CN / organisation from the leaf certificate
    public var issuer: String?
    public var validUntil: Date?
    public var evaluatedOK: Bool        // system trust evaluation result as reported by WebKit
    public init(host: String, encrypted: Bool, subject: String? = nil, issuer: String? = nil, validUntil: Date? = nil, evaluatedOK: Bool = false) {
        self.host = host; self.encrypted = encrypted; self.subject = subject; self.issuer = issuer; self.validUntil = validUntil; self.evaluatedOK = evaluatedOK
    }
    public var headline: String {
        if !encrypted { return "Your connection to \(host) is not encrypted." }
        if !evaluatedOK { return "The certificate for \(host) could not be verified." }
        return "Your connection to \(host) is encrypted and the certificate is trusted by macOS."
    }
    public var caveat: String {
        "A padlock means the connection is private, not that the site is honest. Check that the domain is the one you expect."
    }
}

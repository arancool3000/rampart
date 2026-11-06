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
            return DomainDisplay(scheme: scheme, prefix: "", domain: full == "about:blank" ? "New tab" : full, suffixPath: "", identity: .local,
                                 fullText: full == "about:blank" ? "" : full)
        }
        let asciiHost = (url.host ?? "").lowercased()
        let unicodeHost = Punycode.decodeHost(asciiHost)
        let split = PublicSuffix.split(asciiHost)
        let registrableASCII = split?.registrable ?? asciiHost
        let registrable = Punycode.decodeHost(registrableASCII)
        let sub = asciiHost.hasSuffix(registrableASCII) && asciiHost.count > registrableASCII.count
            ? String(unicodeHost.dropLast(registrable.count)) : ""
        var pathPart = url.path
        if pathPart == "/" { pathPart = "" }
        if let q = url.query, !q.isEmpty { pathPart += "?" + q }
        if let port = url.port { pathPart = ":\(port)" + pathPart }

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
        return DomainDisplay(scheme: scheme, prefix: scheme + "://" + sub, domain: registrable, suffixPath: pathPart, identity: identity, fullText: full,
                             asciiHost: asciiHost.contains("xn--") ? asciiHost : "")
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

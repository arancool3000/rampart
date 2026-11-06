import Foundation

/// Cheap offline URL signals for the AI link explainer when RampartWeb's full analyser isn't wired in.
public enum URLLocalSignals {
    static let shorteners: Set<String> = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "s.id", "rb.gy", "t.ly"]
    static let riskyTLDs: Set<String> = ["zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "support", "cam", "icu"]
    static let lures = ["login", "signin", "verify", "account", "update", "secure", "wallet", "password", "billing", "support", "unlock", "recover"]
    static let brands = ["apple", "icloud", "paypal", "microsoft", "google", "amazon", "netflix", "bank", "coinbase", "binance", "dhl", "fedex", "usps", "royalmail"]

    public static func basic(_ raw: String) -> [String] {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let c = URLComponents(string: s.contains("://") ? s : "https://" + s), let host = c.host?.lowercased(), !host.isEmpty else {
            return ["Couldn't parse this as a web address"]
        }
        var out: [String] = []
        if c.scheme == "http" { out.append("Uses unencrypted http://") }
        if host.split(separator: ".").allSatisfy({ Int($0) != nil }) || host.contains(":") { out.append("Host is a raw IP address, not a domain name") }
        if host.contains("xn--") { out.append("Punycode (internationalised) domain: possible lookalike letters") }
        if c.user != nil || s.contains("@") && s.range(of: "@")!.lowerBound < (s.range(of: host)?.lowerBound ?? s.endIndex) { out.append("Contains '@' before the host, which can hide the real destination") }
        let labels = host.split(separator: ".")
        if labels.count >= 5 { out.append("Many subdomains (\(labels.count - 2)), common in disguised links") }
        if let tld = labels.last, riskyTLDs.contains(String(tld)) { out.append("Top-level domain .\(tld) is frequently abused") }
        if shorteners.contains(host) { out.append("Link shortener hides the final destination") }
        if host.filter({ $0 == "-" }).count >= 3 { out.append("Many hyphens in the domain") }
        let full = (host + c.path).lowercased()
        let lure = lures.filter { full.contains($0) }
        if !lure.isEmpty { out.append("Credential/urgency words in the address: \(lure.prefix(3).joined(separator: ", "))") }
        let registrable = labels.suffix(2).joined(separator: ".")
        if let brand = brands.first(where: { host.contains($0) && !registrable.hasPrefix($0) }) { out.append("Mentions \(brand) but the actual domain is \(registrable)") }
        if s.count > 200 { out.append("Very long address (\(s.count) characters)") }
        return out
    }
}

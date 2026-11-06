import Foundation

/// Parses a URL leniently (people paste "paypal-secure.test/login" without a scheme) and scores
/// its structure and host against the brand list. Pure and synchronous; reputation providers
/// are optional and injected.
public struct ParsedURL: Hashable, Sendable {
    public var original: String
    public var scheme: String            // lowercased; "" when absent
    public var userInfo: String?
    public var asciiHost: String         // lowercased, punycode form
    public var unicodeHost: String       // punycode-decoded for display
    public var port: Int?
    public var path: String
    public var query: String?
    public var isIPLiteral: Bool
    public var registrable: String?      // e.g. "paypal.co.uk"
    public var registrableLabel: String? // e.g. "paypal"
    public var suffix: String?           // e.g. "co.uk"
    public var labels: [String] { asciiHost.split(separator: ".").map(String.init) }
    public var subdomainLabels: [String] {
        guard let r = registrable, asciiHost.hasSuffix(r), asciiHost.count > r.count else { return [] }
        return String(asciiHost.dropLast(r.count + 1)).split(separator: ".").map(String.init)
    }
}

public struct URLAnalyzer: Sendable {
    public var blocklists: [any WebBlocklistProvider]
    public var seenDomains: (any SeenDomainStore)?
    public var allowlist: (any WebAllowlist)?

    public init(blocklists: [any WebBlocklistProvider] = [], seenDomains: (any SeenDomainStore)? = nil, allowlist: (any WebAllowlist)? = nil) {
        self.blocklists = blocklists; self.seenDomains = seenDomains; self.allowlist = allowlist
    }

    // MARK: Parsing

    public static let shorteners: Set<String> = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
        "tiny.cc", "t.ly", "s.id", "lnkd.in", "rebrand.ly", "bl.ink", "short.io", "clck.ru", "v.gd", "qr.ae", "u.to",
        "x.co", "1url.com", "tr.im", "snip.ly", "shorte.st", "adf.ly", "bc.vc", "ouo.io", "han.gl", "urlz.fr", "surl.li",
    ]
    public static let riskyTLDs: Set<String> = [
        "zip", "mov", "top", "xyz", "icu", "cfd", "sbs", "rest", "click", "link", "work", "buzz", "monster", "quest", "cyou",
        "tk", "ml", "ga", "cf", "gq", "pw", "cc", "ws", "su", "ru", "cn", "cam", "bond", "lol", "fun", "life", "today", "win",
        "bid", "loan", "men", "party", "racing", "review", "stream", "trade", "date", "download", "gdn", "kim", "science",
        "support", "live", "online", "site", "website", "shop", "store", "vip", "wang", "pro", "autos", "boats", "yachts",
        "homes", "motorcycles", "hair", "skin", "beauty", "makeup", "lat", "ink", "biz", "info", "cloud", "digital", "ltd",
        "pics", "surf", "fit", "firm", "tokyo", "cfd", "one", "best", "mom",
    ]
    static let bareDomainRegex = try! NSRegularExpression(pattern: #"^(?:[a-z0-9¡-￿-]+\.)+[a-z¡-￿]{2,}(?::\d+)?(?:[/?#].*)?$"#, options: [.caseInsensitive])

    /// Lenient parse. Returns nil if the string is not URL-like at all.
    public static func parse(_ raw: String) -> ParsedURL? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // Strip common wrappers: <...>, (...), trailing punctuation.
        while let f = s.first, "<([\"'“".contains(f) { s.removeFirst() }
        while let l = s.last, ">)]\"'”.,;:!".contains(l) { s.removeLast() }
        guard !s.isEmpty else { return nil }
        // De-obfuscate "hxxp://", "example[.]com".
        s = s.replacingOccurrences(of: "[.]", with: ".").replacingOccurrences(of: "(.)", with: ".")
        if s.lowercased().hasPrefix("hxxp") { s = "http" + s.dropFirst(4) }

        var scheme = ""
        var rest = Substring(s)
        if let r = s.range(of: ":"), s[s.startIndex..<r.lowerBound].allSatisfy({ $0.isLetter || $0.isNumber || $0 == "+" || $0 == "-" || $0 == "." }),
           !s[s.startIndex..<r.lowerBound].isEmpty, !s[s.startIndex..<r.lowerBound].allSatisfy(\.isNumber) {
            scheme = String(s[s.startIndex..<r.lowerBound]).lowercased()
            rest = s[r.upperBound...]
            if rest.hasPrefix("//") { rest = rest.dropFirst(2) }
        } else {
            let ns = s as NSString
            guard bareDomainRegex.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) != nil
                || s.hasPrefix("www.") || isIPv4(String(s.prefix { $0 != "/" && $0 != ":" })) else { return nil }
        }
        if scheme == "data" || scheme == "javascript" || scheme == "mailto" || scheme == "tel" || scheme == "sms" {
            return ParsedURL(original: raw, scheme: scheme, userInfo: nil, asciiHost: "", unicodeHost: "", port: nil,
                             path: String(rest), query: nil, isIPLiteral: false, registrable: nil, registrableLabel: nil, suffix: nil)
        }
        // authority
        let authorityEnd = rest.firstIndex(where: { "/?#".contains($0) }) ?? rest.endIndex
        var authority = String(rest[..<authorityEnd])
        let tail = String(rest[authorityEnd...])
        var userInfo: String? = nil
        if let at = authority.lastIndex(of: "@") {
            userInfo = String(authority[..<at]); authority = String(authority[authority.index(after: at)...])
        }
        var port: Int? = nil
        var hostPart = authority
        if hostPart.hasPrefix("[") , let close = hostPart.firstIndex(of: "]") {   // IPv6
            let h = String(hostPart[hostPart.index(after: hostPart.startIndex)..<close])
            let after = hostPart[hostPart.index(after: close)...]
            if after.hasPrefix(":") { port = Int(after.dropFirst()) }
            return ParsedURL(original: raw, scheme: scheme, userInfo: userInfo, asciiHost: h, unicodeHost: h, port: port,
                             path: tail, query: nil, isIPLiteral: true, registrable: nil, registrableLabel: nil, suffix: nil)
        }
        if let colon = hostPart.lastIndex(of: ":") {
            port = Int(hostPart[hostPart.index(after: colon)...]); hostPart = String(hostPart[..<colon])
        }
        var host = hostPart.lowercased()
        while host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty else { return nil }
        let unicode = Punycode.decodeHost(host)
        let ascii = Punycode.encodeHost(unicode)
        let ip = isIPv4(ascii)
        let split = ip ? nil : PublicSuffix.split(ascii)
        var path = tail, query: String? = nil
        if let q = tail.firstIndex(of: "?") { path = String(tail[..<q]); query = String(tail[tail.index(after: q)...]) }
        return ParsedURL(original: raw, scheme: scheme, userInfo: userInfo, asciiHost: ascii, unicodeHost: unicode, port: port,
                         path: path, query: query, isIPLiteral: ip, registrable: split?.registrable,
                         registrableLabel: split?.label, suffix: split?.suffix)
    }

    static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) && Int($0)! <= 255 }
    }

    // MARK: Analysis

    public func analyze(_ raw: String) -> URLReport {
        guard let u = URLAnalyzer.parse(raw) else {
            return URLReport(original: raw, host: nil, asciiHost: nil, registrableDomain: nil, verdict: .likelySafe, score: 0, signals: [], brandMatch: nil)
        }
        return analyze(u)
    }

    public func analyze(_ u: ParsedURL) -> URLReport {
        var signals: [ScamSignal] = []
        var brand: String? = nil
        let hostHL = ScamHighlight(text: u.unicodeHost.isEmpty ? u.original : u.unicodeHost, kind: .domain)

        if let allowlist, !u.asciiHost.isEmpty, allowlist.isAllowed(host: u.asciiHost) {
            return URLReport(original: u.original, host: u.unicodeHost, asciiHost: u.asciiHost, registrableDomain: u.registrable,
                             verdict: .likelySafe, score: 0, signals: [ScamSignal(id: "url.allowlisted", category: .benign, title: "You trusted this site",
                             explanation: "You chose to continue to this site before, so RamPart doesn't warn about it.", score: 0)], brandMatch: nil)
        }

        // Dangerous schemes
        switch u.scheme {
        case "javascript":
            signals.append(ScamSignal(id: "url.scheme.javascript", category: .urlStructure, title: "Runs code instead of opening a page",
                                      explanation: "A javascript: link executes script in the current page. Legitimate links never need this.", score: 85, evidence: [ScamHighlight(text: u.original, kind: .link)]))
        case "data":
            signals.append(ScamSignal(id: "url.scheme.data", category: .urlStructure, title: "Page embedded inside the link",
                                      explanation: "A data: link carries a whole hidden page inside it, a common way to host a fake login form with no server to take down.", score: 80, evidence: [ScamHighlight(text: String(u.original.prefix(60)), kind: .link)]))
        default: break
        }
        if u.asciiHost.isEmpty {
            return finish(u, signals, brand)
        }

        // Structure
        if u.isIPLiteral {
            signals.append(ScamSignal(id: "url.ip", category: .urlStructure, title: "Uses a raw IP address instead of a name",
                                      explanation: "Real companies use their domain name. Raw addresses hide who owns the site.", score: 45, evidence: [hostHL]))
        }
        if let ui = u.userInfo, !ui.isEmpty {
            signals.append(ScamSignal(id: "url.userinfo", category: .urlStructure, title: "Hidden destination after an @ sign",
                                      explanation: "Everything before the @ is ignored by the browser. The link looks like \(ui.prefix(40)) but actually goes to \(u.unicodeHost).", score: 75, evidence: [ScamHighlight(text: "@" + u.unicodeHost, kind: .link)]))
        }
        if u.scheme == "http" && !u.isIPLiteral {
            signals.append(ScamSignal(id: "url.http", category: .urlStructure, title: "Not encrypted (http://)",
                                      explanation: "Anything you type here can be read on the way. Sign-in pages should always use https://.", score: 15, evidence: [ScamHighlight(text: "http://", kind: .link)]))
        }
        if let port = u.port, ![80, 443].contains(port) {
            signals.append(ScamSignal(id: "url.port", category: .urlStructure, title: "Unusual port \(port)",
                                      explanation: "Public websites almost never use a custom port.", score: 20, evidence: [ScamHighlight(text: ":\(port)", kind: .link)]))
        }
        let subs = u.subdomainLabels
        if subs.count >= 3 {
            signals.append(ScamSignal(id: "url.subdomains", category: .urlStructure, title: "Many nested subdomains",
                                      explanation: "\(subs.count) subdomains in front of \(u.registrable ?? u.unicodeHost) suggest an attempt to push a real-looking name into view and the real domain out of it.", score: 25, evidence: [hostHL]))
        }
        if u.asciiHost.count > 50 {
            signals.append(ScamSignal(id: "url.longhost", category: .urlStructure, title: "Very long address",
                                      explanation: "Long hostnames hide the real domain on phones.", score: 15, evidence: [hostHL]))
        }
        if let r = u.registrable, URLAnalyzer.shorteners.contains(r) {
            signals.append(ScamSignal(id: "url.shortener", category: .urlStructure, title: "Shortened link",
                                      explanation: "You can't see where a \(r) link goes until you open it. Scammers use shorteners to hide their real site.", score: 30, evidence: [hostHL]))
        }
        if let suffix = u.suffix, let tld = suffix.split(separator: ".").last, URLAnalyzer.riskyTLDs.contains(String(tld)),
           !(u.registrable.map(BrandList.isLegitimate) ?? false) {
            signals.append(ScamSignal(id: "url.tld", category: .urlStructure, title: "Cheap or frequently abused domain ending (.\(tld))",
                                      explanation: "This ending is popular with throwaway scam sites because it is cheap or free to register.", score: 20, evidence: [hostHL]))
        }
        if let r = u.registrable, PublicSuffix.sharedHostingSuffixes.contains(r) {
            signals.append(ScamSignal(id: "url.sharedhosting", category: .urlStructure, title: "Free hosting page",
                                      explanation: "Anyone can publish under \(r). Companies don't put their sign-in pages here.", score: 15, evidence: [hostHL]))
        }
        if u.query?.contains("redirect") == true || u.query?.contains("url=http") == true || u.query?.contains("next=http") == true {
            signals.append(ScamSignal(id: "url.redirect", category: .urlStructure, title: "Redirects somewhere else",
                                      explanation: "The link forwards to another address hidden in its parameters.", score: 20, evidence: [ScamHighlight(text: "?" + (u.query ?? "").prefix(50), kind: .link)]))
        }
        let pathLower = (u.path + "?" + (u.query ?? "")).lowercased()
        let loginWords = ["login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "confirm", "wallet", "unlock", "suspended", "billing", "invoice", "password", "recover", "auth"]
        let pathHits = loginWords.filter { pathLower.contains($0) }
        if !pathHits.isEmpty, !(u.registrable.map(BrandList.isLegitimate) ?? false) {
            signals.append(ScamSignal(id: "url.path.login", category: .urlStructure, title: "Sign-in or verification words in the path",
                                      explanation: "The address mentions \(pathHits.prefix(3).joined(separator: ", ")) on a domain that isn't the company's own.", score: 12, evidence: [ScamHighlight(text: u.path, kind: .link)]))
        }
        if pathLower.hasSuffix(".exe") || pathLower.hasSuffix(".dmg") || pathLower.hasSuffix(".pkg") || pathLower.hasSuffix(".scr") || pathLower.hasSuffix(".msi") || pathLower.hasSuffix(".apk") {
            signals.append(ScamSignal(id: "url.download", category: .urlStructure, title: "Links straight to an installer",
                                      explanation: "Only download software from the maker's own site or the App Store.", score: 25, evidence: [ScamHighlight(text: u.path, kind: .link)]))
        }

        // Lookalikes
        if !u.isIPLiteral, let r = u.registrable, let label = u.registrableLabel {
            let look = URLAnalyzer.lookalike(host: u.asciiHost, unicodeHost: u.unicodeHost, registrable: r, label: label, subdomains: subs)
            signals += look.signals
            brand = look.brand
        }

        // Reputation
        for bl in blocklists {
            if let hit = bl.lookup(url: u.original) ?? bl.lookup(host: u.asciiHost) {
                signals.append(ScamSignal(id: "url.blocklist", category: .blocklist, title: "On a known-bad list",
                                          explanation: "\(hit.source) lists \(hit.rule)\(hit.category.map { " as \($0)" } ?? "").", score: 95, evidence: [hostHL]))
                break
            }
        }
        if let store = seenDomains, let r = u.registrable, !BrandList.isLegitimate(registrableDomain: r) {
            let first = store.firstSeen(r)
            if Date().timeIntervalSince(first) < 60 {
                signals.append(ScamSignal(id: "url.newlyseen", category: .domainReputation, title: "First time this Mac sees this domain",
                                          explanation: "Not bad by itself; new sites are new to everyone once. It matters when combined with other warning signs.", score: 8, evidence: [hostHL]))
            }
        }

        return finish(u, signals, brand)
    }

    private func finish(_ u: ParsedURL, _ signals: [ScamSignal], _ brand: String?) -> URLReport {
        let score = ScamScoring.combine(signals)
        return URLReport(original: u.original, host: u.unicodeHost.isEmpty ? nil : u.unicodeHost, asciiHost: u.asciiHost.isEmpty ? nil : u.asciiHost,
                         registrableDomain: u.registrable, verdict: ScamVerdict.from(score: score), score: score,
                         signals: signals.sorted { $0.score > $1.score }, brandMatch: brand)
    }

    // MARK: Lookalike detection

    struct LookalikeResult { var signals: [ScamSignal] = []; var brand: String? = nil }

    /// Words scammers glue onto brand names. A brand embedded without separators only counts when
    /// what's left over is made of these (secureappleid → secure + apple + id; pineapple → pine, no).
    static let affixes: Set<String> = ["secure", "security", "login", "logon", "signin", "sign", "id", "ids", "verify", "verification", "account", "accounts", "support", "update", "updates", "billing", "help", "helpdesk", "service", "services", "pay", "payment", "payments", "my", "online", "auth", "center", "centre", "team", "alert", "alerts", "notice", "official", "store", "app", "apps", "mail", "web", "net", "info", "admin", "check", "confirm", "portal", "access", "wallet", "claim", "bonus", "gift", "reward", "rewards", "refund", "invoice", "order", "orders", "delivery", "tracking", "track", "parcel", "fee", "fees", "toll", "tax", "customer", "client", "user", "users", "password", "reset", "recovery", "unlock", "locked", "limited", "suspended", "review", "case", "dispute", "resolution", "desk", "care", "us", "uk", "ca", "au", "de", "fr", "eu", "the", "get", "go", "now", "new", "safe", "safety", "protect", "protection", "device", "devices", "sync", "validate", "validation", "migration", "upgrade", "connect", "airdrop", "nft", "drop", "cloud", "drive", "mobile", "banking", "bank", "card", "cards", "shop", "shopping", "prime", "video", "music", "tv", "plus", "pro", "premium", "member", "members", "membership", "renew", "renewal", "subscription", "cancel", "notification", "notifications", "manage", "settings", "status", "activity", "redelivery", "reschedule", "schedule", "customs", "shipment", "shipping", "express", "post", "www", "web3", "defi", "stake", "staking", "mint", "voucher"]

    static func remainderIsAffixes(_ folded: String, keyword: String) -> Bool {
        guard let r = folded.range(of: keyword) else { return false }
        let before = String(folded[..<r.lowerBound]), after = String(folded[r.upperBound...])
        func ok(_ s: String) -> Bool {
            if s.isEmpty { return true }
            for i in (1...s.count).reversed() {
                let head = String(s.prefix(i))
                if affixes.contains(head), ok(String(s.dropFirst(i))) { return true }
            }
            return false
        }
        return ok(before) && ok(after)
    }

    static func lookalike(host: String, unicodeHost: String, registrable: String, label: String, subdomains: [String]) -> LookalikeResult {
        var r = LookalikeResult()
        if BrandList.isLegitimate(registrableDomain: registrable) { return r }
        let hostHL = ScamHighlight(text: unicodeHost, kind: .domain)
        let uniLabel = PublicSuffix.split(unicodeHost)?.label ?? label

        // 1. Homographs: punycode / non-ASCII / mixed script in the registrable label.
        if Confusables.hasNonASCII(uniLabel) {
            let skel = Confusables.skeleton(uniLabel)
            let mixed = Confusables.isMixedScript(uniLabel)
            if let b = brandFor(skeleton: skel) {
                r.brand = b.name
                r.signals.append(ScamSignal(id: "url.homograph", category: .lookalike, title: "Looks like \(b.name) but uses foreign letters",
                                            explanation: "“\(uniLabel)” is spelled with characters from another alphabet so it looks like “\(skel)”. The real address is \(b.domains[0]). In the address bar it may appear as \(host).", score: 92, evidence: [hostHL]))
                return r
            }
            if mixed {
                r.signals.append(ScamSignal(id: "url.mixedscript", category: .lookalike, title: "Mixes alphabets in the domain name",
                                            explanation: "The name combines Latin letters with look-alike letters from another script (\(host)). Genuine international domains don't do this.", score: 55, evidence: [hostHL]))
            }
        }

        // 2. Exact brand keyword on a non-brand registrable domain (wrong TLD / combosquat).
        let folded = Confusables.typoFold(Confusables.skeleton(uniLabel))
        let tokens = folded.split(whereSeparator: { $0 == "-" || $0 == "_" }).map(String.init)
        for t in tokens {
            if let b = BrandList.brand(forKeyword: t), t.count >= 3 {
                r.brand = b.name
                let isWholeLabel = tokens.count == 1
                let digitsSwapped = folded != uniLabel.lowercased()
                let id = isWholeLabel ? (digitsSwapped ? "url.typosquat.digits" : "url.wrongtld") : "url.combosquat"
                let title = isWholeLabel ? (digitsSwapped ? "Imitates \(b.name) with swapped characters" : "\(b.name) name on the wrong domain ending")
                                         : "\(b.name) name combined with extra words"
                let expl = isWholeLabel
                    ? (digitsSwapped ? "“\(uniLabel)” swaps letters for look-alike digits or letters to imitate “\(t)”. \(b.name)'s real site is \(b.domains[0])."
                                     : "“\(registrable)” is not a \(b.name) domain. \(b.name)'s real site is \(b.domains[0]).")
                    : "“\(registrable)” adds words around the \(b.name) name. Scammers register names like this because the real one is taken. \(b.name)'s real site is \(b.domains[0])."
                let suffix = PublicSuffix.split(registrable)?.suffix ?? ""
                let ccTLD = suffix.count == 2 || suffix.hasSuffix(".uk") || suffix.hasSuffix(".au") || suffix.hasSuffix(".nz") || suffix.hasSuffix(".jp") || suffix.hasSuffix(".br") || suffix.hasSuffix(".in") || suffix.hasSuffix(".za")
                let score = id == "url.wrongtld" ? (ccTLD && !URLAnalyzer.riskyTLDs.contains(suffix) ? 45 : 80) : (isWholeLabel ? 80 : 75)
                r.signals.append(ScamSignal(id: id, category: .lookalike, title: title, explanation: ccTLD && id == "url.wrongtld" ? expl + " Some companies do own country-specific domains, so this may be fine; check the site carefully." : expl, score: score, evidence: [hostHL]))
                return r
            }
        }
        // Brand embedded without separators ("paypalsecure", "secure-paypal-login", "appleid-verify").
        for b in BrandList.brands {
            for k in b.keywords where k.count >= 5 && folded.contains(k) && folded != k && remainderIsAffixes(folded, keyword: k) {
                r.brand = b.name
                r.signals.append(ScamSignal(id: "url.combosquat", category: .lookalike, title: "\(b.name) name combined with extra words",
                                            explanation: "“\(registrable)” contains the \(b.name) name with extra words. \(b.name)'s real site is \(b.domains[0]).", score: 75, evidence: [hostHL]))
                return r
            }
        }

        // 3. Typosquats: small edit distance to a brand keyword.
        if folded.count >= 4 {
            var best: (Brand, String, Int)? = nil
            let candidates = tokens.count > 1 ? tokens.filter { $0.count >= 4 && !affixes.contains($0) } : [folded]
            let otherTokensAreAffixes = tokens.count == 1 || tokens.filter { !affixes.contains($0) }.count <= 1
            for cand in candidates where otherTokensAreAffixes {
                for b in BrandList.brands {
                    for k in b.keywords where k.count >= 4 {
                        let maxDist = k.count >= 8 ? 2 : 1
                        // Short names: only substitutions/transpositions (chaser is not chase).
                        if k.count < 7, cand.count != k.count { continue }
                        if abs(k.count - cand.count) > maxDist { continue }
                        let d = editDistance(cand, k)
                        if d > 0, d <= maxDist, best == nil || d < best!.2 { best = (b, k, d) }
                    }
                }
            }
            if let (b, k, d) = best {
                r.brand = b.name
                r.signals.append(ScamSignal(id: "url.typosquat", category: .lookalike, title: "One letter away from \(b.name)",
                                            explanation: "“\(uniLabel)” differs from “\(k)” by \(d) character\(d == 1 ? "" : "s"). \(b.name)'s real site is \(b.domains[0]).", score: 70, evidence: [hostHL]))
                return r
            }
        }

        // 4. Brand in a subdomain of an unrelated domain (login.apple.com.evil.test).
        for s in subdomains {
            let sf = Confusables.typoFold(Confusables.skeleton(s))
            for t in sf.split(whereSeparator: { $0 == "-" || $0 == "_" }).map(String.init) {
                if let b = BrandList.brand(forKeyword: t), t.count >= 3 {
                    r.brand = b.name
                    r.signals.append(ScamSignal(id: "url.brandsubdomain", category: .lookalike, title: "\(b.name) name hidden in a subdomain",
                                                explanation: "The site is really \(registrable). “\(s)” is just a label its owner chose. \(b.name)'s real site is \(b.domains[0]).", score: 80, evidence: [hostHL]))
                    return r
                }
            }
        }
        return r
    }

    static func brandFor(skeleton: String) -> Brand? {
        let folded = Confusables.typoFold(skeleton)
        if let b = BrandList.brand(forKeyword: folded) { return b }
        for b in BrandList.brands { for k in b.keywords where k.count >= 4 && editDistance(folded, k) <= 1 { return b } }
        return nil
    }

    /// Damerau-Levenshtein (adjacent transpositions count as one edit).
    public static func editDistance(_ a: String, _ b: String) -> Int {
        let a = Array(a.unicodeScalars), b = Array(b.unicodeScalars)
        if a.isEmpty { return b.count }; if b.isEmpty { return a.count }
        var d = [[Int]](repeating: [Int](repeating: 0, count: b.count + 1), count: a.count + 1)
        for i in 0...a.count { d[i][0] = i }
        for j in 0...b.count { d[0][j] = j }
        for i in 1...a.count {
            for j in 1...b.count {
                let cost = a[i - 1] == b[j - 1] ? 0 : 1
                d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
                if i > 1, j > 1, a[i - 1] == b[j - 2], a[i - 2] == b[j - 1] { d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1) }
            }
        }
        return d[a.count][b.count]
    }
}

// MARK: - Default stores

/// JSON-file-backed store of first-seen dates per registrable domain, under the per-user support folder.
public final class FileSeenDomainStore: SeenDomainStore, @unchecked Sendable {
    private let lock = NSLock()
    private var map: [String: Date]
    private let url: URL
    private var dirty = false
    public var count: Int { lock.lock(); defer { lock.unlock() }; return map.count }

    public init(url: URL) {
        self.url = url
        if let d = try? Data(contentsOf: url), let m = try? JSONDecoder.rampart.decode([String: Date].self, from: d) { map = m } else { map = [:] }
    }
    public convenience init() {
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Rampart/Web")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.init(url: dir.appendingPathComponent("seen-domains.json"))
    }
    public func firstSeen(_ registrableDomain: String) -> Date {
        lock.lock(); defer { lock.unlock() }
        if let d = map[registrableDomain] { return d }
        let now = Date(); map[registrableDomain] = now; dirty = true
        if map.count % 20 == 0 { flushLocked() }
        return now
    }
    public func flush() { lock.lock(); defer { lock.unlock() }; flushLocked() }
    private func flushLocked() {
        guard dirty, let d = try? JSONEncoder.rampart.encode(map) else { return }
        try? d.write(to: url, options: .atomic); dirty = false
    }
}

/// In-memory seen-domain store for tests.
public final class MemorySeenDomainStore: SeenDomainStore, @unchecked Sendable {
    private let lock = NSLock(); private var map: [String: Date] = [:]
    public init(preseeded: [String] = []) { let past = Date(timeIntervalSinceNow: -86400 * 30); for d in preseeded { map[d] = past } }
    public var count: Int { lock.lock(); defer { lock.unlock() }; return map.count }
    public func firstSeen(_ r: String) -> Date { lock.lock(); defer { lock.unlock() }; if let d = map[r] { return d }; let n = Date(); map[r] = n; return n }
}

/// Simple file-backed allowlist (one host per line) plus in-memory additions.
public final class FileWebAllowlist: WebAllowlist, @unchecked Sendable {
    private let lock = NSLock(); private var hosts: Set<String>; private let url: URL?
    public init(url: URL?) {
        self.url = url
        if let url, let s = try? String(contentsOf: url, encoding: .utf8) {
            hosts = Set(s.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty && !$0.hasPrefix("#") })
        } else { hosts = [] }
    }
    public convenience init() {
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Rampart/Web")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.init(url: dir.appendingPathComponent("allowlist.txt"))
    }
    public func isAllowed(host: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        var h = host.lowercased()
        while true {
            if hosts.contains(h) { return true }
            guard let dot = h.firstIndex(of: ".") else { return false }
            h = String(h[h.index(after: dot)...])
            if !h.contains(".") { return false }
        }
    }
    public func allow(host: String) {
        lock.lock(); defer { lock.unlock() }
        hosts.insert(host.lowercased())
        if let url { try? hosts.sorted().joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8) }
    }
}

/// Blocklist provider backed by a plain text file of domains (one per line, `#` comments, hosts-file lines tolerated).
public final class FileBlocklistProvider: WebBlocklistProvider, @unchecked Sendable {
    public let name: String
    private let domains: Set<String>
    public init(name: String, domains: Set<String>) { self.name = name; self.domains = domains }
    public convenience init(name: String, fileURL: URL) {
        var set = Set<String>()
        if let s = try? String(contentsOf: fileURL, encoding: .utf8) {
            for line in s.split(separator: "\n") {
                var l = line.trimmingCharacters(in: .whitespaces).lowercased()
                if l.isEmpty || l.hasPrefix("#") || l.hasPrefix("!") { continue }
                if l.hasPrefix("||") { l = String(l.dropFirst(2)); if l.hasSuffix("^") { l.removeLast() } }
                let parts = l.split(separator: " ", omittingEmptySubsequences: true)
                if parts.count >= 2, parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" { l = String(parts[1]) }
                if l.hasPrefix("*.") { l.removeFirst(2) }
                if l.contains(".") { set.insert(l) }
            }
        }
        self.init(name: name, domains: set)
    }
    public var count: Int { domains.count }
    public func lookup(host: String) -> BlocklistHit? {
        var h = host.lowercased()
        while true {
            if domains.contains(h) { return BlocklistHit(rule: h, source: name) }
            guard let dot = h.firstIndex(of: ".") else { return nil }
            h = String(h[h.index(after: dot)...])
            if !h.contains(".") { return nil }
        }
    }
}

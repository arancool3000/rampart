import Foundation

/// The Scam Check engine. Entry points:
///  - `check(_ input:)` auto-detects whether the pasted thing is a URL, an email (raw headers) or a message.
///  - `checkMessage`, `checkURL`, `checkEmail`, `checkPage` for explicit kinds.
/// Everything is synchronous and offline. `withAI(_:)` adds an optional second opinion afterwards.
public struct ScamChecker: Sendable {
    public var urls: URLAnalyzer
    public var pages: PageAnalyzer
    public init(urls: URLAnalyzer = URLAnalyzer(), pages: PageAnalyzer = PageAnalyzer()) { self.urls = urls; self.pages = pages }

    // MARK: Dispatch

    public static func detectKind(_ input: String) -> ScamInputKind {
        let t = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if ParsedEmail.looksLikeRawEmail(t) { return .email }
        if !t.contains(where: \.isWhitespace), URLAnalyzer.parse(t) != nil { return .url }
        if t.lowercased().hasPrefix("<!doctype html") || t.lowercased().hasPrefix("<html") { return .page }
        return .message
    }

    public func check(_ input: String) -> ScamReport {
        switch ScamChecker.detectKind(input) {
        case .url: return checkURL(input)
        case .email: return checkEmail(raw: input)
        case .page: return checkPage(url: nil, html: input, signals: nil)
        case .message: return checkMessage(input)
        }
    }

    // MARK: URL

    public func checkURL(_ raw: String) -> ScamReport {
        let r = urls.analyze(raw)
        let lang = "en"
        var signals = r.signals
        if signals.isEmpty { signals.append(benign("url.nosignals", "No warning signs in the address", "The address itself looks ordinary. That doesn't prove the site is honest, only that it isn't trying to look like someone else.")) }
        return build(kind: .url, text: raw, signals: signals, urls: [r], language: lang)
    }

    // MARK: Message

    public func checkMessage(_ text: String, html: String? = nil, language: String? = nil) -> ScamReport {
        let lang = language ?? LexiconRegistry.detectLanguage(text)
        var signals = ScamChecker.textSignals(text, language: lang)
        let (links, mismatches) = ScamChecker.extractLinks(text: text, html: html)
        signals += mismatches
        let urlReports = links.map { urls.analyze($0) }
        signals += ScamChecker.liftURLSignals(urlReports)
        signals += ScamChecker.structuralSignals(text, linkCount: links.count)
        return build(kind: .message, text: text, signals: signals, urls: urlReports, language: lang)
    }

    // MARK: Email

    public func checkEmail(raw: String) -> ScamReport {
        let mail = ParsedEmail(raw: raw)
        return checkEmail(mail)
    }

    public func checkEmail(_ mail: ParsedEmail) -> ScamReport {
        let body = mail.plainText
        let lang = LexiconRegistry.detectLanguage(body.isEmpty ? mail.subject : body)
        let analysed = (mail.subject.isEmpty ? "" : "Subject: " + mail.subject + "\n\n") + body
        var signals = ScamChecker.textSignals(analysed, language: lang)
        signals += ScamChecker.headerSignals(mail)
        let (links, mismatches) = ScamChecker.extractLinks(text: body, html: mail.html)
        signals += mismatches
        let urlReports = links.map { urls.analyze($0) }
        signals += ScamChecker.liftURLSignals(urlReports)
        signals += ScamChecker.structuralSignals(analysed, linkCount: links.count)
        if !mail.attachments.isEmpty {
            let risky = mail.attachments.filter { a in ["zip", "iso", "img", "dmg", "pkg", "exe", "scr", "js", "vbs", "hta", "lnk", "html", "htm", "shtml", "one", "docm", "xlsm"].contains((a as NSString).pathExtension.lowercased()) }
            if !risky.isEmpty {
                signals.append(ScamSignal(id: "email.attachment", category: .link, title: "Risky attachment type",
                                          explanation: "Attachments like \(risky.prefix(2).joined(separator: ", ")) can run code or open fake sign-in pages. Don't open them unless you expected exactly this file from this person.", score: 45,
                                          evidence: risky.map { ScamHighlight(text: $0, kind: .link) }))
            }
        }
        return build(kind: .email, text: analysed, signals: signals, urls: urlReports, language: lang)
    }

    // MARK: Page

    public func checkPage(url: String?, html: String?, signals pageSignals: PageSignals?) -> ScamReport {
        var signals: [ScamSignal] = []
        var urlReports: [URLReport] = []
        var brand: String? = nil
        var parsed: ParsedURL? = nil
        if let url, let p = URLAnalyzer.parse(url) {
            parsed = p
            let r = urls.analyze(p)
            urlReports.append(r)
            signals += r.signals
            brand = r.brandMatch
        }
        let pageResult = pages.analyze(url: parsed, html: html, signals: pageSignals, brandFromURL: brand)
        signals += pageResult
        let text = pageSignals?.visibleText ?? (html.map(PageAnalyzer.visibleText) ?? "")
        return build(kind: .page, text: text, signals: signals, urls: urlReports, language: "en")
    }

    // MARK: AI hook

    /// Adds an AI second opinion to an existing report. Never changes the offline verdict; the UI shows both.
    public func withAI(_ report: ScamReport, input: String, assessor: any ScamAIAssessor) async throws -> ScamReport {
        var r = report
        r.aiOpinion = try await assessor.assess(input: input, kind: report.kind, offlineReport: report)
        return r
    }

    // MARK: Building

    private func benign(_ id: String, _ title: String, _ explanation: String) -> ScamSignal {
        ScamSignal(id: id, category: .benign, title: title, explanation: explanation, score: 0)
    }

    private func build(kind: ScamInputKind, text: String, signals: [ScamSignal], urls: [URLReport], language: String) -> ScamReport {
        let sorted = signals.sorted { ($0.score, $0.title) > ($1.score, $1.title) }
        let score = ScamScoring.combine(sorted)
        let verdict = ScamVerdict.from(score: score)
        let lexicon = LexiconRegistry.pack(for: language) ?? .english
        var tips: [String] = []
        for s in sorted where s.score >= 20 { if let t = lexicon.tips[s.category], !tips.contains(t) { tips.append(t) } }
        if tips.isEmpty {
            tips = verdict == .likelySafe
                ? ["Nothing here looks like a known scam pattern. Still, if it asks for money or a password, check with the organisation through a channel you already trust."]
                : ["When in doubt, don't click, don't pay, don't reply. Contact the organisation through its official app or website instead."]
        }
        return ScamReport(kind: kind, verdict: verdict, score: score, headline: ScamChecker.headline(kind: kind, verdict: verdict, signals: sorted),
                          signals: sorted, urls: urls, language: language, tips: Array(tips.prefix(4)), analysedText: text)
    }

    static func headline(kind: ScamInputKind, verdict: ScamVerdict, signals: [ScamSignal]) -> String {
        let strong = signals.filter { $0.score >= 30 }.prefix(2).map { $0.title.lowercased() }
        let subject: String
        switch kind {
        case .message: subject = "This message"
        case .url: subject = "This link"
        case .email: subject = "This email"
        case .page: subject = "This page"
        }
        switch verdict {
        case .likelySafe:
            return "\(subject) shows no strong signs of a scam."
        case .suspicious:
            return strong.isEmpty ? "\(subject) has some warning signs. Treat it with care." : "\(subject) has warning signs: \(strong.joined(separator: " and "))."
        case .likelyScam:
            return strong.isEmpty ? "\(subject) looks like a scam." : "\(subject) looks like a scam: \(strong.joined(separator: " and "))."
        }
    }

    // MARK: Text signals

    /// Phrases that turn a scary-sounding match into reassurance ("Don't share this code", "No action needed").
    static let benignContext = try! NSRegularExpression(pattern: #"(?i)\b(no\s+action\s+(is\s+)?(needed|required)|nothing\s+(to\s+do|is\s+needed|further\s+is\s+needed)|you\s+can\s+ignore|(we\s+will|we'll|we)\s+never\s+(ask|share|request)|(don'?t|do\s+not|never)\s+(share|give|tell|read\s+out|forward)\s+(this|your|the|it|anyone)|paid\s+automatically|if\s+this\s+was\s+you,?\s+(you\s+can\s+)?ignore)\b"#)

    public static func textSignals(_ text: String, language: String) -> [ScamSignal] {
        let packs = [LexiconRegistry.pack(for: language) ?? .english, .shared]
        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)
        var out: [ScamSignal] = []
        for pack in packs {
            for p in pack.patterns {
                var matches = p.regex.matches(in: text, range: full)
                // Drop matches whose surrounding sentence reassures rather than pressures.
                matches = matches.filter { m in
                    let lo = max(0, m.range.location - 80), hi = min(ns.length, m.range.location + m.range.length + 80)
                    let window = ns.substring(with: NSRange(location: lo, length: hi - lo))
                    return benignContext.firstMatch(in: window, range: NSRange(location: 0, length: (window as NSString).length)) == nil
                }
                guard !matches.isEmpty else { continue }
                var ev: [ScamHighlight] = []
                var seen = Set<String>()
                for m in matches.prefix(6) {
                    let r = m.range
                    guard r.length > 0 else { continue }
                    let s = ns.substring(with: r).trimmingCharacters(in: .whitespacesAndNewlines)
                    if seen.insert(s.lowercased()).inserted { ev.append(ScamHighlight(text: s, kind: .phrase, start: r.location, end: r.location + r.length)) }
                }
                // Several distinct matches of the same pattern nudge the score up a little.
                let bonus = min(10, (ev.count - 1) * 4)
                out.append(ScamSignal(id: p.id, category: p.category, title: p.title, explanation: p.explanation, score: min(100, p.score + bonus), evidence: ev))
            }
        }
        return out
    }

    /// Cheap structural cues that aren't phrases.
    static func structuralSignals(_ text: String, linkCount: Int) -> [ScamSignal] {
        var out: [ScamSignal] = []
        let letters = text.filter(\.isLetter)
        if letters.count > 40 {
            let upper = letters.filter(\.isUppercase).count
            if Double(upper) / Double(letters.count) > 0.45 {
                out.append(ScamSignal(id: "text.shouting", category: .urgency, title: "Written mostly in capitals", explanation: "Shouting is a pressure tactic; real notices are written normally.", score: 15))
            }
        }
        let bangs = text.filter { $0 == "!" }.count
        if bangs >= 3 { out.append(ScamSignal(id: "text.exclaim", category: .urgency, title: "Lots of exclamation marks", explanation: "\(bangs) exclamation marks. Genuine companies don't write like this.", score: 10)) }
        if text.unicodeScalars.contains(where: { (0x200B...0x200F).contains($0.value) || $0.value == 0x2060 || $0.value == 0xFEFF }) {
            out.append(ScamSignal(id: "text.invisible", category: .sender, title: "Contains invisible characters", explanation: "Zero-width characters are used to slip past spam filters and to make look-alike words.", score: 35))
        }
        if Confusables.isMixedScript(text.filter { $0.isLetter }) {
            // Only count when a word mixes scripts, not a bilingual message.
            let words = text.split(whereSeparator: { !$0.isLetter })
            let mixedWords = words.filter { Confusables.isMixedScript(String($0)) }
            if !mixedWords.isEmpty {
                out.append(ScamSignal(id: "text.mixedscript", category: .sender, title: "Words spelled with look-alike foreign letters",
                                      explanation: "Words such as “\(mixedWords.prefix(2).joined(separator: "”, “"))” mix alphabets to dodge spam filters.", score: 35,
                                      evidence: mixedWords.prefix(3).map { ScamHighlight(text: String($0), kind: .phrase) }))
            }
        }
        return out
    }

    // MARK: Links

    static let urlRegex = try! NSRegularExpression(pattern: #"(?i)\b((?:https?|hxxps?|ftp)://[^\s<>"'\)\]]+|(?:www\.)[^\s<>"'\)\]]+|(?:[a-z0-9][a-z0-9-]{0,62}\.)+(?:com|net|org|io|co|uk|de|fr|app|dev|xyz|top|info|biz|me|tv|cc|ru|cn|in|br|au|ca|us|eu|nl|es|it|ch|se|no|dk|fi|pl|jp|kr|link|click|shop|site|online|live|life|store|vip|buzz|icu|cfd|sbs|rest|work|zip|mov|test|example|gov|edu|tk|ml|ga|cf|gq|pw|ly|gl|to|be|us|is|gd|st|at|ro|su|ws|ai|cloud|email|support|help|page|zone|website|digital|services|solutions|center|run|sh)(?:\b|/)[^\s<>"'\)\]]*)"#)
    static let anchorRegex = try! NSRegularExpression(pattern: #"(?is)<a\b[^>]*?href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>(.*?)</a>"#)
    static let markdownLink = try! NSRegularExpression(pattern: #"\[([^\]]+)\]\(([^)\s]+)\)"#)
    static let tagStrip = try! NSRegularExpression(pattern: #"<[^>]+>"#)

    /// Finds links in plain text and (optionally) HTML. Returns unique URLs plus link-text mismatch signals.
    public static func extractLinks(text: String, html: String?) -> ([String], [ScamSignal]) {
        var urls: [String] = []
        var seen = Set<String>()
        var signals: [ScamSignal] = []
        func add(_ u: String) {
            let t = u.trimmingCharacters(in: CharacterSet(charactersIn: ".,;:!?)\"'"))
            if t.lowercased().hasPrefix("mailto:") || t.lowercased().hasPrefix("tel:") { return }
            if seen.insert(t.lowercased()).inserted { urls.append(t) }
        }
        func checkMismatch(linkText: String, href: String, kind: String) {
            let shown = linkText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let target = URLAnalyzer.parse(href), !target.asciiHost.isEmpty else { return }
            if let shownURL = URLAnalyzer.parse(shown), !shownURL.asciiHost.isEmpty {
                if shownURL.registrable != target.registrable {
                    signals.append(ScamSignal(id: "link.mismatch", category: .link, title: "Link text doesn't match where it goes",
                                              explanation: "The link shows “\(shown.prefix(60))” but actually opens \(target.unicodeHost).", score: 70,
                                              evidence: [ScamHighlight(text: shown, kind: .link), ScamHighlight(text: target.unicodeHost, kind: .domain)]))
                }
            } else {
                // Brand name in link text, target not that brand.
                let folded = Confusables.typoFold(Confusables.skeleton(shown)).lowercased()
                for b in BrandList.brands {
                    if b.keywords.contains(where: { $0.count >= 4 && folded.contains($0) }) || folded.contains(b.name.lowercased()),
                       let reg = target.registrable, !b.domains.contains(reg), !BrandList.isLegitimate(registrableDomain: reg) {
                        signals.append(ScamSignal(id: "link.brandtext", category: .link, title: "“\(b.name)” link goes elsewhere",
                                                  explanation: "The link says \(b.name) but opens \(target.unicodeHost), which isn't a \(b.name) site.", score: 60,
                                                  evidence: [ScamHighlight(text: shown, kind: .link), ScamHighlight(text: target.unicodeHost, kind: .domain)]))
                        break
                    }
                }
            }
        }
        if let html {
            let ns = html as NSString
            for m in anchorRegex.matches(in: html, range: NSRange(location: 0, length: ns.length)) {
                let href = ns.substring(with: m.range(at: 1)).replacingOccurrences(of: "&amp;", with: "&")
                let inner = ns.substring(with: m.range(at: 2))
                let innerText = tagStrip.stringByReplacingMatches(in: inner, range: NSRange(location: 0, length: (inner as NSString).length), withTemplate: "")
                add(href)
                checkMismatch(linkText: PageAnalyzer.decodeEntities(innerText), href: href, kind: "html")
            }
        }
        let ns = text as NSString
        for m in markdownLink.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let shown = ns.substring(with: m.range(at: 1)), href = ns.substring(with: m.range(at: 2))
            add(href); checkMismatch(linkText: shown, href: href, kind: "md")
        }
        for m in urlRegex.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let s = ns.substring(with: m.range)
            // Skip things that are clearly a filename or a version number.
            if s.contains("@") == false, URLAnalyzer.parse(s) != nil { add(s) }
        }
        return (Array(urls.prefix(40)), signals)
    }

    /// Promotes the strongest signals of each analysed URL into the message's signal list.
    static func liftURLSignals(_ reports: [URLReport]) -> [ScamSignal] {
        var out: [ScamSignal] = []
        var seenIDs = Set<String>()
        for r in reports {
            for s in r.signals where s.score >= 15 {
                let key = s.id + "|" + (r.registrableDomain ?? r.original)
                guard seenIDs.insert(key).inserted else { continue }
                var s2 = s
                s2.id = "link." + s.id
                if s2.evidence.isEmpty { s2.evidence = [ScamHighlight(text: r.original, kind: .link)] }
                out.append(s2)
            }
        }
        return out
    }

    // MARK: Headers

    public static func headerSignals(_ mail: ParsedEmail) -> [ScamSignal] {
        var out: [ScamSignal] = []
        let from = mail.from
        let fromDomain = from.domain

        // Authentication-Results / Received-SPF
        let auth = mail.header("Authentication-Results").lowercased() + " " + mail.header("Received-SPF").lowercased() + " " + mail.header("ARC-Authentication-Results").lowercased()
        func result(_ key: String) -> String? {
            guard let r = auth.range(of: key + "=") else { return nil }
            let rest = auth[r.upperBound...]
            return String(rest.prefix { $0.isLetter })
        }
        let spf = result("spf"), dkim = result("dkim"), dmarc = result("dmarc")
        if let dmarc, ["fail", "permerror"].contains(dmarc) {
            out.append(ScamSignal(id: "email.dmarc.fail", category: .authentication, title: "Failed DMARC check", explanation: "The sending domain's policy says this message isn't authorised. It was very likely not sent by \(fromDomain ?? "the claimed sender").", score: 80, evidence: [ScamHighlight(text: "dmarc=\(dmarc)", kind: .header)]))
        }
        if let spf, ["fail", "softfail"].contains(spf) {
            out.append(ScamSignal(id: "email.spf.fail", category: .authentication, title: "Failed SPF check", explanation: "The server that sent this isn't allowed to send mail for \(fromDomain ?? "that domain").", score: spf == "fail" ? 65 : 45, evidence: [ScamHighlight(text: "spf=\(spf)", kind: .header)]))
        }
        if let dkim, dkim == "fail" {
            out.append(ScamSignal(id: "email.dkim.fail", category: .authentication, title: "Failed DKIM signature", explanation: "The message was altered after it was signed, or it was never signed by \(fromDomain ?? "the sender").", score: 50, evidence: [ScamHighlight(text: "dkim=fail", kind: .header)]))
        }
        if spf == "none" && dkim == "none" && fromDomain != nil {
            out.append(ScamSignal(id: "email.auth.none", category: .authentication, title: "No sender authentication at all", explanation: "Neither SPF nor DKIM vouch for this message, so anyone could have put \(fromDomain!) in the From line.", score: 35, evidence: [ScamHighlight(text: "spf=none dkim=none", kind: .header)]))
        }
        if let dmarc, dmarc == "pass", let spf, spf == "pass" {
            out.append(ScamSignal(id: "email.auth.pass", category: .benign, title: "Sender authentication passed", explanation: "SPF and DMARC confirm the message really came from \(fromDomain ?? "the sender's domain"). The content can still be a scam, so read the other findings.", score: 0, evidence: [ScamHighlight(text: "dmarc=pass", kind: .header)]))
        }

        // Display name vs address
        if let name = from.displayName, let fd = fromDomain {
            let nameFold = Confusables.typoFold(Confusables.skeleton(name)).lowercased()
            if let emailInName = ParsedEmail.firstEmail(in: name), let d = emailInName.split(separator: "@").last.map(String.init), d.lowercased() != fd {
                out.append(ScamSignal(id: "email.displayname.email", category: .sender, title: "Display name contains a different email address", explanation: "The name shows “\(emailInName)” but the message was really sent from \(from.address ?? fd).", score: 75, evidence: [ScamHighlight(text: name, kind: .header), ScamHighlight(text: from.address ?? fd, kind: .header)]))
            } else {
                for b in BrandList.brands {
                    let hit = b.keywords.contains(where: { $0.count >= 4 && nameFold.contains($0) }) || nameFold.contains(b.name.lowercased())
                    if hit {
                        let reg = PublicSuffix.split(fd)?.registrable ?? fd
                        if !b.domains.contains(reg) && !BrandList.isLegitimate(registrableDomain: reg) {
                            out.append(ScamSignal(id: "email.displayname.brand", category: .sender, title: "Claims to be \(b.name) but isn't sent from \(b.name)", explanation: "The sender name says “\(name)” but the address is \(from.address ?? fd). \(b.name) sends from \(b.domains[0]).", score: 70, evidence: [ScamHighlight(text: name, kind: .header), ScamHighlight(text: from.address ?? fd, kind: .header)]))
                        }
                        break
                    }
                }
            }
        }
        // From domain lookalike
        if let fd = fromDomain, let p = URLAnalyzer.parse("https://" + fd) {
            let look = URLAnalyzer.lookalike(host: p.asciiHost, unicodeHost: p.unicodeHost, registrable: p.registrable ?? fd, label: p.registrableLabel ?? fd, subdomains: p.subdomainLabels)
            for var s in look.signals { s.id = "email." + s.id; s.evidence = [ScamHighlight(text: from.address ?? fd, kind: .header)]; out.append(s) }
        }
        // Reply-To mismatch
        if let rt = mail.replyTo.domain, let fd = fromDomain, rt != fd {
            let fdReg = PublicSuffix.split(fd)?.registrable ?? fd, rtReg = PublicSuffix.split(rt)?.registrable ?? rt
            if fdReg != rtReg {
                let freemail = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "protonmail.com", "icloud.com", "aol.com", "mail.com", "gmx.com", "yandex.com"].contains(rtReg)
                out.append(ScamSignal(id: "email.replyto", category: .sender, title: "Replies go to a different address", explanation: "Sent from \(fd) but replies go to \(mail.replyTo.address ?? rt)\(freemail ? ", a free webmail account" : ""). Companies reply from their own domain.", score: freemail ? 60 : 40, evidence: [ScamHighlight(text: mail.replyTo.address ?? rt, kind: .header)]))
            }
        }
        // Return-Path mismatch (bounce address on another domain is common for bulk mail; low weight).
        if let rp = mail.returnPath.domain, let fd = fromDomain {
            let rpReg = PublicSuffix.split(rp)?.registrable ?? rp, fdReg = PublicSuffix.split(fd)?.registrable ?? fd
            if rpReg != fdReg, spf != "pass", dkim != "pass" {
                out.append(ScamSignal(id: "email.returnpath", category: .sender, title: "Bounce address on another domain", explanation: "The envelope sender is \(rp), not \(fd), and nothing authenticated the message.", score: 25, evidence: [ScamHighlight(text: "Return-Path: " + (mail.returnPath.address ?? rp), kind: .header)]))
            }
        }
        // Freemail sender claiming a brand in the subject
        if let fd = fromDomain, ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com", "mail.com", "gmx.com"].contains(fd) {
            let subj = Confusables.typoFold(Confusables.skeleton(mail.subject)).lowercased()
            for b in BrandList.brands where b.keywords.contains(where: { $0.count >= 4 && subj.contains($0) }) {
                out.append(ScamSignal(id: "email.freemail.brand", category: .sender, title: "Business notice from a personal webmail address", explanation: "The subject talks about \(b.name) but the sender is a \(fd) account.", score: 45, evidence: [ScamHighlight(text: from.address ?? fd, kind: .header)]))
                break
            }
        }
        // To: undisclosed recipients / not addressed to anyone specific
        let to = mail.header("To").lowercased()
        if to.contains("undisclosed") || (to.isEmpty && !mail.headers.isEmpty) {
            out.append(ScamSignal(id: "email.undisclosed", category: .sender, title: "Sent to undisclosed recipients", explanation: "Bulk-sent with recipients hidden, which is how mass phishing is sent.", score: 20, evidence: [ScamHighlight(text: "To: " + (to.isEmpty ? "(empty)" : mail.header("To")), kind: .header)]))
        }
        return out
    }
}

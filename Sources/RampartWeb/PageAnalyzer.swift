import Foundation

/// Heuristics over page content: HTML text (from a paste or a fetched page) and/or the structured
/// `PageSignals` the browser extension collects. Patterns target ClickFix, clipboard hijacks,
/// wallet drainers, fake virus alerts and credential forms on impostor domains.
public struct PageAnalyzer: Sendable {
    public init() {}

    static let scriptStyle = try! NSRegularExpression(pattern: #"(?is)<(script|style|noscript|template)\b[^>]*>.*?</\1>"#)
    static let tags = try! NSRegularExpression(pattern: #"(?s)<[^>]+>"#)
    static let scriptBody = try! NSRegularExpression(pattern: #"(?is)<script\b[^>]*>(.*?)</script>"#)
    static let titleTag = try! NSRegularExpression(pattern: #"(?is)<title[^>]*>(.*?)</title>"#)
    static let formTag = try! NSRegularExpression(pattern: #"(?is)<form\b[^>]*>.*?</form>"#)
    static let actionAttr = try! NSRegularExpression(pattern: #"(?i)\baction\s*=\s*["']?([^"'\s>]+)"#)
    static let inputType = try! NSRegularExpression(pattern: #"(?i)<input\b[^>]*\btype\s*=\s*["']?(password|email|tel|text|number)["']?[^>]*>"#)
    static let imgAlt = try! NSRegularExpression(pattern: #"(?i)<img\b[^>]*?(?:alt|src)\s*=\s*["']([^"']+)["']"#)
    static let phone = try! NSRegularExpression(pattern: #"(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b|\b0\d{3}[\s-]?\d{3}[\s-]?\d{3,4}\b|\b\d{3}[\s-]\d{3}[\s-]\d{4}\b"#)

    public static func visibleText(_ html: String) -> String {
        var s = scriptStyle.stringByReplacingMatches(in: html, range: NSRange(location: 0, length: (html as NSString).length), withTemplate: " ")
        s = s.replacingOccurrences(of: "<br", with: "\n<br").replacingOccurrences(of: "</p>", with: "\n").replacingOccurrences(of: "</div>", with: "\n").replacingOccurrences(of: "</li>", with: "\n")
        s = tags.stringByReplacingMatches(in: s, range: NSRange(location: 0, length: (s as NSString).length), withTemplate: " ")
        s = decodeEntities(s)
        // collapse whitespace
        var out = ""; var lastSpace = false
        for ch in s {
            if ch == "\n" { out.append("\n"); lastSpace = true }
            else if ch.isWhitespace { if !lastSpace { out.append(" ") }; lastSpace = true }
            else { out.append(ch); lastSpace = false }
        }
        return out.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public static func decodeEntities(_ s: String) -> String {
        guard s.contains("&") else { return s }
        var r = s
        for (k, v) in [("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&#39;", "'"), ("&apos;", "'"), ("&#x27;", "'"), ("&rsquo;", "’"), ("&lsquo;", "‘"), ("&mdash;", "—"), ("&ndash;", "–"), ("&hellip;", "…"), ("&copy;", "©")] {
            r = r.replacingOccurrences(of: k, with: v)
        }
        return r
    }

    // MARK: Patterns

    struct Rule { let id: String; let category: ScamSignal.Category; let score: Int; let title: String; let explanation: String; let regex: NSRegularExpression
        init(_ id: String, _ c: ScamSignal.Category, _ s: Int, _ t: String, _ e: String, _ p: String) { self.id = id; category = c; score = s; title = t; explanation = e; regex = try! NSRegularExpression(pattern: p, options: [.caseInsensitive, .dotMatchesLineSeparators]) }
    }

    static let textRules: [Rule] = [
        Rule("page.clickfix.steps", .pageClickFix, 90, "Fake verification that tells you to run a command",
             "A real “I'm not a robot” check never asks you to open Terminal, press ⌘+Space or Win+R, or paste anything. This is ClickFix, which installs malware.",
             #"(verify|verification|i'?m\s+not\s+a\s+robot|prove\s+you\s+are\s+human|human\s+verification|captcha|ray\s*id|checking\s+your\s+browser|complete\s+(these|the\s+following)\s+steps|to\s+(continue|proceed|view|access))\b.{0,400}?\b(open\s+(the\s+)?(terminal|command\s+prompt|cmd|powershell|run\s+(dialog|window|box)|spotlight)|press\s+(the\s+)?(win(dows)?(\s*key)?\s*\+\s*r|⌘\s*\+?\s*space|cmd\s*\+\s*space|command\s*\+\s*space|ctrl\s*\+\s*v|cmd\s*\+\s*v|⌘\s*\+?\s*v|enter|return)|paste\s+(the\s+)?(command|code|text|it)|type\s+terminal)"#),
        Rule("page.clickfix.terminal", .pageClickFix, 80, "Instructions to open Terminal and paste",
             "Web pages that walk you through Terminal, Spotlight and ⌘V are trying to get you to run their script.",
             #"\b(open\s+(the\s+)?terminal|type\s+["“]?terminal["”]?|launch\s+terminal|terminal\.app|spotlight\s+search|⌘\s*\+?\s*space|command\s*\+\s*space)\b.{0,300}?\b(paste|⌘\s*\+?\s*v|cmd\s*\+\s*v|command\s*\+\s*v|press\s+(enter|return)|run\s+(the\s+)?(command|script))"#),
        Rule("page.clickfix.winr", .pageClickFix, 80, "Instructions to use Win+R / PowerShell",
             "The Windows version of the same trick: Win+R, Ctrl+V, Enter runs a hidden PowerShell command.",
             #"\b(win(dows)?(\s*key)?\s*\+\s*r|run\s+dialog|mshta|powershell\s+-|cmd\s*/c)\b"#),
        Rule("page.clickfix.command", .pageClickFix, 85, "Contains a shell command meant to be pasted",
             "The page carries a command that downloads and runs code (curl … | bash, osascript, base64 -d). Nothing legitimate asks you to run it.",
             #"(curl|wget)\s+[^\s]{0,8}\s*(-[a-zA-Z]+\s+)*["']?https?://[^\s"']+["']?\s*(\|\s*(bash|sh|zsh|python3?|osascript|perl)|&&|;\s*(bash|sh|chmod))|echo\s+["']?[A-Za-z0-9+/=]{40,}["']?\s*\|\s*base64\s+(-d|--decode)|osascript\s+-e\s+["']|xattr\s+-[cdr]\s+[^\n]*(quarantine|\*|\.app)|nohup\s+[^\n]*&\s*$"#),
        Rule("page.scareware.alert", .pageScareware, 75, "Fake virus alert",
             "Browser pages cannot scan your Mac. “Your Mac is infected” pages with a phone number are scams; close the tab.",
             #"\b((your|this)\s+(mac|computer|pc|device|iphone|system|browser)\s+(is|has\s+been|may\s+be)\s+(infected|compromised|hacked|at\s+risk|blocked|locked|under\s+attack)|(virus|malware|spyware|trojan)e?s?\s+(has\s+been\s+|have\s+been\s+|was\s+|were\s+)?(detected|found)|(apple|microsoft|windows|mac)\s+(security|support|defender)\s+(alert|warning|center)|(critical|security|system)\s+(alert|warning|error)\s*[:!]|(\d+|several|multiple)\s+(viruses|threats|infections)\s+(found|detected)|do\s+not\s+(shut\s*down|restart|close\s+this\s+(window|page|browser))|(error|threat)\s*(code|id)\s*[:#]?\s*[A-Z0-9x#-]{4,}|(call|contact)\s+(apple|microsoft|windows|mac)\s+support\s+(at|on|now|immediately))"#),
        Rule("page.drainer.text", .pageDrainer, 60, "Crypto airdrop / claim with wallet connect",
             "“Connect wallet to claim” pages ask you to sign a transaction that gives the site permission to move your tokens.",
             #"\b(connect\s+(your\s+)?wallet|wallet\s*connect)\b.{0,300}?\b(claim|airdrop|mint|reward|eligib|free\s+(nft|tokens?)|migrat|whitelist|validate|sync(hroni[sz]e)?|revoke|unstake|bonus)|\b(claim|airdrop|mint|migrat|validate)\b.{0,300}?\b(connect\s+(your\s+)?wallet|wallet\s*connect)"#),
        Rule("page.credform.reward", .pageCredentialForm, 30, "Gift card / survey reward funnel",
             "Survey pages promising a free gift ask for card details “for shipping”.",
             #"\b(answer\s+(a\s+few|\d+)\s+(short\s+)?questions|complete\s+(this|the|a\s+short)\s+survey)\b.{0,200}?\b(win|receive|claim|get)\s+(a\s+|your\s+)?(free\s+)?(iphone|gift\s*card|reward|prize|macbook|airpods|\$\d+)"#),
    ]

    static let scriptRules: [Rule] = [
        Rule("page.clipboard.write", .pageClipboard, 20, "Page can write to your clipboard",
             "A script on this page copies text to your clipboard. Normal for code sites with copy buttons; a warning sign next to “verification” instructions.",
             #"navigator\s*\.\s*clipboard\s*\.\s*writeText|execCommand\s*\(\s*["']copy["']\s*\)|ClipboardItem\s*\(|\.setData\s*\(\s*["']text/plain["']"#),
        Rule("page.clipboard.auto", .pageClipboard, 75, "Copies to the clipboard automatically",
             "The script copies to the clipboard when you click anywhere or on a “verify” checkbox, then tells you to paste. That's ClickFix.",
             #"((document|window|document\.body|document\.documentElement)\s*\.\s*(addEventListener\s*\(\s*["'](click|mousedown|pointerdown|keydown|load|DOMContentLoaded)["']|on(click|mousedown|load)\s*=)|(verify|captcha|robot|human|checkbox|cf-turnstile)[^\n]{0,200}?(clipboard\s*\.\s*writeText|execCommand\s*\(\s*["']copy["']\s*\)))[\s\S]{0,400}?(clipboard\s*\.\s*writeText|execCommand\s*\(\s*["']copy["']\s*\))|(clipboard\s*\.\s*writeText|execCommand\s*\(\s*["']copy["']\s*\))[\s\S]{0,400}?(terminal|powershell|cmd\s*/c|mshta|osascript|curl\s|wget\s|\|\s*bash|\|\s*sh\b|base64)"#),
        Rule("page.clipboard.command", .pageClickFix, 85, "Clipboard payload is a shell command",
             "The text the page copies is a command (curl/bash/osascript/PowerShell). Never paste it anywhere.",
             #"(writeText|execCommand|textarea\.value|\.value\s*=)\s*[\s\S]{0,300}?(curl\s+|wget\s+|osascript|powershell|mshta|cmd\s*/c|bash\s+-c|sh\s+-c|\|\s*bash|\|\s*sh\b|base64\s+-d|xattr\s+-)|(curl\s+|wget\s+|osascript|powershell|mshta|cmd\s*/c|bash\s+-c|sh\s+-c|\|\s*bash|\|\s*sh\b|base64\s+-d|xattr\s+-)[\s\S]{0,300}?(clipboard\s*\.\s*writeText|execCommand\s*\(\s*["']copy["']\s*\))"#),
        Rule("page.drainer.script", .pageDrainer, 70, "Wallet-drainer code pattern",
             "The page's scripts request token approvals (setApprovalForAll, permit, increaseAllowance) or sweep signatures. Signing hands over your assets.",
             #"setApprovalForAll|increaseAllowance|\bpermit2?\b\s*\(|eth_signTypedData_v4|personal_sign\b[^\n]{0,200}?(approve|transfer|drain|sweep)|\bdrainer\b|seaport\b[^\n]{0,100}?(bulk|sweep)|\btransferFrom\b[^\n]{0,200}?(getAccounts|requestAccounts)|window\.ethereum\.request\s*\([^\n]{0,80}?eth_requestAccounts[^\n]{0,800}?(approve|setApprovalForAll|transfer)"#),
        Rule("page.scareware.script", .pageScareware, 60, "Page traps you with alerts or fullscreen",
             "Scripts that loop alert() dialogs, force fullscreen or play alarm sounds exist only on scam pages.",
             #"(setInterval|while\s*\(\s*true\s*\)|for\s*\(\s*;;\s*\))[^\n]{0,120}?(alert|confirm)\s*\(|requestFullscreen\s*\(\)[^\n]{0,200}?(alert|virus|infected|support)|onbeforeunload\s*=\s*function[^\n]{0,120}?(virus|infected|support|call)|new\s+Audio\s*\([^\n]{0,80}?(alarm|alert|siren|beep)|speechSynthesis\.speak[^\n]{0,200}?(virus|infected|support|call)"#),
        Rule("page.keylogger", .pageCredentialForm, 60, "Captures what you type",
             "A script sends keystrokes or form fields to another server as you type them.",
             #"addEventListener\s*\(\s*["'](keydown|keyup|keypress|input)["'][^\n]{0,400}?(fetch|XMLHttpRequest|sendBeacon|new\s+Image\(\)\.src|WebSocket)\s*\(|\.value\s*\)\s*[^\n]{0,200}?(sendBeacon|fetch\s*\(\s*["']https?://)"#),
    ]

    // MARK: Analyse

    public func analyze(url: ParsedURL?, html: String?, signals: PageSignals?, brandFromURL: String?) -> [ScamSignal] {
        var out: [ScamSignal] = []
        var text = signals?.visibleText ?? ""
        var overlay = signals?.overlayText ?? ""
        var scripts: [String] = signals?.scriptSnippets ?? []
        var title = signals?.title ?? ""
        var forms: [PageSignals.Form] = signals?.forms ?? []
        var alts: [String] = signals?.imageAlts ?? []
        var clipboardFlag = signals?.usesClipboardWrite ?? false
        let walletFlag = signals?.hasWalletConnect ?? false

        if let html {
            let ns = html as NSString, full = NSRange(location: 0, length: ns.length)
            if text.isEmpty { text = PageAnalyzer.visibleText(html) }
            if title.isEmpty, let m = PageAnalyzer.titleTag.firstMatch(in: html, range: full) { title = PageAnalyzer.decodeEntities(ns.substring(with: m.range(at: 1))).trimmingCharacters(in: .whitespacesAndNewlines) }
            for m in PageAnalyzer.scriptBody.matches(in: html, range: full) { let s = ns.substring(with: m.range(at: 1)); if !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { scripts.append(s) } }
            // inline handlers count as script too
            if html.range(of: "onclick=", options: .caseInsensitive) != nil { scripts.append(html) }
            if forms.isEmpty {
                for m in PageAnalyzer.formTag.matches(in: html, range: full) {
                    let f = ns.substring(with: m.range)
                    let fns = f as NSString
                    var form = PageSignals.Form()
                    if let a = PageAnalyzer.actionAttr.firstMatch(in: f, range: NSRange(location: 0, length: fns.length)) { form.action = fns.substring(with: a.range(at: 1)) }
                    for im in PageAnalyzer.inputType.matches(in: f, range: NSRange(location: 0, length: fns.length)) {
                        let t = fns.substring(with: im.range(at: 1)).lowercased()
                        let tag = fns.substring(with: im.range).lowercased()
                        if t == "password" { form.hasPassword = true }
                        if t == "email" || tag.contains("user") || tag.contains("login") || tag.contains("email") { form.hasEmailOrUser = true }
                        if tag.contains("card") || tag.contains("cc-number") || tag.contains("cvv") { form.hasCardNumber = true }
                        if tag.contains("otp") || tag.contains("one-time") || tag.contains("code") && tag.contains("maxlength=\"6\"") { form.hasOTP = true }
                    }
                    forms.append(form)
                }
            }
            if alts.isEmpty { for m in PageAnalyzer.imgAlt.matches(in: html, range: full) { alts.append(ns.substring(with: m.range(at: 1))) } }
        }

        // Textual rules: run over overlay text (strongest), then page text + title.
        let combinedText = [title, overlay, text].joined(separator: "\n")
        for r in PageAnalyzer.textRules {
            let hay = combinedText
            let m = r.regex.matches(in: hay, range: NSRange(location: 0, length: (hay as NSString).length))
            if let first = m.first {
                let ev = ScamHighlight(text: String((hay as NSString).substring(with: first.range).prefix(160)), kind: .phrase)
                var score = r.score
                if !overlay.isEmpty, r.regex.firstMatch(in: overlay, range: NSRange(location: 0, length: (overlay as NSString).length)) != nil { score = min(100, score + 5) }
                out.append(ScamSignal(id: r.id, category: r.category, title: r.title, explanation: r.explanation, score: score, evidence: [ev]))
            }
        }
        // Script rules
        let scriptBlob = scripts.joined(separator: "\n")
        if !scriptBlob.isEmpty {
            for r in PageAnalyzer.scriptRules {
                if let m = r.regex.firstMatch(in: scriptBlob, range: NSRange(location: 0, length: (scriptBlob as NSString).length)) {
                    var snippet = (scriptBlob as NSString).substring(with: m.range)
                    snippet = String(snippet.prefix(140)).replacingOccurrences(of: "\n", with: " ")
                    out.append(ScamSignal(id: r.id, category: r.category, title: r.title, explanation: r.explanation, score: r.score, evidence: [ScamHighlight(text: snippet, kind: .script)]))
                    if r.category == .pageClipboard { clipboardFlag = true }
                }
            }
        }
        if clipboardFlag, !out.contains(where: { $0.category == .pageClipboard }) {
            // Extension-reported clipboard use with no matching script text: weak on its own, strong with ClickFix wording.
            let clickfix = out.contains { $0.category == .pageClickFix }
            out.append(ScamSignal(id: "page.clipboard.reported", category: .pageClipboard, title: clickfix ? "Copies a command to your clipboard" : "Uses the clipboard",
                                  explanation: clickfix ? "The page writes to the clipboard while telling you to paste into Terminal." : "The page can write to your clipboard. Common on code sites; a warning sign next to “verification” instructions.",
                                  score: clickfix ? 70 : 10))
        }
        if walletFlag, !out.contains(where: { $0.category == .pageDrainer }) {
            out.append(ScamSignal(id: "page.wallet.reported", category: .pageDrainer, title: "Asks to connect a crypto wallet", explanation: "Only connect wallets on sites you navigated to yourself and already trust.", score: 15))
        }

        // Phone number next to scareware text.
        if out.contains(where: { $0.category == .pageScareware }) {
            if let m = PageAnalyzer.phone.firstMatch(in: combinedText, range: NSRange(location: 0, length: (combinedText as NSString).length)) {
                let num = (combinedText as NSString).substring(with: m.range)
                out.append(ScamSignal(id: "page.scareware.phone", category: .techSupport, title: "Shows a phone number to call", explanation: "Real security alerts never include a phone number. Calling \(num) connects you to the scammers.", score: 70, evidence: [ScamHighlight(text: num, kind: .phrase)]))
            }
        }

        // Credential forms
        let credForms = forms.filter { $0.hasPassword || $0.hasCardNumber || $0.hasOTP }
        if !credForms.isEmpty {
            let pageHost = url?.registrable
            let legit = pageHost.map(BrandList.isLegitimate) ?? false
            // Brand claimed by title / logos
            var claimed: Brand? = nil
            let claimText = Confusables.typoFold(Confusables.skeleton(title + " " + alts.joined(separator: " ") + " " + text.prefix(600))).lowercased()
            for b in BrandList.brands where b.keywords.contains(where: { $0.count >= 4 && claimText.contains($0) }) || claimText.contains(b.name.lowercased()) { claimed = b; break }
            if let b = claimed, !legit, let host = pageHost, !b.domains.contains(host) {
                out.append(ScamSignal(id: "page.credform.brand", category: .pageCredentialForm, title: "\(b.name) sign-in form on a site that isn't \(b.name)",
                                      explanation: "The page shows \(b.name) branding and asks for a password, but the address is \(url?.unicodeHost ?? host). \(b.name) signs you in only at \(b.domains[0]).", score: 85,
                                      evidence: [ScamHighlight(text: title.isEmpty ? b.name : title, kind: .phrase), ScamHighlight(text: url?.unicodeHost ?? host, kind: .domain)]))
            } else if brandFromURL != nil, !legit {
                out.append(ScamSignal(id: "page.credform.lookalike", category: .pageCredentialForm, title: "Password form on a look-alike domain",
                                      explanation: "This address imitates \(brandFromURL!) and asks for a password.", score: 80))
            }
            for f in credForms {
                if let a = f.action, let target = URLAnalyzer.parse(a), !target.asciiHost.isEmpty, let host = pageHost, target.registrable != host, !(target.registrable.map(BrandList.isLegitimate) ?? false) {
                    out.append(ScamSignal(id: "page.credform.crossorigin", category: .pageCredentialForm, title: "Login form sends your password to another site",
                                          explanation: "The form posts to \(target.unicodeHost), not to \(url?.unicodeHost ?? host).", score: 75, evidence: [ScamHighlight(text: a, kind: .link)]))
                    break
                }
            }
            if let s = signals, !s.isHTTPS, url?.scheme == "http" {
                out.append(ScamSignal(id: "page.credform.http", category: .pageCredentialForm, title: "Password form on an unencrypted page", explanation: "Anything typed here travels in clear text.", score: 40))
            }
            if credForms.contains(where: { $0.hasOTP }) && credForms.contains(where: { $0.hasPassword }) && !legit {
                out.append(ScamSignal(id: "page.credform.otp", category: .pageCredentialForm, title: "Asks for password and one-time code together", explanation: "Real-time phishing kits ask for both so they can log in as you immediately.", score: 50))
            }
        }
        return out
    }
}

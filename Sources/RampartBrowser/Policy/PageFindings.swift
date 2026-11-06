import Foundation

// Findings the injected content script reports (via WKScriptMessageHandler) and the pure policy that
// turns them into a banner, a block, or nothing. Kept free of WebKit so it is selftestable.

public struct PageFinding: Codable, Hashable, Identifiable, Sendable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        case fakeCaptcha        // "verify you are human" + press Win+R / Cmd+Space / paste
        case clipboardCommand   // page tried to write a shell command to the clipboard (blocked)
        case walletDrainer      // wallet connect / seed phrase / "approve all" prompts
        case credentialForm     // password form on a look-alike or free-host domain
        case fakeVirusAlert     // scareware overlay: "your Mac is infected, call ..."
        case hiddenIframe       // 0x0 / offscreen iframe pointing off-site
        case overlayCapture     // full-viewport overlay that captures clicks
    }
    public var id: String { kind.rawValue + ":" + detail.prefix(40) }
    public var kind: Kind
    public var detail: String        // what matched (short, plain)
    public var sample: String?       // excerpt the user can read
    public init(kind: Kind, detail: String, sample: String? = nil) { self.kind = kind; self.detail = detail; self.sample = sample }

    public var severity: Int {   // 0...100, used with noisy-OR like the rest of RamPart
        switch kind {
        case .fakeCaptcha: return 85
        case .clipboardCommand: return 95
        case .walletDrainer: return 80
        case .credentialForm: return 70
        case .fakeVirusAlert: return 85
        case .hiddenIframe: return 25
        case .overlayCapture: return 30
        }
    }
    public var title: String {
        switch kind {
        case .fakeCaptcha: return "Fake \"verify you're human\" instructions"
        case .clipboardCommand: return "Blocked a command copied to your clipboard"
        case .walletDrainer: return "Crypto wallet drain attempt"
        case .credentialForm: return "Sign-in form on a look-alike domain"
        case .fakeVirusAlert: return "Fake virus alert"
        case .hiddenIframe: return "Hidden frame from another site"
        case .overlayCapture: return "Invisible layer over the page"
        }
    }
    public var explanation: String {
        switch kind {
        case .fakeCaptcha: return "Real CAPTCHAs never ask you to open Terminal, Spotlight or the Run box and paste something. This is the \"ClickFix\" trick: the pasted text is a command that installs malware."
        case .clipboardCommand: return "The page put a shell command on your clipboard without asking. RamPart replaced it with a harmless note so you can't paste it into Terminal by accident."
        case .walletDrainer: return "The page asks you to connect a wallet, sign an open-ended approval, or type a seed phrase. Legitimate services never ask for your recovery phrase."
        case .credentialForm: return "This page asks for a password, but its domain only resembles the brand it shows. Type your bank's or shop's address yourself instead."
        case .fakeVirusAlert: return "A web page cannot scan your Mac. Alerts with a phone number or a \"download cleaner\" button are scams; RamPart's real alerts come from the menu bar app."
        case .hiddenIframe: return "A frame too small to see is loading another site, which is a common way to hide ad fraud or clickjacking."
        case .overlayCapture: return "A transparent layer covers the page and intercepts clicks, which can redirect any click to an ad or a download."
        }
    }
}

public enum PageVerdict: Equatable, Sendable {
    case clean
    case notice([PageFinding])           // subtle banner
    case warning([PageFinding], score: Int)   // prominent banner, Banking mode blurs forms
    case block([PageFinding], score: Int)     // replace the page with an interstitial

    public var findings: [PageFinding] {
        switch self {
        case .clean: return []
        case .notice(let f), .warning(let f, _), .block(let f, _): return f
        }
    }
}

public enum PageFindingPolicy {
    public static func combine(_ findings: [PageFinding]) -> Int {
        var product = 1.0
        var seen = Set<PageFinding.Kind>()
        for f in findings {
            // Count each kind once at full weight; repeats add a small bonus.
            let w = seen.insert(f.kind).inserted ? Double(f.severity) : Double(f.severity) * 0.15
            product *= (1 - min(97, w) / 100)
        }
        return Int((100 * (1 - product)).rounded())
    }

    public static func verdict(_ findings: [PageFinding], bankingMode: Bool = false) -> PageVerdict {
        guard !findings.isEmpty else { return .clean }
        let sorted = findings.sorted { $0.severity > $1.severity }
        let score = combine(sorted)
        let kinds = Set(sorted.map(\.kind))
        // ClickFix and drainer pages are not worth "continuing": the page's purpose is the attack.
        if kinds.contains(.fakeCaptcha) || kinds.contains(.clipboardCommand) && kinds.contains(.fakeVirusAlert) { return .block(sorted, score: score) }
        if score >= 90 { return .block(sorted, score: score) }
        if score >= 60 || (bankingMode && kinds.contains(.credentialForm)) { return .warning(sorted, score: score) }
        return .notice(sorted)
    }

    /// Decode what the JS side posts: {"findings":[{"kind":..,"detail":..,"sample":..}]}.
    public static func decode(_ body: Any) -> [PageFinding] {
        guard let dict = body as? [String: Any], let arr = dict["findings"] as? [[String: Any]] else { return [] }
        var out: [PageFinding] = []
        for item in arr.prefix(32) {
            guard let k = item["kind"] as? String, let kind = PageFinding.Kind(rawValue: k) else { continue }
            let detail = String((item["detail"] as? String ?? "").prefix(160))
            let sample = (item["sample"] as? String).map { String($0.prefix(240)) }
            out.append(PageFinding(kind: kind, detail: detail, sample: sample))
        }
        return out
    }
}

/// The clipboard rule: does a string the page wants to copy look like a shell/PowerShell command?
public enum ClipboardRule {
    static let shellMarkers = ["curl ", "wget ", "bash -c", "sh -c", "| sh", "| bash", "|sh", "|bash", "base64 -d", "base64 --decode",
                               "osascript", "chmod +x", "xattr -d", "xattr -c", "nohup ", "powershell", "mshta", "rundll32", "cmd /c", "cmd.exe",
                               "iwr ", "irm ", "invoke-webrequest", "invoke-expression", "iex ", "certutil", "bitsadmin", "python -c", "python3 -c",
                               "eval \"$(", "$(curl", "sudo ", "launchctl", "open -a terminal", "zsh -c"]
    public static func looksLikeShellCommand(_ s: String) -> Bool {
        let t = s.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.count >= 6, t.count <= 4000 else { return false }
        if shellMarkers.contains(where: { t.contains($0) }) { return true }
        // Something that starts like a command invocation with a URL argument.
        if t.range(of: #"^(/bin/|/usr/bin/|~/)?[a-z0-9_.-]{2,20}\s+.*https?://"#, options: .regularExpression) != nil { return true }
        if t.hasPrefix("echo ") && t.contains("|") { return true }
        return false
    }
}

/// The ClickFix text rule, mirrored in the JS so both sides agree on what the content script reports.
public enum ClickFixRule {
    static let verifyPhrases = ["verify you are human", "verify you're human", "i'm not a robot", "i am not a robot", "verification step",
                                "to continue, complete", "complete these verification steps", "ray id", "cloudflare"]
    static let actionPhrases = ["press windows", "press win", "win + r", "win+r", "command + space", "cmd + space", "⌘ + space", "⌘+space", "open terminal",
                                "press ctrl + v", "ctrl+v", "command + v", "cmd + v", "⌘ + v", "⌘+v", "press enter", "paste the", "run dialog", "spotlight",
                                "copy the fix", "copy fix", "apply fix"]
    public static func matches(_ text: String) -> Bool {
        let t = text.lowercased()
        return verifyPhrases.contains(where: { t.contains($0) }) && actionPhrases.filter({ t.contains($0) }).count >= 2
    }
}

public enum ScarewareRule {
    static let phrases = ["your mac is infected", "your computer is infected", "your mac has been infected", "virus detected", "viruses detected",
                          "trojan detected", "call apple support", "call microsoft", "toll-free", "do not close this window", "your computer has been locked",
                          "system warning", "apple security alert", "immediately call", "your ip address", "has been compromised"]
    public static func matches(_ text: String) -> Bool {
        let t = text.lowercased()
        return phrases.filter({ t.contains($0) }).count >= 2
    }
}

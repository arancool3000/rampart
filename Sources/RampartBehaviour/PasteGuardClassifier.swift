import Foundation

/// Behaviour categories the local paste classifier scores.
public enum PasteCategory: String, Codable, Sendable, CaseIterable {
    case downloadExecute, quarantineStrip, persistence, credentialAccess, passwordLure, reverseShell,
         disableSecurity, logDeletion, obfuscation, tempExecution, privilege
}

/// Result of the deterministic local assessment.
public struct PasteLocalResult: Sendable {
    public var runIntended: Bool
    public var score: Int                         // 0...100
    public var categories: [PasteCategory]
    public var reasons: [String]
    public var decodedLayers: [String]            // de-obfuscated text, outermost first (not including the original)
    public var allowedInstaller: String?          // matched pinned installer, if any
    public init(runIntended: Bool, score: Int, categories: [PasteCategory] = [], reasons: [String] = [],
                decodedLayers: [String] = [], allowedInstaller: String? = nil) {
        self.runIntended = runIntended; self.score = score; self.categories = categories; self.reasons = reasons
        self.decodedLayers = decodedLayers; self.allowedInstaller = allowedInstaller
    }
}

/// Anything that can score pasted text locally (the default is `PasteClassifier`; tests inject stubs).
public protocol PasteLocalClassifier: Sendable {
    func classify(_ text: String) -> PasteLocalResult
}

/// Deterministic classifier reusing the behaviour rules' LOLBin knowledge. Never executes anything.
public struct PasteClassifier: PasteLocalClassifier {
    /// Pinned known-good installer one-liners: exact host plus path pattern.
    public struct PinnedInstaller: Sendable { public var name: String; public var host: String; public var pathRegex: String }
    public var installers: [PinnedInstaller] = [
        .init(name: "Homebrew", host: "raw.githubusercontent.com", pathRegex: "^/Homebrew/install/(HEAD|master)/install\\.sh$"),
        .init(name: "rustup", host: "sh.rustup.rs", pathRegex: "^/?$"),
        .init(name: "nvm", host: "raw.githubusercontent.com", pathRegex: "^/nvm-sh/nvm/v[0-9.]+/install\\.sh$"),
        .init(name: "Oh My Zsh", host: "raw.githubusercontent.com", pathRegex: "^/ohmyzsh/ohmyzsh/(master|HEAD)/tools/install\\.sh$"),
        .init(name: "Oh My Zsh", host: "install.ohmyz.sh", pathRegex: "^/?$"),
        .init(name: "Docker", host: "get.docker.com", pathRegex: "^/?$"),
        .init(name: "uv", host: "astral.sh", pathRegex: "^/uv/(([0-9.]+)/)?install\\.sh$"),
        .init(name: "Bun", host: "bun.sh", pathRegex: "^/install$"),
        .init(name: "Deno", host: "deno.land", pathRegex: "^/install\\.sh$"),
        .init(name: "Poetry", host: "install.python-poetry.org", pathRegex: "^/?$"),
        .init(name: "Ollama", host: "ollama.com", pathRegex: "^/install\\.sh$"),
        .init(name: "Claude Code", host: "claude.ai", pathRegex: "^/install\\.sh$"),
        .init(name: "pnpm", host: "get.pnpm.io", pathRegex: "^/install\\.sh$"),
    ]

    public init() {}

    // MARK: run intent

    static let commandWords: Set<String> = ["sudo", "curl", "wget", "bash", "sh", "zsh", "python", "python3", "perl", "ruby", "node",
        "osascript", "xattr", "chmod", "chown", "launchctl", "defaults", "security", "brew", "git", "npm", "npx", "pip", "pip3",
        "cd", "ls", "rm", "cp", "mv", "mkdir", "echo", "cat", "open", "export", "eval", "source", "base64", "openssl", "nc",
        "ssh", "scp", "tar", "unzip", "ditto", "hdiutil", "softwareupdate", "spctl", "csrutil", "tmutil", "log", "kill", "killall",
        "pkill", "crontab", "dscl", "networksetup", "systemsetup", "swift", "cargo", "go", "make", "docker", "kubectl", "rustup",
        "xcode-select", "pkgutil", "installer", "tccutil", "sqlite3", "printf", "env", "nohup", "screen", "tmux", "find", "grep"]

    static let runPatterns = [
        #"^#!"#, #"\|\s*(sudo\s+)?(/\S*/)?(ba|z|da|k)?sh\b"#, #"\|\s*(python[0-9.]*|perl|ruby|node|osascript)\b"#,
        #"base64\s+(-d|--decode|-D)"#, #"\b(curl|wget)\s"#, #"\bxattr\s"#, #"chmod\s+[+0-7]"#, #"\blaunchctl\s"#,
        #"osascript\s+-e"#, #"(^|[;&|]\s*)sudo\s"#, #"\$\("#, #"do\s+shell\s+script"#,
    ]

    /// True when the text looks like something meant to be run (shell command or AppleScript).
    public static func isRunIntended(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.count < 64 * 1024 else { return false }
        let first = t.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" }).first.map { String($0) } ?? ""
        let firstWord = (first.hasPrefix("/") ? (first as NSString).lastPathComponent : first).lowercased()
        if commandWords.contains(firstWord) { return true }
        if first.hasPrefix("./") || first.hasPrefix("~/") { return true }
        return runPatterns.contains { RegexCache.shared.matches($0, t) }
    }

    // MARK: de-obfuscation

    /// Removes shell/AppleScript string-splitting tricks: adjacent quotes, + / & joins, backslash-letter escapes.
    public static func deobfuscate(_ s: String) -> String {
        var t = s
        for (p, r) in [(#"(["'])\s*(\+|&|\.)?\s*\1"#, ""), (#"\\(?!x[0-9A-Fa-f]{2})([A-Za-z])"#, "$1")] {
            if let re = RegexCache.shared.regex(p) {
                t = re.stringByReplacingMatches(in: t, range: NSRange(t.startIndex..., in: t), withTemplate: r)
            }
        }
        return t
    }

    static func printable(_ d: Data) -> String? {
        guard d.count >= 4, let s = String(data: d, encoding: .utf8) else { return nil }
        let ok = s.unicodeScalars.filter { ($0.value >= 0x20 && $0.value < 0x7F) || $0 == "\n" || $0 == "\t" || $0 == "\r" }.count
        return Double(ok) / Double(max(1, s.unicodeScalars.count)) >= 0.9 ? s : nil
    }

    /// One decoding pass: base64 blobs, hex (\xHH escapes and long hex runs), URL encoding.
    public static func decodeOnce(_ s: String) -> [String] {
        var out: [String] = []
        if let re = RegexCache.shared.regex(#"[A-Za-z0-9+/]{16,}={0,2}"#) {
            for m in re.matches(in: s, range: NSRange(s.startIndex..., in: s)) {
                guard let r = Range(m.range, in: s) else { continue }
                var b = String(s[r]); while b.count % 4 != 0 { b += "=" }
                if let d = Data(base64Encoded: b), let p = printable(d), p != String(s[r]) { out.append(p) }
            }
        }
        if s.contains("\\x") {
            let d = ArgvText.normalise([s]); if d != s { out.append(d) }
        }
        if let re = RegexCache.shared.regex(#"\b(?:[0-9a-fA-F]{2}){12,}\b"#) {
            for m in re.matches(in: s, range: NSRange(s.startIndex..., in: s)) {
                guard let r = Range(m.range, in: s) else { continue }
                let hex = Array(s[r]); var bytes: [UInt8] = []
                var i = 0; while i + 1 < hex.count { bytes.append(UInt8(String(hex[i...i + 1]), radix: 16) ?? 0); i += 2 }
                if let p = printable(Data(bytes)) { out.append(p) }
            }
        }
        if s.range(of: #"%[0-9A-Fa-f]{2}"#, options: .regularExpression) != nil, let d = s.removingPercentEncoding, d != s { out.append(d) }
        return out
    }

    /// Decodes up to `maxDepth` nested layers; returns every distinct decoded layer (de-obfuscated).
    public static func decodeLayers(_ text: String, maxDepth: Int = 3) -> [String] {
        var layers: [String] = []
        let clean = deobfuscate(text)
        var frontier = clean == text ? [text] : [text, clean]
        if clean != text { layers.append(clean) }
        for _ in 0..<maxDepth {
            var next: [String] = []
            for f in frontier { for d in decodeOnce(f) { let c = deobfuscate(d); if !layers.contains(c) && c != text { layers.append(c); next.append(c) } } }
            if next.isEmpty { break }
            frontier = next
        }
        return Array(layers.prefix(16))
    }

    // MARK: redaction

    static let secretPatterns: [(String, String)] = [
        (#"(?i)(authorization:\s*)[^'"\n]+"#, "$1[REDACTED]"),
        (#"(?i)\b(bearer|token|basic)\s+[A-Za-z0-9._~+/=-]{8,}"#, "$1 [REDACTED]"),
        (#"(?i)(--?(p|password|passwd|pass|token|secret|api-?key))(=|\s+)\S+"#, "$1$3[REDACTED]"),
        (#"(?i)\b(password|passwd|pwd|token|secret|api_?key|access_?key)=\S+"#, "$1=[REDACTED]"),
        (#"\b(ghp|gho|ghs|github_pat|sk|xox[abp]|AKIA)[A-Za-z0-9_-]{12,}"#, "[REDACTED]"),
        (#"(?i)(://[^/\s:@]+:)[^@\s/]+@"#, "$1[REDACTED]@"),
        (#"(\s-u\s+[^\s:]+:)\S+"#, "$1[REDACTED]"),
    ]

    /// Removes credentials before text leaves the machine (AI) or is shown in evidence.
    public static func redact(_ s: String) -> String {
        var t = s
        for (p, r) in secretPatterns {
            if let re = RegexCache.shared.regex(p) { t = re.stringByReplacingMatches(in: t, range: NSRange(t.startIndex..., in: t), withTemplate: r) }
        }
        return t
    }

    // MARK: scoring

    /// Signature patterns per category, aligned with the behaviour rule file (R06, R07–R18, R27, R30, R34–R36, R53, R55, L01–L06).
    static let signatures: [(PasteCategory, Int, String, String)] = [
        (.downloadExecute, 70, #"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(/\S*/)?((ba|z|da|k)?sh|python[0-9.]*|perl|ruby|osascript|node)\b"#, "downloads code and pipes it straight into an interpreter"),
        (.downloadExecute, 70, #"(eval|source|\.)\s+["']?\$\(\s*(curl|wget)|(ba|z)?sh\s+-c\s+["']?\$\(\s*(curl|wget)|<\(\s*(curl|wget)"#, "runs the output of a download"),
        (.downloadExecute, 60, #"\b(curl|wget)\b.*(-o|-O|>)\s*\S+.*(&&|;)\s*(chmod|open|\./|/tmp/|bash|sh)\b"#, "downloads a file and then runs it"),
        (.quarantineStrip, 45, #"xattr\s+(-[a-z]*d[a-z]*\s+com\.apple\.quarantine|-[a-z]*c)"#, "removes the download quarantine flag (skips Gatekeeper)"),
        (.persistence, 55, #"Library/Launch(Agents|Daemons)|launchctl\s+(load|bootstrap|submit)|crontab\s+(-\s|[^-l])|LoginHook|>>?\s*~?/?\S*\.(zshrc|zprofile|bash_profile|bashrc)\b"#, "installs something that starts automatically"),
        (.credentialAccess, 70, #"find-generic-password|dump-keychain|Safe Storage|Library/Keychains|Login Data|Cookies\.binarycookies|key4\.db|logins\.json|wallet"#, "reads saved passwords, keychain or wallet data"),
        (.passwordLure, 75, #"display\s+dialog.*hidden\s+answer|dscl\s+\S*\s*-authonly"#, "shows a fake password prompt or checks your password"),
        (.reverseShell, 85, #"/dev/tcp/|\b(nc|ncat|netcat)\b.*\s-e\s|socket\.socket.*(dup2|subprocess)|mkfifo\s+\S+.*\b(nc|sh)\b"#, "opens a remote shell to another computer"),
        (.disableSecurity, 65, #"spctl\s+--(master|global)-disable|LSQuarantine\s+-bool\s+(no|false)|csrutil\s+disable|tccutil\s+reset|(killall|pkill)\s+.*(xprotect|rampart|lulu|little ?snitch)"#, "turns off macOS or third-party security protections"),
        (.logDeletion, 50, #"rm\s+-[a-z]*r[a-z]*\s+\S*/var/log|log\s+erase|rm\s+\S*\.(bash|zsh)_history|history\s+-c|tmutil\s+(delete|disable)"#, "deletes logs, history or backups"),
        (.tempExecution, 30, #"(^|[\s;&|])(/private)?/(tmp|var/folders|Users/Shared)/\S+(\s|$)"#, "runs something from a temporary or shared folder"),
        (.privilege, 15, #"(^|[;&|]\s*)sudo\s|do\s+shell\s+script.*administrator\s+privileges"#, "asks for administrator rights"),
    ]

    public func classify(_ text: String) -> PasteLocalResult {
        guard Self.isRunIntended(text) else { return PasteLocalResult(runIntended: false, score: 0) }
        let layers = Self.decodeLayers(text)
        let all = [text] + layers
        var cats: [PasteCategory: Int] = [:]
        var reasons: [String] = []
        for (c, w, p, why) in Self.signatures where cats[c] == nil {
            if all.contains(where: { RegexCache.shared.matches(p, $0) }) { cats[c] = w; reasons.append(why) }
        }
        let encodedLayers = layers.filter { $0 != Self.deobfuscate(text) }.count
        if encodedLayers > 0 || Self.deobfuscate(text) != text {
            let w = min(45, 20 + 10 * encodedLayers)
            cats[.obfuscation] = w
            reasons.append("hides its real content (\(encodedLayers) encoded layer\(encodedLayers == 1 ? "" : "s"))")
        }
        // Pinned installer: only when the sole risky behaviour is download-and-run and every URL is pinned.
        let urls = all.flatMap { Self.urls(in: $0) }
        if let pinned = matchInstaller(urls), Set(cats.keys).subtracting([.downloadExecute, .privilege]).isEmpty {
            return PasteLocalResult(runIntended: true, score: 0, categories: [], reasons: ["pinned installer: \(pinned)"],
                                    decodedLayers: layers, allowedInstaller: pinned)
        }
        var prod = 1.0
        for (_, w) in cats { prod *= 1 - Double(w) / 100 }
        var score = 100 * (1 - prod)
        // Raw-IP or throwaway hosts in a download raise it further.
        if cats[.downloadExecute] != nil, urls.contains(where: { RegexCache.shared.matches(#"^https?://\d+\.\d+\.\d+\.\d+"#, $0) }) {
            score = min(100, score + 10); reasons.append("downloads from a bare IP address")
        }
        return PasteLocalResult(runIntended: true, score: Int(score.rounded()), categories: cats.keys.sorted { $0.rawValue < $1.rawValue },
                                reasons: reasons, decodedLayers: layers)
    }

    static func urls(in s: String) -> [String] {
        guard let re = RegexCache.shared.regex(#"https?://[^\s'"|;)<>]+"#) else { return [] }
        return re.matches(in: s, range: NSRange(s.startIndex..., in: s)).compactMap { Range($0.range, in: s).map { String(s[$0]) } }
    }

    func matchInstaller(_ urls: [String]) -> String? {
        guard !urls.isEmpty else { return nil }
        var name: String?
        for u in urls {
            guard let c = URLComponents(string: u), c.scheme == "https", let host = c.host?.lowercased() else { return nil }
            guard let hit = installers.first(where: { $0.host == host && RegexCache.shared.matches($0.pathRegex, c.path) }) else { return nil }
            name = hit.name
        }
        return name
    }
}

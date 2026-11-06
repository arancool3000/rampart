import Foundation

/// Removes personal and secret data from text before it leaves the Mac.
public struct Redactor: Sendable {
    public enum Kind: String, CaseIterable, Codable, Sendable {
        case privateKey, apiKey, secretValue, email, card, iban, phone, homePath, userName
        public var placeholder: String {
            switch self {
            case .privateKey: return "[PRIVATE-KEY]"
            case .apiKey: return "[KEY]"
            case .secretValue: return "[SECRET]"
            case .email: return "[EMAIL]"
            case .card: return "[CARD]"
            case .iban: return "[IBAN]"
            case .phone: return "[PHONE]"
            case .homePath: return "~"
            case .userName: return "[USER]"
            }
        }
        public var label: String {
            switch self {
            case .privateKey: return "private key"
            case .apiKey: return "key-like string"
            case .secretValue: return "password or token value"
            case .email: return "email address"
            case .card: return "card number"
            case .iban: return "IBAN"
            case .phone: return "phone number"
            case .homePath: return "home folder path"
            case .userName: return "your user name"
            }
        }
    }

    public struct Result: Sendable, Equatable {
        public var text: String
        public var counts: [Kind: Int]
        public var total: Int { counts.values.reduce(0, +) }
        /// e.g. "2 email addresses, 1 card number"
        public var summary: String {
            if counts.isEmpty { return "Nothing needed removing." }
            return Kind.allCases.compactMap { k in counts[k].map { "\($0) \(k.label)\($0 == 1 ? "" : "s")" } }.joined(separator: ", ")
        }
    }

    public var homeDirectory: String
    public var userNames: [String]

    public init(homeDirectory: String = NSHomeDirectory(), userNames: [String]? = nil) {
        self.homeDirectory = homeDirectory
        if let userNames { self.userNames = userNames } else {
            var names = [NSUserName()]
            names += NSFullUserName().split(separator: " ").map(String.init)
            self.userNames = names
        }
        self.userNames = self.userNames.filter { $0.count >= 3 }
    }

    public static let `default` = Redactor()

    private static func re(_ p: String, _ o: NSRegularExpression.Options = []) -> NSRegularExpression {
        try! NSRegularExpression(pattern: p, options: o)
    }
    private static let privateKeyRE = re(#"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"#)
    private static let knownKeyREs: [NSRegularExpression] = [
        re(#"AIza[0-9A-Za-z_\-]{30,}"#),                    // Google API key
        re(#"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}"#),     // OpenAI / Anthropic style
        re(#"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}"#),  // GitHub
        re(#"\bgithub_pat_[A-Za-z0-9_]{30,}"#),
        re(#"\bxox[abprs]-[A-Za-z0-9\-]{10,}"#),             // Slack
        re(#"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"#),               // AWS access key id
        re(#"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"#), // JWT
        re(#"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"#), // Stripe
        re(#"(?i)\bBearer\s+[A-Za-z0-9._\-~+/]{12,}=*"#),     // HTTP bearer tokens
    ]
    /// `password=...`, `token: ...`, `api_key "..."`, URL params like `?sig=...`
    private static let secretValueRE = re(#"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth|session|sig|signature|otp|pin|code)(\s*[:=]\s*|=)("[^"]*"|'[^']*'|[^\s&"',;]+)"#)
    /// Long opaque tokens with mixed letters and digits (not pure hex hashes, which are kept).
    private static let opaqueTokenRE = re(#"(?<![A-Za-z0-9_\-/.])[A-Za-z0-9_\-]{32,}(?![A-Za-z0-9_\-])"#)
    private static let emailRE = re(#"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"#)
    private static let cardRE = re(#"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)"#)
    private static let ibanRE = re(#"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b"#)
    private static let phoneRE = re(#"(?<![\w.])(?:\+|00)?\(?\d[\d\s().\-]{7,}\d(?![\w.])"#)
    private static let homeRE = re(#"/(?:Users|home)/(?!Shared\b)[^/\s"'`]+"#)

    public func redact(_ input: String) -> Result {
        var text = input
        var counts: [Kind: Int] = [:]
        func apply(_ re: NSRegularExpression, _ kind: Kind, transform: ((String, NSTextCheckingResult, String) -> String?)? = nil) {
            let ns = text as NSString
            var out = ""
            var last = 0
            for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                let match = ns.substring(with: m.range)
                let replacement: String?
                if let transform { replacement = transform(match, m, text) } else { replacement = kind.placeholder }
                guard let replacement else { continue }
                out += ns.substring(with: NSRange(location: last, length: m.range.location - last)) + replacement
                last = m.range.location + m.range.length
                counts[kind, default: 0] += 1
            }
            if last > 0 { out += ns.substring(from: last); text = out }
        }

        apply(Self.privateKeyRE, .privateKey)
        for r in Self.knownKeyREs { apply(r, .apiKey) }
        apply(Self.secretValueRE, .secretValue) { match, m, full in
            let ns = full as NSString
            let value = ns.substring(with: m.range(at: 3))
            if value.hasPrefix("[") || value.count < 3 { return nil }
            return ns.substring(with: m.range(at: 1)) + ns.substring(with: m.range(at: 2)) + Kind.secretValue.placeholder
        }
        apply(Self.emailRE, .email)
        // Home paths before opaque tokens so "/Users/name" collapses to "~".
        apply(Self.homeRE, .homePath)
        apply(Self.opaqueTokenRE, .apiKey) { match, _, _ in
            let isHex = match.allSatisfy { $0.isHexDigit }
            let hasLetter = match.contains { $0.isLetter }, hasDigit = match.contains { $0.isNumber }
            if isHex || !(hasLetter && hasDigit) { return nil }       // keep SHA-256/MD5 hashes and plain words
            if match.contains("-") && match.split(separator: "-").allSatisfy({ $0.count < 12 }) { return nil } // slugs/UUID-ish
            return Kind.apiKey.placeholder
        }
        apply(Self.ibanRE, .iban) { match, _, _ in Self.ibanValid(match) ? Kind.iban.placeholder : nil }
        apply(Self.cardRE, .card) { match, _, _ in
            let digits = match.filter(\.isNumber)
            return (13...19).contains(digits.count) && Self.luhn(digits) ? Kind.card.placeholder : nil
        }
        apply(Self.phoneRE, .phone) { match, _, _ in
            let digits = match.filter(\.isNumber).count
            let hasSep = match.contains { " ()-.".contains($0) } || match.hasPrefix("+")
            // Version numbers and dates use dots; require phone-like separators and 9...15 digits.
            if match.filter({ $0 == "." }).count >= 2 && !match.hasPrefix("+") { return nil }
            return (9...15).contains(digits) && (hasSep || digits >= 10) ? Kind.phone.placeholder : nil
        }
        for name in userNames where !name.isEmpty {
            let r = Self.re("(?i)(?<![A-Za-z0-9])" + NSRegularExpression.escapedPattern(for: name) + "(?![A-Za-z0-9])")
            apply(r, .userName)
        }
        return Result(text: text, counts: counts)
    }

    static func luhn(_ digits: String) -> Bool {
        var sum = 0
        for (i, ch) in digits.reversed().enumerated() {
            guard var d = ch.wholeNumberValue else { return false }
            if i % 2 == 1 { d *= 2; if d > 9 { d -= 9 } }
            sum += d
        }
        return sum % 10 == 0 && !digits.allSatisfy { $0 == "0" }
    }

    static func ibanValid(_ raw: String) -> Bool {
        let s = raw.replacingOccurrences(of: " ", with: "").uppercased()
        guard (15...34).contains(s.count) else { return false }
        let rearranged = s.dropFirst(4) + s.prefix(4)
        var rem = 0
        for ch in rearranged {
            let v: Int
            if let d = ch.wholeNumberValue { v = d } else if let a = ch.asciiValue, (65...90).contains(a) { v = Int(a) - 55 } else { return false }
            for digit in String(v) { rem = (rem * 10 + digit.wholeNumberValue!) % 97 }
        }
        return rem == 1
    }

    /// Reduces a file path to a non-identifying description: "~/Downloads/Installer.dmg".
    public func describePath(_ path: String?) -> String? {
        guard let path, !path.isEmpty else { return nil }
        return redact(path).text
    }
}

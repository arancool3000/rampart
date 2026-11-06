import Foundation

/// Offline strength estimate in the spirit of zxcvbn: the password is segmented into the cheapest mix of
/// guessable patterns (common passwords, dictionary words with capitals or l33t, sequences, repeats,
/// keyboard runs, years) and brute-force characters. The result is an estimate, not a guarantee.
public struct PasswordStrength: Hashable, Sendable {
    public enum Level: Int, Comparable, Sendable, CaseIterable {
        case veryWeak = 0, weak, fair, strong, veryStrong
        public static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }
        public var label: String { ["Very weak", "Weak", "Fair", "Strong", "Very strong"][rawValue] }
    }

    public var entropyBits: Double
    public var level: Level
    /// Seconds to crack at 10 billion guesses per second (fast hash, offline GPU rig).
    public var offlineFastSeconds: Double
    /// Seconds to crack at 10,000 guesses per second (slow hash such as bcrypt or PBKDF2, offline).
    public var offlineSlowSeconds: Double
    /// Seconds to crack at 10 guesses per second (online, rate-limited login form).
    public var onlineSeconds: Double
    public var warning: String?
    public var suggestions: [String]

    public static func level(forBits b: Double) -> Level {
        switch b {
        case ..<28: return .veryWeak
        case ..<40: return .weak
        case ..<60: return .fair
        case ..<80: return .strong
        default: return .veryStrong
        }
    }

    /// Strength for a password whose generation entropy is known exactly (generator output).
    public static func known(entropyBits: Double) -> PasswordStrength {
        make(bits: entropyBits, warning: nil, suggestions: [])
    }

    static func make(bits: Double, warning: String?, suggestions: [String]) -> PasswordStrength {
        // Expected time is half the keyspace.
        let guesses = pow(2, max(0, bits)) / 2
        return PasswordStrength(entropyBits: bits, level: level(forBits: bits),
                                offlineFastSeconds: guesses / 1e10, offlineSlowSeconds: guesses / 1e4,
                                onlineSeconds: guesses / 10, warning: warning, suggestions: suggestions)
    }

    /// Human form of a duration ("instantly", "3 hours", "centuries").
    public static func describe(seconds s: Double) -> String {
        if s < 1 { return "instantly" }
        let units: [(Double, String)] = [(60, "second"), (3600, "minute"), (86400, "hour"), (86400 * 30.4, "day"),
                                         (86400 * 365.25, "month"), (86400 * 365.25 * 100, "year")]
        var prev = 1.0
        for (limit, name) in units {
            if s < limit { let n = Int(s / prev); return "\(n) \(name)\(n == 1 ? "" : "s")" }
            prev = limit
        }
        return "centuries"
    }

    // MARK: Estimation

    public static func evaluate(_ password: String, userInputs: [String] = []) -> PasswordStrength {
        let chars = Array(password)
        guard !chars.isEmpty else { return make(bits: 0, warning: "Enter a password.", suggestions: []) }
        let lower = password.lowercased()
        let unleet = String(lower.map { leet[$0] ?? $0 })
        if let rank = commonRank[lower] ?? commonRank[unleet] {
            return make(bits: log2(Double(rank + 1)), warning: "This is one of the most common passwords.",
                        suggestions: ["Use a generated password or a passphrase of four or more random words."])
        }

        let perChar = log2(Double(max(10, charsetSize(chars))))
        let n = chars.count
        var matches: [(start: Int, end: Int, bits: Double, kind: String)] = []
        let lc = Array(lower), ul = Array(unleet)

        // Dictionary words (wordlist + user inputs), with capitalisation and l33t costs.
        let user = Set(userInputs.map { $0.lowercased() }.filter { $0.count >= 3 })
        for i in 0..<n {
            var j = min(n, i + 12)
            while j >= i + 3 {
                let word = String(ul[i..<j])
                let isUser = user.contains(word) || user.contains(String(lc[i..<j]))
                if isUser || dictionary.contains(word) {
                    var bits = isUser ? 1.0 : log2(Double(dictionary.count))
                    let orig = chars[i..<j]
                    let uppers = orig.filter(\.isUppercase).count
                    if uppers == orig.count || (uppers == 1 && orig.first!.isUppercase) { bits += 1 } else if uppers > 0 { bits += Double(min(uppers, orig.count - uppers)) * 2 }
                    if String(lc[i..<j]) != word { bits += 1 }
                    matches.append((i, j, bits, isUser ? "user" : "word"))
                }
                j -= 1
            }
        }
        // Repeats (aaa, ababab).
        var i = 0
        while i < n {
            var j = i + 1
            while j < n && chars[j] == chars[i] { j += 1 }
            if j - i >= 3 { matches.append((i, j, perChar + log2(Double(j - i)), "repeat")) }
            i = max(i + 1, j)
        }
        for unit in 2...3 where n >= unit * 2 {
            for s in 0...(n - unit * 2) {
                var e = s + unit
                while e + unit <= n && Array(chars[e..<(e + unit)]) == Array(chars[s..<(s + unit)]) { e += unit }
                if e - s >= unit * 2 { matches.append((s, e, Double(unit) * perChar + log2(Double((e - s) / unit)), "repeat")) }
            }
        }
        // Sequences (abc, 4321) and keyboard runs (qwerty, asdf).
        let scalars = lc.map { $0.unicodeScalars.first!.value }
        for s in 0..<n {
            for dir in [1, -1] {
                var e = s + 1
                while e < n && Int(scalars[e]) - Int(scalars[e - 1]) == dir { e += 1 }
                if e - s >= 3 { matches.append((s, e, 4 + log2(Double(e - s)) + (dir < 0 ? 1 : 0), "sequence")) }
            }
            for row in keyboardRows {
                var e = s
                while e < n, let ri = row.firstIndex(of: lc[e]), e == s || (row.firstIndex(of: lc[e - 1]).map { ri - $0 == 1 } ?? false) { e += 1 }
                if e - s >= 4 { matches.append((s, e, 5 + log2(Double(e - s)), "keyboard")) }
            }
        }
        // Years and dates.
        if n >= 4 {
            for s in 0...(n - 4) {
                if let y = Int(String(chars[s..<(s + 4)])), (1900...2039).contains(y) { matches.append((s, s + 4, log2(140), "year")) }
            }
        }

        // Cheapest segmentation.
        var cost = [Double](repeating: .infinity, count: n + 1)
        var kinds = [Set<String>](repeating: [], count: n + 1)
        cost[0] = 0
        for e in 1...n {
            if cost[e - 1] + perChar < cost[e] { cost[e] = cost[e - 1] + perChar; kinds[e] = kinds[e - 1] }
            for m in matches where m.end == e {
                let c = cost[m.start] + m.bits
                if c < cost[e] { cost[e] = c; kinds[e] = kinds[m.start].union([m.kind]) }
            }
        }
        let bits = cost[n]
        let found = kinds[n]

        var warning: String?
        var suggestions: [String] = []
        if found.contains("user") { warning = "Avoid your name, email or the site name in the password." }
        else if found.contains("keyboard") { warning = "Keyboard patterns like qwerty are easy to guess." }
        else if found.contains("sequence") { warning = "Sequences like abc or 1234 are easy to guess." }
        else if found.contains("repeat") { warning = "Repeated characters add little strength." }
        else if found.contains("year") { warning = "Years and dates are easy to guess." }
        else if found.contains("word") && bits < 60 { warning = "Single dictionary words, even with capitals or symbols swapped in, are easy to guess." }
        if n < 12 { suggestions.append("Use at least 12 characters; 16 or more is better.") }
        if level(forBits: bits) < .strong { suggestions.append("Add more random words or characters; length helps more than symbols.") }
        if level(forBits: bits) < .fair { suggestions.append("Let RamPart generate a password for you.") }
        return make(bits: bits, warning: warning, suggestions: suggestions)
    }

    static func charsetSize(_ chars: [Character]) -> Int {
        var size = 0
        if chars.contains(where: { $0.isLowercase }) { size += 26 }
        if chars.contains(where: { $0.isUppercase }) { size += 26 }
        if chars.contains(where: { $0.isNumber }) { size += 10 }
        if chars.contains(where: { !$0.isLetter && !$0.isNumber && $0.isASCII }) { size += 33 }
        if chars.contains(where: { !$0.isASCII }) { size += 100 }
        return size
    }

    static let leet: [Character: Character] = ["4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t", "8": "b", "9": "g"]
    static let keyboardRows: [[Character]] = [Array("`1234567890-="), Array("qwertyuiop[]"), Array("asdfghjkl;'"), Array("zxcvbnm,./"),
                                              Array("1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p")]
    static let dictionary: Set<String> = Set(Wordlist.words).union(commonWords)
    static let commonWords: Set<String> = ["password", "pass", "love", "secret", "admin", "login", "welcome", "dragon", "monkey", "master",
        "shadow", "sunshine", "princess", "football", "baseball", "soccer", "hockey", "letmein", "trustno", "iloveyou", "summer",
        "winter", "spring", "autumn", "flower", "hello", "freedom", "whatever", "qwerty", "michael", "jessica", "charlie", "jordan",
        "superman", "batman", "pokemon", "starwars", "computer", "internet", "cookie", "chocolate", "banana", "orange", "apple",
        "google", "facebook", "mac", "macbook", "iphone", "test", "guest", "user", "root", "default", "changeme", "mustang", "ninja",
        "killer", "pepper", "ginger", "maggie", "buster", "tigger", "hunter", "ranger", "thomas", "robert", "daniel", "andrew"]
    static let commonRank: [String: Int] = {
        let list = ["123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567", "111111", "1234567890", "123123",
                    "abc123", "1234", "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon", "sunshine",
                    "princess", "letmein", "654321", "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop", "superman", "asdfghjkl",
                    "football", "baseball", "welcome", "admin", "login", "master", "shadow", "michael", "passw0rd", "trustno1",
                    "whatever", "hello", "freedom", "starwars", "666666", "121212", "7777777", "123qwe", "qazwsx", "password123",
                    "1q2w3e", "charlie", "aa123456", "donald", "batman", "access", "hottie", "loveme", "flower", "mustang",
                    "jordan23", "ninja", "azerty", "solo", "michelle", "jessica", "pepper", "zxcvbnm", "killer", "pokemon",
                    "lovely", "hunter", "secret", "summer", "ashley", "bailey", "passport", "computer", "cheese", "internet",
                    "qwerty1", "football1", "princess1", "welcome1", "admin123", "abcd1234", "changeme", "default", "guest", "test123",
                    "p@ssw0rd", "letmein1", "mypassword", "iloveyou1", "q1w2e3r4", "11111111", "987654321", "999999", "888888", "555555"]
        var d: [String: Int] = [:]
        for (i, p) in list.enumerated() where d[p] == nil { d[p] = i }
        return d
    }()
}

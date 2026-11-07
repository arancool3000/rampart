import Foundation

extension PasswordGenerator {
    // MARK: Pronounceable

    public struct PronounceableOptions: Hashable, Sendable {
        public var length = 16
        public var capitalize = true
        public var digits = true
        public var symbol = false
        public init() {}
    }
    /// Consonants without l/q/x/y (easy to mishear or mistype) and the five vowels.
    public static let syllableConsonants = Array("bcdfghjkmnprstvwz")
    public static let syllableVowels = Array("aeiou")

    /// Alternating consonant–vowel letters ("bakomiturefa"), then optional capital, 2 digits and a symbol.
    /// Entropy is exact for the process: each letter, the capital position, the digits and the symbol.
    public static func pronounceable(_ o: PronounceableOptions = PronounceableOptions()) -> Result {
        let total = max(8, min(64, o.length))
        let letters = max(6, total - (o.digits ? 2 : 0) - (o.symbol ? 1 : 0))
        var bits = 0.0
        var chars: [Character] = (0..<letters).map { i in
            let set = i % 2 == 0 ? syllableConsonants : syllableVowels
            bits += log2(Double(set.count))
            return set[SecureRandom.uniform(set.count)]
        }
        if o.capitalize {
            let i = SecureRandom.uniform(letters)
            chars[i] = Character(chars[i].uppercased()); bits += log2(Double(letters))
        }
        if o.digits { for _ in 0..<2 { chars.append(digits[SecureRandom.uniform(10)]) }; bits += log2(100) }
        if o.symbol { chars.append(symbols[SecureRandom.uniform(symbols.count)]); bits += log2(Double(symbols.count)) }
        return Result(password: String(chars), entropyBits: bits)
    }

    // MARK: Passphrase presets

    public struct PassphrasePreset: Hashable, Sendable, Identifiable {
        public var name: String
        public var options: PassphraseOptions
        public var id: String { name }
    }
    public static let passphrasePresets: [PassphrasePreset] = {
        func p(_ name: String, _ words: Int, _ sep: String, _ caps: Bool, _ digit: Bool) -> PassphrasePreset {
            var o = PassphraseOptions(); o.words = words; o.separator = sep; o.capitalize = caps; o.includeDigit = digit
            return PassphrasePreset(name: name, options: o)
        }
        return [p("Easy to type", 5, " ", false, false), p("Balanced", 5, "-", true, true),
                p("Strong", 7, "-", true, true), p("Master password", 8, " ", false, true)]
    }()

    // MARK: Site rules

    /// Requirements some sites impose. Applied on top of the user's generator options.
    public struct SiteRule: Hashable, Sendable, Identifiable {
        public var name: String
        public var maxLength: Int?
        public var minLength: Int = 8
        public var allowSymbols = true
        /// Only these symbols are accepted (nil = all of PasswordGenerator.symbols).
        public var allowedSymbols: String?
        public var id: String { name }
    }
    public static let siteRules: [SiteRule] = [
        SiteRule(name: "No restrictions"),
        SiteRule(name: "At most 16 characters", maxLength: 16),
        SiteRule(name: "At most 12 characters", maxLength: 12),
        SiteRule(name: "Letters and digits only", allowSymbols: false),
        SiteRule(name: "Limited symbols (!@#$%&*)", allowedSymbols: "!@#$%&*"),
        SiteRule(name: "Bank style: 8–20, limited symbols", maxLength: 20, allowedSymbols: "!@#$%^&*"),
    ]

    /// Generates a random password satisfying `rule`, starting from `o`.
    public static func random(_ o: Options, rule: SiteRule) -> Result {
        var o = o
        o.length = max(rule.minLength, min(rule.maxLength ?? 128, o.length))
        if !rule.allowSymbols { o.symbols = false }
        guard o.symbols, let allowed = rule.allowedSymbols, !allowed.isEmpty else { return random(o) }
        let sym = Array(Set(allowed)).sorted()
        var sets = sets(o).filter { $0 != (o.excludeAmbiguous ? symbols.filter { !ambiguous.contains($0) } : symbols) }
        sets.append(sym)
        let alpha = sets.flatMap { $0 }
        var out: [Character]
        repeat { out = (0..<o.length).map { _ in alpha[SecureRandom.uniform(alpha.count)] } }
        while o.requireEachSet && o.length >= sets.count && !sets.allSatisfy { s in out.contains(where: s.contains) }
        return Result(password: String(out), entropyBits: entropyOfRandom(length: o.length, sets: sets.map(\.count), requireEach: o.requireEachSet))
    }
}

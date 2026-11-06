import Foundation

/// Random passwords, passphrases and PINs. All randomness comes from `SecRandomCopyBytes` through
/// `SecureRandom.uniform`, which uses rejection sampling (no modulo bias).
public enum PasswordGenerator {
    public static let lowercase = Array("abcdefghijklmnopqrstuvwxyz")
    public static let uppercase = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    public static let digits = Array("0123456789")
    public static let symbols = Array("!@#$%^&*()-_=+[]{};:,.<>/?~")
    /// Characters that are easy to confuse when read or typed by hand.
    public static let ambiguous = Set("Il1|O0o`'\";:,.")

    public struct Options: Codable, Hashable, Sendable {
        public var length = 20
        public var lowercase = true
        public var uppercase = true
        public var digits = true
        public var symbols = true
        public var excludeAmbiguous = false
        /// Guarantee at least one character from each enabled set.
        public var requireEachSet = true
        public init() {}
    }

    public struct PassphraseOptions: Codable, Hashable, Sendable {
        public var words = 5
        public var separator = "-"
        public var capitalize = true
        public var includeDigit = true
        public init() {}
    }

    public struct Result: Hashable, Sendable {
        public var password: String
        /// Exact entropy of the generation process in bits (what an attacker who knows the settings faces).
        public var entropyBits: Double
        public init(password: String, entropyBits: Double) { self.password = password; self.entropyBits = entropyBits }
    }

    static func sets(_ o: Options) -> [[Character]] {
        var s: [[Character]] = []
        if o.lowercase { s.append(lowercase) }
        if o.uppercase { s.append(uppercase) }
        if o.digits { s.append(digits) }
        if o.symbols { s.append(symbols) }
        if s.isEmpty { s.append(lowercase) }
        if o.excludeAmbiguous { s = s.map { $0.filter { !ambiguous.contains($0) } }.filter { !$0.isEmpty } }
        return s
    }

    public static func alphabet(_ o: Options) -> [Character] { sets(o).flatMap { $0 } }

    public static func random(_ o: Options = Options()) -> Result {
        let sets = sets(o)
        let alpha = sets.flatMap { $0 }
        let length = max(4, min(128, o.length))
        var out: [Character]
        // Rejection: redraw until every set is represented. This keeps the output uniform over all
        // passwords that satisfy the rule, instead of forcing characters into fixed slots.
        repeat {
            out = (0..<length).map { _ in alpha[SecureRandom.uniform(alpha.count)] }
        } while o.requireEachSet && length >= sets.count && !sets.allSatisfy { s in out.contains(where: s.contains) }
        let pw = String(out)
        out = []
        return Result(password: pw, entropyBits: entropyOfRandom(length: length, sets: sets.map(\.count), requireEach: o.requireEachSet))
    }

    /// log2 of the number of strings of `length` over the union that contain each set (inclusion–exclusion).
    static func entropyOfRandom(length: Int, sets: [Int], requireEach: Bool) -> Double {
        let total = Double(sets.reduce(0, +))
        guard requireEach, sets.count > 1, length >= sets.count else { return Double(length) * log2(total) }
        var count = 0.0
        let k = sets.count
        for mask in 0..<(1 << k) {
            var missing = 0, bits = 0
            for i in 0..<k where mask & (1 << i) != 0 { missing += sets[i]; bits += 1 }
            let term = pow((total - Double(missing)) / total, Double(length))
            count += (bits % 2 == 0 ? 1 : -1) * term
        }
        return Double(length) * log2(total) + log2(max(count, 1e-300))
    }

    public static func passphrase(_ o: PassphraseOptions = PassphraseOptions()) -> Result {
        let list = Wordlist.words
        let n = max(3, min(12, o.words))
        var words = (0..<n).map { _ in list[SecureRandom.uniform(list.count)] }
        if o.capitalize { words = words.map { $0.prefix(1).uppercased() + $0.dropFirst() } }
        var bits = Double(n) * log2(Double(list.count))
        if o.includeDigit {
            let i = SecureRandom.uniform(n)
            words[i] += String(SecureRandom.uniform(10))
            bits += log2(Double(n)) + log2(10)
        }
        return Result(password: words.joined(separator: o.separator), entropyBits: bits)
    }

    public static var wordlistCount: Int { Wordlist.words.count }

    public static func pin(length: Int = 6) -> Result {
        let n = max(4, min(16, length))
        let s = String((0..<n).map { _ in digits[SecureRandom.uniform(10)] })
        return Result(password: s, entropyBits: Double(n) * log2(10))
    }
}

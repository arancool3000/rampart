import Foundation
import CryptoKit

/// RFC 6238 time-based one-time passwords (RFC 4226 HOTP with a time counter). `kind == .hotp` makes it a
/// counter-based RFC 4226 token instead.
public struct TOTP: Codable, Hashable, Sendable {
    public enum Algorithm: String, Codable, Sendable, CaseIterable { case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512" }
    public enum Kind: String, Codable, Sendable, CaseIterable { case totp, hotp }
    public var kind: Kind = .totp
    /// HOTP moving counter (ignored for TOTP).
    public var counter: UInt64 = 0

    public var secret: Data
    public var digits: Int
    public var period: Int
    public var algorithm: Algorithm
    public var issuer: String?
    public var account: String?

    public init(secret: Data, digits: Int = 6, period: Int = 30, algorithm: Algorithm = .sha1, issuer: String? = nil, account: String? = nil) {
        self.secret = secret; self.digits = digits; self.period = period; self.algorithm = algorithm
        self.issuer = issuer; self.account = account
    }

    /// Parses either a bare Base32 secret or an `otpauth://totp/...` URI.
    public init?(string: String) {
        let s = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.lowercased().hasPrefix("otpauth://") {
            guard let c = URLComponents(string: s), let host = c.host?.lowercased(), let kind = Kind(rawValue: host) else { return nil }
            let q = Dictionary((c.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
            guard let sec = q["secret"].flatMap(Base32.decode), !sec.isEmpty else { return nil }
            let label = c.path.hasPrefix("/") ? String(c.path.dropFirst()) : c.path
            let parts = label.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            let qIssuer = q["issuer"].map { $0.trimmingCharacters(in: .whitespaces) }.flatMap { $0.isEmpty ? nil : $0 }
            let account = parts.last.flatMap { $0.isEmpty ? nil : $0 }
            guard let alg = Algorithm(rawValue: (q["algorithm"] ?? "SHA1").uppercased()) else { return nil }
            self.init(secret: sec,
                      digits: Int(q["digits"] ?? "") ?? 6,
                      period: Int(q["period"] ?? "") ?? 30,
                      algorithm: alg,
                      issuer: qIssuer ?? (parts.count == 2 && !parts[0].isEmpty ? parts[0] : nil),
                      account: account)
            self.kind = kind
            if kind == .hotp { guard let ctr = UInt64(q["counter"] ?? "0") else { return nil }; counter = ctr }
            guard (6...10).contains(digits), (1...300).contains(period) else { return nil }
        } else {
            guard let sec = Base32.decode(s), sec.count >= 10 else { return nil }
            self.init(secret: sec)
        }
    }

    public var uri: String {
        var c = URLComponents()
        c.scheme = "otpauth"; c.host = kind.rawValue
        c.path = "/" + [issuer, account].compactMap { $0 }.joined(separator: ":")
        c.queryItems = [URLQueryItem(name: "secret", value: Base32.encode(secret)),
                        URLQueryItem(name: "algorithm", value: algorithm.rawValue),
                        URLQueryItem(name: "digits", value: String(digits)),
                        kind == .hotp ? URLQueryItem(name: "counter", value: String(counter)) : URLQueryItem(name: "period", value: String(period))]
            + (issuer.map { [URLQueryItem(name: "issuer", value: $0)] } ?? [])
        // URLComponents leaves "+" and ":" in queries; encode "+" so issuers like "A+B" survive.
        return (c.string ?? "").replacingOccurrences(of: "+", with: "%2B")
    }

    public func code(at date: Date = Date()) -> String {
        if kind == .hotp { return Self.hotp(secret: secret, counter: counter, digits: digits, algorithm: algorithm) }
        return Self.hotp(secret: secret, counter: UInt64(max(0, date.timeIntervalSince1970) / Double(period)), digits: digits, algorithm: algorithm)
    }

    public func secondsRemaining(at date: Date = Date()) -> Int {
        period - Int(date.timeIntervalSince1970.rounded(.down)) % period
    }

    public static func hotp(secret: Data, counter: UInt64, digits: Int, algorithm: Algorithm) -> String {
        var c = counter.bigEndian
        let msg = withUnsafeBytes(of: &c) { Data($0) }
        let key = SymmetricKey(data: secret)
        let mac: [UInt8]
        switch algorithm {
        case .sha1: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: key))
        case .sha256: mac = Array(HMAC<SHA256>.authenticationCode(for: msg, using: key))
        case .sha512: mac = Array(HMAC<SHA512>.authenticationCode(for: msg, using: key))
        }
        let o = Int(mac[mac.count - 1] & 0x0f)
        let bin = (UInt32(mac[o] & 0x7f) << 24) | (UInt32(mac[o + 1]) << 16) | (UInt32(mac[o + 2]) << 8) | UInt32(mac[o + 3])
        var mod: UInt64 = 1
        for _ in 0..<digits { mod *= 10 }
        let v = UInt64(bin) % mod
        let s = String(v)
        return String(repeating: "0", count: max(0, digits - s.count)) + s
    }
}

public enum Base32 {
    static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    public static func decode(_ s: String) -> Data? {
        var bits: UInt64 = 0, n = 0
        var out = Data()
        for ch in s.uppercased() where ch != "=" && ch != " " && ch != "-" {
            guard let v = alphabet.firstIndex(of: ch) else { return nil }
            bits = (bits << 5) | UInt64(v); n += 5
            if n >= 8 { n -= 8; out.append(UInt8((bits >> UInt64(n)) & 0xff)) }
        }
        return out
    }

    public static func encode(_ d: Data) -> String {
        var bits: UInt64 = 0, n = 0, out = ""
        for b in d {
            bits = (bits << 8) | UInt64(b); n += 8
            while n >= 5 { n -= 5; out.append(alphabet[Int((bits >> UInt64(n)) & 31)]) }
        }
        if n > 0 { out.append(alphabet[Int((bits << UInt64(5 - n)) & 31)]) }
        return out
    }
}

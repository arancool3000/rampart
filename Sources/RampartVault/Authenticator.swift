import Foundation

/// 2FA authenticator helpers: parsing setup links and other apps' exports, dedupe, weak-parameter warnings.
/// Accounts are stored as `.totp` vault items (the otpauth URI in `totpSecret`), so they live only inside the
/// encrypted vault. Nothing here logs or persists secrets.
public enum Authenticator {
    public struct ParseResult: Sendable {
        public var accounts: [TOTP] = []
        public var errors: [String] = []
        public init(accounts: [TOTP] = [], errors: [String] = []) { self.accounts = accounts; self.errors = errors }
    }

    /// Parses pasted text: otpauth://totp|hotp links and otpauth-migration:// links, one per line (Keyring's
    /// "Copy all", Google Authenticator export), or an Aegis / 2FAS / Bitwarden JSON export.
    /// Input caps: a pasted export or QR payload is never anywhere near these.
    public static let maxInputBytes = 2 * 1_048_576
    public static let maxAccounts = 2000

    public static func parse(_ text: String) -> ParseResult {
        guard text.utf8.count <= maxInputBytes else { return ParseResult(errors: ["That's too much text to be an authenticator export."]) }
        var r = parseUnchecked(text)
        // Drop anything a code can't be computed from safely (zero/huge digits or period, empty secret).
        let before = r.accounts.count
        r.accounts = r.accounts.filter(\.isWellFormed)
        if r.accounts.count < before { r.errors.append("Skipped \(before - r.accounts.count) account\(before - r.accounts.count == 1 ? "" : "s") with invalid settings.") }
        if r.accounts.count > maxAccounts { r.accounts = Array(r.accounts.prefix(maxAccounts)); r.errors.append("Only the first \(maxAccounts) accounts were read.") }
        return r
    }

    static func parseUnchecked(_ text: String) -> ParseResult {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("{") || trimmed.hasPrefix("[") { return parseJSON(trimmed) }
        var r = ParseResult()
        for (n, raw) in trimmed.split(whereSeparator: \.isNewline).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            let lower = line.lowercased()
            if lower.hasPrefix("otpauth-migration://") {
                if let a = GoogleMigration.decode(line) { r.accounts += a } else { r.errors.append("Line \(n + 1): not a readable Google Authenticator export.") }
            } else if lower.hasPrefix("otpauth://") {
                if let t = TOTP(string: line) { r.accounts.append(t) } else { r.errors.append("Line \(n + 1): not a valid setup link (check the secret).") }
            } else {
                r.errors.append("Line \(n + 1): not an otpauth:// link.")
            }
        }
        return r
    }

    /// Identity used to detect duplicates: issuer + account (case-insensitive) + secret.
    public static func dedupeKey(_ t: TOTP) -> String {
        [(t.issuer ?? "").lowercased(), (t.account ?? "").lowercased(), Base32.encode(t.secret)].joined(separator: "\u{1F}")
    }

    /// Removes duplicates within `new` and against `existing`. Returns kept accounts and the skipped count.
    public static func dedupe(_ new: [TOTP], against existing: [TOTP]) -> (kept: [TOTP], duplicates: Int) {
        var seen = Set(existing.map(dedupeKey)), kept: [TOTP] = [], dup = 0
        for t in new { if seen.insert(dedupeKey(t)).inserted { kept.append(t) } else { dup += 1 } }
        return (kept, dup)
    }

    /// Plain-language warnings about weak or unusual parameters.
    public static func warnings(_ t: TOTP) -> [String] {
        var w: [String] = []
        if t.secret.count < 10 { w.append("The secret is short (\(t.secret.count * 8) bits); 160 bits is standard.") }
        if t.digits < 6 { w.append("Fewer than 6 digits is easy to guess.") }
        if t.kind == .totp && t.period > 60 { w.append("A \(t.period)-second period keeps each code valid for a long time.") }
        if t.kind == .totp && t.period < 15 { w.append("A \(t.period)-second period is unusually short; codes may expire before you type them.") }
        return w
    }

    /// Validates a manually typed Base32 secret (spaces and dashes allowed).
    public static func validSecret(_ s: String) -> Data? {
        let clean = s.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "-", with: "")
        guard !clean.isEmpty, let d = Base32.decode(clean), d.count >= 5 else { return nil }
        return d
    }

    public static func makeItem(_ t: TOTP) -> VaultItem {
        var i = VaultItem(kind: .totp, title: t.issuer ?? t.account ?? "Account")
        i.username = t.account ?? ""
        i.totpSecret = t.uri
        return i
    }

    /// Letter avatar text: first letter of the issuer (or account).
    public static func initial(_ t: TOTP) -> String {
        String((t.issuer ?? t.account ?? "?").trimmingCharacters(in: .whitespaces).prefix(1)).uppercased()
    }

    // MARK: JSON exports (unencrypted ones only)

    static func parseJSON(_ text: String) -> ParseResult {
        var r = ParseResult()
        guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
            r.errors.append("That JSON isn't a recognised export."); return r
        }
        func alg(_ s: Any?) -> TOTP.Algorithm { TOTP.Algorithm(rawValue: ((s as? String) ?? "SHA1").uppercased()) ?? .sha1 }
        func int(_ v: Any?, _ d: Int) -> Int { (v as? Int) ?? Int((v as? String) ?? "") ?? d }
        // Counters from a file: negative or non-numeric values become 0 instead of trapping in UInt64(_:).
        func counter(_ v: Any?) -> UInt64 { (v as? UInt64) ?? UInt64(exactly: int(v, 0)) ?? UInt64((v as? String) ?? "") ?? 0 }
        if let db = obj["db"] {
            // Aegis (plain). An encrypted Aegis vault has "db" as a string.
            guard let db = db as? [String: Any], let entries = db["entries"] as? [[String: Any]] else {
                r.errors.append("This Aegis export is encrypted. Export it unencrypted, import, then delete the file."); return r
            }
            for e in entries {
                let type = ((e["type"] as? String) ?? "totp").lowercased()
                guard type == "totp" || type == "hotp", let info = e["info"] as? [String: Any],
                      let sec = (info["secret"] as? String).flatMap(validSecret) else { r.errors.append("Skipped an unsupported Aegis entry."); continue }
                var t = TOTP(secret: sec, digits: int(info["digits"], 6), period: int(info["period"], 30), algorithm: alg(info["algo"]),
                             issuer: (e["issuer"] as? String).flatMap { $0.isEmpty ? nil : $0 }, account: e["name"] as? String)
                if type == "hotp" { t.kind = .hotp; t.counter = counter(info["counter"]) }
                r.accounts.append(t)
            }
        } else if let services = obj["services"] as? [[String: Any]] {
            // 2FAS
            for s in services {
                guard let sec = (s["secret"] as? String).flatMap(validSecret) else { r.errors.append("Skipped a 2FAS entry without a secret."); continue }
                let otp = s["otp"] as? [String: Any] ?? [:]
                var t = TOTP(secret: sec, digits: int(otp["digits"], 6), period: int(otp["period"], 30), algorithm: alg(otp["algorithm"]),
                             issuer: (otp["issuer"] as? String) ?? (s["name"] as? String), account: otp["account"] as? String)
                if ((otp["tokenType"] as? String) ?? "").uppercased() == "HOTP" { t.kind = .hotp; t.counter = counter(otp["counter"]) }
                r.accounts.append(t)
            }
        } else if let items = obj["items"] as? [[String: Any]] {
            // Bitwarden (unencrypted JSON): login.totp holds an otpauth link or a bare secret.
            for i in items {
                guard let login = i["login"] as? [String: Any], let totp = login["totp"] as? String, !totp.isEmpty else { continue }
                if var t = TOTP(string: totp) {
                    if t.issuer == nil { t.issuer = i["name"] as? String }
                    if t.account == nil { t.account = login["username"] as? String }
                    r.accounts.append(t)
                } else { r.errors.append("Skipped “\((i["name"] as? String) ?? "item")”: unreadable TOTP.") }
            }
        } else {
            r.errors.append("That JSON isn't a recognised Aegis, 2FAS or Bitwarden export.")
        }
        return r
    }
}

/// Google Authenticator "Transfer accounts" export: otpauth-migration://offline?data=<base64 protobuf>.
/// MigrationPayload { repeated OtpParameters otp_parameters = 1; ... }
/// OtpParameters { bytes secret = 1; string name = 2; string issuer = 3; Algorithm algorithm = 4;
///                 DigitCount digits = 5; OtpType type = 6; int64 counter = 7; }
public enum GoogleMigration {
    public static func decode(_ uri: String) -> [TOTP]? {
        guard let c = URLComponents(string: uri.trimmingCharacters(in: .whitespaces)),
              c.scheme?.lowercased() == "otpauth-migration",
              var b64 = c.queryItems?.first(where: { $0.name == "data" })?.value else { return nil }
        b64 = b64.replacingOccurrences(of: " ", with: "+").replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        guard let data = Data(base64Encoded: b64) else { return nil }
        return decodePayload(data)
    }

    public static func decodePayload(_ data: Data) -> [TOTP]? {
        var r = ProtoReader(Array(data)), out: [TOTP] = []
        while !r.atEnd {
            guard let (field, wire) = r.key() else { return nil }
            if field == 1 && wire == 2 {
                guard let sub = r.bytes(), let t = otp(sub) else { return nil }
                if let t { out.append(t) }
            } else if !r.skip(wire) { return nil }
        }
        return out
    }

    /// nil = malformed; .some(nil) = valid but unsupported entry.
    private static func otp(_ bytes: [UInt8]) -> TOTP?? {
        var r = ProtoReader(bytes)
        var secret = Data(), name = "", issuer = "", alg: UInt64 = 1, digits: UInt64 = 1, type: UInt64 = 2, counter: UInt64 = 0
        while !r.atEnd {
            guard let (f, w) = r.key() else { return nil }
            switch (f, w) {
            case (1, 2): guard let b = r.bytes() else { return nil }; secret = Data(b)
            case (2, 2): guard let b = r.bytes() else { return nil }; name = String(decoding: b, as: UTF8.self)
            case (3, 2): guard let b = r.bytes() else { return nil }; issuer = String(decoding: b, as: UTF8.self)
            case (4, 0): guard let v = r.varint() else { return nil }; alg = v
            case (5, 0): guard let v = r.varint() else { return nil }; digits = v
            case (6, 0): guard let v = r.varint() else { return nil }; type = v
            case (7, 0): guard let v = r.varint() else { return nil }; counter = v
            default: guard r.skip(w) else { return nil }
            }
        }
        guard !secret.isEmpty else { return .some(nil) }
        let algorithm: TOTP.Algorithm
        switch alg { case 2: algorithm = .sha256; case 3: algorithm = .sha512; case 0, 1: algorithm = .sha1; default: return .some(nil) }
        // Name is "issuer:account" or just "account".
        var account = name
        if let i = name.firstIndex(of: ":") {
            if issuer.isEmpty { issuer = String(name[..<i]) }
            account = String(name[name.index(after: i)...]).trimmingCharacters(in: .whitespaces)
        }
        var t = TOTP(secret: secret, digits: digits == 2 ? 8 : 6, period: 30, algorithm: algorithm,
                     issuer: issuer.isEmpty ? nil : issuer, account: account.isEmpty ? nil : account)
        if type == 1 { t.kind = .hotp; t.counter = counter } else if type != 2 && type != 0 { return .some(nil) }
        return .some(t)
    }
}

struct ProtoReader {
    let b: [UInt8]; var i = 0
    init(_ b: [UInt8]) { self.b = b }
    var atEnd: Bool { i >= b.count }
    mutating func varint() -> UInt64? {
        var v: UInt64 = 0, shift: UInt64 = 0
        while i < b.count, shift < 64 {
            let x = b[i]; i += 1
            v |= UInt64(x & 0x7f) << shift
            if x & 0x80 == 0 { return v }
            shift += 7
        }
        return nil
    }
    mutating func key() -> (Int, Int)? { guard let k = varint() else { return nil }; return (Int(k >> 3), Int(k & 7)) }
    mutating func bytes() -> [UInt8]? {
        guard let n = varint(), n <= UInt64(b.count - i) else { return nil }
        let out = Array(b[i..<i + Int(n)]); i += Int(n); return out
    }
    mutating func skip(_ wire: Int) -> Bool {
        switch wire {
        case 0: return varint() != nil
        case 1: guard b.count - i >= 8 else { return false }; i += 8; return true
        case 2: return bytes() != nil
        case 5: guard b.count - i >= 4 else { return false }; i += 4; return true
        default: return false
        }
    }
}

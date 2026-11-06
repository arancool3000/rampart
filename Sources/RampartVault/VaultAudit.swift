import Foundation
import CryptoKit
import RampartShared

/// Pwned Passwords k-anonymity check (same approach as RampartNetwork.PwnedPasswords, which this
/// module can't import): only the first 5 hex characters of the SHA-1 leave the Mac, and
/// `Add-Padding: true` hides the true response size. Opt-in only.
public final class BreachChecker: @unchecked Sendable {
    public let baseURL: URL
    private let session: URLSession
    private var cache: [String: String] = [:]   // prefix -> body
    private let lock = NSLock()

    public init(baseURL: URL = URL(string: "https://api.pwnedpasswords.com/range/")!) {
        self.baseURL = baseURL
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 15
        cfg.urlCache = nil
        session = URLSession(configuration: cfg)
    }

    public static func sha1Hex(_ password: String) -> String {
        Insecure.SHA1.hash(data: Data(password.utf8)).map { String(format: "%02X", $0) }.joined()
    }

    public static func count(in body: String, suffix: String) -> Int {
        let target = suffix.uppercased()
        for line in body.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":")
            guard parts.count == 2 else { continue }
            if parts[0].trimmingCharacters(in: .whitespaces).uppercased() == target {
                return Int(parts[1].trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            }
        }
        return 0
    }

    public func breachCount(for password: String) async throws -> Int {
        let hash = Self.sha1Hex(password)
        let prefix = String(hash.prefix(5)), suffix = String(hash.dropFirst(5))
        if let body = lock.withLock({ cache[prefix] }) { return Self.count(in: body, suffix: suffix) }
        var req = URLRequest(url: baseURL.appendingPathComponent(prefix))
        req.setValue("true", forHTTPHeaderField: "Add-Padding")
        req.setValue("RamPart/\(Product.version)", forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
            throw VaultError.io("Breach check failed (HTTP \((resp as? HTTPURLResponse)?.statusCode ?? 0)).")
        }
        let body = String(decoding: data, as: UTF8.self)
        guard let first = body.split(whereSeparator: \.isNewline).first, first.split(separator: ":").first?.count == 35 else {
            throw VaultError.io("Breach check got an unexpected response (a web filter may be blocking api.pwnedpasswords.com).")
        }
        lock.withLock { cache[prefix] = body }
        return Self.count(in: body, suffix: suffix)
    }
}

/// Security audit of the vault and its health score.
public struct VaultAudit: Sendable {
    public enum Issue: String, Sendable, CaseIterable, Identifiable {
        case breached, weak, reused, old, no2FA
        public var id: String { rawValue }
        public var title: String {
            switch self {
            case .breached: return "Found in data breaches"
            case .weak: return "Weak passwords"
            case .reused: return "Reused passwords"
            case .old: return "Not changed in over a year"
            case .no2FA: return "Two-factor available but not set up"
            }
        }
        public var symbol: String {
            switch self {
            case .breached: return "exclamationmark.octagon.fill"
            case .weak: return "lock.open.trianglebadge.exclamationmark"
            case .reused: return "arrow.triangle.2.circlepath"
            case .old: return "calendar.badge.clock"
            case .no2FA: return "person.badge.key"
            }
        }
        public var weight: Double {
            switch self { case .breached: return 1.0; case .weak: return 0.8; case .reused: return 0.7; case .old: return 0.25; case .no2FA: return 0.2 }
        }
        public var advice: String {
            switch self {
            case .breached: return "These passwords appear in known breaches and are tried first by attackers. Change them now."
            case .weak: return "Replace these with generated passwords of 16+ characters."
            case .reused: return "If one site leaks, every account sharing the password is at risk. Give each its own."
            case .old: return "Consider rotating important passwords you haven't changed in a year."
            case .no2FA: return "These sites support two-factor authentication. Turn it on and store the code here."
            }
        }
    }

    public var findings: [Issue: [UUID]]
    public var breachCounts: [UUID: Int]
    public var checkedBreaches: Bool
    public var loginCount: Int
    /// 0–100. Starts at 100 and loses points in proportion to affected logins, weighted by severity.
    public var score: Int

    public func items(_ issue: Issue) -> [UUID] { findings[issue] ?? [] }

    public static let oldAfter: TimeInterval = 365 * 86400

    /// Sites known to offer 2FA (a small built-in list; absent ≠ unsupported).
    public static let twoFactorDomains: Set<String> = [
        "google.com", "gmail.com", "youtube.com", "apple.com", "icloud.com", "microsoft.com", "live.com", "outlook.com", "office.com",
        "github.com", "gitlab.com", "bitbucket.org", "amazon.com", "amazon.co.uk", "aws.amazon.com", "facebook.com", "instagram.com",
        "twitter.com", "x.com", "linkedin.com", "reddit.com", "discord.com", "slack.com", "zoom.us", "dropbox.com", "box.com",
        "paypal.com", "stripe.com", "coinbase.com", "binance.com", "kraken.com", "robinhood.com", "fidelity.com", "vanguard.com",
        "schwab.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "capitalone.com", "americanexpress.com", "discover.com",
        "monzo.com", "revolut.com", "wise.com", "ebay.com", "etsy.com", "shopify.com", "squarespace.com", "wix.com", "wordpress.com",
        "cloudflare.com", "digitalocean.com", "linode.com", "heroku.com", "vercel.com", "netlify.com", "godaddy.com", "namecheap.com",
        "twitch.tv", "steampowered.com", "epicgames.com", "playstation.com", "xbox.com", "nintendo.com", "ea.com", "ubisoft.com",
        "battle.net", "blizzard.com", "roblox.com", "tiktok.com", "snapchat.com", "pinterest.com", "tumblr.com", "yahoo.com",
        "proton.me", "protonmail.com", "fastmail.com", "zoho.com", "atlassian.com", "atlassian.net", "notion.so", "figma.com",
        "adobe.com", "salesforce.com", "hubspot.com", "mailchimp.com", "openai.com", "anthropic.com", "claude.ai", "npmjs.com",
        "pypi.org", "docker.com", "heroku.com", "okta.com", "1password.com", "bitwarden.com", "lastpass.com", "evernote.com",
        "airbnb.com", "uber.com", "lyft.com", "booking.com", "expedia.com", "venmo.com", "cash.app", "patreon.com", "kickstarter.com",
        "hmrc.gov.uk", "gov.uk", "irs.gov", "ssa.gov", "login.gov", "nhs.uk", "tesla.com", "spotify.com", "duolingo.com"]

    public static func run(items: [VaultItem], breachCounts: [UUID: Int] = [:], checkedBreaches: Bool = false, now: Date = Date()) -> VaultAudit {
        let logins = items.filter { $0.kind == .login && !$0.password.isEmpty }
        var f: [Issue: [UUID]] = [:]
        var byPassword: [String: [UUID]] = [:]
        for i in logins {
            let userInputs = [i.username, i.title] + (i.primaryDomain.map { [$0, String($0.split(separator: ".").first ?? "")] } ?? [])
            if PasswordStrength.evaluate(i.password, userInputs: userInputs).level <= .weak { f[.weak, default: []].append(i.id) }
            byPassword[i.password, default: []].append(i.id)
            if now.timeIntervalSince(i.passwordModified ?? i.created) > oldAfter { f[.old, default: []].append(i.id) }
            if let d = i.primaryDomain, twoFactorDomains.contains(d), i.totp == nil { f[.no2FA, default: []].append(i.id) }
            if (breachCounts[i.id] ?? 0) > 0 { f[.breached, default: []].append(i.id) }
        }
        f[.reused] = byPassword.values.filter { $0.count > 1 }.flatMap { $0 }
        if f[.reused]?.isEmpty == true { f[.reused] = nil }
        var score = 100.0
        if !logins.isEmpty {
            let n = Double(logins.count)
            for (issue, ids) in f { score -= 100 * issue.weight * Double(Set(ids).count) / n / 2.5 }
        }
        return VaultAudit(findings: f, breachCounts: breachCounts, checkedBreaches: checkedBreaches, loginCount: logins.count,
                          score: max(0, min(100, Int(score.rounded()))))
    }

    /// Checks every distinct password once against Pwned Passwords (k-anonymity), then audits.
    public static func runWithBreachCheck(items: [VaultItem], checker: BreachChecker = BreachChecker()) async -> (VaultAudit, String?) {
        var counts: [UUID: Int] = [:], cache: [String: Int] = [:]
        var failure: String?
        for i in items where i.kind == .login && !i.password.isEmpty {
            if let c = cache[i.password] { counts[i.id] = c; continue }
            do { let c = try await checker.breachCount(for: i.password); cache[i.password] = c; counts[i.id] = c }
            catch { failure = error.localizedDescription; break }
        }
        cache = [:]
        return (run(items: items, breachCounts: counts, checkedBreaches: failure == nil), failure)
    }
}

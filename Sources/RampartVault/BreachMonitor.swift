import Foundation
import CryptoKit

/// Per-vault cache of breach results, stored encrypted inside the vault meta. Keys are HMAC-SHA256 of the
/// password under a random per-vault salt, so neither the password nor its SHA-1 is kept.
public struct BreachCache: Codable, Hashable, Sendable {
    public struct Entry: Codable, Hashable, Sendable {
        public var count: Int
        public var checked: Date
        public init(count: Int, checked: Date) { self.count = count; self.checked = checked }
    }
    /// Re-check a password at most once a day.
    public static let interval: TimeInterval = 86400
    public var salt: Data
    public var entries: [String: Entry] = [:]

    public init(salt: Data = SecureRandom.data(32)) { self.salt = salt }

    public func key(_ password: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(password.utf8), using: SymmetricKey(data: salt))
        return mac.map { String(format: "%02x", $0) }.joined()
    }
    public func result(for password: String) -> Entry? { entries[key(password)] }
    public func isFresh(_ password: String, now: Date = Date()) -> Bool {
        guard let e = result(for: password) else { return false }
        return now.timeIntervalSince(e.checked) < Self.interval && e.checked <= now.addingTimeInterval(60)
    }
    public mutating func record(_ password: String, count: Int, now: Date = Date()) {
        entries[key(password)] = Entry(count: count, checked: now)
    }
    /// Drops entries for passwords no longer in the vault.
    public mutating func prune(keeping passwords: [String]) {
        let keep = Set(passwords.map(key))
        entries = entries.filter { keep.contains($0.key) }
    }
}

/// Automatic breach monitoring logic (no UI, no storage): which passwords are due and the sweep itself.
public enum BreachMonitor {
    /// Every non-empty password stored in the vault (logins, Wi-Fi, authenticator items).
    public static func passwords(in items: [VaultItem]) -> [String] {
        var seen = Set<String>(), out: [String] = []
        for i in items where !i.password.isEmpty && seen.insert(i.password).inserted { out.append(i.password) }
        return out
    }

    /// Distinct passwords without a fresh (< 1 day) cached result.
    public static func due(_ passwords: [String], cache: BreachCache, now: Date = Date()) -> [String] {
        var seen = Set<String>()
        return passwords.filter { !$0.isEmpty && seen.insert($0).inserted && !cache.isFresh($0, now: now) }
    }

    public struct SweepResult: Sendable {
        public var updates: [String: BreachCache.Entry] = [:]
        public var failure: String?
        public var checked = 0
        public var found = 0
    }

    /// Checks each password once (sequentially, so at most one request is in flight). Stops on the first
    /// failure or on cancellation. Returns cache updates for the caller to merge.
    public static func sweep(_ passwords: [String], cache: BreachCache, checker: BreachChecker,
                             now: Date = Date(), force: Bool = false) async -> SweepResult {
        var r = SweepResult()
        let list = force ? Array(Set(passwords.filter { !$0.isEmpty })) : due(passwords, cache: cache, now: now)
        for pw in list {
            if Task.isCancelled { break }
            do {
                let c = try await checker.breachCount(for: pw)
                r.updates[cache.key(pw)] = .init(count: c, checked: now)
                r.checked += 1
                if c > 0 { r.found += 1 }
            } catch { r.failure = error.localizedDescription; break }
        }
        return r
    }

    /// Breach counts per item id from the cache (items never checked are absent).
    public static func counts(items: [VaultItem], cache: BreachCache) -> [UUID: Int] {
        var out: [UUID: Int] = [:]
        for i in items where !i.password.isEmpty { if let e = cache.result(for: i.password) { out[i.id] = e.count } }
        return out
    }

    /// "Found in known breaches (seen 1,234 times)" / "Not found in known breaches".
    public static func describe(count: Int) -> String {
        count > 0 ? "Found in known breaches (seen \(count.formatted()) time\(count == 1 ? "" : "s"))" : "Not found in known breaches"
    }
}

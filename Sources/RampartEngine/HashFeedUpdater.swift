import Foundation
import RampartShared

/// A downloadable list of known-bad SHA-256 hashes.
public struct HashFeed: Sendable {
    public var name: String
    public var url: URL
    /// Value stored in `KnownBadHash.source`.
    public var source: String
    /// abuse.ch Auth-Key (sent as the `Auth-Key` header when set).
    public var authKey: String?
    /// Reject downloads with fewer valid hashes than this (guards against block pages / truncation).
    public var minimumEntries: Int
    /// Entries of this feed older than this are pruned after a successful update (rolling feeds). nil = keep.
    public var retention: TimeInterval?

    public init(name: String, url: URL, source: String, authKey: String? = nil, minimumEntries: Int = 10,
                retention: TimeInterval? = nil) {
        self.name = name; self.url = url; self.source = source; self.authKey = authKey
        self.minimumEntries = minimumEntries; self.retention = retention
    }

    /// abuse.ch MalwareBazaar "recent additions" SHA-256 list (plain text, '#' comments, one hash per line).
    /// Free for non-commercial use (see docs/research/04). Entries are kept for 180 days.
    public static func malwareBazaarRecent(authKey: String? = nil) -> HashFeed {
        HashFeed(name: "MalwareBazaar recent", url: URL(string: "https://bazaar.abuse.ch/export/txt/sha256/recent/")!,
                 source: "malwarebazaar", authKey: authKey, minimumEntries: 10, retention: 180 * 86_400)
    }
}

/// Result of one feed update.
public struct FeedUpdateResult: Sendable {
    public var feed: String
    public var received: Int
    public var stored: Int
    public var pruned: Int
    public var signatureVersion: String
}

/// Downloads hash feeds, validates them strictly (HTTP status, size, content shape) and merges them
/// into `HashDatabase`. A web filter or captive portal returning HTML is rejected rather than imported.
public final class HashFeedUpdater: @unchecked Sendable {
    public let database: HashDatabase
    private let session: URLSession
    /// Maximum accepted body size.
    public var maxBytes = 64 << 20

    public init(database: HashDatabase, session: URLSession = .shared) {
        self.database = database; self.session = session
    }

    /// Downloads and imports `feed`. Throws `EngineError.feedInvalid` on any validation failure; the DB is unchanged then.
    @discardableResult
    public func update(_ feed: HashFeed = .malwareBazaarRecent()) async throws -> FeedUpdateResult {
        var req = URLRequest(url: feed.url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 60)
        req.setValue("Rampart/\(Product.version)", forHTTPHeaderField: "User-Agent")
        if let key = feed.authKey, !key.isEmpty { req.setValue(key, forHTTPHeaderField: "Auth-Key") }
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw EngineError.feedInvalid("no HTTP response") }
        guard http.statusCode == 200 else { throw EngineError.feedInvalid("HTTP \(http.statusCode)") }
        if let host = http.url?.host, let want = feed.url.host, host != want {
            throw EngineError.feedInvalid("redirected to \(host)")
        }
        guard data.count <= maxBytes else { throw EngineError.feedInvalid("body too large (\(data.count) bytes)") }
        if let ct = http.value(forHTTPHeaderField: "Content-Type")?.lowercased(), ct.contains("html") {
            throw EngineError.feedInvalid("unexpected content type \(ct)")
        }
        return try importFeed(data, feed: feed)
    }

    /// Validates and imports already-downloaded feed bytes (also used for offline/bundled updates).
    @discardableResult
    public func importFeed(_ data: Data, feed: HashFeed, now: Date = Date()) throws -> FeedUpdateResult {
        let hashes = try Self.parse(data, minimumEntries: feed.minimumEntries)
        let stored = try database.addKnownBad(hashes.map { KnownBadHash(sha256: $0, source: feed.source, added: now) })
        var pruned = 0
        if let retention = feed.retention {
            pruned = try database.pruneKnownBad(source: feed.source, olderThan: now.addingTimeInterval(-retention))
        }
        try database.setMeta("feed.\(feed.source).updated", ISO8601DateFormatter().string(from: now))
        try database.setMeta("feed.\(feed.source).count", String(hashes.count))
        try database.bumpSignatureGeneration()
        return FeedUpdateResult(feed: feed.name, received: hashes.count, stored: stored, pruned: pruned,
                                signatureVersion: database.signatureVersion)
    }

    /// Parses a hash list: blank lines and `#` comments ignored; each other line must be (or start with, for
    /// CSV) a 64-hex SHA-256, optionally quoted. More than 1% malformed lines, HTML, or fewer than
    /// `minimumEntries` hashes -> `EngineError.feedInvalid`. Returns unique lowercase hashes.
    public static func parse(_ data: Data, minimumEntries: Int = 1) throws -> [String] {
        guard let text = String(data: data, encoding: .utf8) else { throw EngineError.feedInvalid("not UTF-8") }
        let trimmedStart = text.drop(while: { $0.isWhitespace })
        if trimmedStart.hasPrefix("<") { throw EngineError.feedInvalid("looks like HTML/XML") }
        var out: [String] = []
        var seen = Set<String>()
        var bad = 0, total = 0
        for raw in text.split(omittingEmptySubsequences: true, whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            total += 1
            var field = Substring(line)
            if let comma = field.firstIndex(of: ",") { field = field[..<comma] }
            field = Substring(field.trimmingCharacters(in: CharacterSet(charactersIn: "\" ")))
            if FileHasher.isSHA256Hex(field) {
                let h = field.lowercased()
                if seen.insert(h).inserted { out.append(h) }
            } else if field.count == 64 || !line.contains(",") {
                bad += 1
            } else if total > 1 {
                bad += 1
            } else {
                total -= 1 // CSV header row
            }
        }
        if total > 0 && Double(bad) / Double(total) > 0.01 {
            throw EngineError.feedInvalid("\(bad) of \(total) lines are not SHA-256 hashes")
        }
        guard out.count >= minimumEntries else { throw EngineError.feedInvalid("only \(out.count) hashes") }
        return out
    }
}

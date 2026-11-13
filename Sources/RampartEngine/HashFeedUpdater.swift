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
    /// wms-fc: base64 raw Ed25519 public key. When set the feed is RamPart's own: the body must be accompanied by a
    /// signed manifest (`FeedSigning`, at `manifestURL` or `<url>.manifest.json`) that pins its SHA-256, size, feed id,
    /// a monotonic version (no rollback) and a creation date (no stale replay). Signed feeds may live on any https host.
    public var publicKey: String?
    public var manifestURL: URL?

    public init(name: String, url: URL, source: String, authKey: String? = nil, minimumEntries: Int = 10,
                retention: TimeInterval? = nil, publicKey: String? = nil, manifestURL: URL? = nil) {
        self.name = name; self.url = url; self.source = source; self.authKey = authKey
        self.minimumEntries = minimumEntries; self.retention = retention
        self.publicKey = publicKey; self.manifestURL = manifestURL
    }

    public var effectiveManifestURL: URL { manifestURL ?? FeedSigning.defaultManifestURL(for: url) }

    /// abuse.ch MalwareBazaar "recent additions" SHA-256 list (plain text, '#' comments, one hash per line).
    /// Free for non-commercial use (see docs/research/04). Entries are kept for 180 days.
    public static func malwareBazaarRecent(authKey: String? = nil) -> HashFeed {
        HashFeed(name: "MalwareBazaar recent", url: URL(string: "https://bazaar.abuse.ch/export/txt/sha256/recent/")!,
                 source: "malwarebazaar", authKey: authKey, minimumEntries: 10, retention: 180 * 86_400)
    }

    /// RamPart's own curated hash feed, signed with the release key. Returns nil until the lead has set
    /// `FeedSigning.productionPublicKeyBase64` (the hook): an unsigned "RamPart feed" can't be configured by accident.
    public static func rampartSigned(name: String, url: URL, source: String, minimumEntries: Int = 1,
                                     publicKey: String? = FeedSigning.productionPublicKeyBase64) -> HashFeed? {
        guard let publicKey, FeedSigning.keyID(publicKeyBase64: publicKey) != nil else { return nil }
        return HashFeed(name: name, url: url, source: source, minimumEntries: minimumEntries, retention: nil, publicKey: publicKey)
    }
}

/// Result of one feed update.
public struct FeedUpdateResult: Sendable {
    public var feed: String
    public var received: Int
    public var stored: Int
    public var pruned: Int
    public var signatureVersion: String
    /// Version of the signed manifest that was accepted (signed feeds only).
    public var manifestVersion: Int?
}

/// Downloads hash feeds, validates them strictly (HTTP status, size, content shape) and merges them
/// into `HashDatabase`. A web filter or captive portal returning HTML is rejected rather than imported.
///
/// wms-fc hardening: a poisoned hash feed is a file-deletion primitive (a hash hit scores 100 and is quarantined), so
/// the transport is pinned: https only, unsigned feeds only from `trustedHosts`, TLS 1.2 floor, no cookies or cache,
/// redirects only to https on the same host, the body streamed under a hard byte ceiling (no gigabyte buffering),
/// and RamPart's own feeds verified against a signed manifest with rollback and freshness checks. The database is
/// untouched unless every check passes (last known good stays).
public final class HashFeedUpdater: @unchecked Sendable {
    public let database: HashDatabase
    private let session: URLSession
    /// Maximum accepted body size.
    public var maxBytes = 64 << 20
    /// Unsigned feeds are fetched only from these hosts (hosts-file / DNS redirects to look-alikes are refused).
    public static let trustedHosts: Set<String> = ["bazaar.abuse.ch"]

    /// Redirects are followed only to https on the same host (pinned-host policy).
    private final class PinnedRedirects: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            let from = task.originalRequest?.url?.host?.lowercased()
            let ok = request.url?.scheme?.lowercased() == "https" && request.url?.host?.lowercased() == from
            completionHandler(ok ? request : nil)
        }
    }

    /// `protocolClasses` is for tests (mock URLProtocol); production passes nil.
    public init(database: HashDatabase, timeout: TimeInterval = 60, protocolClasses: [AnyClass]? = nil) {
        self.database = database
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout * 4
        cfg.httpCookieStorage = nil
        cfg.httpShouldSetCookies = false
        cfg.urlCache = nil
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.tlsMinimumSupportedProtocolVersion = .TLSv12
        if let protocolClasses { cfg.protocolClasses = protocolClasses }
        session = URLSession(configuration: cfg, delegate: PinnedRedirects(), delegateQueue: nil)
    }

    deinit { session.invalidateAndCancel() }

    /// Why a feed may not be fetched at all (nil = allowed).
    public static func sourceRefusal(_ feed: HashFeed) -> String? {
        guard feed.url.scheme?.lowercased() == "https", let host = feed.url.host?.lowercased(), !host.isEmpty,
              feed.url.user == nil, feed.url.password == nil else { return "feed URL must be https without credentials" }
        if let pk = feed.publicKey {
            guard FeedSigning.keyID(publicKeyBase64: pk) != nil else { return "feed public key is not a valid Ed25519 key" }
            guard feed.effectiveManifestURL.scheme?.lowercased() == "https" else { return "manifest URL must be https" }
            return nil
        }
        return trustedHosts.contains(host) ? nil : "host \(host) is not a pinned feed host and the feed is unsigned"
    }

    private func request(_ url: URL, feed: HashFeed) -> URLRequest {
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 60)
        req.setValue("Rampart/\(Product.version)", forHTTPHeaderField: "User-Agent")
        if let key = feed.authKey, !key.isEmpty { req.setValue(key, forHTTPHeaderField: "Auth-Key") }
        return req
    }

    /// Streams a response under `limit` bytes; a longer body is abandoned, never buffered.
    private func fetch(_ url: URL, feed: HashFeed, limit: Int) async throws -> (Data, HTTPURLResponse) {
        let (bytes, resp) = try await session.bytes(for: request(url, feed: feed))
        guard let http = resp as? HTTPURLResponse else { throw EngineError.feedInvalid("no HTTP response") }
        guard http.statusCode == 200 else { throw EngineError.feedInvalid("HTTP \(http.statusCode)") }
        if let host = http.url?.host?.lowercased(), let want = url.host?.lowercased(), host != want {
            throw EngineError.feedInvalid("redirected to \(host)")
        }
        if http.url?.scheme?.lowercased() != "https" { throw EngineError.feedInvalid("non-TLS response") }
        if http.expectedContentLength > Int64(limit) { throw EngineError.feedInvalid("body too large (\(http.expectedContentLength) bytes)") }
        var data = Data()
        if http.expectedContentLength > 0 { data.reserveCapacity(Int(http.expectedContentLength)) }
        var chunk = [UInt8](); chunk.reserveCapacity(65_536)
        for try await b in bytes {
            chunk.append(b)
            if chunk.count == 65_536 {
                data.append(contentsOf: chunk); chunk.removeAll(keepingCapacity: true)
                if data.count > limit { throw EngineError.feedInvalid("body too large (over \(limit) bytes)") }
            }
        }
        data.append(contentsOf: chunk)
        guard data.count <= limit else { throw EngineError.feedInvalid("body too large (\(data.count) bytes)") }
        return (data, http)
    }

    /// Downloads and imports `feed`. Throws `EngineError.feedInvalid` on any validation failure; the DB is unchanged then.
    @discardableResult
    public func update(_ feed: HashFeed = .malwareBazaarRecent(), now: Date = Date()) async throws -> FeedUpdateResult {
        if let why = Self.sourceRefusal(feed) { throw EngineError.feedInvalid(why) }
        let (data, http) = try await fetch(feed.url, feed: feed, limit: maxBytes)
        if let ct = http.value(forHTTPHeaderField: "Content-Type")?.lowercased(), ct.contains("html") {
            throw EngineError.feedInvalid("unexpected content type \(ct)")
        }
        var manifest: FeedSigning.Manifest?
        if let pk = feed.publicKey {
            let (signed, _) = try await fetch(feed.effectiveManifestURL, feed: feed, limit: FeedSigning.maxManifestBytes)
            let prev = database.meta("feed.\(feed.source).version").flatMap(Int.init).map {
                FeedSigning.Previous(version: $0, sha256: database.meta("feed.\(feed.source).sha256"))
            }
            switch FeedSigning.verify(signed: signed, body: data, feed: feed.source, publicKeyBase64: pk, previous: prev, now: now) {
            case .success(let m): manifest = m
            case .failure(let f): throw EngineError.feedInvalid("signed manifest refused: \(f)")
            }
        }
        var r = try importFeed(data, feed: feed, now: now)
        if let m = manifest {
            try database.setMeta("feed.\(feed.source).version", String(m.version))
            try database.setMeta("feed.\(feed.source).sha256", m.sha256.lowercased())
            r.manifestVersion = m.version
        }
        return r
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

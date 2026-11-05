import Foundation
import RampartShared

/// Downloads domain lists, validates them (web filters such as Securly answer with HTML login pages and
/// status 200), stores them atomically and builds a `DomainBlocklist`.
public final class BlocklistUpdater: @unchecked Sendable {
    public struct Source: Codable, Hashable, Sendable {
        public var id: String
        public var url: URL
        public var format: DomainBlocklist.Format
        /// Fewer parsed domains than this means the download is not a real list.
        public var minimumEntries: Int
        public var refreshInterval: TimeInterval
        public init(id: String, url: URL, format: DomainBlocklist.Format, minimumEntries: Int, refreshInterval: TimeInterval) {
            self.id = id; self.url = url; self.format = format
            self.minimumEntries = minimumEntries; self.refreshInterval = refreshInterval
        }
    }

    /// Defaults from research doc 06.
    public static let hageziTIF = Source(
        id: "hagezi-tif",
        url: URL(string: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt")!,
        format: .plain, minimumEntries: 10_000, refreshInterval: 12 * 3600)
    /// URLhaus domains via the malware-filter mirror (no auth). The official
    /// `https://urlhaus.abuse.ch/downloads/hostfile/` answered HTTP 410 Gone on 2026-11-05.
    public static let urlhausHosts = Source(
        id: "urlhaus",
        url: URL(string: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt")!,
        format: .hosts, minimumEntries: 50, refreshInterval: 3600)
    /// Official abuse.ch hostfile, kept for when it returns (currently 410).
    public static let urlhausOfficialHosts = Source(
        id: "urlhaus-official",
        url: URL(string: "https://urlhaus.abuse.ch/downloads/hostfile/")!,
        format: .hosts, minimumEntries: 50, refreshInterval: 3600)
    public static let defaultSources = [hageziTIF, urlhausHosts]

    public enum Outcome: Sendable, CustomStringConvertible {
        case updated(entries: Int)
        case notModified
        case rejected(String)
        case failed(String)
        public var description: String {
            switch self {
            case .updated(let n): return "updated (\(n) entries)"
            case .notModified: return "not modified"
            case .rejected(let r): return "rejected: \(r)"
            case .failed(let r): return "failed: \(r)"
            }
        }
        public var isSuccess: Bool { if case .updated = self { return true }; if case .notModified = self { return true }; return false }
    }

    public let sources: [Source]
    public let directory: URL
    private let session: URLSession
    private let log = RLog.logger("blocklist")

    public init(sources: [Source] = BlocklistUpdater.defaultSources,
                directory: URL = Paths.effectiveRoot.appendingPathComponent("Blocklists"),
                timeout: TimeInterval = 60) {
        self.sources = sources; self.directory = directory
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout * 4
        session = URLSession(configuration: cfg)
    }

    func listURL(_ s: Source) -> URL { directory.appendingPathComponent(s.id + ".txt") }
    func metaURL(_ s: Source) -> URL { directory.appendingPathComponent(s.id + ".meta.json") }

    struct Meta: Codable { var etag: String?; var lastModified: String?; var fetched: Date; var entries: Int }

    public struct Rejection: Error, CustomStringConvertible {
        public let reason: String
        public var description: String { reason }
    }

    /// Validates a downloaded body. Returns the parsed entry count, or a rejection reason.
    public static func validate(data: Data, statusCode: Int, contentType: String?, source: Source) -> Result<Int, Rejection> {
        guard statusCode == 200 else { return .failure(Rejection(reason: "HTTP \(statusCode)")) }
        let ct = (contentType ?? "").lowercased()
        if ct.contains("html") || ct.contains("json") || ct.contains("xml") {
            return .failure(Rejection(reason: "unexpected content-type \(ct) (web filter or error page)"))
        }
        let head = String(decoding: data.prefix(512), as: UTF8.self).lowercased()
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if head.hasPrefix("<!doctype") || head.hasPrefix("<html") || head.hasPrefix("<?xml") || head.contains("<head") {
            return .failure(Rejection(reason: "body is HTML, not a domain list (web filter login page?)"))
        }
        // Count parseable lines without building a trie (lists can exceed 1M entries).
        var entries = 0
        String(decoding: data, as: UTF8.self).enumerateLines { line, _ in
            if case .block = DomainBlocklist.parseLine(Substring(line), format: source.format) { entries += 1 }
        }
        guard entries >= source.minimumEntries else {
            return .failure(Rejection(reason: "only \(entries) domains parsed (minimum \(source.minimumEntries))"))
        }
        return .success(entries)
    }

    /// Fetches one source with ETag / If-Modified-Since; on success writes the list atomically.
    public func update(_ source: Source, force: Bool = false) async -> Outcome {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let meta = (try? Data(contentsOf: metaURL(source))).flatMap { try? JSONDecoder.rampart.decode(Meta.self, from: $0) }
        var req = URLRequest(url: source.url)
        req.setValue("Rampart/\(Product.version)", forHTTPHeaderField: "User-Agent")
        if !force, FileManager.default.fileExists(atPath: listURL(source).path), let meta {
            if let e = meta.etag { req.setValue(e, forHTTPHeaderField: "If-None-Match") }
            if let l = meta.lastModified { req.setValue(l, forHTTPHeaderField: "If-Modified-Since") }
        }
        let data: Data, resp: URLResponse
        do { (data, resp) = try await session.data(for: req) } catch {
            log.error("blocklist \(source.id, privacy: .public) fetch failed: \(error.localizedDescription, privacy: .public)")
            return .failed(error.localizedDescription)
        }
        guard let http = resp as? HTTPURLResponse else { return .failed("no HTTP response") }
        if http.statusCode == 304 { return .notModified }
        if let final = http.url?.host, final != source.url.host {
            log.info("blocklist \(source.id, privacy: .public) redirected to \(final, privacy: .public)")
        }
        switch Self.validate(data: data, statusCode: http.statusCode,
                             contentType: http.value(forHTTPHeaderField: "Content-Type"), source: source) {
        case .failure(let why):
            log.error("blocklist \(source.id, privacy: .public) rejected: \(why.reason, privacy: .public)")
            return .rejected(why.reason)
        case .success(let n):
            do {
                try data.write(to: listURL(source), options: .atomic)
                let m = Meta(etag: http.value(forHTTPHeaderField: "ETag"),
                             lastModified: http.value(forHTTPHeaderField: "Last-Modified"), fetched: Date(), entries: n)
                try JSONEncoder.rampart.encode(m).write(to: metaURL(source), options: .atomic)
            } catch { return .failed("write: \(error.localizedDescription)") }
            return .updated(entries: n)
        }
    }

    /// Updates sources that are due (or all, with `force`).
    public func updateAll(force: Bool = false) async -> [String: Outcome] {
        var out: [String: Outcome] = [:]
        for s in sources {
            if !force, let d = lastFetched(s), Date().timeIntervalSince(d) < s.refreshInterval { out[s.id] = .notModified; continue }
            out[s.id] = await update(s, force: force)
        }
        return out
    }

    public func lastFetched(_ s: Source) -> Date? {
        (try? Data(contentsOf: metaURL(s))).flatMap { try? JSONDecoder.rampart.decode(Meta.self, from: $0) }?.fetched
    }

    /// Builds a blocklist from every stored list plus optional user allow/block files (one domain per line).
    public func buildBlocklist(userBlock: [String] = [], userAllow: [String] = []) -> DomainBlocklist {
        let bl = DomainBlocklist()
        for s in sources {
            if let data = try? Data(contentsOf: listURL(s)) {
                bl.load(text: String(decoding: data, as: UTF8.self), format: s.format, source: s.id)
            }
        }
        for d in userBlock { bl.add(d, source: "user") }
        for d in userAllow { bl.allow(d) }
        return bl
    }
}

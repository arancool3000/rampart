import Foundation
import CryptoKit
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
        /// Base64 raw Ed25519 public key (32 bytes). When set, the list must carry a valid detached signature
        /// at `signatureURL` (default `<url>.sig`, raw 64 bytes or base64) and may come from any https host.
        public var publicKey: String?
        public var signatureURL: URL?
        /// wms-fc: when set (with `publicKey`), the list is RamPart's own and is verified against a signed manifest
        /// (`FeedSigning`: SHA-256 + size + feed id + monotonic version + creation date) instead of a bare `.sig`.
        /// A bare signature can be replayed with an old list; the manifest can't.
        public var manifestURL: URL?
        public init(id: String, url: URL, format: DomainBlocklist.Format, minimumEntries: Int, refreshInterval: TimeInterval,
                    publicKey: String? = nil, signatureURL: URL? = nil, manifestURL: URL? = nil) {
            self.id = id; self.url = url; self.format = format
            self.minimumEntries = minimumEntries; self.refreshInterval = refreshInterval
            self.publicKey = publicKey; self.signatureURL = signatureURL; self.manifestURL = manifestURL
        }
        public var effectiveSignatureURL: URL { signatureURL ?? URL(string: url.absoluteString + ".sig")! }

        /// RamPart's own signed domain list. nil until the lead sets `FeedSigning.productionPublicKeyBase64` (the hook).
        public static func rampartSigned(id: String, url: URL, format: DomainBlocklist.Format, minimumEntries: Int,
                                         refreshInterval: TimeInterval = 12 * 3600,
                                         publicKey: String? = FeedSigning.productionPublicKeyBase64) -> Source? {
            guard let publicKey, FeedSigning.keyID(publicKeyBase64: publicKey) != nil else { return nil }
            return Source(id: id, url: url, format: format, minimumEntries: minimumEntries, refreshInterval: refreshInterval,
                          publicKey: publicKey, manifestURL: FeedSigning.defaultManifestURL(for: url))
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

    /// Hard ceilings (hx4): a hostile or broken mirror can't exhaust the root daemon's memory or disk, or
    /// replace a big list with a tiny one (truncation / takeover) or a huge one (blocking the internet).
    public static let maxBytes = 64 * 1024 * 1024
    public static let maxEntries = 4_000_000
    /// A new copy with fewer than this fraction of the previous entry count is rejected as truncated.
    public static let minRetainedFraction = 0.25

    /// Redirects are followed only to https on the same host (pinned-host policy).
    private final class PinnedRedirects: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            let from = task.originalRequest?.url?.host?.lowercased()
            let ok = request.url?.scheme?.lowercased() == "https" && request.url?.host?.lowercased() == from
            completionHandler(ok ? request : nil)
        }
    }

    public init(sources: [Source] = BlocklistUpdater.defaultSources,
                directory: URL = Paths.effectiveRoot.appendingPathComponent("Blocklists"),
                timeout: TimeInterval = 60, protocolClasses: [AnyClass]? = nil) {
        // Only https sources with a safe file id (the id becomes a file name in `directory`).
        self.sources = sources.filter { Self.isSafeSource($0) }; self.directory = directory
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout * 4
        cfg.httpCookieStorage = nil
        cfg.tlsMinimumSupportedProtocolVersion = .TLSv12
        if let protocolClasses { cfg.protocolClasses = protocolClasses }
        session = URLSession(configuration: cfg, delegate: PinnedRedirects(), delegateQueue: nil)
    }

    /// Pinned feed hosts (hx4 / N-X1-2): an unsigned feed is fetched only from these hosts, so a hosts-file or
    /// DNS redirect to a lookalike host, or a source added by tampering, is refused. Signed feeds may live anywhere.
    public static let trustedHosts: Set<String> = ["cdn.jsdelivr.net", "malware-filter.gitlab.io", "urlhaus.abuse.ch"]

    public static func hostAllowed(_ s: Source) -> Bool {
        s.publicKey != nil || trustedHosts.contains(s.url.host?.lowercased() ?? "")
    }

    /// Verifies a detached Ed25519 signature over the exact list bytes. `signature` is raw 64 bytes or base64 text.
    public static func verifySignature(data: Data, signature: Data, publicKeyBase64: String) -> Bool {
        guard let raw = Data(base64Encoded: publicKeyBase64), raw.count == 32,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else { return false }
        var sig = signature
        if sig.count != 64,
           let d = Data(base64Encoded: String(decoding: signature, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) {
            sig = d
        }
        return sig.count == 64 && key.isValidSignature(sig, for: data)
    }

    public static func isSafeSource(_ s: Source) -> Bool {
        s.url.scheme?.lowercased() == "https" && !(s.url.host ?? "").isEmpty && s.url.user == nil
            && !s.id.isEmpty && s.id.count <= 64 && !s.id.hasPrefix(".")
            && s.id.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "-_.".unicodeScalars.contains($0)) }
    }

    func listURL(_ s: Source) -> URL { directory.appendingPathComponent(s.id + ".txt") }
    func metaURL(_ s: Source) -> URL { directory.appendingPathComponent(s.id + ".meta.json") }

    /// `version` / `sha256`: the last accepted signed manifest (rollback protection for RamPart's own lists).
    struct Meta: Codable { var etag: String?; var lastModified: String?; var fetched: Date; var entries: Int; var version: Int?; var sha256: String? }

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
        guard data.count <= maxBytes else { return .failure(Rejection(reason: "list larger than \(maxBytes / 1_048_576) MB")) }
        // A text list never contains NUL bytes; binary/compressed bodies do.
        if data.contains(0) { return .failure(Rejection(reason: "body is binary, not a text domain list")) }
        // Count parseable lines without building a trie (lists can exceed 1M entries).
        var entries = 0
        String(decoding: data, as: UTF8.self).enumerateLines { line, _ in
            if case .block = DomainBlocklist.parseLine(Substring(line), format: source.format) { entries += 1 }
        }
        guard entries >= source.minimumEntries else {
            return .failure(Rejection(reason: "only \(entries) domains parsed (minimum \(source.minimumEntries))"))
        }
        guard entries <= maxEntries else { return .failure(Rejection(reason: "\(entries) domains is implausibly large")) }
        return .success(entries)
    }

    /// Rejects a list that shrank far below the copy we already have (truncated download or hijacked mirror).
    public static func checkShrink(new: Int, previous: Int?) -> Rejection? {
        guard let previous, previous >= 1000 else { return nil }
        return Double(new) < Double(previous) * minRetainedFraction
            ? Rejection(reason: "only \(new) domains vs \(previous) last time (truncated or replaced list?)") : nil
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
        guard Self.isSafeSource(source) else { return .rejected("source must be an https URL with a safe id") }
        guard Self.hostAllowed(source) else { return .rejected("host \(source.url.host ?? "?") is not a pinned feed host and the feed is unsigned") }
        var data = Data(), resp: URLResponse
        do {
            // Streamed with a hard byte ceiling so a hostile server can't make the root daemon buffer gigabytes.
            let (bytes, r) = try await session.bytes(for: req)
            resp = r
            if r.expectedContentLength > Int64(Self.maxBytes) { return .rejected("list larger than \(Self.maxBytes / 1_048_576) MB") }
            if r.expectedContentLength > 0 { data.reserveCapacity(Int(r.expectedContentLength)) }
            var chunk = [UInt8](); chunk.reserveCapacity(65_536)
            for try await b in bytes {
                chunk.append(b)
                if chunk.count == 65_536 {
                    data.append(contentsOf: chunk); chunk.removeAll(keepingCapacity: true)
                    if data.count > Self.maxBytes { return .rejected("list larger than \(Self.maxBytes / 1_048_576) MB") }
                }
            }
            data.append(contentsOf: chunk)
        } catch {
            log.error("blocklist \(source.id, privacy: .public) fetch failed: \(error.localizedDescription, privacy: .public)")
            return .failed(error.localizedDescription)
        }
        guard let http = resp as? HTTPURLResponse else { return .failed("no HTTP response") }
        if http.statusCode == 304 { return .notModified }
        if let final = http.url?.host?.lowercased(), final != source.url.host?.lowercased() {
            return .rejected("redirected off the pinned host to \(final)")
        }
        switch Self.validate(data: data, statusCode: http.statusCode,
                             contentType: http.value(forHTTPHeaderField: "Content-Type"), source: source) {
        case .failure(let why):
            log.error("blocklist \(source.id, privacy: .public) rejected: \(why.reason, privacy: .public)")
            return .rejected(why.reason)
        case .success(let n):
            var accepted: FeedSigning.Manifest?
            if let pk = source.publicKey, let murl = source.manifestURL {
                // RamPart's own list: signed manifest with rollback + freshness checks (wms-fc).
                guard murl.scheme?.lowercased() == "https" else { return .rejected("manifest URL must be https") }
                var mreq = URLRequest(url: murl)
                mreq.setValue("Rampart/\(Product.version)", forHTTPHeaderField: "User-Agent")
                guard let (signed, mresp) = try? await session.data(for: mreq), (mresp as? HTTPURLResponse)?.statusCode == 200,
                      (mresp as? HTTPURLResponse)?.url?.host?.lowercased() == murl.host?.lowercased() else {
                    log.error("blocklist \(source.id, privacy: .public) rejected: signed manifest missing")
                    return .rejected("signed manifest missing")
                }
                let prev = meta?.version.map { FeedSigning.Previous(version: $0, sha256: meta?.sha256) }
                switch FeedSigning.verify(signed: signed, body: data, feed: source.id, publicKeyBase64: pk, previous: prev) {
                case .success(let m): accepted = m
                case .failure(let f):
                    log.error("blocklist \(source.id, privacy: .public) rejected: \(f.description, privacy: .public)")
                    return .rejected("signed manifest refused: \(f)")
                }
            } else if let pk = source.publicKey {
                var sreq = URLRequest(url: source.effectiveSignatureURL)
                sreq.setValue("Rampart/\(Product.version)", forHTTPHeaderField: "User-Agent")
                guard let (sig, sresp) = try? await session.data(for: sreq), (sresp as? HTTPURLResponse)?.statusCode == 200,
                      sig.count <= 1024, Self.verifySignature(data: data, signature: sig, publicKeyBase64: pk) else {
                    log.error("blocklist \(source.id, privacy: .public) rejected: bad or missing signature")
                    return .rejected("signature missing or invalid")
                }
            }
            if let why = Self.checkShrink(new: n, previous: meta?.entries),
               FileManager.default.fileExists(atPath: listURL(source).path) {
                log.error("blocklist \(source.id, privacy: .public) rejected: \(why.reason, privacy: .public)")
                return .rejected(why.reason)
            }
            do {
                try data.write(to: listURL(source), options: .atomic)
                let m = Meta(etag: http.value(forHTTPHeaderField: "ETag"),
                             lastModified: http.value(forHTTPHeaderField: "Last-Modified"), fetched: Date(), entries: n,
                             version: accepted?.version ?? meta?.version, sha256: accepted?.sha256.lowercased() ?? meta?.sha256)
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
            let size = (try? FileManager.default.attributesOfItem(atPath: listURL(s).path)[.size] as? Int) ?? 0
            if size <= Self.maxBytes, let data = try? Data(contentsOf: listURL(s)) {
                // Feeds may only ADD block entries; allow rules (`@@||x^`) in a downloaded feed are ignored.
                bl.load(text: String(decoding: data, as: UTF8.self), format: s.format, source: s.id, acceptAllowRules: false)
            }
        }
        for d in userBlock { bl.add(d, source: "user") }
        for d in userAllow { bl.allow(d) }
        return bl
    }
}

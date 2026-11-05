import Foundation

public enum DoHError: Error, CustomStringConvertible {
    case http(Int, URL), badContentType(String, URL), malformed(URL), transport(String, URL), allFailed([String])
    public var description: String {
        switch self {
        case .http(let s, let u): return "HTTP \(s) from \(u.host ?? "?")"
        case .badContentType(let c, let u): return "unexpected content-type '\(c)' from \(u.host ?? "?") (web filter?)"
        case .malformed(let u): return "malformed DNS message from \(u.host ?? "?")"
        case .transport(let e, let u): return "\(u.host ?? "?"): \(e)"
        case .allFailed(let e): return "all DoH upstreams failed: " + e.joined(separator: "; ")
        }
    }
}

/// RFC 8484 DNS-over-HTTPS client (POST, application/dns-message) with ordered fallback.
public final class DoHClient: @unchecked Sendable {
    public static let defaultUpstreams = [
        URL(string: "https://security.cloudflare-dns.com/dns-query")!,
        URL(string: "https://dns.quad9.net/dns-query")!,
    ]
    public let upstreams: [URL]
    private let session: URLSession

    public init(upstreams: [URL] = DoHClient.defaultUpstreams, timeout: TimeInterval = 4) {
        self.upstreams = upstreams
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout * 2
        cfg.httpMaximumConnectionsPerHost = 4
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.urlCache = nil
        // The resolver itself must not resolve through a proxy that might point back at us.
        cfg.connectionProxyDictionary = [:]
        session = URLSession(configuration: cfg)
    }

    /// Sends `query` (wire format). The message ID is zeroed on the wire (RFC 8484 4.1) and restored in the reply.
    public func resolve(_ query: Data, completion: @escaping @Sendable (Result<(Data, URL), DoHError>) -> Void) {
        guard query.count >= 12 else { completion(.failure(.allFailed(["query too short"]))); return }
        let originalID = UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1])
        let wire = DNSWire.withID(query, 0)
        attempt(0, wire, originalID, [], completion)
    }

    private func attempt(_ i: Int, _ wire: Data, _ id: UInt16, _ errors: [String],
                         _ completion: @escaping @Sendable (Result<(Data, URL), DoHError>) -> Void) {
        guard i < upstreams.count else { completion(.failure(.allFailed(errors))); return }
        let url = upstreams[i]
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        req.httpBody = wire
        session.dataTask(with: req) { [self] data, resp, err in
            if let result = Self.validate(data: data, response: resp, error: err, url: url) {
                switch result {
                case .success(let body): completion(.success((DNSWire.withID(body, id), url)))
                case .failure(let e): attempt(i + 1, wire, id, errors + [e.description], completion)
                }
            }
        }.resume()
    }

    static func validate(data: Data?, response: URLResponse?, error: Error?, url: URL) -> Result<Data, DoHError>? {
        if let error { return .failure(.transport(error.localizedDescription, url)) }
        guard let http = response as? HTTPURLResponse else { return .failure(.transport("no response", url)) }
        guard http.statusCode == 200 else { return .failure(.http(http.statusCode, url)) }
        let ctype = (http.value(forHTTPHeaderField: "Content-Type") ?? "").lowercased()
        guard ctype.hasPrefix("application/dns-message") else { return .failure(.badContentType(ctype, url)) }
        guard let data, data.count >= 12, let m = try? DNSMessage.parse(data), m.isResponse else {
            return .failure(.malformed(url))
        }
        return .success(data)
    }
}

/// Small TTL-respecting response cache. Cached replies have their TTLs decremented on the way out.
public final class DNSResponseCache: @unchecked Sendable {
    struct Key: Hashable { let name: String; let type: UInt16; let qclass: UInt16 }
    struct Entry { let data: Data; let stored: Date; let expires: Date; let ttlOffsets: [(Int, UInt32)] }

    private let lock = NSLock()
    private var entries: [Key: Entry] = [:]
    public let capacity: Int
    public let maxTTL: UInt32
    public let negativeTTL: UInt32
    public private(set) var hits = 0, misses = 0

    public init(capacity: Int = 4096, maxTTL: UInt32 = 86_400, negativeTTL: UInt32 = 30) {
        self.capacity = capacity; self.maxTTL = maxTTL; self.negativeTTL = negativeTTL
    }

    public var count: Int { lock.lock(); defer { lock.unlock() }; return entries.count }

    public func store(_ response: Data, for q: DNSQuestion, now: Date = Date()) {
        guard let m = try? DNSMessage.parse(response), !m.truncated else { return }
        let ttl: UInt32
        var offsets: [(Int, UInt32)] = []
        for rr in m.answers + m.authorities + m.additionals where rr.type != DNSType.opt && rr.ttlOffset >= 0 {
            offsets.append((rr.ttlOffset, rr.ttl))
        }
        switch m.rcode {
        case DNSRCode.noError where !m.answers.isEmpty:
            ttl = m.answers.map(\.ttl).min() ?? 0
        case DNSRCode.noError, DNSRCode.nxDomain:
            // RFC 2308: negative TTL = min(SOA TTL, SOA MINIMUM).
            if let soa = m.authorities.first(where: { $0.type == DNSType.soa }), soa.rdata.count >= 4 {
                let r = [UInt8](soa.rdata.suffix(4))
                let minimum = UInt32(r[0]) << 24 | UInt32(r[1]) << 16 | UInt32(r[2]) << 8 | UInt32(r[3])
                ttl = min(soa.ttl, minimum)
            } else { ttl = negativeTTL }
        default:
            return   // never cache SERVFAIL/REFUSED
        }
        let capped = min(ttl, maxTTL)
        guard capped > 0 else { return }
        lock.lock(); defer { lock.unlock() }
        if entries.count >= capacity { evict(now: now) }
        entries[Key(name: q.name, type: q.type, qclass: q.qclass)] =
            Entry(data: response, stored: now, expires: now.addingTimeInterval(TimeInterval(capped)), ttlOffsets: offsets)
    }

    /// Returns a cached response with the caller's ID and remaining TTLs, or nil.
    public func lookup(_ q: DNSQuestion, id: UInt16, now: Date = Date()) -> Data? {
        lock.lock()
        let key = Key(name: q.name, type: q.type, qclass: q.qclass)
        guard let e = entries[key] else { misses += 1; lock.unlock(); return nil }
        if e.expires <= now { entries[key] = nil; misses += 1; lock.unlock(); return nil }
        hits += 1
        lock.unlock()
        let elapsed = UInt32(max(0, now.timeIntervalSince(e.stored)))
        var d = DNSWire.withID(e.data, id)
        d.withUnsafeMutableBytes { raw in
            for (off, ttl) in e.ttlOffsets where off + 4 <= raw.count {
                let v = ttl > elapsed ? ttl - elapsed : 0
                raw[off] = UInt8(v >> 24); raw[off + 1] = UInt8((v >> 16) & 0xFF)
                raw[off + 2] = UInt8((v >> 8) & 0xFF); raw[off + 3] = UInt8(v & 0xFF)
            }
        }
        return d
    }

    public func clear() { lock.lock(); entries.removeAll(); lock.unlock() }

    private func evict(now: Date) {
        entries = entries.filter { $0.value.expires > now }
        if entries.count >= capacity {
            // Drop the oldest quarter.
            let sorted = entries.sorted { $0.value.stored < $1.value.stored }
            for (k, _) in sorted.prefix(max(1, capacity / 4)) { entries[k] = nil }
        }
    }
}

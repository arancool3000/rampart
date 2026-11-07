import Foundation
import CryptoKit
import Security

public enum DoHError: Error, CustomStringConvertible {
    case http(Int, URL), badContentType(String, URL), malformed(URL), transport(String, URL), allFailed([String]), pinMismatch(URL)
    public var description: String {
        switch self {
        case .pinMismatch(let u): return "\(u.host ?? "?"): TLS key does not match the pinned key (interception?)"
        case .http(let s, let u): return "HTTP \(s) from \(u.host ?? "?")"
        case .badContentType(let c, let u): return "unexpected content-type '\(c)' from \(u.host ?? "?") (web filter?)"
        case .malformed(let u): return "malformed DNS message from \(u.host ?? "?")"
        case .transport(let e, let u): return "\(u.host ?? "?"): \(e)"
        case .allFailed(let e): return "all DoH upstreams failed: " + e.joined(separator: "; ")
        }
    }
}

/// Public-key pinning for DoH upstreams (hx4 / N-X1-1). A pin is base64(SHA-256(subjectPublicKey bits)), i.e.
/// the hash of `SecKeyCopyExternalRepresentation` of a certificate's key (same bytes as the SPKI BIT STRING).
///
/// Policy: the system trust evaluation must pass first, then at least one certificate in the chain must match
/// a pin. Static pins (`staticPins`) win; for hosts without static pins the chain's keys are learned on first
/// use (TOFU), and the intermediate/root keys keep matching across leaf rotations. A mismatch rejects that
/// upstream and raises `onPinFailure` (an alert). RamPart never falls back to an unpinned resolver; if every
/// upstream fails, queries get SERVFAIL and the daemon watchdog restores the original DNS (visible to the user).
public final class DoHPinStore: @unchecked Sendable {
    /// Ship-time pins per host. Left empty on purpose: the real Cloudflare/Quad9 key hashes must be taken from
    /// a trusted network (`DoHPinStore.keyHash`) by the release owner; inventing them would break DNS.
    public static let staticPins: [String: Set<String>] = [:]

    public enum Decision: Equatable, Sendable { case match, learned, mismatch }

    private let lock = NSLock()
    private var learned: [String: Set<String>]
    private let statics: [String: Set<String>]
    public let stateURL: URL?

    public init(stateURL: URL? = nil, staticPins: [String: Set<String>] = DoHPinStore.staticPins) {
        self.stateURL = stateURL; self.statics = staticPins
        if let u = stateURL, let d = try? Data(contentsOf: u), d.count < 1_000_000,
           let m = try? JSONDecoder().decode([String: Set<String>].self, from: d) { learned = m } else { learned = [:] }
    }

    public static func keyHash(_ key: SecKey) -> String? {
        guard let raw = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
        return Data(SHA256.hash(data: raw)).base64EncodedString()
    }

    /// Pure decision for a host and its chain's key hashes (fixture-testable).
    public func evaluate(host: String, chain: [String]) -> Decision {
        let h = host.lowercased()
        guard !chain.isEmpty else { return .mismatch }
        if let pins = statics[h], !pins.isEmpty { return pins.isDisjoint(with: chain) ? .mismatch : .match }
        lock.lock(); defer { lock.unlock() }
        if let pins = learned[h], !pins.isEmpty { return pins.isDisjoint(with: chain) ? .mismatch : .match }
        learned[h] = Set(chain)
        persistLocked()
        return .learned
    }

    /// User-confirmed re-pin (e.g. the provider changed CA).
    public func forget(host: String) { lock.lock(); learned[host.lowercased()] = nil; persistLocked(); lock.unlock() }

    private func persistLocked() {
        guard let u = stateURL else { return }
        try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(learned) { try? d.write(to: u, options: .atomic) }
    }
}

/// RFC 8484 DNS-over-HTTPS client (POST, application/dns-message) with ordered fallback.
///
/// Hardening (hx4):
/// - TLS only: non-`https` upstreams (and ones with user-info) are dropped; if none remain the built-in
///   defaults are used. TLS 1.2 is the floor and redirects are refused (a redirect could downgrade to http
///   or point at a third party).
/// - Replies are bounded to 65,535 bytes and must be a real response to *our* query: QR set, opcode 0,
///   ID 0 (what we sent), exactly one question equal to ours (name/type/class), and every answer record must
///   sit on the CNAME chain that starts at the question name (bailiwick check; stray records are a poisoning
///   attempt). A failing upstream is skipped, never trusted.
public final class DoHClient: @unchecked Sendable {
    public static let defaultUpstreams = [
        URL(string: "https://security.cloudflare-dns.com/dns-query")!,
        URL(string: "https://dns.quad9.net/dns-query")!,
    ]
    /// Pinned addresses for the default upstream hostnames. The local filter answers these names itself so
    /// the resolver never depends on itself to find its upstream (bootstrap loop = Mac without DNS).
    public static let bootstrapAddresses: [String: [String]] = [
        "security.cloudflare-dns.com": ["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"],
        "dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
    ]
    public static let maxResponseBytes = 65_535

    public let upstreams: [URL]
    private let session: URLSession

    /// Keeps only well-formed `https` URLs with a host and no credentials.
    public static func sanitizeUpstreams(_ urls: [URL]) -> [URL] {
        let ok = urls.filter { u in
            u.scheme?.lowercased() == "https" && !(u.host ?? "").isEmpty && u.user == nil && u.password == nil
        }
        return ok.isEmpty ? defaultUpstreams : ok
    }

    public let pins: DoHPinStore
    /// Raised (host, detail) when an upstream presents a key that doesn't match its pin.
    public var onPinFailure: (@Sendable (String, String) -> Void)?

    private final class Delegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        let pins: DoHPinStore
        weak var owner: DoHClient?
        private let lock = NSLock()
        private var mismatched = Set<Int>()
        init(pins: DoHPinStore) { self.pins = pins }
        func tookMismatch(_ id: Int) -> Bool { lock.lock(); defer { lock.unlock() }; return mismatched.remove(id) != nil }

        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil); return
            }
            let host = challenge.protectionSpace.host
            guard SecTrustEvaluateWithError(trust, nil) else { completionHandler(.cancelAuthenticationChallenge, nil); return }
            let certs = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
            let chain = certs.compactMap { SecCertificateCopyKey($0).flatMap(DoHPinStore.keyHash) }
            if pins.evaluate(host: host, chain: chain) == .mismatch {
                lock.lock(); mismatched.insert(task.taskIdentifier); lock.unlock()
                owner?.onPinFailure?(host, "TLS key for \(host) changed from the pinned key. Lookups through it are blocked.")
                completionHandler(.cancelAuthenticationChallenge, nil); return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        }
    }
    private let delegate: Delegate

    /// `protocolClasses` is for tests (mock URLProtocol); production passes nil.
    public init(upstreams: [URL] = DoHClient.defaultUpstreams, timeout: TimeInterval = 4, protocolClasses: [AnyClass]? = nil,
                pins: DoHPinStore = DoHPinStore()) {
        self.upstreams = Self.sanitizeUpstreams(upstreams)
        self.pins = pins
        delegate = Delegate(pins: pins)
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout * 2
        cfg.httpMaximumConnectionsPerHost = 4
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.urlCache = nil
        cfg.httpCookieStorage = nil
        cfg.httpShouldSetCookies = false
        cfg.tlsMinimumSupportedProtocolVersion = .TLSv12
        // The resolver itself must not resolve through a proxy that might point back at us.
        cfg.connectionProxyDictionary = [:]
        if let protocolClasses { cfg.protocolClasses = protocolClasses }
        session = URLSession(configuration: cfg, delegate: delegate, delegateQueue: nil)
        delegate.owner = self
    }

    deinit { session.invalidateAndCancel() }

    /// Sends `query` (wire format). The message ID is zeroed on the wire (RFC 8484 4.1) and restored in the reply.
    public func resolve(_ query: Data, completion: @escaping @Sendable (Result<(Data, URL), DoHError>) -> Void) {
        guard query.count >= 12, query.count <= Self.maxResponseBytes,
              let parsed = try? DNSMessage.parse(query), parsed.questions.count == 1, let q = parsed.questions.first else {
            completion(.failure(.allFailed(["query malformed"]))); return
        }
        let originalID = UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1])
        let wire = DNSWire.withID(query, 0)
        attempt(0, wire, q, originalID, [], completion)
    }

    private func attempt(_ i: Int, _ wire: Data, _ q: DNSQuestion, _ id: UInt16, _ errors: [String],
                         _ completion: @escaping @Sendable (Result<(Data, URL), DoHError>) -> Void) {
        guard i < upstreams.count else { completion(.failure(.allFailed(errors))); return }
        let url = upstreams[i]
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        req.httpBody = wire
        let idBox = TaskIDBox()
        let task = session.dataTask(with: req) { [self] data, resp, err in
            if delegate.tookMismatch(idBox.id) {
                attempt(i + 1, wire, q, id, errors + [DoHError.pinMismatch(url).description], completion); return
            }
            switch Self.validate(data: data, response: resp, error: err, url: url, question: q) {
            case .success(let body): completion(.success((DNSWire.withID(body, id), url)))
            case .failure(let e): attempt(i + 1, wire, q, id, errors + [e.description], completion)
            }
        }
        idBox.id = task.taskIdentifier
        task.resume()
    }

    private final class TaskIDBox: @unchecked Sendable { var id = -1 }

    /// Validates one upstream reply against the question we asked (see type doc).
    public static func validate(data: Data?, response: URLResponse?, error: Error?, url: URL,
                                question: DNSQuestion? = nil) -> Result<Data, DoHError> {
        if let error { return .failure(.transport(error.localizedDescription, url)) }
        guard let http = response as? HTTPURLResponse else { return .failure(.transport("no response", url)) }
        guard http.statusCode == 200 else { return .failure(.http(http.statusCode, url)) }
        if let final = http.url, final.scheme?.lowercased() != "https" { return .failure(.transport("non-TLS reply", url)) }
        let ctype = (http.value(forHTTPHeaderField: "Content-Type") ?? "").lowercased()
        guard ctype.hasPrefix("application/dns-message") else { return .failure(.badContentType(ctype, url)) }
        guard let data, data.count >= 12, data.count <= maxResponseBytes,
              let m = try? DNSMessage.parse(data), m.isResponse, m.opcode == 0 else {
            return .failure(.malformed(url))
        }
        if let question {
            guard m.id == 0, m.questions.count == 1, let rq = m.questions.first,
                  rq.name == question.name, rq.type == question.type, rq.qclass == question.qclass,
                  answersInBailiwick(m, question: question) else { return .failure(.malformed(url)) }
        }
        return .success(data)
    }

    /// Every answer must be owned by the question name or a name reached through the CNAME/DNAME chain.
    static func answersInBailiwick(_ m: DNSMessage, question: DNSQuestion) -> Bool {
        var chain: Set<String> = [question.name]
        var changed = true, rounds = 0
        while changed && rounds < 16 {   // answers need not be in chain order
            changed = false; rounds += 1
            for rr in m.answers where rr.type == DNSType.cname && chain.contains(rr.name) {
                if let t = rr.value, chain.insert(t).inserted { changed = true }
            }
        }
        return m.answers.allSatisfy { rr in
            if chain.contains(rr.name) { return true }
            // DNAME (39) owners are ancestors of a chain name; RRSIG (46) covers an in-chain RRset.
            if rr.type == 39 { return chain.contains { $0.hasSuffix("." + rr.name) } }
            return false
        }
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
    /// Bounds cache memory (capacity x this). Larger replies are served but not cached.
    public let maxEntryBytes = 8_192

    public init(capacity: Int = 4096, maxTTL: UInt32 = 86_400, negativeTTL: UInt32 = 30) {
        self.capacity = capacity; self.maxTTL = maxTTL; self.negativeTTL = negativeTTL
    }

    public var count: Int { lock.lock(); defer { lock.unlock() }; return entries.count }

    public func store(_ response: Data, for q: DNSQuestion, now: Date = Date()) {
        guard response.count <= maxEntryBytes, let m = try? DNSMessage.parse(response), !m.truncated,
              m.questions.count == 1, m.questions.first == q else { return }
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

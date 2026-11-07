import Foundation
import RampartShared

// Safe link-chain analysis. Follows up to `maxHops` redirects with a hardened ephemeral URLSession:
// no cookies, no cache, no credentials, no JavaScript (meta-refresh / location= are parsed as text),
// HEAD then a range-limited GET (64 KB), per-hop timeout, http/https only, SSRF guard (no private,
// loopback, link-local, CGNAT, multicast or reserved addresses, resolved before every hop).
// Run only when the user asks or a high-risk URL was found. Tests inject a mock URLProtocol.

public struct ChainHop: Codable, Hashable, Sendable {
    public var url: String
    public var status: Int?
    public var via: String               // "start", "http-30x", "meta-refresh", "js-location"
    public var contentType: String?
    public var contentDisposition: String?
    public var magic: String?            // "mach-o", "zip", "xar/pkg", "script", "pe", "dmg?"
    public var urlScore: Int
    public var brandMatch: String?
    public var note: String?
}

public struct ChainReport: Codable, Sendable {
    public var start: String
    public var hops: [ChainHop]
    public var finalURL: String?
    public var servesDownload: Bool
    public var downloadKind: String?
    public var stoppedReason: String?    // "max-hops", "ssrf-refused", "scheme-refused", "loop", "error: ..."
    public var score: Int
    public var verdict: ScamVerdict
    public var reasons: [String]
}

public final class RedirectChainInspector: @unchecked Sendable {
    public var maxHops = 10
    public var perHopTimeout: TimeInterval = 6
    public var maxBodyBytes = 64 * 1024
    public var allowedPorts: Set<Int> = [80, 443, 8080, 8443]
    public var analyzer: URLAnalyzer
    /// Resolves a host to IP strings. Default uses getaddrinfo; tests inject a fake (never real DNS).
    public var resolver: @Sendable (String) -> [String]
    let session: URLSession
    let delegate = NoRedirectDelegate()

    public init(analyzer: URLAnalyzer = URLAnalyzer(), protocolClasses: [AnyClass]? = nil,
                resolver: (@Sendable (String) -> [String])? = nil) {
        self.analyzer = analyzer
        self.resolver = resolver ?? RedirectChainInspector.systemResolve
        let cfg = URLSessionConfiguration.ephemeral
        cfg.httpCookieAcceptPolicy = .never
        cfg.httpShouldSetCookies = false
        cfg.httpCookieStorage = nil
        cfg.urlCache = nil
        cfg.urlCredentialStorage = nil
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        cfg.timeoutIntervalForRequest = 6
        cfg.timeoutIntervalForResource = 10
        cfg.httpMaximumConnectionsPerHost = 1
        cfg.waitsForConnectivity = false
        cfg.connectionProxyDictionary = [:]
        cfg.httpAdditionalHeaders = ["User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
                                     "Accept": "*/*"]
        if let pc = protocolClasses { cfg.protocolClasses = pc }
        session = URLSession(configuration: cfg, delegate: delegate, delegateQueue: nil)
    }
    deinit { session.invalidateAndCancel() }

    final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
        func urlSession(_ s: URLSession, task: URLSessionTask, willPerformHTTPRedirection r: HTTPURLResponse,
                        newRequest: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
        func urlSession(_ s: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            // Never answer auth challenges (no basic auth, no client certs); default TLS validation for server trust.
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
                completionHandler(.performDefaultHandling, nil)
            } else { completionHandler(.cancelAuthenticationChallenge, nil) }
        }
    }

    // MARK: SSRF guard

    public static func isForbiddenIP(_ ip: String) -> Bool {
        var a4 = in_addr()
        if inet_pton(AF_INET, ip, &a4) == 1 {
            let v = UInt32(bigEndian: a4.s_addr)
            let b0 = v >> 24, b1 = (v >> 16) & 0xff
            if b0 == 0 || b0 == 10 || b0 == 127 || b0 >= 224 { return true }
            if b0 == 169 && b1 == 254 { return true }
            if b0 == 172 && (16...31).contains(b1) { return true }
            if b0 == 192 && b1 == 168 { return true }
            if b0 == 100 && (64...127).contains(b1) { return true }       // CGNAT
            if b0 == 198 && (b1 == 18 || b1 == 19) { return true }       // benchmarking
            if b0 == 192 && b1 == 0 && ((v >> 8) & 0xff) == 0 { return true }
            return false
        }
        var a6 = in6_addr()
        if inet_pton(AF_INET6, ip, &a6) == 1 {
            let b = withUnsafeBytes(of: a6) { Array($0) }
            if b.allSatisfy({ $0 == 0 }) || (b[0..<15].allSatisfy { $0 == 0 } && b[15] == 1) { return true }  // :: and ::1
            if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 { return true }   // fe80::/10
            if (b[0] & 0xfe) == 0xfc { return true }                    // fc00::/7
            if b[0] == 0xff { return true }                             // multicast
            if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff {  // ::ffff:a.b.c.d
                return isForbiddenIP("\(b[12]).\(b[13]).\(b[14]).\(b[15])")
            }
            if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 { return true } // documentation
            return false
        }
        return true   // not an address: refuse
    }

    public static let forbiddenHostSuffixes = ["localhost", "local", "internal", "lan", "home.arpa", "intranet", "corp", "localdomain"]

    public static func systemResolve(_ host: String) -> [String] {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(first) }
        var out: [String] = []
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                out.append(String(cString: buf))
            }
            p = ai.pointee.ai_next
        }
        return out
    }

    /// nil = allowed; otherwise the refusal reason.
    func refusal(_ u: URL) -> String? {
        guard let scheme = u.scheme?.lowercased(), scheme == "http" || scheme == "https" else { return "scheme-refused" }
        guard let host = u.host?.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]")), !host.isEmpty else { return "no-host" }
        if u.user != nil || u.password != nil { return "credentials-in-url-refused" }
        let port = u.port ?? (scheme == "https" ? 443 : 80)
        if !allowedPorts.contains(port) { return "port-refused" }
        if Self.forbiddenHostSuffixes.contains(where: { host == $0 || host.hasSuffix("." + $0) }) { return "ssrf-refused" }
        var a4 = in_addr(), a6 = in6_addr()
        let isLiteral = inet_pton(AF_INET, host, &a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1
        // Numeric forms like 0x7f.1 or 2130706433 that inet_aton accepts are refused outright.
        if !isLiteral, host.allSatisfy({ $0.isNumber || $0 == "." || $0 == "x" }) && host.first?.isNumber == true { return "ssrf-refused" }
        let ips = isLiteral ? [host] : resolver(host)
        if ips.isEmpty { return "unresolvable" }
        if ips.contains(where: Self.isForbiddenIP) { return "ssrf-refused" }
        return nil
    }

    // MARK: textual redirects

    static let metaRefreshRegex = try! NSRegularExpression(pattern: #"(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d*\s*;?\s*url\s*=\s*['"]?([^"'>\s]+)"#)
    static let jsLocationRegex = try! NSRegularExpression(pattern: #"(?is)(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.(?:replace|assign)\(\s*["']([^"']+)["']"#)

    public static func textualRedirect(_ body: String) -> (String, String)? {
        let ns = body as NSString
        let r = NSRange(location: 0, length: ns.length)
        if let m = metaRefreshRegex.firstMatch(in: body, range: r) { return (ns.substring(with: m.range(at: 1)), "meta-refresh") }
        if let m = jsLocationRegex.firstMatch(in: body, range: r) {
            let g = m.range(at: 1).location != NSNotFound ? m.range(at: 1) : m.range(at: 2)
            return (ns.substring(with: g).replacingOccurrences(of: "\\/", with: "/"), "js-location")
        }
        return nil
    }

    // MARK: download classification

    static let downloadTypes = ["application/octet-stream", "application/x-apple-diskimage", "application/x-diskcopy", "application/zip",
                                "application/x-zip", "application/x-mach-binary", "application/x-executable", "application/x-msdownload",
                                "application/vnd.apple.installer+xml", "application/x-newton-compatible-pkg", "application/x-xar",
                                "application/x-sh", "text/x-shellscript", "application/x-csh", "application/x-python", "text/x-python",
                                "application/x-apple-aspen-config", "application/x-7z-compressed", "application/x-rar", "application/vnd.rar",
                                "application/x-tar", "application/gzip", "application/x-bzip2", "application/java-archive", "application/x-iso9660-image"]
    static let downloadExts: Set<String> = ["dmg", "pkg", "mpkg", "zip", "app", "command", "tool", "sh", "py", "scpt", "applescript",
                                            "exe", "msi", "jar", "iso", "img", "7z", "rar", "tgz", "gz", "bz2", "xz", "bin", "terminal", "workflow", "mobileconfig"]

    static func magic(_ d: Data) -> String? {
        let b = [UInt8](d.prefix(8))
        guard b.count >= 4 else { return nil }
        let m = UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
        if [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].contains(m) { return "mach-o" }
        if b[0] == 0x50, b[1] == 0x4b, b[2] == 3, b[3] == 4 { return "zip" }
        if b[0] == 0x78, b[1] == 0x61, b[2] == 0x72, b[3] == 0x21 { return "xar/pkg" }
        if b[0] == 0x23, b[1] == 0x21 { return "script" }
        if b[0] == 0x4d, b[1] == 0x5a { return "pe" }
        if b[0] == 0x1f, b[1] == 0x8b { return "gzip" }
        if b[0] == 0x42, b[1] == 0x5a, b[2] == 0x68 { return "bzip2/dmg?" }
        if b[0] == 0x37, b[1] == 0x7a, b[2] == 0xbc, b[3] == 0xaf { return "7z" }
        if d.count >= 512, d.suffix(512).prefix(4) == Data("koly".utf8) { return "dmg" }
        return nil
    }

    // MARK: run

    public func inspect(_ start: String) async -> ChainReport {
        var hops: [ChainHop] = []
        var stopped: String?
        var visited: Set<String> = []
        var current = URL(string: start.trimmingCharacters(in: .whitespacesAndNewlines))
        var via = "start"
        var download: String?
        while let u = current {
            if hops.count >= maxHops + 1 { stopped = "max-hops"; break }
            if !visited.insert(u.absoluteString).inserted { stopped = "loop"; break }
            let ur = analyzer.analyze(u.absoluteString)
            var hop = ChainHop(url: u.absoluteString, status: nil, via: via, contentType: nil, contentDisposition: nil, magic: nil,
                               urlScore: ur.score, brandMatch: ur.brandMatch, note: nil)
            if let why = refusal(u) { hop.note = why; hops.append(hop); stopped = why; break }
            current = nil
            do {
                var head = URLRequest(url: u, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: perHopTimeout)
                head.httpMethod = "HEAD"; head.httpShouldHandleCookies = false
                let (_, hr) = try await session.data(for: head)
                var http = hr as? HTTPURLResponse
                var body = Data()
                let redirectStatus = { (s: Int) in [301, 302, 303, 307, 308].contains(s) }
                if http.map({ !redirectStatus($0.statusCode) }) ?? true {
                    var get = URLRequest(url: u, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: perHopTimeout)
                    get.httpShouldHandleCookies = false
                    get.setValue("bytes=0-\(maxBodyBytes - 1)", forHTTPHeaderField: "Range")
                    let (stream, gr) = try await session.bytes(for: get)
                    http = (gr as? HTTPURLResponse) ?? http
                    for try await byte in stream { body.append(byte); if body.count >= maxBodyBytes { break } }
                    stream.task.cancel()
                }
                guard let h = http else { hop.note = "non-http"; hops.append(hop); break }
                hop.status = h.statusCode
                hop.contentType = (h.value(forHTTPHeaderField: "Content-Type"))?.lowercased()
                hop.contentDisposition = h.value(forHTTPHeaderField: "Content-Disposition")
                hop.magic = Self.magic(body)
                if redirectStatus(h.statusCode), let loc = h.value(forHTTPHeaderField: "Location"), let next = URL(string: loc, relativeTo: u)?.absoluteURL {
                    current = next; via = "http-\(h.statusCode)"
                } else if let dk = Self.downloadKind(hop, url: u) {
                    download = dk
                } else if hop.contentType.map({ $0.contains("html") || $0.contains("javascript") || $0.contains("text") }) ?? true,
                          let (loc, how) = Self.textualRedirect(String(decoding: body, as: UTF8.self)),
                          let next = URL(string: loc, relativeTo: u)?.absoluteURL {
                    current = next; via = how
                }
            } catch {
                hop.note = "error: \(error.localizedDescription.prefix(80))"; stopped = hop.note
            }
            hops.append(hop)
            if download != nil { break }
        }
        if current != nil && stopped == nil { stopped = "max-hops" }
        return Self.score(start: start, hops: hops, download: download, stopped: stopped)
    }

    /// Blocking wrapper for synchronous IPC handlers. Do not call on the main thread of a UI process.
    public func inspectBlocking(_ start: String, overallTimeout: TimeInterval = 60) -> ChainReport {
        let sem = DispatchSemaphore(value: 0)
        final class Box: @unchecked Sendable { var r: ChainReport? }
        let box = Box()
        let task = Task { box.r = await self.inspect(start); sem.signal() }
        if sem.wait(timeout: .now() + overallTimeout) == .timedOut { task.cancel() }
        return box.r ?? Self.score(start: start, hops: [], download: nil, stopped: "timeout")
    }

    static func downloadKind(_ hop: ChainHop, url: URL) -> String? {
        if let m = hop.magic, m != "gzip" { return m }
        if let cd = hop.contentDisposition?.lowercased(), cd.contains("attachment") || cd.contains("filename") {
            if let r = cd.range(of: #"filename\*?=["']?(?:utf-8'')?([^"';]+)"#, options: .regularExpression) {
                let fn = String(cd[r]).components(separatedBy: "=").last?.trimmingCharacters(in: CharacterSet(charactersIn: "\"' ")) ?? ""
                let ext = (fn as NSString).pathExtension
                if downloadExts.contains(ext) { return "attachment .\(ext)" }
            }
            if cd.contains("attachment") { return "attachment" }
        }
        if let ct = hop.contentType, let t = ct.split(separator: ";").first.map({ $0.trimmingCharacters(in: .whitespaces) }), downloadTypes.contains(t) {
            return t
        }
        let ext = url.pathExtension.lowercased()
        if downloadExts.contains(ext), hop.status.map({ (200..<300).contains($0) }) ?? false,
           !(hop.contentType?.contains("html") ?? false) { return ".\(ext) file" }
        return nil
    }

    static func score(start: String, hops: [ChainHop], download: String?, stopped: String?) -> ChainReport {
        var parts: [Int] = []
        var reasons: [String] = []
        let lookalikes = hops.filter { $0.brandMatch != nil && $0.urlScore >= 30 }
        if let l = lookalikes.first {
            parts.append(min(80, max(50, l.urlScore))); reasons.append("hop \(hops.firstIndex(of: l)! + 1) impersonates \(l.brandMatch!): \(URL(string: l.url)?.host ?? l.url)")
        }
        let risky = hops.filter { h in
            guard let host = URL(string: h.url)?.host?.lowercased(), let tld = host.split(separator: ".").last else { return false }
            return URLAnalyzer.riskyTLDs.contains(String(tld))
        }
        if !risky.isEmpty { parts.append(min(30, 12 * risky.count)); reasons.append("\(risky.count) hop(s) on throwaway-style domain endings") }
        let hosts = Set(hops.compactMap { URL(string: $0.url)?.host?.lowercased() })
        if hops.count >= 4 && hosts.count >= 3 { parts.append(min(35, 5 * hops.count)); reasons.append("\(hops.count) hops across \(hosts.count) domains") }
        let textual = hops.filter { $0.via == "meta-refresh" || $0.via == "js-location" }.count
        if textual >= 2 { parts.append(20); reasons.append("\(textual) script/meta-refresh redirects (disguised pages)") }
        if let d = download {
            parts.append(lookalikes.isEmpty ? 45 : 70); reasons.append("final page serves a download (\(d))")
        }
        if stopped == "ssrf-refused" { reasons.append("a hop pointed at a private/local address (refused)"); parts.append(40) }
        if stopped == "max-hops" { reasons.append("more than the allowed number of redirects"); parts.append(30) }
        var p = 1.0; for x in parts { p *= 1 - Double(x) / 100 }
        let score = Int((100 * (1 - p)).rounded())
        let verdict: ScamVerdict = score >= 60 ? .likelyScam : score >= 30 ? .suspicious : .likelySafe
        return ChainReport(start: start, hops: hops, finalURL: hops.last?.url, servesDownload: download != nil, downloadKind: download,
                           stoppedReason: stopped, score: score, verdict: verdict, reasons: reasons)
    }
}

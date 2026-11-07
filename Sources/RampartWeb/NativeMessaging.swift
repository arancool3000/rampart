import Foundation
import RampartShared

// Contract between the browser extensions (Chromium via native messaging, Safari via the
// SafariWebExtensionHandler) and the host. One JSON object per message, in both directions.
// Chrome's native messaging framing: a 32-bit native-endian length followed by UTF-8 JSON,
// at most 1 MiB host→browser and 64 MiB browser→host.

public struct NMRequest: Codable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case ping, checkURL, checkPage, checkText, checkClipboard, allowHost, reportDecision, status
    }
    public var id: String?
    public var type: Kind
    public var url: String?
    public var html: String?
    public var text: String?
    public var signals: PageSignals?
    public var host: String?
    public var decision: String?          // "continued" | "wentBack" | "dismissedBanner"
    public var tamper: [String]?          // in-page tamper observations from the Safari JS-control scanner
    public init(id: String? = nil, type: Kind, url: String? = nil, html: String? = nil, text: String? = nil, signals: PageSignals? = nil, host: String? = nil, decision: String? = nil, tamper: [String]? = nil) {
        self.id = id; self.type = type; self.url = url; self.html = html; self.text = text; self.signals = signals; self.host = host; self.decision = decision; self.tamper = tamper
    }
}

public struct NMReason: Codable, Hashable, Sendable {
    public var title: String
    public var detail: String
    public var score: Int
    public var evidence: [String]
    public init(_ s: ScamSignal) { title = s.title; detail = s.explanation; score = s.score; evidence = s.evidence.map(\.text) }
}

public struct NMResponse: Codable, Sendable {
    public var id: String?
    public var ok: Bool
    public var error: String?
    public var verdict: ScamVerdict?
    public var action: ScamAction?
    public var score: Int?
    public var headline: String?
    public var reasons: [NMReason]?
    public var tips: [String]?
    public var brand: String?
    public var host: String?
    public var version: String?
    public var daemon: Bool?               // true when rampartd answered (reputation lists loaded)
    public var blocklistDomains: Int?
    public init(id: String? = nil, ok: Bool = true, error: String? = nil) { self.id = id; self.ok = ok; self.error = error }

    public init(id: String?, report: ScamReport, daemon: Bool) {
        self.id = id; ok = true
        verdict = report.verdict; action = report.verdict.action; score = report.score; headline = report.headline
        reasons = report.signals.filter { $0.score > 0 }.prefix(8).map(NMReason.init)
        tips = report.tips; brand = report.urls.first?.brandMatch; host = report.urls.first?.host
        version = Product.version; self.daemon = daemon
    }
}

/// Framing helpers for Chrome's stdio native messaging protocol.
public enum NativeMessaging {
    public static let maxInbound = 64 * 1024 * 1024
    public static let maxOutbound = 1024 * 1024

    public static func frame(_ json: Data) -> Data {
        var len = UInt32(json.count)        // native endian, per Chrome's docs
        return Data(bytes: &len, count: 4) + json
    }

    public static func encode<T: Encodable>(_ v: T) throws -> Data {
        let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601
        var body = try e.encode(v)
        if body.count > maxOutbound {
            body = try e.encode(NMResponse(id: nil, ok: false, error: "response too large"))
        }
        return frame(body)
    }

    /// Reads one framed message from a file descriptor; nil on EOF or oversize.
    public static func readFrame(fd: Int32) -> Data? {
        func readExactly(_ n: Int) -> Data? {
            var buf = [UInt8](repeating: 0, count: n); var got = 0
            while got < n {
                let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, n - got) }
                if r <= 0 { return nil }
                got += r
            }
            return Data(buf)
        }
        guard let head = readExactly(4) else { return nil }
        let len = head.withUnsafeBytes { $0.load(as: UInt32.self) }
        guard len > 0, Int(len) <= maxInbound else { return nil }
        return readExactly(Int(len))
    }

    /// Splits a buffer of concatenated frames (for tests and for non-stdio transports).
    public static func unframe(_ data: Data) -> [Data] {
        var out: [Data] = []; var off = 0
        while off + 4 <= data.count {
            let len = Int(data.subdata(in: off..<(off + 4)).withUnsafeBytes { $0.load(as: UInt32.self) })
            guard len >= 0, off + 4 + len <= data.count else { break }
            out.append(data.subdata(in: (off + 4)..<(off + 4 + len))); off += 4 + len
        }
        return out
    }
}

/// Answers extension requests. Shared by rampart-nmh (Chromium) and the Safari extension handler.
/// Uses RampartWeb locally and, when a `DaemonBridge` is supplied, asks rampartd for reputation.
public protocol DaemonBridge: Sendable {
    var isAvailable: Bool { get }
    /// Ask the daemon's blocklist whether a host is known-bad. Returns nil when unknown/unavailable.
    func lookup(host: String) -> BlocklistHit?
    /// Tell the daemon about a web verdict so it appears in Protection Activity.
    func report(url: String, verdict: ScamVerdict, score: Int, headline: String)
}

public final class WebVerdictService: @unchecked Sendable {
    public let checker: ScamChecker
    public let allowlist: FileWebAllowlist
    public let bridge: (any DaemonBridge)?
    private let cacheLock = NSLock()
    private var cache: [String: (Date, NMResponse)] = [:]

    public init(bridge: (any DaemonBridge)? = nil, seenStore: (any SeenDomainStore)? = nil, allowlist: FileWebAllowlist? = nil, extraBlocklists: [any WebBlocklistProvider] = []) {
        let al = allowlist ?? FileWebAllowlist()
        var lists: [any WebBlocklistProvider] = extraBlocklists
        if let bridge { lists.append(DaemonBlocklistProvider(bridge: bridge)) }
        self.allowlist = al
        self.bridge = bridge
        self.checker = ScamChecker(urls: URLAnalyzer(blocklists: lists, seenDomains: seenStore ?? FileSeenDomainStore(), allowlist: al))
    }

    public func handle(_ req: NMRequest) -> NMResponse {
        let daemon = bridge?.isAvailable ?? false
        switch req.type {
        case .ping, .status:
            var r = NMResponse(id: req.id); r.version = Product.version; r.daemon = daemon; return r
        case .checkURL:
            guard let url = req.url else { return NMResponse(id: req.id, ok: false, error: "url required") }
            if let c = cached(url) { var c = c; c.id = req.id; return c }
            let report = checker.checkURL(url)
            let resp = NMResponse(id: req.id, report: report, daemon: daemon)
            store(url, resp)
            if report.verdict != .likelySafe { bridge?.report(url: url, verdict: report.verdict, score: report.score, headline: report.headline) }
            return resp
        case .checkPage:
            guard let url = req.url else { return NMResponse(id: req.id, ok: false, error: "url required") }
            var report = checker.checkPage(url: url, html: req.html, signals: req.signals)
            if let tamper = req.tamper, !tamper.isEmpty {
                let onCredPage = req.signals?.forms.contains { $0.hasPassword || $0.hasCardNumber || $0.hasOTP } ?? false
                let sig = ScamSignal(id: "page.tamper", category: .pageCredentialForm, title: "Page scripts were changed after loading",
                                     explanation: "RamPart's scanner saw " + tamper.prefix(3).joined(separator: "; ") + ". On a sign-in page this can mean another app or extension is injecting code.",
                                     score: onCredPage ? 55 : 15, evidence: tamper.prefix(3).map { ScamHighlight(text: $0, kind: .script) })
                report.signals.append(sig)
                report.signals.sort { $0.score > $1.score }
                report.score = ScamScoring.combine(report.signals)
                report.verdict = ScamVerdict.from(score: report.score)
            }
            let resp = NMResponse(id: req.id, report: report, daemon: daemon)
            if report.verdict != .likelySafe { bridge?.report(url: url, verdict: report.verdict, score: report.score, headline: report.headline) }
            return resp
        case .checkText, .checkClipboard:
            guard let text = req.text else { return NMResponse(id: req.id, ok: false, error: "text required") }
            let report = req.type == .checkClipboard ? WebVerdictService.clipboardReport(text, pageURL: req.url) : checker.checkMessage(text)
            return NMResponse(id: req.id, report: report, daemon: daemon)
        case .allowHost:
            guard let host = req.host, !host.isEmpty else { return NMResponse(id: req.id, ok: false, error: "host required") }
            // N7: a strict hostname that is more than a bare public suffix (never "com", "co.uk", "github.io").
            guard let clean = WebVerdictService.allowableHost(host) else { return NMResponse(id: req.id, ok: false, error: "not a valid site name") }
            allowlist.allow(host: clean)
            cacheLock.lock(); cache.removeAll(); cacheLock.unlock()
            return NMResponse(id: req.id)
        case .reportDecision:
            return NMResponse(id: req.id)
        }
    }

    /// N7: the host the user chose to allow, validated: ASCII letters/digits/hyphens in dot-separated labels (1-63
    /// characters, no leading or trailing hyphen), at most 253 characters, no newlines/spaces/ports/paths/IP
    /// literals, and more than a bare public suffix. Returns the lowercased host, or nil.
    public static func allowableHost(_ raw: String) -> String? {
        var h = raw.lowercased()
        if h.hasSuffix(".") { h.removeLast() }
        guard !h.isEmpty, h.utf8.count <= 253 else { return nil }
        let labels = h.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return nil }
        for l in labels {
            guard (1...63).contains(l.utf8.count), l.first != "-", l.last != "-",
                  l.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d }) else { return nil }
        }
        guard labels.last.map({ !$0.allSatisfy(\.isNumber) }) ?? false else { return nil }   // no IPv4 literal
        guard let p = URLAnalyzer.parse("https://" + h), !p.isIPLiteral, let reg = p.registrable, !reg.isEmpty,
              p.suffix != h else { return nil }
        return h
    }

    /// Copy-to-clipboard interception: is this text a shell command, and is the page a developer site?
    public static let developerHosts: Set<String> = [
        "github.com", "gitlab.com", "stackoverflow.com", "stackexchange.com", "superuser.com", "askubuntu.com", "serverfault.com",
        "npmjs.com", "pypi.org", "brew.sh", "docs.brew.sh", "rubygems.org", "crates.io", "docs.python.org", "developer.apple.com",
        "learn.microsoft.com", "docs.microsoft.com", "developer.mozilla.org", "docs.docker.com", "kubernetes.io", "rust-lang.org",
        "go.dev", "nodejs.org", "swift.org", "readthedocs.io", "dev.to", "medium.com", "gist.github.com", "bitbucket.org",
        "apple.com", "support.apple.com", "ubuntu.com", "debian.org", "archlinux.org", "wiki.archlinux.org", "digitalocean.com",
        "cloudflare.com", "developers.cloudflare.com", "aws.amazon.com", "docs.aws.amazon.com", "cloud.google.com", "vercel.com", "netlify.com",
        "heroku.com", "raw.githubusercontent.com", "sourceforge.net", "localhost",
    ]
    static let shellCommand = try! NSRegularExpression(pattern: #"(?im)^\s*(sudo\s+)?(curl|wget|bash|sh|zsh|osascript|python3?|perl|ruby|powershell|mshta|cmd(\.exe)?|xattr|chmod|open\s+-a|nohup|base64|eval|echo\s+[A-Za-z0-9+/=]{30,})\b|\|\s*(bash|sh|zsh|python3?)\b|\$\(|`[^`]+`|;\s*(bash|sh)\s"#)

    public static func isDeveloperHost(_ host: String?) -> Bool {
        guard var h = host?.lowercased() else { return false }
        while true {
            if developerHosts.contains(h) { return true }
            guard let dot = h.firstIndex(of: ".") else { return false }
            h = String(h[h.index(after: dot)...]); if !h.contains(".") { return false }
        }
    }

    public static func looksLikeShellCommand(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.count < 4000 else { return false }
        return shellCommand.firstMatch(in: t, range: NSRange(location: 0, length: (t as NSString).length)) != nil
    }

    public static func clipboardReport(_ text: String, pageURL: String?) -> ScamReport {
        let host = pageURL.flatMap { URLAnalyzer.parse($0)?.asciiHost }
        var signals: [ScamSignal] = []
        let isCmd = looksLikeShellCommand(text)
        let dev = isDeveloperHost(host)
        if isCmd {
            let dangerous = text.range(of: #"(curl|wget)[^\n]*\|\s*(bash|sh|zsh)|base64\s+-d|osascript|xattr\s+-[cdr]|nohup|mshta|powershell\s+-(e|enc|w\s+hidden)"#, options: [.regularExpression, .caseInsensitive]) != nil
            signals.append(ScamSignal(id: "clip.command", category: .pageClickFix, title: dangerous ? "Copied a command that downloads and runs code" : "Copied a shell command",
                                      explanation: dev ? "This is a developer site, so copying commands is normal. Still read it before you run it." : "A non-developer site put a shell command on your clipboard. Pasting it into Terminal would run it with your permissions. Don't.",
                                      score: dev ? (dangerous ? 25 : 5) : (dangerous ? 90 : 60), evidence: [ScamHighlight(text: String(text.prefix(160)), kind: .script)]))
        }
        let score = ScamScoring.combine(signals)
        return ScamReport(kind: .page, verdict: ScamVerdict.from(score: score), score: score,
                          headline: isCmd ? (dev ? "Command copied from a developer site." : "This site copied a command to your clipboard.") : "Nothing suspicious was copied.",
                          signals: signals, urls: [], language: "en", tips: isCmd && !dev ? [ScamLexicon.english.tips[.pageClickFix]!] : [], analysedText: text)
    }

    private func cached(_ url: String) -> NMResponse? {
        cacheLock.lock(); defer { cacheLock.unlock() }
        if let (t, r) = cache[url], Date().timeIntervalSince(t) < 300 { return r }
        return nil
    }
    private func store(_ url: String, _ r: NMResponse) {
        cacheLock.lock(); defer { cacheLock.unlock() }
        if cache.count > 500 { cache.removeAll() }
        cache[url] = (Date(), r)
    }
}

struct DaemonBlocklistProvider: WebBlocklistProvider {
    let bridge: any DaemonBridge
    var name: String { "RamPart web protection" }
    func lookup(host: String) -> BlocklistHit? { bridge.isAvailable ? bridge.lookup(host: host) : nil }
}

/// Talks to rampartd over the RampartShared IPC socket using the web cases
/// (`.webLookup(host:)` → `.webLookup(Data?)`, `.webVerdict(...)` → `.ok`). Short timeouts; everything
/// degrades to nil when the daemon is down. Also exposes `checkURL`/`scamCheck` for callers that want
/// the daemon's (list-backed) verdict instead of a local one.
public final class IPCDaemonBridge: DaemonBridge, @unchecked Sendable {
    private let lock = NSLock()
    private var lastProbe: Date = .distantPast
    private var available = false
    public private(set) var blocklistDomains = 0
    public init() {}

    public var isAvailable: Bool {
        lock.lock(); defer { lock.unlock() }
        if Date().timeIntervalSince(lastProbe) < 30 { return available }
        lastProbe = Date()
        if case .status? = roundTrip(.status) { available = true } else { available = false }
        if available, case .networkStats(let n)? = roundTrip(.networkStats) { blocklistDomains = n.blocklistDomains }
        return available
    }

    public func lookup(host: String) -> BlocklistHit? {
        guard isAvailable, case .webLookup(let data)? = roundTrip(.webLookup(host: host)), let data else { return nil }
        return try? JSONDecoder.rampart.decode(BlocklistHit.self, from: data)
    }

    public func report(url: String, verdict: ScamVerdict, score: Int, headline: String) {
        guard isAvailable else { return }
        _ = roundTrip(.webVerdict(url: url, verdict: verdict.rawValue, score: score, headline: headline))
    }

    public func daemonURLReport(_ url: String) -> URLReport? {
        guard isAvailable, case .urlVerdict(let data)? = roundTrip(.checkURL(url: url), timeoutMs: 3000) else { return nil }
        return try? JSONDecoder.rampart.decode(URLReport.self, from: data)
    }

    public func daemonScamReport(_ text: String, kind: ScamInputKind) -> ScamReport? {
        guard isAvailable, case .scamReport(let data)? = roundTrip(.scamCheck(text: text, kind: kind.rawValue), timeoutMs: 5000) else { return nil }
        return try? JSONDecoder.rampart.decode(ScamReport.self, from: data)
    }

    private func roundTrip(_ req: IPCRequest, timeoutMs: Int32 = 800) -> IPCResponse? {
        let path = getuid() == 0 ? IPC.socketPath : (FileManager.default.fileExists(atPath: IPC.socketPath) ? IPC.socketPath : IPC.userSocketPath)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: Int(timeoutMs / 1000), tv_usec: Int32(timeoutMs % 1000) * 1000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in for (i, b) in bytes.enumerated() { raw[i] = b }; raw[bytes.count] = 0 }
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard rc == 0, let data = try? IPC.encode(req), IPC.writeFrame(fd: fd, data), let resp = IPC.readFrame(fd: fd) else { return nil }
        return try? JSONDecoder.rampart.decode(IPCResponse.self, from: resp)
    }
}

import Foundation
import RampartShared
import RampartWeb

/// The browser's single door into RampartWeb (URL analysis, brand look-alikes, blocklists). Everything
/// WebKit-facing asks this adapter, so a RampartWeb API change touches one file.
final class WebEngineAdapter: @unchecked Sendable {
    static let shared = WebEngineAdapter()

    private let lock = NSLock()
    private var analyzer: URLAnalyzer
    private let allowlist: FileWebAllowlist
    private(set) var blocklistNames: [String] = []
    private(set) var blocklistDomains = 0
    private var cache: [String: URLFacts] = [:]
    /// hx6: hosts the user clicked "Continue anyway" for in this app session. Never written to disk.
    private var sessionAllowed: Set<String> = []

    init(allowlistURL: URL? = nil) {
        allowlist = allowlistURL.map { FileWebAllowlist(url: $0) } ?? FileWebAllowlist()
        analyzer = URLAnalyzer(blocklists: [], seenDomains: FileSeenDomainStore(), allowlist: allowlist)
        reloadBlocklists()
    }

    /// Loads every `*.txt` list the daemon keeps (root or per-user folder). Cheap enough to do at launch;
    /// the daemon is the only writer. `block_ips.txt` belongs to pf, not to web filtering.
    func reloadBlocklists() {
        var providers: [any WebBlocklistProvider] = []
        var names: [String] = []
        var total = 0
        for dir in [Paths.blocklistDir, Paths.userRoot.appendingPathComponent("Blocklists")] {
            guard let items = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else { continue }
            for f in items where f.pathExtension == "txt" && f.lastPathComponent != "block_ips.txt" {
                let p = FileBlocklistProvider(name: f.deletingPathExtension().lastPathComponent, fileURL: f)
                if p.count > 0 { providers.append(p); names.append(p.name); total += p.count }
            }
        }
        lock.lock()
        analyzer.blocklists = providers
        blocklistNames = names
        blocklistDomains = total
        cache.removeAll()
        lock.unlock()
    }

    /// Facts for the navigation policy. Synchronous and cached per absolute URL; RampartWeb is pure CPU.
    func facts(for url: URL) -> URLFacts {
        let key = url.absoluteString
        lock.lock()
        if let c = cache[key] { lock.unlock(); return c }
        let a = analyzer
        lock.unlock()
        let report = a.analyze(key)
        let host = (url.host ?? "").lowercased()
        var hit: String? = nil
        for bl in a.blocklists { if let h = bl.lookup(host: host) { hit = h.source; break } }
        let facts = URLFacts(blocklistHit: hit, scamScore: report.score, scamVerdict: report.verdict,
                             brandMatch: report.brandMatch, allowlisted: allowlist.isAllowed(host: host) || isSessionAllowed(host))
        lock.lock(); if cache.count > 2000 { cache.removeAll() }; cache[key] = facts; lock.unlock()
        return facts
    }

    func report(for url: URL) -> URLReport {
        lock.lock(); let a = analyzer; lock.unlock()
        return a.analyze(url.absoluteString)
    }

    func allow(host: String) {
        allowlist.allow(host: host)
        lock.lock(); cache.removeAll(); lock.unlock()
    }
    func isAllowed(host: String) -> Bool { allowlist.isAllowed(host: host) || isSessionAllowed(host) }

    /// Exact host only (no subdomains), memory only. Blocklist hits are never affected by it.
    func allowForSession(host: String) {
        let h = host.lowercased()
        guard !h.isEmpty else { return }
        lock.lock(); sessionAllowed.insert(h); cache.removeAll(); lock.unlock()
    }
    private func isSessionAllowed(_ host: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return sessionAllowed.contains(host.lowercased())
    }

    /// Does the page's form target look like a brand it isn't? Used by the credential-form finding.
    func brandImpersonated(byHost host: String) -> String? {
        lock.lock(); let a = analyzer; lock.unlock()
        return a.analyze("https://" + host + "/").brandMatch
    }
}

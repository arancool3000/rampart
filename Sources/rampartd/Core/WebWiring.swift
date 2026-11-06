import Foundation
import RampartShared
import RampartWeb
import RampartNetwork

/// The DNS filter's domain blocklist as a RampartWeb blocklist provider.
struct DomainBlocklistProvider: WebBlocklistProvider, @unchecked Sendable {
    let list: () -> DomainBlocklist
    var name: String { "RamPart DNS blocklists" }
    func lookup(host: String) -> BlocklistHit? {
        if case .blocked(let rule, let source) = list().verdict(for: host) {
            return BlocklistHit(rule: rule, source: source, category: "malicious")
        }
        return nil
    }
}

/// URL / scam verdicts for the app, the CLI and rampart-nmh (v4 IPC).
final class WebCheckService {
    let checker: ScamChecker
    let provider: DomainBlocklistProvider
    init(runtime: Runtime, web: WebProtection) {
        provider = DomainBlocklistProvider(list: { web.currentBlocklist() })
        let seen = FileSeenDomainStore(url: runtime.root.appendingPathComponent("web-seen.json"))
        checker = ScamChecker(urls: URLAnalyzer(blocklists: [provider], seenDomains: seen))
    }
    func checkURL(_ url: String) throws -> Data { try JSONEncoder.rampart.encode(checker.urls.analyze(url)) }
    func scamCheck(_ text: String, kind: String) throws -> Data {
        let r: ScamReport
        switch kind.lowercased() {
        case "url": r = checker.checkURL(text)
        case "email": r = checker.checkEmail(raw: text)
        case "message", "text": r = checker.checkMessage(text)
        default: r = checker.check(text)
        }
        return try JSONEncoder.rampart.encode(r)
    }
    func lookup(_ host: String) throws -> Data? {
        guard let hit = provider.lookup(host: host.lowercased()) else { return nil }
        return try JSONEncoder.rampart.encode(hit)
    }
}

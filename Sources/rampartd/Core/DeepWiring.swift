import Foundation
import RampartShared
import RampartWeb
import RampartBehaviour

/// Deep content inspection + Apple impersonation + safe link-chain checks + threat-chain behaviour rules.
/// Wiring (lead): construct once, then
///  - on-write: FSEvents/eslogger fileCreate/fileWrite/fileClose(modified)/fileRename for
///    `DeepContentInspector.isInteresting(path:)` -> `inspectFile(path)`; same detector in scans via
///    `fileDetectors` (append to ScanCoordinator's detector list).
///  - every SecurityEvent -> `ingest(_:)` (alongside BehaviourEngine.process).
///  - IPC: `.checkURL(url:)` stays a fast local verdict; a chain check is requested with a NEW case
///    `.checkURLChain(url: String)` -> `.urlVerdict(Data)` carrying JSON of RampartWeb.ChainReport (run off the
///    IPC thread; it does network I/O). Auto-run: when `checkURL` scores >= 60 and the setting allows it.
final class DeepProtectionService: @unchecked Sendable {
    let analyzer: URLAnalyzer
    let inspector: DeepContentInspector
    let chain: RedirectChainInspector
    let threatChain: ThreatChainDetector
    let seen: FileSeenDomainStore
    var fileDetectors: [any FileDetector] { [DeepContentDetector(inspector: inspector), AppleImpersonationDetector()] }

    init(root: URL, blocklists: [any WebBlocklistProvider] = []) {
        seen = FileSeenDomainStore(url: root.appendingPathComponent("web-seen.json"))
        // No seenDomains in the file inspector: scanning old files must not mark domains as "seen".
        analyzer = URLAnalyzer(blocklists: blocklists)
        let classifier = PasteClassifier()
        inspector = DeepContentInspector(analyzer: analyzer, classifyCommand: { cmd in
            let r = classifier.classify(cmd); return (r.score, r.reasons)
        })
        chain = RedirectChainInspector(analyzer: analyzer)
        let a = analyzer
        let seen = self.seen
        threatChain = ThreatChainDetector(isLookalikeHost: { host in
            let r = a.analyze("https://" + host); return r.brandMatch != nil && r.score >= 40
        }, firstSeen: { seen.firstSeen($0) })
    }

    func inspectFile(_ path: String) -> Detection? {
        guard DeepContentInspector.isInteresting(path: path), let r = inspector.inspect(path: path), r.score >= 30 else { return nil }
        let conf = min(89, r.score)   // heuristic content findings never auto-quarantine on their own
        return Detection(path: path, name: r.evidence.first?.title ?? "Suspicious content", category: .phishing,
                         severity: conf >= 60 ? .high : .medium, confidence: conf, evidence: r.evidence)
    }

    func ingest(_ e: SecurityEvent) -> [Detection] { threatChain.ingest(e) }

    func checkChain(_ url: String) throws -> Data { try JSONEncoder.rampart.encode(chain.inspectBlocking(url)) }
}

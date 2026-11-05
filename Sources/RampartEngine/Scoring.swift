import Foundation
import RampartShared

/// Combines Evidence into a confidence score, verdict, severity and category (ARCHITECTURE.md "Scoring").
public enum Scoring {
    public static let quarantineThreshold = 90
    public static let alertThreshold = 60
    public static let logThreshold = 30
    /// Signing heuristics on their own never exceed this.
    public static let signingOnlyCap = 50

    /// What to do with a scored finding.
    public enum Verdict: Int, Comparable, Sendable, Codable {
        case clean, log, alert, quarantine
        public static func < (a: Verdict, b: Verdict) -> Bool { a.rawValue < b.rawValue }
    }

    /// Score assigned to signing evidence reporting an Apple-revoked certificate or notarization.
    public static let revokedSigningScore = 95

    /// True if signing evidence reports a revoked certificate / notarization (title or detail says "revoked",
    /// ignoring negations such as "not revoked").
    public static func isRevokedSigning(_ e: Evidence) -> Bool {
        guard e.source == .signing else { return false }
        let t = (e.title + " " + e.detail).lowercased()
        guard t.contains("revoked") else { return false }
        return !(t.contains("not revoked") || t.contains("no revoked") || t.contains("isn't revoked") || t.contains("unrevoked"))
    }

    /// Normalises detector output: revoked-signature evidence is raised to 95 (auto-quarantine); all other
    /// scores are clamped to 0...100. Optionally adds evidence when the enriched `SigningInfo` is `.revoked`
    /// but no detector reported it.
    public static func normalize(_ evidence: [Evidence], signing: SigningInfo? = nil) -> [Evidence] {
        var out = evidence.map { e -> Evidence in
            var e = e
            e.score = min(100, max(0, e.score))
            if isRevokedSigning(e) { e.score = max(e.score, revokedSigningScore) }
            return e
        }
        if signing?.status == .revoked, !out.contains(where: isRevokedSigning) {
            out.append(Evidence(source: .signing, title: "Revoked code signature",
                                detail: "Apple has revoked the signing certificate or notarization\(signing?.teamID.map { " for team \($0)" } ?? "").",
                                score: revokedSigningScore))
        }
        return out
    }

    /// confidence = 100·(1 − Π(1 − s/100)), each s clamped to 0...100; capped at 50 if all evidence is `.signing`.
    public static func confidence(_ evidence: [Evidence]) -> Int {
        guard !evidence.isEmpty else { return 0 }
        var remain = 1.0
        for e in evidence { remain *= 1.0 - Double(min(100, max(0, e.score))) / 100.0 }
        var c = Int((100.0 * (1.0 - remain)).rounded())
        // Signing heuristics alone (invalid, unsigned, ad-hoc) stay at or below 50; Apple revocation is exempt.
        if evidence.allSatisfy({ $0.source == .signing && !isRevokedSigning($0) }) { c = min(c, signingOnlyCap) }
        return min(100, max(0, c))
    }

    public static func verdict(confidence c: Int) -> Verdict {
        c >= quarantineThreshold ? .quarantine : c >= alertThreshold ? .alert : c >= logThreshold ? .log : .clean
    }

    public static func severity(confidence c: Int) -> Severity {
        c >= 90 ? .critical : c >= 75 ? .high : c >= 60 ? .medium : c >= 30 ? .low : .info
    }

    /// Negative prior for trusted code: Apple platform / App Store / notarized Developer ID files lose all
    /// weak heuristic and signing evidence (score < 90). Hash, YARA, XProtect and EICAR evidence is kept.
    public static func applyTrustPrior(_ evidence: [Evidence], signing: SigningInfo?) -> [Evidence] {
        guard let signing, isTrusted(signing) else { return evidence }
        return evidence.filter { e in
            switch e.source {
            case .signing: return isRevokedSigning(e)
            case .heuristic, .behaviour, .persistence: return e.score >= 90
            default: return true
            }
        }
    }

    /// Apple, App Store, or notarized Developer ID.
    public static func isTrusted(_ s: SigningInfo) -> Bool {
        switch s.status {
        case .apple, .appStore: return true
        case .developerID: return s.notarized == true
        default: return false
        }
    }

    /// Best-effort category from evidence titles and sources.
    public static func category(for evidence: [Evidence]) -> ThreatCategory {
        let titles = evidence.map { ($0.title + " " + $0.detail).lowercased() }
        func any(_ words: [String]) -> Bool { titles.contains { t in words.contains { t.contains($0) } } }
        if evidence.contains(where: { $0.title == EICAR.detectionName }) { return .test }
        if any(["ransom"]) { return .ransomware }
        if any(["stealer", "amos", "atomic", "poseidon", "banshee", "cuckoo"]) { return .infostealer }
        if any(["adload", "adware", "pirrit", "bundlore", "shlayer"]) { return .adware }
        if any(["miner", "xmrig", "cryptojack"]) { return .miner }
        if any(["backdoor", "rat ", "trojan"]) { return .backdoor }
        if any(["pua", "pup", "potentially unwanted"]) { return .pua }
        if evidence.contains(where: { [.hash, .xprotect, .yara].contains($0.source) && $0.score >= 90 }) { return .malware }
        if evidence.contains(where: isRevokedSigning) { return .malware }
        if evidence.contains(where: { $0.source == .persistence }) { return .persistence }
        return .suspicious
    }

    /// Builds a Detection from evidence, or nil if below the log threshold.
    /// The name is the title of the strongest evidence.
    /// Evidence is passed through `normalize` first, so callers outside `ScanCoordinator` get the same rules.
    public static func makeDetection(path: String?, sha256: String?, evidence rawEvidence: [Evidence], pid: Int32? = nil) -> Detection? {
        let evidence = normalize(rawEvidence)
        let c = confidence(evidence)
        guard c >= logThreshold, let top = evidence.max(by: { $0.score < $1.score }) else { return nil }
        let sorted = evidence.sorted { $0.score > $1.score }
        let cat = category(for: evidence)
        return Detection(path: path, pid: pid, sha256: sha256, name: top.title, category: cat,
                         severity: cat == .test ? .medium : severity(confidence: c), confidence: c, evidence: sorted)
    }
}

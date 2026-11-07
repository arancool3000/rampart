import Foundation
import RampartShared
import RampartBehaviour

/// Startup clean-up of stored detections after an upgrade (product version or rule change).
enum DetectionReevaluator {
    /// MDM framework paths flagged by an older RampartGuard (fixed there); always resolved.
    static let knownFalsePositivePrefixes = ["/System/Library/PrivateFrameworks/RemoteManagement.framework/"]

    static func fingerprint(rules: RuleSet = .default) -> String {
        let body = rules.rules.map { "\($0.id):\($0.score)" }.joined(separator: ",")
        var h: UInt64 = 1469598103934665603
        for b in body.utf8 { h = (h ^ UInt64(b)) &* 1099511628211 }
        return "\(Product.version)|\(rules.version)|\(String(h, radix: 16))"
    }

    static func ruleIDs(_ d: Detection) -> Set<String> {
        Set(d.evidence.compactMap { $0.title.split(separator: " ").first.map(String.init) })
    }

    /// Decides whether a stored, unresolved detection is no longer flagged by the current rules.
    /// `stillFlagged` re-assesses a launchd plist and returns the strong rule IDs that still apply.
    static func shouldResolve(_ d: Detection, upgraded: Bool, canariesOn: Bool,
                              stillFlagged: (String) -> Set<String>?) -> Bool {
        guard !d.resolved else { return false }
        if let p = d.path, p == "/System/Library/PrivateFrameworks/RemoteManagement.framework"
            || knownFalsePositivePrefixes.contains(where: { p.hasPrefix($0) }) { return true }
        guard upgraded else { return false }
        let ids = ruleIDs(d)
        if let p = d.path {
            // RamPart's own launch items and binaries.
            if (p as NSString).lastPathComponent.hasPrefix("app.rampart.") || p.hasPrefix("/Library/PrivilegedHelperTools/app.rampart.")
                || p.hasPrefix("/Applications/Rampart.app/") { return true }
            // Canary detections while canaries are off (the files are removed).
            if !canariesOn, !ids.isDisjoint(with: ["R01", "R39"]),
               ["000 Budget Notes.rtf", "zzz Archive Notes.rtf"].contains((p as NSString).lastPathComponent) { return true }
            // Launch item detections: re-assess the plist with the current rules.
            if ids.contains("R07"), p.hasSuffix(".plist"), p.contains("/LaunchAgents/") || p.contains("/LaunchDaemons/") {
                guard let now = stillFlagged(p) else { return true }   // plist gone
                return !now.contains("R07")
            }
        }
        return false
    }

    /// Runs at daemon start. Returns the number of detections resolved.
    @discardableResult
    static func run(_ p: Protection, engine: BehaviourEngine?) -> Int {
        let fp = fingerprint()
        let upgraded = p.state.value.detectionsEvaluatedFor != fp
        let canariesOn = p.runtime.config.ransomwareCanaries
        var n = 0
        for d in p.store.all() where shouldResolve(d, upgraded: upgraded, canariesOn: canariesOn, stillFlagged: { path in
            let kind: PersistenceItem.Kind = path.contains("/LaunchDaemons/") ? .launchDaemon : .launchAgent
            guard let r = PersistenceScanner.parseLaunchdPlist(path: path, kind: kind) else { return nil }
            guard let engine else { return ["R07"] }   // can't re-check: keep it
            return Set(engine.reviewPersistence([r]).map(\.finding.ruleID))
        }) {
            _ = p.store.update(d.id) { $0.resolved = true }
            n += 1
        }
        if upgraded { p.state.update { $0.detectionsEvaluatedFor = fp } }
        if n > 0 {
            logInfo("re-evaluated stored detections: resolved \(n) no longer flagged by the current rules")
            p.activity.add(.system, "Resolved \(n) earlier alert(s)", detail: "No longer flagged after the protection update", outcome: "resolved")
        }
        return n
    }
}

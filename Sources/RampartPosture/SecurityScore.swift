import Foundation
import RampartShared

/// Security Score, 0–100. Weighted over checks with a known result; `unknown` never counts as a fail
/// (it is left out and counted in `unknownCount`), `notApplicable` is left out, ignored checks are left out.
/// Bonus checks (Lockdown Mode) add points when on and never cost points when off.
public struct SecurityScore: Codable, Hashable, Sendable {
    public enum Label: String, Codable, Sendable {
        case excellent = "Excellent", good = "Good", fair = "Fair", needsAttention = "Needs attention"
    }
    public var value: Int
    public var label: Label
    public var earnedWeight: Int
    public var possibleWeight: Int
    public var failedCount: Int
    /// Checks we couldn't read (needs admin, Full Disk Access, or a tool failed). Shown as "X checks need permissions".
    public var unknownCount: Int

    public static let bonusCheckIDs: Set<String> = ["lockdownMode"]

    public static func label(for value: Int) -> Label {
        switch value {
        case 90...: return .excellent
        case 75..<90: return .good
        case 50..<75: return .fair
        default: return .needsAttention
        }
    }

    public static func compute(_ checks: [PostureCheck], ignoring ignored: Set<String> = []) -> SecurityScore {
        var earned = 0, possible = 0, bonus = 0, failed = 0, unknown = 0
        for c in checks where !ignored.contains(c.id) {
            if bonusCheckIDs.contains(c.id) {
                if c.state == .pass { bonus += c.weight }
                continue
            }
            switch c.state {
            case .pass: earned += c.weight; possible += c.weight
            case .fail: possible += c.weight; if c.weight > 0 { failed += 1 }
            case .unknown: unknown += 1
            case .notApplicable: break
            }
        }
        let value: Int
        if possible == 0 { value = bonus > 0 ? 100 : 0 }
        else { value = min(100, Int((Double(earned + bonus) * 100 / Double(possible)).rounded())) }
        return SecurityScore(value: value, label: label(for: value), earnedWeight: earned + bonus,
                             possibleWeight: possible, failedCount: failed, unknownCount: unknown)
    }
}

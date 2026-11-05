import Foundation
import RampartShared

/// Signing tier of a binary as used by the behaviour scorer.
public enum TrustClass: String, Codable, Sendable {
    case apple, appStore, notarized, developerID, adHoc, unsigned, invalid, unknown

    /// "Untrusted" per doc 05: unsigned, ad-hoc, invalid/revoked, or Developer ID explicitly not notarized.
    public var isUntrusted: Bool { self == .adHoc || self == .unsigned || self == .invalid }

    /// Context multiplier from doc 05 §12.2.
    public var multiplier: Double {
        switch self {
        case .apple: return 0.2
        case .appStore, .notarized: return 0.3
        case .developerID: return 0.8
        case .adHoc: return 1.4
        case .unsigned, .invalid: return 1.5
        case .unknown: return 1.0
        }
    }

    public init(_ info: SigningInfo) {
        switch info.status {
        case .apple: self = .apple
        case .appStore: self = .appStore
        case .developerID:
            if info.notarized == false { self = .developerID } else if info.notarized == true { self = .notarized } else { self = .developerID }
        case .adHoc: self = .adHoc
        case .unsigned: self = .unsigned
        case .invalid, .revoked: self = .invalid
        case .unknown: self = .unknown
        }
    }
}

/// Resolves a TrustClass for a process or file path. Uses the injected signing provider (cached),
/// falling back to the facts carried by the event (platform flag, Team ID, telemetry "signing" tier).
final class TrustEvaluator: @unchecked Sendable {
    private let provider: SigningProvider?
    private var cache: [String: (TrustClass, SigningInfo?, Date)] = [:]
    private let lock = NSLock()
    var ttl: TimeInterval = 600

    init(provider: SigningProvider?) { self.provider = provider }

    func info(path: String) -> SigningInfo? {
        lookup(path: path).1
    }

    func trust(path: String, platformHint: Bool = false, teamID: String? = nil, tierHint: String? = nil) -> TrustClass {
        if platformHint { return .apple }
        let (t, _) = lookup(path: path)
        if t != .unknown { return t }
        switch tierHint {
        case "apple": return .apple
        case "adHoc": return .adHoc
        case "unsigned": return .unsigned
        case "team": return .developerID
        default: break
        }
        if teamID != nil { return .developerID }
        // Paths inside the sealed system volume are Apple even when we cannot ask.
        if PathClass.classify(path) == .system { return .apple }
        return .unknown
    }

    private func lookup(path: String) -> (TrustClass, SigningInfo?) {
        guard let provider, !path.isEmpty else { return (.unknown, nil) }
        lock.lock()
        if let c = cache[path], Date().timeIntervalSince(c.2) < ttl { lock.unlock(); return (c.0, c.1) }
        lock.unlock()
        let info = provider(path)
        let t = info.map(TrustClass.init) ?? .unknown
        lock.lock(); cache[path] = (t, info, Date())
        if cache.count > 20_000 { cache.removeAll(keepingCapacity: true) }
        lock.unlock()
        return (t, info)
    }
}

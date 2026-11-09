import Foundation
import RampartShared

/// Payload of IPC `.netGuard(Data)` (App Firewall, content filter, privacy report, tracker counts).
/// Answered with `.netGuard(Data)` = JSON of `NetGuardStatus`.
public struct NetGuardCommand: Codable, Sendable {
    public enum Op: String, Codable, Sendable {
        case status, report, plan, classifyHosts
        case firewallDecide, firewallForget, filterSet
    }
    public enum Access: Sendable { case anyLocal, read, change }

    public var op: Op
    public var key: String?
    public var decision: FirewallDecision?
    public var config: ContentFilterConfig?
    public var hosts: [String]?
    public var pageHost: String?

    public init(op: Op, key: String? = nil, decision: FirewallDecision? = nil, config: ContentFilterConfig? = nil,
                hosts: [String]? = nil, pageHost: String? = nil) {
        self.op = op; self.key = key; self.decision = decision; self.config = config; self.hosts = hosts; self.pageHost = pageHost
    }

    public var access: Access {
        switch op {
        case .classifyHosts: return .anyLocal
        case .status, .report, .plan: return .read
        case .firewallDecide:
            return decision == .askLater ? .read : .change
        case .firewallForget, .filterSet: return .change
        }
    }

    /// Access level of an encoded command (undecodable = change, the strictest).
    public static func access(of data: Data) -> Access {
        (try? JSONDecoder.rampart.decode(NetGuardCommand.self, from: data))?.access ?? .change
    }

    public func encoded() -> Data { (try? JSONEncoder.rampart.encode(self)) ?? Data() }
}

public struct NetGuardStatus: Codable, Sendable {
    public var firewall: AppFirewallStatus
    public var filter: ContentFilterConfig
    /// Categories blocking right now (after schedules).
    public var activeNow: [String]
    public var categoryDomains: Int
    public var listsUpdated: [String: Date]
    public var webProtectionOn: Bool
    public var report: PrivacyReport
    public var plan: AppBlockPlan?
    public var classified: TrackerClassifier.Result?
    public var limitations: [String]

    public init(firewall: AppFirewallStatus, filter: ContentFilterConfig, activeNow: [String], categoryDomains: Int,
                listsUpdated: [String: Date], webProtectionOn: Bool, report: PrivacyReport, plan: AppBlockPlan?,
                classified: TrackerClassifier.Result?, limitations: [String]) {
        self.firewall = firewall; self.filter = filter; self.activeNow = activeNow; self.categoryDomains = categoryDomains
        self.listsUpdated = listsUpdated; self.webProtectionOn = webProtectionOn; self.report = report; self.plan = plan
        self.classified = classified; self.limitations = limitations
    }

    public static let filterLimitations = [
        "Filtering works through RamPart's local DNS resolver, so Web Protection must be on.",
        "Apps and browsers that use their own encrypted DNS (DNS over HTTPS) or a VPN can bypass it; RamPart signals Firefox to turn its own DNS off.",
        "SafeSearch is enforced by DNS: Google, Bing, DuckDuckGo and YouTube get their safe/restricted servers.",
    ]
}

/// Pushed over `subscribeEvents` as `.netGuard(Data)` when an unknown, untrusted app connects out for the first time.
public struct NetGuardPush: Codable, Sendable {
    public var prompts: [FirewallPrompt]
    public init(prompts: [FirewallPrompt]) { self.prompts = prompts }
}

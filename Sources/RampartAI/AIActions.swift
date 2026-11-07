import Foundation
import RampartShared

// AI-proposed actions. The model may only SUGGEST changes from a fixed allow-list; nothing runs until the user
// clicks Apply (and confirms again for anything that lowers protection). Titles and change descriptions are
// generated locally, never taken from model output. Only the Security Assistant chat can propose actions:
// scam, link, detection and posture tools have no action field, so content in those can never yield one.

public enum AIAction: Hashable, Codable, Sendable {
    public enum Toggle: String, Codable, CaseIterable, Sendable {
        case realtimeOn, autoQuarantine, scanArchives, scheduledQuickScan, notifyThreats, notifyInfo,
             learningMode, developerMode, ransomwareCanaries, autoUpdate, webProtection, blockTrackers
        var label: String {
            switch self {
            case .realtimeOn: return "real-time protection"
            case .autoQuarantine: return "automatic quarantine"
            case .scanArchives: return "scanning inside archives"
            case .scheduledQuickScan: return "the daily quick scan"
            case .notifyThreats: return "threat notifications"
            case .notifyInfo: return "informational notifications"
            case .learningMode: return "learning mode"
            case .developerMode: return "developer mode"
            case .ransomwareCanaries: return "ransomware canary files"
            case .autoUpdate: return "automatic definition updates"
            case .webProtection: return "web protection"
            case .blockTrackers: return "tracker blocking"
            }
        }
        /// Turning these OFF lowers protection (developer mode is the reverse: turning it ON lowers it).
        func lowers(_ on: Bool) -> Bool {
            switch self {
            case .developerMode: return on
            case .realtimeOn, .autoQuarantine, .scanArchives, .autoUpdate, .webProtection, .notifyThreats, .ransomwareCanaries: return !on
            case .scheduledQuickScan, .notifyInfo, .learningMode, .blockTrackers: return false
            }
        }
    }
    case setToggle(Toggle, Bool)
    case setScanHour(Int)
    case addExclusion(String)
    case removeExclusion(String)
    case fixPosture(String)
    case quickScan
    case remoteLockdown(Bool)
    case updateDefinitions

    public static let fixableCheckIDs: Set<String> = ["firewall", "stealthMode", "guestAccount", "remoteLogin", "autoUpdates"]
    static let fixTitles = ["firewall": "Turn the firewall on", "stealthMode": "Turn on firewall stealth mode",
                            "guestAccount": "Turn off the guest account", "remoteLogin": "Turn off Remote Login (SSH)",
                            "autoUpdates": "Turn on automatic macOS updates"]

    public var lowersProtection: Bool {
        switch self {
        case .setToggle(let t, let on): return t.lowers(on)
        case .addExclusion: return true
        case .remoteLockdown(let on): return !on
        case .setScanHour, .removeExclusion, .fixPosture, .quickScan, .updateDefinitions: return false
        }
    }

    /// Short human title, e.g. "Turn the firewall on".
    public var title: String {
        switch self {
        case .setToggle(let t, let on): return "Turn \(on ? "on" : "off") \(t.label)"
        case .setScanHour(let h): return "Run the daily scan at \(String(format: "%02d:00", h))"
        case .addExclusion(let p): return "Exclude \((p as NSString).lastPathComponent) from scanning"
        case .removeExclusion(let p): return "Scan \((p as NSString).lastPathComponent) again"
        case .fixPosture(let id): return Self.fixTitles[id] ?? "Fix \(id)"
        case .quickScan: return "Run a Quick Scan"
        case .remoteLockdown(let on): return on ? "Turn on remote-access lockdown" : "Turn off remote-access lockdown"
        case .updateDefinitions: return "Update threat definitions"
        }
    }

    /// The exact change, shown on the card.
    public var change: String {
        switch self {
        case .setToggle(let t, let on): return "Settings › \(t.rawValue) = \(on ? "on" : "off")"
        case .setScanHour(let h): return "Settings › scheduledScanHour = \(h)"
        case .addExclusion(let p): return "Add exclusion: \(p)"
        case .removeExclusion(let p): return "Remove exclusion: \(p)"
        case .fixPosture(let id): return "One-click fix for the “\(id)” Security Score check (asks macOS for permission if needed)"
        case .quickScan: return "Start a Quick Scan now"
        case .remoteLockdown(let on): return "Remote-access lockdown = \(on ? "on" : "off")"
        case .updateDefinitions: return "Download the latest signatures and blocklists"
        }
    }

    /// Result line after it ran, e.g. "Done: firewall is on".
    public var doneText: String {
        switch self {
        case .setToggle(let t, let on): return "Done: \(t.label) is \(on ? "on" : "off")."
        case .setScanHour(let h): return "Done: the daily scan now runs at \(String(format: "%02d:00", h))."
        case .addExclusion(let p): return "Done: \(p) is excluded from scanning."
        case .removeExclusion(let p): return "Done: \(p) will be scanned again."
        case .fixPosture(let id):
            let names = ["firewall": "the firewall is on", "stealthMode": "stealth mode is on", "guestAccount": "the guest account is off",
                         "remoteLogin": "Remote Login is off", "autoUpdates": "automatic updates are on"]
            return "Done: \(names[id] ?? "\(id) is fixed")."
        case .quickScan: return "Done: a Quick Scan has started."
        case .remoteLockdown(let on): return "Done: remote-access lockdown is \(on ? "on" : "off")."
        case .updateDefinitions: return "Done: threat definitions are up to date."
        }
    }

    /// Plain-language warning for protection-lowering changes.
    public var warning: String? {
        guard lowersProtection else { return nil }
        switch self {
        case .addExclusion: return "Files in this folder will no longer be scanned. Malware placed there won't be detected."
        case .remoteLockdown: return "Other devices could connect to this Mac remotely again."
        case .setToggle(.developerMode, _): return "Developer mode relaxes some heuristics and can hide real threats."
        case .setToggle(let t, _): return "This turns off \(t.label), which lowers your protection."
        default: return "This lowers your protection."
        }
    }
}

public struct AIProposedAction: Hashable, Codable, Sendable, Identifiable {
    public var id: UUID
    public var action: AIAction
    public var reason: String
    public var title: String { action.title }
    public var change: String { action.change }
    public var lowersProtection: Bool { action.lowersProtection }
    public init(id: UUID = UUID(), action: AIAction, reason: String) { self.id = id; self.action = action; self.reason = reason }
}

/// What the model is allowed to emit (strict schema; everything is re-validated anyway).
public struct AIRawAction: Codable, Hashable, Sendable {
    public var action: String
    public var value: String?
    public var reason: String?
    public init(action: String, value: String? = nil, reason: String? = nil) { self.action = action; self.value = value; self.reason = reason }
}

public enum AIActionValidator {
    public static let actionNames: [String] = AIAction.Toggle.allCases.map(\.rawValue)
        + ["scheduledScanHour", "addExclusion", "removeExclusion", "fixPosture", "quickScan", "remoteLockdown", "updateDefinitions"]

    public static let schema: JSONValue = .list(.obj([
        "action": .str("One allowed action name", enum: actionNames),
        "value": .str("on/off for toggles and remoteLockdown; 0-23 for scheduledScanHour; an absolute folder path for exclusions; a check id for fixPosture; empty otherwise"),
        "reason": .str("One sentence: why this helps the user, tied to their question."),
    ], order: ["action", "value", "reason"]),
    "Optional changes RamPart can make if the user clicks Apply. Only when the user asked for help changing something. At most 3.", maxItems: 3)

    public struct Context: Sendable {
        public var settings: RampartSettings?
        public var fixableFailing: Set<String>     // posture ids that are failing and fixable now
        public var lockdownOn: Bool?
        public init(settings: RampartSettings? = nil, fixableFailing: Set<String> = AIAction.fixableCheckIDs, lockdownOn: Bool? = nil) {
            self.settings = settings; self.fixableFailing = fixableFailing; self.lockdownOn = lockdownOn
        }
    }

    static let broadPaths: Set<String> = ["/", "~", "~/", "/Users", "/Applications", "/System", "/Library", "/private", "/tmp",
                                          "/usr", "/bin", "/sbin", "/var", "/opt", "/Volumes", "~/Downloads", "~/Desktop", "~/Documents", "~/Library"]

    static func bool(_ v: String?) -> Bool? {
        switch v?.trimmingCharacters(in: .whitespaces).lowercased() {
        case "on", "true", "yes", "enable", "enabled": return true
        case "off", "false", "no", "disable", "disabled": return false
        default: return nil
        }
    }

    static func path(_ v: String?) -> String? {
        guard var p = v?.trimmingCharacters(in: .whitespacesAndNewlines), !p.isEmpty, p.count <= 512 else { return nil }
        guard p.hasPrefix("/") || p.hasPrefix("~/"), !p.contains("\n"), !p.contains("\0"), !p.contains(".."), !p.contains("*") else { return nil }
        while p.count > 1 && p.hasSuffix("/") { p.removeLast() }
        return broadPaths.contains(p) ? nil : p
    }

    /// Maps raw model output to allow-listed actions. Unknown names, bad values, no-ops and duplicates are dropped.
    public static func validate(_ raw: [AIRawAction], context: Context = Context()) -> [AIProposedAction] {
        var out: [AIProposedAction] = []
        var seen = Set<AIAction>()
        for r in raw.prefix(5) {
            let name = r.action.trimmingCharacters(in: .whitespaces)
            var a: AIAction?
            if let t = AIAction.Toggle(rawValue: name), let on = bool(r.value) {
                a = .setToggle(t, on)
                if let s = context.settings, current(t, s) == on { a = nil }
            } else {
                switch name {
                case "scheduledScanHour":
                    if let v = r.value?.trimmingCharacters(in: .whitespaces), let h = Int(v), (0...23).contains(h), context.settings?.scheduledScanHour != h { a = .setScanHour(h) }
                case "addExclusion":
                    if let p = path(r.value), context.settings?.exclusions.contains(p) != true { a = .addExclusion(p) }
                case "removeExclusion":
                    if let p = path(r.value) ?? r.value, let s = context.settings, s.exclusions.contains(p) { a = .removeExclusion(p) }
                case "fixPosture":
                    if let id = r.value?.trimmingCharacters(in: .whitespaces), AIAction.fixableCheckIDs.contains(id), context.fixableFailing.contains(id) { a = .fixPosture(id) }
                case "quickScan": a = .quickScan
                case "remoteLockdown":
                    if let on = bool(r.value), context.lockdownOn != on { a = .remoteLockdown(on) }
                case "updateDefinitions": a = .updateDefinitions
                default: a = nil
                }
            }
            guard let action = a, seen.insert(action).inserted else { continue }
            out.append(AIProposedAction(action: action, reason: Clean.text(r.reason, max: 240)))
            if out.count == 3 { break }
        }
        return out
    }

    static func current(_ t: AIAction.Toggle, _ s: RampartSettings) -> Bool {
        switch t {
        case .realtimeOn: return s.realtimeOn
        case .autoQuarantine: return s.autoQuarantine
        case .scanArchives: return s.scanArchives
        case .scheduledQuickScan: return s.scheduledQuickScan
        case .notifyThreats: return s.notifyThreats
        case .notifyInfo: return s.notifyInfo
        case .learningMode: return s.learningMode
        case .developerMode: return s.developerMode
        case .ransomwareCanaries: return s.ransomwareCanaries
        case .autoUpdate: return s.autoUpdate
        case .webProtection: return s.webProtection
        case .blockTrackers: return s.blockTrackers
        }
    }

    /// Applies a settings action to a settings value (read-modify-write). Non-settings actions return nil.
    public static func applying(_ a: AIAction, to s: RampartSettings) -> RampartSettings? {
        var n = s
        switch a {
        case .setToggle(let t, let on):
            switch t {
            case .realtimeOn: n.realtimeOn = on
            case .autoQuarantine: n.autoQuarantine = on
            case .scanArchives: n.scanArchives = on
            case .scheduledQuickScan: n.scheduledQuickScan = on
            case .notifyThreats: n.notifyThreats = on
            case .notifyInfo: n.notifyInfo = on
            case .learningMode: n.learningMode = on
            case .developerMode: n.developerMode = on
            case .ransomwareCanaries: n.ransomwareCanaries = on
            case .autoUpdate: n.autoUpdate = on
            case .webProtection: n.webProtection = on
            case .blockTrackers: n.blockTrackers = on
            }
        case .setScanHour(let h): n.scheduledScanHour = h
        case .addExclusion(let p): if !n.exclusions.contains(p) { n.exclusions.append(p) }
        case .removeExclusion(let p): n.exclusions.removeAll { $0 == p }
        default: return nil
        }
        return n
    }
}

/// Executes approved actions. Implemented by the app (AppModel / DaemonClient).
public protocol AIActionExecutor: Sendable {
    /// Returns a short result line, e.g. "Done: firewall is on".
    func execute(_ action: AIAction) async throws -> String
}

/// The only path from a proposal to execution. Each proposal runs at most once, only after `approve`,
/// and protection-lowering ones need `confirmedLowering: true` (the second confirmation).
public final class AIActionGate: @unchecked Sendable {
    public enum State: Equatable, Sendable { case pending, dismissed, running, done(String), failed(String) }
    private let lock = NSLock()
    private var proposals: [UUID: AIProposedAction] = [:]
    private var states: [UUID: State] = [:]
    public init() {}

    public func register(_ p: [AIProposedAction]) {
        lock.lock(); defer { lock.unlock() }
        for a in p where proposals[a.id] == nil { proposals[a.id] = a; states[a.id] = .pending }
    }
    public func dismiss(_ id: UUID) { lock.lock(); defer { lock.unlock() }; if states[id] == .pending { states[id] = .dismissed } }
    public func state(_ id: UUID) -> State? { lock.lock(); defer { lock.unlock() }; return states[id] }

    public enum ApproveError: Error, Equatable { case unknown, notPending, needsConfirmation }

    /// Claims a proposal for execution (pending or failed -> running). Throws if it can't run.
    private func claim(_ id: UUID, confirmedLowering: Bool) throws -> AIProposedAction {
        lock.lock(); defer { lock.unlock() }
        guard let p = proposals[id] else { throw ApproveError.unknown }
        var runnable = states[id] == .pending
        if case .failed = states[id] { runnable = true }
        guard runnable else { throw ApproveError.notPending }
        if p.lowersProtection && !confirmedLowering { throw ApproveError.needsConfirmation }
        states[id] = .running
        return p
    }
    private func finish(_ id: UUID, _ s: State) { lock.lock(); states[id] = s; lock.unlock() }

    /// Runs an action after the user's click. Returns the result line.
    @discardableResult
    public func approve(_ id: UUID, confirmedLowering: Bool, executor: AIActionExecutor) async throws -> String {
        let p = try claim(id, confirmedLowering: confirmedLowering)
        do {
            let r = try await executor.execute(p.action)
            finish(id, .done(r))
            return r
        } catch {
            finish(id, .failed("\(error)"))
            throw error
        }
    }
}

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
        /// Turning these OFF lowers protection (developer and learning mode are the reverse: turning them ON lowers it).
        /// wms-o5: kept in step with the root daemon's `IPCAuthz.settingsWeaken` (a selftest compares every toggle).
        /// Before, learning mode on, the daily quick scan off and tracker blocking off were "harmless" here while the
        /// daemon counted them as weakening, so injected text could get them proposed as a one-click, non-red card.
        func lowers(_ on: Bool) -> Bool {
            switch self {
            case .developerMode, .learningMode: return on
            case .realtimeOn, .autoQuarantine, .scanArchives, .autoUpdate, .webProtection, .notifyThreats, .ransomwareCanaries,
                 .scheduledQuickScan, .blockTrackers: return !on
            case .notifyInfo: return false
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
        case .setToggle(.learningMode, _): return "Learning mode holds back behaviour alerts while it learns, so a real threat could go unreported."
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
        /// The user's own words (current question plus their recent questions). When set, a protection-lowering
        /// proposal survives only if the user themselves asked to lower something: text in DATA blocks (posture
        /// details, pasted messages) can never be the reason a lowering card appears.
        public var userIntent: String?
        public init(settings: RampartSettings? = nil, fixableFailing: Set<String> = AIAction.fixableCheckIDs, lockdownOn: Bool? = nil,
                    userIntent: String? = nil) {
            self.settings = settings; self.fixableFailing = fixableFailing; self.lockdownOn = lockdownOn; self.userIntent = userIntent
        }
    }

    private static let loweringIntentRE = try! NSRegularExpression(pattern:
        #"(?i)\b(off|disable[ds]?|disabling|deactivate|stop|pause|exclude|excluding|exclusion|exception|ignore|whitelist|allowlist|allow|skip|lower|less|fewer|quiet|silence|too many|false (positive|alarm)|developer|dev mode|unlock|remove|turn it off|annoying|slow(s|ing)? (down|my)|interfer\w*|block(s|ing|ed)? my)\b"#)

    /// Whether the user's own words ask to relax protection in some way.
    public static func hasLoweringIntent(_ text: String) -> Bool {
        loweringIntentRE.firstMatch(in: text, range: NSRange(location: 0, length: (text as NSString).length)) != nil
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
            if action.lowersProtection, let intent = context.userIntent, !hasLoweringIntent(intent) { continue }
            out.append(AIProposedAction(action: action, reason: Clean.text(r.reason, max: 240)))
            if out.count == 3 { break }
        }
        return out
    }

    /// wms-o5: RampartAI's copy of the root daemon's `IPCAuthz.settingsWeaken` (rampartd can't be imported here; a
    /// selftest checks the two agree). The executor refuses a settings write that weakens protection unless the
    /// approved action itself was flagged as lowering, so no unflagged card can ever weaken anything.
    public static func settingsWeaken(old: RampartSettings, new: RampartSettings) -> Bool {
        if old.realtimeOn && !new.realtimeOn { return true }
        if old.autoQuarantine && !new.autoQuarantine { return true }
        if old.scanArchives && !new.scanArchives { return true }
        if old.scheduledQuickScan && !new.scheduledQuickScan { return true }
        if old.notifyThreats && !new.notifyThreats { return true }
        if old.webProtection && !new.webProtection { return true }
        if old.autoUpdate && !new.autoUpdate { return true }
        if old.blockTrackers && !new.blockTrackers { return true }
        if !old.learningMode && new.learningMode { return true }
        if !old.developerMode && new.developerMode { return true }
        if old.ransomwareCanaries && !new.ransomwareCanaries { return true }
        if !Set(new.exclusions).isSubset(of: Set(old.exclusions)) { return true }
        return false
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
    private var registered: [UUID: Date] = [:]
    /// A proposal is only valid while the conversation is fresh: after this long it expires, so an old card
    /// (validated against settings that may since have changed) can't be applied later.
    public let ttl: TimeInterval
    private let now: @Sendable () -> Date
    public init(ttl: TimeInterval = 15 * 60, now: @escaping @Sendable () -> Date = { Date() }) { self.ttl = ttl; self.now = now }

    /// Registers fresh proposals. Ids already seen (even after they ran or were dismissed) are never re-armed.
    public func register(_ p: [AIProposedAction]) {
        lock.lock(); defer { lock.unlock() }
        for a in p where proposals[a.id] == nil { proposals[a.id] = a; states[a.id] = .pending; registered[a.id] = now() }
    }
    public func dismiss(_ id: UUID) { lock.lock(); defer { lock.unlock() }; if states[id] == .pending { states[id] = .dismissed } }
    public func state(_ id: UUID) -> State? { lock.lock(); defer { lock.unlock() }; return states[id] }

    public enum ApproveError: Error, Equatable, CustomStringConvertible {
        case unknown, notPending, needsConfirmation, expired, mismatch
        public var description: String {
            switch self {
            case .unknown: return "this suggestion isn't from the current conversation"
            case .notPending: return "this suggestion was already handled"
            case .needsConfirmation: return "it needs your confirmation first"
            case .expired: return "this suggestion expired. Ask again to get a fresh one"
            case .mismatch: return "the change shown on the card doesn't match the suggestion, so nothing was changed"
            }
        }
    }

    /// Claims a proposal for execution (pending or failed -> running). Throws if it can't run.
    private func claim(_ id: UUID, displayed: AIProposedAction?, confirmedLowering: Bool) throws -> AIProposedAction {
        lock.lock(); defer { lock.unlock() }
        guard let p = proposals[id] else { throw ApproveError.unknown }
        // wms-o5: the click is bound to the exact card the user saw (action, value and reason). A card whose content
        // differs from the registered proposal (a forged or edited copy reusing the id) is refused and nothing runs.
        if let d = displayed, d != p { states[id] = .dismissed; throw ApproveError.mismatch }
        var runnable = states[id] == .pending
        if case .failed = states[id] { runnable = true }
        guard runnable else { throw ApproveError.notPending }
        if let t = registered[id], now().timeIntervalSince(t) > ttl || now() < t { states[id] = .dismissed; throw ApproveError.expired }
        if p.lowersProtection && !confirmedLowering { throw ApproveError.needsConfirmation }
        states[id] = .running
        return p
    }
    private func finish(_ id: UUID, _ s: State) { lock.lock(); states[id] = s; lock.unlock() }

    /// Runs an action after the user's click. Returns the result line.
    @discardableResult
    public func approve(_ id: UUID, confirmedLowering: Bool, executor: AIActionExecutor) async throws -> String {
        try await run(try claim(id, displayed: nil, confirmedLowering: confirmedLowering), executor: executor)
    }

    /// wms-o5: approval bound to the proposal exactly as displayed. The app calls only this one.
    @discardableResult
    public func approve(displayed: AIProposedAction, confirmedLowering: Bool, executor: AIActionExecutor) async throws -> String {
        try await run(try claim(displayed.id, displayed: displayed, confirmedLowering: confirmedLowering), executor: executor)
    }

    private func run(_ p: AIProposedAction, executor: AIActionExecutor) async throws -> String {
        let id = p.id
        do {
            let r = try await executor.execute(p.action)
            finish(id, .done(r))
            return r
        } catch {
            finish(id, .failed(Clean.text("\(error)", max: 300)))
            throw error
        }
    }
}

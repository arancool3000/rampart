import Foundation
import RampartShared

/// Trust baseline: a point-in-time set of persistence records (RansomWhere/KnockKnock approach).
public struct PersistenceSnapshot: Codable, Sendable {
    public var date: Date
    public var host: String
    public var records: [PersistenceRecord]
    /// Kinds whose source failed during this scan (e.g. sfltool timed out).
    public var incompleteKinds: [PersistenceItem.Kind]? = nil

    public init(date: Date = Date(), records: [PersistenceRecord]) {
        self.date = date; self.records = records
        self.host = ProcessInfo.processInfo.hostName
    }

    /// Team IDs present in the baseline (used by R26 "unfamiliar developer").
    public var teamIDs: Set<String> {
        Set(records.compactMap { $0.attributes["teamID"] ?? $0.item.signing?.teamID }.filter { !$0.isEmpty && $0 != "-" })
    }

    public func save(to url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let enc = JSONEncoder.rampart; enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode(self).write(to: url, options: .atomic)
    }

    public static func load(from url: URL) throws -> PersistenceSnapshot {
        try JSONDecoder.rampart.decode(PersistenceSnapshot.self, from: Data(contentsOf: url))
    }

    public static var defaultURL: URL { Paths.effectiveRoot.appendingPathComponent("DB/persistence-baseline.json") }
}

public struct PersistenceChange: Codable, Sendable, Hashable {
    public var old: PersistenceRecord
    public var new: PersistenceRecord
}

public struct PersistenceDiff: Codable, Sendable {
    public var added: [PersistenceRecord]
    public var removed: [PersistenceRecord]
    public var changed: [PersistenceChange]
    public var isEmpty: Bool { added.isEmpty && removed.isEmpty && changed.isEmpty }

    /// Converts the diff into events the BehaviourEngine (or the daemon's event bus) can consume.
    public func events(date: Date = Date()) -> [SecurityEvent] {
        added.map { PersistenceDiffer.event(for: $0, kind: .persistenceAdded, date: date) }
            + changed.map { PersistenceDiffer.event(for: $0.new, kind: .persistenceAdded, date: date, changed: true) }
            + removed.map { PersistenceDiffer.event(for: $0, kind: .persistenceRemoved, date: date) }
    }
}

public enum PersistenceDiffer {
    /// Items of kinds the current scan could not read are never reported as removed.
    public static func diff(baseline: PersistenceSnapshot, current: PersistenceSnapshot) -> PersistenceDiff {
        var d = diff(old: baseline.records, new: current.records)
        let skip = Set(current.incompleteKinds ?? [])
        if !skip.isEmpty { d.removed.removeAll { skip.contains($0.item.kind) } }
        return d
    }

    public static func diff(old: [PersistenceRecord], new: [PersistenceRecord]) -> PersistenceDiff {
        let o = Dictionary(old.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let n = Dictionary(new.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let added = new.filter { o[$0.id] == nil }
        let removed = old.filter { n[$0.id] == nil }
        let changed = new.compactMap { r -> PersistenceChange? in
            guard let prev = o[r.id], prev.fingerprint != r.fingerprint || prev.item.target != r.item.target else { return nil }
            return PersistenceChange(old: prev, new: r)
        }
        return PersistenceDiff(added: added, removed: removed, changed: changed)
    }

    static func event(for r: PersistenceRecord, kind: SecurityEventKind, date: Date, changed: Bool = false) -> SecurityEvent {
        var d: [String: String] = ["persistence_kind": r.item.kind.rawValue, "label": r.item.label, "record_id": r.id]
        if let t = r.item.target { d["executable"] = t }
        if changed { d["changed"] = "1" }
        if !r.arguments.isEmpty { d["args"] = r.arguments.joined(separator: " ") }
        for k in r.environment.keys where k.hasPrefix("DYLD_") { d["env_" + k] = r.environment[k] }
        for (k, v) in r.attributes { d["attr_" + k] = v }
        return SecurityEvent(date: date, kind: kind, path: r.item.location, detail: d, source: "persistence")
    }

    /// Rebuilds a record from a persistence event (from the differ, eslogger BTM events or the unified log).
    public static func record(from e: SecurityEvent) -> PersistenceRecord? {
        guard let loc = e.path ?? e.detail["executable"] ?? e.detail["profile_identifier"].map({ "profile:" + $0 }) else { return nil }
        var kind = PersistenceItem.Kind(rawValue: e.detail["persistence_kind"] ?? "") ?? .other
        if e.detail["persistence_kind"] == nil {
            let t = (e.detail["item_type"] ?? "").lowercased()
            if t.contains("agent") { kind = .launchAgent }
            else if t.contains("daemon") { kind = .launchDaemon }
            else if t.contains("login") || t.contains("app") { kind = .loginItem }
            else if e.detail["channel"] == "btm" || e.detail["es_event"]?.hasPrefix("btm") == true { kind = .btm }
            else if loc.contains("/LaunchAgents/") { kind = .launchAgent }
            else if loc.contains("/LaunchDaemons/") { kind = .launchDaemon }
        }
        var attrs: [String: String] = [:]
        var env: [String: String] = [:]
        for (k, v) in e.detail {
            if k.hasPrefix("attr_") { attrs[String(k.dropFirst(5))] = v }
            if k.hasPrefix("env_") { env[String(k.dropFirst(4))] = v }
        }
        if let pi = e.detail["profile_identifier"] { attrs["identifier"] = pi }
        if let org = e.detail["profile_organization"] { attrs["organization"] = org }
        // Launchd plist on disk: parse it for the full picture.
        if (kind == .launchAgent || kind == .launchDaemon), loc.hasSuffix(".plist"),
           var r = PersistenceScanner.parseLaunchdPlist(path: loc, kind: kind) {
            r.attributes.merge(attrs) { a, _ in a }
            return r
        }
        let args = e.detail["args"].map { $0.split(separator: " ").map(String.init) } ?? []
        return PersistenceRecord(item: PersistenceItem(kind: kind, label: e.detail["label"] ?? PathUtil.basename(loc), location: loc,
                                                       target: e.detail["executable"]),
                                 arguments: args, environment: env, attributes: attrs)
    }
}

/// A rule hit derived from a persistence record, before scoring.
public struct PersistenceFinding: Sendable {
    public var ruleID: String
    public var detail: String
    public var targetPath: String?
}

/// Inspects a new/changed persistence record and says which rules (R07, R09–R12, R14, R17, R20–R23, R26) apply.
public struct PersistenceAssessor: Sendable {
    let trust: @Sendable (String) -> TrustClass
    public var knownTeamIDs: Set<String>
    /// Profile identifiers expected on this Mac (MDM, Screen Time).
    public var benignProfilePrefixes = ["com.apple.ManagedSettings.", "com.apple.screentime"]

    public init(trust: @escaping @Sendable (String) -> TrustClass, knownTeamIDs: Set<String> = []) {
        self.trust = trust; self.knownTeamIDs = knownTeamIDs
    }

    func describe(_ path: String) -> (TrustClass, PathClass, Bool) {
        let exists = FileManager.default.fileExists(atPath: path)
        return (trust(path), PathClass.classify(path), exists)
    }

    func targetProblem(_ path: String) -> String? {
        let (t, c, exists) = describe(path)
        var reasons: [String] = []
        if t.isUntrusted { reasons.append("signature: \(t.rawValue)") }
        if c.isSuspiciousLocation { reasons.append("location: \(c.rawValue) folder") }
        if !exists && c != .system { reasons.append("file missing (dropped later or deleted)") }
        if !exists && c == .hidden { reasons.append("hidden path") }
        guard !reasons.isEmpty, !(reasons.count == 1 && reasons[0].hasPrefix("file missing")) else { return nil }
        return reasons.joined(separator: ", ")
    }

    /// RamPart's own launch items (app agent, root daemon), by label or target.
    public static func isRampartOwn(_ r: PersistenceRecord) -> Bool {
        let label = r.item.label.lowercased()
        let file = PathUtil.basename(r.item.location).lowercased()
        let targets = ([r.item.target] + r.arguments.prefix(1).map { Optional($0) }).compactMap { $0 }
        let ownTarget = targets.allSatisfy { t in
            t.hasPrefix("/Library/PrivilegedHelperTools/app.rampart.") || t.hasPrefix("/Applications/Rampart.app/Contents/")
                || t.hasPrefix("/Applications/RamPart.app/Contents/")
        }
        return (label.hasPrefix("app.rampart.") || file.hasPrefix("app.rampart.")) && ownTarget && !targets.isEmpty
    }

    /// True for plain folders in a user's home (not Downloads, hidden, temp or shared).
    public static func isUserOwnedLocation(_ p: String) -> Bool {
        switch PathClass.classify(p) {
        case .home, .developer, .applications: return p.hasPrefix("/Users/") && !p.hasPrefix("/Users/Shared/")
        default: return false
        }
    }

    /// Concrete malicious signs for a launch item target; nil when there are none.
    func maliciousEvidence(_ r: PersistenceRecord, target t: String) -> String? {
        let c = PathClass.classify(t)
        if c.isSuspiciousLocation || c == .downloads || c == .volume || c == .translocated { return "runs from a \(c.rawValue) folder" }
        if !FileManager.default.fileExists(atPath: t) { return "target missing" }
        if getxattr(t, "com.apple.quarantine", nil, 0, 0, 0) >= 0 { return "target carries a download quarantine flag" }
        let label = r.item.label.lowercased()
        if label.hasPrefix("com.apple.") && trust(t) != .apple { return "Apple-like label with a non-Apple program" }
        if r.attributes["labelMismatch"] == "1" && label.hasPrefix("com.apple") { return "label imitates Apple" }
        let line = r.arguments.joined(separator: " ")
        if let why = PersistenceScanner.shellLineReason(line) { return "command line \(why)" }
        if let why = Self.scriptContentReason(t) { return why }
        return nil
    }

    static let scriptPatterns: [(String, String)] = [
        (#"\b(curl|wget)\b[^#]*\|\s*(ba|z|da)?sh\b|(ba|z)?sh\s+-c\s+["']?\$\(\s*(curl|wget)\b"#, "pipes a download into a shell"),
        (#"base64\s+(-d|--decode|-D)[^#]*\|\s*(ba|z)?sh\b"#, "decodes and runs an encoded blob"),
        (#"/dev/tcp/"#, "opens a raw TCP connection"),
        (#"\b(nc|ncat|socat)\b.*\s-e\s"#, "opens a reverse shell"),
    ]

    /// Looks at the first 64 KB of a script target for download-and-run or obfuscation patterns.
    static func scriptContentReason(_ path: String) -> String? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? fh.close() }
        guard let d = try? fh.read(upToCount: 65536), !d.isEmpty, let s = String(data: d, encoding: .utf8) else { return nil }
        guard s.hasPrefix("#!") || [".sh", ".py", ".zsh", ".bash", ".command", ".rb", ".pl", ".js"].contains(where: { path.hasSuffix($0) }) else { return nil }
        for line in s.components(separatedBy: "\n").prefix(2000) {
            let l = line.trimmingCharacters(in: .whitespaces)
            if l.hasPrefix("#") && !l.hasPrefix("#!") { continue }
            for (pat, why) in Self.scriptPatterns where RegexCache.shared.matches(pat, l) { return "script \(why)" }
            if l.count > 400, l.range(of: "^[A-Za-z0-9+/=\"' ;(]{400,}", options: .regularExpression) != nil,
               l.contains("base64") || l.contains("b64decode") || l.contains("exec(") || l.contains("eval") { return "script holds an obfuscated payload" }
        }
        return nil
    }

    public func assess(_ r: PersistenceRecord, previous: PersistenceRecord? = nil) -> [PersistenceFinding] {
        var out: [PersistenceFinding] = []
        let it = r.item
        switch it.kind {
        case .launchAgent, .launchDaemon:
            var targets = [it.target].compactMap { $0 }
            if let s = r.attributes["script"], s.hasPrefix("/") || s.hasPrefix("~") { targets.append(PathUtil.expand(s)) }
            if Self.isRampartOwn(r) { break }
            for t in targets where t.hasPrefix("/") {
                if let why = targetProblem(t) {
                    // The user's own unsigned scripts/tools in their home folder: log only (R07L, score 25)
                    // unless there is real malicious evidence.
                    if let evidence = maliciousEvidence(r, target: t) {
                        out.append(PersistenceFinding(ruleID: "R07",
                            detail: "Job \(it.label) (\(it.location)) runs \(t) [\(why); \(evidence)].", targetPath: t))
                        break
                    }
                    if Self.isUserOwnedLocation(t) {
                        out.append(PersistenceFinding(ruleID: "R07L",
                            detail: "Job \(it.label) (\(it.location)) runs \(t) [\(why)] from your home folder; no malicious signs.", targetPath: t))
                        break
                    }
                    var extra = [String]()
                    if r.attributes["runAtLoad"] == "1" { extra.append("RunAtLoad") }
                    if r.attributes["keepAlive"] != nil && r.attributes["keepAlive"] != "0" { extra.append("KeepAlive") }
                    if let si = r.attributes["startInterval"] { extra.append("StartInterval \(si)s") }
                    if r.attributes["labelMismatch"] == "1" { extra.append("label differs from file name") }
                    out.append(PersistenceFinding(ruleID: "R07",
                        detail: "Job \(it.label) (\(it.location)) runs \(t) [\(why)]" + (extra.isEmpty ? "" : "; " + extra.joined(separator: ", ")) + ".",
                        targetPath: t))
                    break
                }
            }
            if r.attributes["inline"] == "1", let t = it.target, out.isEmpty {
                let line = r.arguments.joined(separator: " ")
                if PersistenceScanner.shellLineReason(line) != nil {
                    out.append(PersistenceFinding(ruleID: "R07", detail: "Job \(it.label) runs an inline \(PathUtil.basename(t)) command that \(PersistenceScanner.shellLineReason(line)!): \(line.prefix(200))", targetPath: t))
                }
            }
            let dyld = r.environment.keys.filter { $0.hasPrefix("DYLD_") }
            if !dyld.isEmpty {
                out.append(PersistenceFinding(ruleID: "R09", detail: "Job \(it.label) sets \(dyld.sorted().joined(separator: ", ")) = \(dyld.compactMap { r.environment[$0] }.joined(separator: ", ")).", targetPath: it.target))
            }
        case .btm, .loginItem:
            if let t = it.target, t.hasPrefix("/"), let why = targetProblem(t), r.attributes["managed"] != "1" {
                out.append(PersistenceFinding(ruleID: "R10", detail: "Background item \(it.label) runs \(t) [\(why)].", targetPath: t))
            }
        case .cron, .periodic:
            out.append(PersistenceFinding(ruleID: "R11", detail: "New \(it.kind.rawValue) entry: \(it.label.prefix(200)) (\(it.location)).", targetPath: it.target))
        case .shellRC:
            let now = Set((r.attributes["suspiciousLines"] ?? "").components(separatedBy: "\n").filter { !$0.isEmpty })
            let before = Set((previous?.attributes["suspiciousLines"] ?? "").components(separatedBy: "\n").filter { !$0.isEmpty })
            let added = now.subtracting(before)
            if let l = added.sorted().first {
                out.append(PersistenceFinding(ruleID: "R12", detail: "\(it.location) gained a line that \(PersistenceScanner.shellLineReason(l) ?? "is suspicious"): \(l.prefix(200))", targetPath: nil))
            }
        case .sshKey:
            out.append(PersistenceFinding(ruleID: "R14", detail: "New SSH key \(r.attributes["keyType"] ?? "") \(r.attributes["fingerprint"] ?? "") \"\(r.attributes["comment"] ?? "no comment")\" in \(it.location.components(separatedBy: "#").first ?? it.location).", targetPath: nil))
        case .profile:
            let id = r.attributes["identifier"] ?? it.label
            if !benignProfilePrefixes.contains(where: { id.hasPrefix($0) }) {
                out.append(PersistenceFinding(ruleID: "R23", detail: "Configuration profile \(id) was installed\(r.attributes["organization"].map { " by \($0)" } ?? "").", targetPath: nil))
            }
        case .browserExtension:
            let perms = (r.attributes["permissions"] ?? "").components(separatedBy: ",")
            let loc = r.attributes["installLocation"] ?? ""
            if r.attributes["fromWebstore"] == "0" || loc == "4" || loc == "5" {
                let how = loc == "4" ? "loaded unpacked (sideloaded)" : loc == "5" ? "force-installed by policy" : "installed outside the store"
                out.append(PersistenceFinding(ruleID: "R20", detail: "\(it.label) [\(r.attributes["extensionID"] ?? "")] was \(how).", targetPath: nil))
            }
            let allSites = perms.contains { $0 == "<all_urls>" || $0 == "*://*/*" || $0 == "http://*/*" || $0 == "https://*/*" }
            let risky = perms.filter { ["cookies", "webRequest", "webRequestBlocking", "nativeMessaging", "proxy", "management", "debugger", "declarativeNetRequest"].contains($0) }
            if allSites && !risky.isEmpty {
                out.append(PersistenceFinding(ruleID: "R21", detail: "\(it.label) can read every site and requests \(risky.joined(separator: ", ")).", targetPath: nil))
            }
        case .systemExtension:
            let team = r.attributes["teamID"] ?? ""
            if !team.isEmpty && !knownTeamIDs.contains(team) {
                out.append(PersistenceFinding(ruleID: "R26", detail: "System extension \(it.label) from Team ID \(team) (\(r.attributes["category"] ?? "")) is new to this Mac.", targetPath: nil))
            }
        case .other:
            if r.attributes["nativeHost"] == "1", let t = it.target, t.hasPrefix("/"), let why = targetProblem(t) {
                out.append(PersistenceFinding(ruleID: "R22", detail: "Native-messaging host \(it.label) (\(it.location)) launches \(t) [\(why)].", targetPath: t))
            } else if ["SecurityAgentPlugins", "PlugIns"].contains(r.attributes["class"] ?? "") {
                let t = it.target ?? it.location
                if trust(t) != .apple && trust(t) != .notarized {
                    out.append(PersistenceFinding(ruleID: "R17", detail: "Authorization/directory plugin \(it.label) added at \(it.location).", targetPath: t))
                }
            } else if r.attributes["class"] == "dock", let problem = r.attributes["dockProblem"] {
                out.append(PersistenceFinding(ruleID: "R19", detail: "Dock tile \"\(r.attributes["label"] ?? it.label)\" opens \(it.target ?? "?"): \(problem).", targetPath: it.target))
            } else if r.attributes["class"] == "loginHook" {
                out.append(PersistenceFinding(ruleID: "R18", detail: "\(it.label) set to \(it.target ?? "?").", targetPath: it.target))
            } else if r.attributes["class"] == "StartupItems" {
                out.append(PersistenceFinding(ruleID: "R11", detail: "Legacy StartupItem \(it.label) present.", targetPath: it.target))
            }
        }
        return out
    }
}

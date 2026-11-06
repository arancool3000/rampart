import Foundation
import RampartShared

/// Turns eslogger JSON lines into `SecurityEvent`s.
///
/// eslogger is not a stable API, so the parser is tolerant: it uses `JSONSerialization` instead of strict
/// `Codable`, finds the event by the single key under `"event"` (not the numeric `event_type`), and checks
/// `schema_version` against the versions it was written for. Unknown schema versions are still parsed
/// best-effort and counted in `stats.schemaMismatches` (and tagged `schema_mismatch=1` in `detail`) so the
/// daemon can surface "eslogger format changed" instead of silently going blind.
public final class EsloggerParser {
    /// Top-level `schema_version` values this parser was written against.
    public static let supportedSchemaVersions: Set<Int> = [1]
    /// Highest ES message `version` seen during development (macOS 27 ships 9+). Newer is accepted.
    public static let minMessageVersion = 2

    public struct Stats: Codable, Sendable, Equatable {
        public var lines = 0
        public var parsed = 0
        public var malformed = 0
        public var ignored = 0
        public var schemaMismatches = 0
        public var lastSchemaVersion: Int?
        public var lastMessageVersion: Int?
    }

    public private(set) var stats = Stats()
    /// Drop `close` events whose `modified` flag is false (huge volume, no value for scan-on-write).
    public var dropUnmodifiedClose = true
    /// When true, events with an unsupported schema version are dropped instead of parsed best-effort.
    public var strictSchema = false
    /// Resolves `responsible_pid` to an executable path for exec events (`detail["responsible_path"]`).
    /// Defaults to libproc; the process is normally still alive when eslogger reports its exec.
    /// Results are cached briefly because one app's helpers exec in bursts.
    public var responsiblePathResolver: ((Int32) -> String?)? = { ProcInspector.path($0) }
    private var responsibleCache: [Int32: (path: String, at: Date)] = [:]

    public init() {}

    public func parse(line: String) -> SecurityEvent? { parse(data: Data(line.utf8)) }

    public func parse(data: Data) -> SecurityEvent? {
        stats.lines += 1
        guard let first = data.first(where: { $0 != 0x20 && $0 != 0x09 }), first == UInt8(ascii: "{"),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            stats.malformed += 1; return nil
        }
        let schema = Self.int(obj["schema_version"])
        stats.lastSchemaVersion = schema
        stats.lastMessageVersion = Self.int(obj["version"])
        var mismatch = false
        if schema == nil || !Self.supportedSchemaVersions.contains(schema!) {
            stats.schemaMismatches += 1
            mismatch = true
            if strictSchema { stats.ignored += 1; return nil }
        }
        guard let eventWrap = obj["event"] as? [String: Any], let (name, body) = eventWrap.first,
              let ev = body as? [String: Any] else {
            stats.malformed += 1; return nil
        }
        let date = Self.parseTime(obj["time"] as? String) ?? Date()
        let actor = (obj["process"] as? [String: Any]).flatMap { Self.process($0) }
        var detail: [String: String] = ["es_event": name]
        if let seq = Self.int(obj["global_seq_num"]) { detail["global_seq"] = String(seq) }
        if mismatch { detail["schema_mismatch"] = "1" }
        if let actorDict = obj["process"] as? [String: Any], let cd = actorDict["cdhash"] as? String { detail["cdhash"] = cd }

        var kind: SecurityEventKind = .other
        var process = actor
        var path: String?
        var dest: String?

        switch name {
        case "exec":
            kind = .exec
            guard let target = ev["target"] as? [String: Any], var p = Self.process(target) else { stats.malformed += 1; return nil }
            p.args = (ev["args"] as? [Any])?.compactMap { $0 as? String } ?? []
            process = p
            path = p.path
            if let cd = target["cdhash"] as? String { detail["cdhash"] = cd }
            if let prev = actor?.path, prev != p.path { detail["prev_path"] = prev }
            if let cwd = Self.filePath(ev["cwd"]) { detail["cwd"] = cwd }
            if let script = Self.filePath(ev["script"]) { detail["script"] = script }
            if let rp = Self.responsiblePid(target) {
                detail["responsible_pid"] = String(rp)
                if rp != p.pid, let path = responsiblePath(Int32(truncatingIfNeeded: rp)) { detail["responsible_path"] = path }
            }
        case "fork":
            kind = .other
            if let child = (ev["child"] as? [String: Any]).flatMap({ Self.process($0) }) {
                detail["child_pid"] = String(child.pid)
                path = child.path
            }
        case "exit":
            kind = .other
            if let st = Self.int(ev["stat"]) { detail["status"] = String(st) }
            path = actor?.path
        case "create":
            kind = .fileCreate
            if let d = ev["destination"] as? [String: Any] {
                if let existing = Self.filePath(d["existing_file"]) { path = existing }
                else if let np = d["new_path"] as? [String: Any], let dir = Self.filePath(np["dir"]),
                        let fn = np["filename"] as? String {
                    path = dir.hasSuffix("/") ? dir + fn : dir + "/" + fn
                }
            }
        case "write":
            kind = .fileWrite; path = Self.filePath(ev["target"])
        case "close":
            let modified = (ev["modified"] as? Bool) ?? false
            if !modified && dropUnmodifiedClose { stats.ignored += 1; return nil }
            kind = .fileClose; path = Self.filePath(ev["target"])
            detail["modified"] = modified ? "1" : "0"
        case "rename":
            kind = .fileRename
            path = Self.filePath(ev["source"])
            if let d = ev["destination"] as? [String: Any] {
                if let existing = Self.filePath(d["existing_file"]) { dest = existing }
                else if let np = d["new_path"] as? [String: Any], let dir = Self.filePath(np["dir"]),
                        let fn = np["filename"] as? String {
                    dest = dir.hasSuffix("/") ? dir + fn : dir + "/" + fn
                }
            }
        case "unlink":
            kind = .fileDelete; path = Self.filePath(ev["target"])
        case "deleteextattr":
            kind = .xattrDelete; path = Self.filePath(ev["target"])
            if let a = ev["extattr"] as? String { detail["xattr"] = a }
        case "setextattr":
            kind = .other; path = Self.filePath(ev["target"])
            if let a = ev["extattr"] as? String { detail["xattr"] = a }
        case "btm_launch_item_add", "btm_launch_item_remove":
            kind = name.hasSuffix("add") ? .persistenceAdded : .persistenceRemoved
            if let item = ev["item"] as? [String: Any] {
                path = Self.urlPath(item["item_url"] as? String)
                if let app = Self.urlPath(item["app_url"] as? String) { detail["app"] = app }
                if let t = Self.int(item["item_type"]) { detail["item_type"] = Self.btmItemType(t) }
                if let l = item["legacy"] as? Bool { detail["legacy"] = l ? "1" : "0" }
                if let m = item["managed"] as? Bool { detail["managed"] = m ? "1" : "0" }
                if let u = Self.int(item["uid"]) { detail["item_uid"] = String(u) }
            }
            if let exe = ev["executable_path"] as? String { detail["executable"] = exe }
            if let inst = (ev["instigator"] as? [String: Any]).flatMap({ Self.process($0) }) { process = inst }
            if let app = (ev["app"] as? [String: Any]).flatMap({ Self.process($0) }) { detail["app_process"] = app.path }
        case "xp_malware_detected", "xp_malware_remediated":
            kind = .xprotectDetection
            detail["action"] = name.hasSuffix("detected") ? "detected" : "remediated"
            for k in ["signature_version", "malware_identifier", "incident_identifier", "action_type",
                      "result_description", "remediated_process_audit_token"] {
                if let v = ev[k] as? String { detail[k] = v } else if let n = Self.int(ev[k]) { detail[k] = String(n) }
            }
            path = (ev["detected_path"] as? String) ?? (ev["remediated_path"] as? String)
        case "tcc_modify":
            kind = .tccRequest
            for k in ["service", "identity", "identity_type", "update_type", "right", "reason"] {
                if let v = ev[k] as? String { detail[k] = v } else if let n = Self.int(ev[k]) { detail[k] = String(n) }
            }
        case "gatekeeper_user_override":
            kind = .other
            if let f = ev["file"] as? [String: Any] {
                path = Self.filePath(f["file"]) ?? (f["file_path"] as? String)
            }
            if let sha = ev["sha256"] as? String { detail["sha256"] = sha }
        case "profile_add", "profile_remove":
            kind = name == "profile_add" ? .persistenceAdded : .persistenceRemoved
            if let prof = ev["profile"] as? [String: Any] {
                for k in ["identifier", "uuid", "organization", "display_name", "scope"] {
                    if let v = prof[k] as? String { detail["profile_" + k] = v }
                }
            }
            detail["persistence_kind"] = "profile"
        default:
            kind = .other
            path = Self.filePath(ev["target"]) ?? Self.filePath(ev["source"])
        }

        stats.parsed += 1
        return SecurityEvent(date: date, kind: kind, process: process, path: path, destPath: dest,
                             detail: detail, source: "eslogger")
    }

    // MARK: helpers

    private func responsiblePath(_ pid: Int32) -> String? {
        if let c = responsibleCache[pid], Date().timeIntervalSince(c.at) < 5 { return c.path }
        guard let path = responsiblePathResolver?(pid), !path.isEmpty else { return nil }
        if responsibleCache.count > 512 { responsibleCache.removeAll(keepingCapacity: true) }
        responsibleCache[pid] = (path, Date())
        return path
    }

    static func int(_ v: Any?) -> Int? {
        if let n = v as? NSNumber { return n.intValue }
        if let s = v as? String { return Int(s) }
        return nil
    }

    static func process(_ d: [String: Any]) -> ProcessInfoLite? {
        let token = d["audit_token"] as? [String: Any]
        guard let pid = int(token?["pid"]) else { return nil }
        let exe = (d["executable"] as? [String: Any])?["path"] as? String ?? ""
        let uid = int(token?["euid"]) ?? int(token?["ruid"]) ?? 0
        return ProcessInfoLite(pid: Int32(truncatingIfNeeded: pid),
                               ppid: Int32(truncatingIfNeeded: int(d["ppid"]) ?? 0),
                               path: exe, args: [], uid: UInt32(truncatingIfNeeded: uid),
                               signingID: d["signing_id"] as? String, teamID: d["team_id"] as? String,
                               isPlatformBinary: (d["is_platform_binary"] as? Bool) ?? false)
    }

    static func responsiblePid(_ d: [String: Any]) -> Int? {
        int((d["responsible_audit_token"] as? [String: Any])?["pid"])
    }

    /// eslogger encodes es_file_t as {"path": "...", "path_truncated": false, "stat": {...}}.
    static func filePath(_ v: Any?) -> String? {
        guard let d = v as? [String: Any], let p = d["path"] as? String, !p.isEmpty else { return nil }
        return p
    }

    static func urlPath(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        if s.hasPrefix("file://"), let u = URL(string: s) { return u.path }
        return s
    }

    static func btmItemType(_ t: Int) -> String {
        switch t { case 0: return "user_item"; case 1: return "app"; case 2: return "login_item"
        case 3: return "agent"; case 4: return "daemon"; default: return "type_\(t)" }
    }

    private static let isoFrac: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return f
    }()
    private static let isoPlain = ISO8601DateFormatter()
    private static let timeLock = NSLock()

    /// eslogger emits nanosecond fractions ("2026-11-05T10:11:12.123456789Z"); trim to milliseconds first.
    static func parseTime(_ s: String?) -> Date? {
        guard var s else { return nil }
        if let dot = s.firstIndex(of: ".") {
            var end = s.index(after: dot)
            while end < s.endIndex, s[end].isNumber { end = s.index(after: end) }
            let frac = s[s.index(after: dot)..<end]
            let ms = String((frac + "000").prefix(3))
            s = String(s[..<dot]) + "." + ms + String(s[end...])
        }
        timeLock.lock(); defer { timeLock.unlock() }
        return isoFrac.date(from: s) ?? isoPlain.date(from: s)
    }
}

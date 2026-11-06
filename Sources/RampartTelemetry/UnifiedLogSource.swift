import Foundation
import RampartShared

/// Parses `log stream --style ndjson` lines into `SecurityEvent`s. Message text is OS-version specific,
/// so classification is keyword-based and conservative; the raw message is always kept in `detail["message"]`.
public final class UnifiedLogParser {
    public private(set) var parsed = 0
    public private(set) var skipped = 0
    public var maxMessageLength = 2048

    public init() {}

    private static let tsFormatter: DateFormatter = {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ"; return f
    }()
    private static let tsLock = NSLock()

    static func parseTimestamp(_ s: String?) -> Date? {
        guard let s else { return nil }
        tsLock.lock(); defer { tsLock.unlock() }
        return tsFormatter.date(from: s)
    }

    public func parse(line: String) -> SecurityEvent? { parse(data: Data(line.utf8)) }

    public func parse(data: Data) -> SecurityEvent? {
        guard data.first == UInt8(ascii: "{"),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            skipped += 1; return nil   // e.g. the "Filtering the log data using ..." banner
        }
        guard (obj["eventType"] as? String).map({ $0 == "logEvent" || $0 == "activityCreateEvent" }) ?? true else {
            skipped += 1; return nil
        }
        let subsystem = obj["subsystem"] as? String ?? ""
        let category = obj["category"] as? String ?? ""
        let message = obj["eventMessage"] as? String ?? ""
        let procPath = obj["processImagePath"] as? String ?? ""
        let procName = (procPath as NSString).lastPathComponent
        let pid = (obj["processID"] as? NSNumber)?.int32Value ?? 0
        var detail: [String: String] = [
            "subsystem": subsystem, "category": category,
            "message": String(message.prefix(maxMessageLength)), "log_process": procName,
        ]
        if let t = obj["messageType"] as? String { detail["level"] = t }
        if let s = obj["senderImagePath"] as? String { detail["sender"] = (s as NSString).lastPathComponent }
        let lower = message.lowercased()
        var kind: SecurityEventKind = .other
        var path: String? = nil

        if subsystem.hasPrefix("com.apple.xprotect") || subsystem == "com.apple.XProtectFramework"
            || procName.hasPrefix("XProtect") || procName == "XprotectService" {
            detail["channel"] = "xprotect"
            if lower.contains("malware") || lower.contains("detect") || lower.contains("remediat")
                || lower.contains("quarantin") || lower.contains("matched") {
                kind = .xprotectDetection
            }
        } else if subsystem == "com.apple.backgroundtaskmanagement" || procName == "backgroundtaskmanagementd" {
            detail["channel"] = "btm"
            if lower.contains("registered") || lower.contains("adding") || lower.contains("added") || lower.contains("new item")
                || lower.contains("notifying") {
                kind = .persistenceAdded
            } else if lower.contains("removed") || lower.contains("removing") || lower.contains("unregister") {
                kind = .persistenceRemoved
            }
        } else if subsystem == "com.apple.TCC" || procName == "tccd" {
            detail["channel"] = "tcc"
            if message.contains("AUTHREQ") || lower.contains("auth request") { kind = .tccRequest }
            if let svc = Self.firstMatch(message, prefix: "kTCCService") { detail["service"] = svc }
        } else if procName == "syspolicyd" || subsystem.hasPrefix("com.apple.syspolicy") {
            detail["channel"] = "gatekeeper"
            if lower.contains("override") { detail["gatekeeper"] = "override" }
            else if lower.contains("deny") || lower.contains("denied") || lower.contains("rejected") { detail["gatekeeper"] = "deny" }
        }
        if let p = Self.firstPath(message) { path = p }
        parsed += 1
        let proc = pid > 0 ? ProcessInfoLite(pid: pid, ppid: 0, path: procPath,
                                             isPlatformBinary: procPath.hasPrefix("/System/") || procPath.hasPrefix("/usr/libexec/")) : nil
        return SecurityEvent(date: Self.parseTimestamp(obj["timestamp"] as? String) ?? Date(), kind: kind,
                             process: proc, path: path, detail: detail, source: "unifiedlog")
    }

    static func firstMatch(_ s: String, prefix: String) -> String? {
        guard let r = s.range(of: prefix) else { return nil }
        let tail = s[r.lowerBound...]
        let end = tail.firstIndex { !($0.isLetter || $0.isNumber || $0 == "_") } ?? tail.endIndex
        return String(tail[..<end])
    }

    /// First absolute path that looks like a file path (not `<private>`).
    static func firstPath(_ s: String) -> String? {
        for token in s.split(whereSeparator: { $0 == " " || $0 == "," || $0 == "\"" || $0 == "'" || $0 == "(" || $0 == ")" }) {
            var t = String(token)
            if t.hasPrefix("file://"), let u = URL(string: t) { t = u.path }
            if t.hasPrefix("/"), t.count > 2, !t.contains("<private>") {
                return t.trimmingCharacters(in: CharacterSet(charactersIn: ".:;]"))
            }
        }
        return nil
    }
}

/// Tails the unified log via `/usr/bin/log stream --style ndjson` with a narrow security predicate
/// (XProtect, BTM, TCC auth requests, syspolicyd/Gatekeeper). Restarts with backoff if `log` dies.
/// Works unprivileged (fewer messages, more `<private>`); full value as root.
public final class UnifiedLogSource: EventSource, CPUReporting {
    public static let defaultPredicate =
        #"subsystem == "com.apple.xprotect" OR subsystem == "com.apple.XProtectFramework" OR process BEGINSWITH "XProtect" "# +
        #"OR subsystem == "com.apple.backgroundtaskmanagement" "# +
        #"OR (subsystem == "com.apple.TCC" AND eventMessage CONTAINS "AUTHREQ") "# +
        #"OR process == "syspolicyd""#
    public static let binary = "/usr/bin/log"

    public let name = "unifiedlog"
    public let cpu = CPUMeter()
    public let predicate: String
    public let level: String
    public let parser = UnifiedLogParser()
    public private(set) var lastError: String?
    private var stream: ChildLineStream?
    private let lock = NSLock()

    public init(predicate: String = UnifiedLogSource.defaultPredicate, level: String = "info") {
        self.predicate = predicate
        self.level = level
    }

    public var isAvailable: Bool { FileManager.default.isExecutableFile(atPath: Self.binary) }
    public var isRunning: Bool { lock.withLock { stream?.isRunning ?? false } }
    public var launches: Int { lock.withLock { stream?.launches ?? 0 } }

    public var arguments: [String] { ["stream", "--style", "ndjson", "--level", level, "--predicate", predicate] }

    public func start(handler: @escaping @Sendable (SecurityEvent) -> Void) throws {
        stop()
        let s = ChildLineStream(executable: Self.binary, arguments: arguments, label: "logstream", maxLineBytes: 1 << 20)
        let parser = self.parser, cpu = self.cpu
        s.onLine = { line in if let ev = cpu.measure({ parser.parse(data: line) }) { handler(ev) } }
        s.onExit = { [weak self] status, err in
            self?.lock.withLock { self?.lastError = "log stream exited \(status): \(err.suffix(300))" }
        }
        lock.withLock { stream = s; lastError = nil }
        try s.start()
    }

    public func stop() {
        let s = lock.withLock { () -> ChildLineStream? in let s = stream; stream = nil; return s }
        s?.stop()
    }

    deinit { stream?.stop() }
}

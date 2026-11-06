import Foundation
import RampartShared

/// Real-time Endpoint Security NOTIFY events via Apple's `/usr/bin/eslogger`.
///
/// Requires root and Full Disk Access for the responsible process (rampartd). As a normal user
/// `isAvailable` is false and `start` throws. The child is restarted with backoff if it dies; a
/// "not permitted" exit (missing FDA) is recorded in `lastError` and stops the restart loop.
public final class EsloggerSource: EventSource, CPUReporting {
    public enum Failure: Error, CustomStringConvertible {
        case notRoot, missingBinary, noSupportedEvents, notPermitted(String)
        public var description: String {
            switch self {
            case .notRoot: return "eslogger requires root"
            case .missingBinary: return "/usr/bin/eslogger not found"
            case .noSupportedEvents: return "none of the requested eslogger events are supported on this OS"
            case .notPermitted(let s): return "eslogger not permitted (grant Full Disk Access to rampartd): \(s)"
            }
        }
    }

    public static let binary = "/usr/bin/eslogger"
    /// Default subscription: everything the behaviour engine and scan-on-write consume.
    public static let defaultEvents = [
        "exec", "fork", "exit", "create", "rename", "close", "unlink", "deleteextattr",
        "btm_launch_item_add", "btm_launch_item_remove", "xp_malware_detected", "xp_malware_remediated",
        "tcc_modify", "gatekeeper_user_override", "profile_add",
    ]

    public let name = "eslogger"
    public let cpu = CPUMeter()
    public let events: [String]
    public let parser = EsloggerParser()
    public private(set) var lastError: String?
    private var stream: ChildLineStream?
    private let lock = NSLock()
    private let log = RLog.logger("telemetry.eslogger")

    public init(events: [String] = EsloggerSource.defaultEvents) { self.events = events }

    public var isAvailable: Bool {
        getuid() == 0 && FileManager.default.isExecutableFile(atPath: Self.binary)
    }

    public var isRunning: Bool { lock.withLock { stream?.isRunning ?? false } }

    /// Events supported by the installed eslogger (`--list-events`); nil if it can't be queried.
    public static func supportedEvents() -> Set<String>? {
        guard FileManager.default.isExecutableFile(atPath: binary) else { return nil }
        let p = Process(); p.executableURL = URL(fileURLWithPath: binary); p.arguments = ["--list-events"]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        let set = Set(String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) })
        return set.isEmpty ? nil : set
    }

    public func start(handler: @escaping @Sendable (SecurityEvent) -> Void) throws {
        guard getuid() == 0 else { throw Failure.notRoot }
        guard FileManager.default.isExecutableFile(atPath: Self.binary) else { throw Failure.missingBinary }
        var subscribed = events
        if let supported = Self.supportedEvents() {
            let missing = events.filter { !supported.contains($0) }
            if !missing.isEmpty { log.notice("eslogger lacks events: \(missing.joined(separator: ","), privacy: .public)") }
            subscribed = events.filter { supported.contains($0) }
        }
        guard !subscribed.isEmpty else { throw Failure.noSupportedEvents }
        stop()
        let s = ChildLineStream(executable: Self.binary, arguments: subscribed, label: "eslogger")
        let parser = self.parser, cpu = self.cpu
        s.onLine = { line in if let ev = cpu.measure({ parser.parse(data: line) }) { handler(ev) } }
        s.onExit = { [weak self, weak s] status, stderr in
            guard let self else { return }
            let lower = stderr.lowercased()
            if lower.contains("not permitted") || lower.contains("not_permitted") || lower.contains("full disk access")
                || lower.contains("not privileged") {
                self.lock.withLock { self.lastError = Failure.notPermitted(stderr.trimmingCharacters(in: .whitespacesAndNewlines)).description }
                s?.restartOnExit = false
            } else {
                self.lock.withLock { self.lastError = "eslogger exited \(status): \(stderr.suffix(300))" }
            }
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

import Foundation
import RampartShared

/// "Learn how risky it is safely": evidence gathered around a catch, a risk verdict, and the hook into the
/// existing quarantine sandbox flow (`IPCRequest.sandboxRun(id:confirmation:)` once the file is quarantined).
public struct DeceptionEvidence: Codable, Hashable, Sendable {
    public var catchID: UUID
    public var processTree: [ProcessInfoLite]       // the catcher first, then its ancestors
    public var signing: String                      // "Apple", "Developer ID (TEAM)", "unsigned / ad-hoc"
    public var filesTouched: [String]
    public var network: [String]                    // "host:port" or IPs the pid connected to
    public var otherDecoysTouched: Int
    public var verdict: DeceptionVerdict
    /// What the app offers: quarantine the binary, then "Study it in the sandbox".
    public var sandboxHook: SandboxHook
}

public struct SandboxHook: Codable, Hashable, Sendable {
    public var executablePath: String
    public var quarantineID: UUID?   // set once rampartd's remediation has vaulted the binary
    public var ready: Bool { quarantineID != nil }
}

public struct DeceptionVerdict: Codable, Hashable, Sendable {
    public enum Level: String, Codable, Sendable {
        case likelyBenign, suspicious, dangerous
        public var label: String { switch self { case .likelyBenign: return "Low risk"; case .suspicious: return "Suspicious"; case .dangerous: return "Dangerous" } }
    }
    public var level: Level
    public var score: Int
    public var reasons: [String]
    public var summary: String { reasons.prefix(3).joined(separator: "; ") }
}

/// Recent events, so evidence can be gathered after the fact. Bounded ring buffer.
public final class DeceptionEventLog: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [SecurityEvent] = []
    public let capacity: Int
    public init(capacity: Int = 5000) { self.capacity = max(100, capacity) }
    public func add(_ e: SecurityEvent) {
        lock.lock(); events.append(e); if events.count > capacity { events.removeFirst(events.count - capacity) }; lock.unlock()
    }
    public func events(pid: Int32, since: Date) -> [SecurityEvent] {
        lock.lock(); defer { lock.unlock() }
        return events.filter { $0.process?.pid == pid && $0.date >= since }
    }
}

public enum DeceptionStudy {
    /// `ancestors(pid)` returns parent chain (from RampartBehaviour's lineage tracker in the daemon).
    public static func gather(_ c: DeceptionCatch, process: ProcessInfoLite?, ancestors: [ProcessInfoLite],
                              log: DeceptionEventLog, registry: DecoyRegistry, window: TimeInterval = 600) -> DeceptionEvidence {
        let evs = log.events(pid: c.pid, since: c.date.addingTimeInterval(-window))
        var files: [String] = []; var net: [String] = []; var decoys = Set<String>()
        for e in evs {
            if e.kind == .networkConnect {
                let host = e.detail["remote"] ?? e.detail["host"] ?? e.path ?? "?"
                let port = e.detail["port"].map { ":" + $0 } ?? ""
                if net.count < 50 { net.append(SafeText.line(host + port, max: 120)) }
            } else if let p = e.path {
                if registry.record(at: p) != nil { decoys.insert(p) }
                else if files.count < 100, !files.contains(p) { files.append(SafeText.path(p)) }
            }
        }
        let proc = process ?? ProcessInfoLite(pid: c.pid, ppid: 0, path: c.processPath, signingID: c.signingID, teamID: c.teamID)
        let signing: String = proc.isPlatformBinary ? "Apple" : proc.teamID.map { "Developer ID (\($0))" } ?? (proc.signingID == nil ? "unsigned" : "ad-hoc / unknown signer")
        let v = verdict(c, signing: signing, process: proc, ancestors: ancestors, filesTouched: files, network: net, decoys: decoys.count)
        return DeceptionEvidence(catchID: c.id, processTree: [proc] + ancestors.prefix(20), signing: signing, filesTouched: files,
                                 network: net, otherDecoysTouched: decoys.count, verdict: v,
                                 sandboxHook: SandboxHook(executablePath: c.processPath, quarantineID: c.quarantineID))
    }

    static let credentialHints = ["Login Data", "Cookies", "keychain", ".ssh", ".aws", "Wallet", "Exodus", "Electrum", "Telegram", "Local State"]
    static let userWritable = ["/tmp/", "/private/tmp/", "/private/var/folders/", "/Users/Shared/", "/Downloads/", "/.Trash/"]

    public static func verdict(_ c: DeceptionCatch, signing: String, process: ProcessInfoLite, ancestors: [ProcessInfoLite],
                               filesTouched: [String], network: [String], decoys: Int) -> DeceptionVerdict {
        var s = 60; var r: [String] = ["touched a decoy no legitimate app opens"]
        if signing == "unsigned" || signing.hasPrefix("ad-hoc") { s += 15; r.append("not signed by a known developer") }
        if userWritable.contains(where: { process.path.contains($0) }) { s += 10; r.append("runs from a temporary or download folder") }
        let creds = filesTouched.filter { f in credentialHints.contains { f.localizedCaseInsensitiveContains($0) } }.count
        if creds > 0 { s += min(20, creds * 5); r.append("also read \(creds) real credential location\(creds == 1 ? "" : "s")") }
        if decoys > 1 { s += 10; r.append("went after \(decoys) decoys") }
        if !network.isEmpty { s += 10; r.append("made \(network.count) network connection\(network.count == 1 ? "" : "s")") }
        if c.access == .rename || c.destPath != nil { s += 10; r.append("tried to copy or move the decoy") }
        if ancestors.contains(where: { ["osascript", "curl", "bash", "sh", "zsh", "python3"].contains(($0.path as NSString).lastPathComponent) }) {
            s += 5; r.append("launched from a script or shell")
        }
        if signing == "Apple" { s -= 40; r.append("Apple-signed tool (could still be driven by a script)") }
        s = min(100, max(0, s))
        return DeceptionVerdict(level: s >= 80 ? .dangerous : s >= 50 ? .suspicious : .likelyBenign, score: s, reasons: r)
    }
}

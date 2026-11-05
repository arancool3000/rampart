import Foundation

/// Where a file came from: the `com.apple.quarantine` xattr and `kMDItemWhereFroms`.
public struct Provenance: Codable, Hashable, Sendable {
    public struct Quarantine: Codable, Hashable, Sendable {
        public var raw: String
        public var flags: UInt32
        public var timestamp: Date?
        public var agentName: String?
        public var eventID: String?        // UUID into QuarantineEventsV2
        public var isDownload: Bool { flags & 0x0001 != 0 }      // QTN_FLAG_DOWNLOAD
        public var isSandboxed: Bool { flags & 0x0002 != 0 }     // QTN_FLAG_SANDBOX
        public var isHard: Bool { flags & 0x0004 != 0 }          // QTN_FLAG_HARD
        public var userApproved: Bool { flags & 0x0040 != 0 }    // QTN_FLAG_USER_APPROVED (opened via Gatekeeper)
    }

    public var quarantine: Quarantine?
    public var whereFroms: [String]

    public var isQuarantined: Bool { quarantine != nil }
    /// Download origin, best effort: WhereFroms[0] (usually the file URL), else the agent name.
    public var origin: String? { whereFroms.first ?? quarantine?.agentName }
    /// Browser metadata says it was downloaded, but the quarantine flag is gone: someone ran `xattr -d`.
    public var quarantineLikelyStripped: Bool { quarantine == nil && !whereFroms.isEmpty }

    public init(quarantine: Quarantine? = nil, whereFroms: [String] = []) {
        self.quarantine = quarantine; self.whereFroms = whereFroms
    }

    public static func read(path: String) -> Provenance {
        var p = Provenance()
        if let d = xattr(path, "com.apple.quarantine"), let s = String(data: d, encoding: .utf8) {
            p.quarantine = parseQuarantine(s)
        }
        if let d = xattr(path, "com.apple.metadata:kMDItemWhereFroms") {
            p.whereFroms = parseWhereFroms(d)
        }
        return p
    }

    /// Parses `FLAGS;HEXTIME;AGENT;UUID` (fields after FLAGS are optional).
    public static func parseQuarantine(_ s: String) -> Quarantine? {
        let raw = s.trimmingCharacters(in: CharacterSet(charactersIn: "\0").union(.whitespacesAndNewlines))
        let f = raw.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        guard let first = f.first, let flags = UInt32(first, radix: 16) else { return nil }
        var q = Quarantine(raw: raw, flags: flags, timestamp: nil, agentName: nil, eventID: nil)
        if f.count > 1, let t = UInt64(f[1], radix: 16), t > 0 { q.timestamp = Date(timeIntervalSince1970: TimeInterval(t)) }
        if f.count > 2, !f[2].isEmpty { q.agentName = f[2] }
        if f.count > 3, !f[3].isEmpty { q.eventID = f[3] }
        return q
    }

    public static func parseWhereFroms(_ d: Data) -> [String] {
        guard let obj = try? PropertyListSerialization.propertyList(from: d, format: nil) else { return [] }
        if let a = obj as? [String] { return a.filter { !$0.isEmpty } }
        if let s = obj as? String { return [s] }
        return []
    }

    static func xattr(_ path: String, _ name: String) -> Data? {
        let n = getxattr(path, name, nil, 0, 0, 0)
        guard n > 0, n < 1 << 20 else { return nil }
        var buf = [UInt8](repeating: 0, count: n)
        let r = getxattr(path, name, &buf, n, 0, 0)
        guard r > 0 else { return nil }
        return Data(buf.prefix(r))
    }
}

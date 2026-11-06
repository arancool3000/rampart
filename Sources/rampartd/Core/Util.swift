import Foundation
import CryptoKit
import RampartShared

// Shared by rampartd and the rampart CLI (Sources/rampart/Core is a symlink to this folder).

enum Eicar {
    /// The EICAR test string, assembled at runtime from fragments so no source or binary file contains it whole.
    static var string: String {
        let parts = ["X5O!P%@AP[4\\PZX5", "4(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-", "FILE!$H+H*"]
        return parts.joined()
    }
    static var data: Data { Data(string.utf8) }

    /// True if the file content is the EICAR test file (prefix + at most trailing whitespace, total ≤ 128 bytes).
    static func matches(_ content: Data) -> Bool {
        let sig = data
        guard content.count >= sig.count, content.count <= 128, content.prefix(sig.count) == sig else { return false }
        return content.dropFirst(sig.count).allSatisfy { [0x20, 0x09, 0x0a, 0x0d, 0x1a].contains($0) }
    }
}

enum Util {
    /// Resident memory of this process in MB (task_info).
    static var residentMB: Double {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count) }
        }
        return kr == KERN_SUCCESS ? Double(info.resident_size) / 1_048_576 : 0
    }

    static func sha256(path: String, limit: UInt64 = .max) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256(); var total: UInt64 = 0
        while true {
            guard let chunk = try? h.read(upToCount: 1 << 20), !chunk.isEmpty else { break }
            hasher.update(data: chunk); total += UInt64(chunk.count)
            if total > limit { return nil }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func sha256(data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    /// Full Disk Access probe: TCC.db is only readable with FDA.
    static var hasFullDiskAccess: Bool {
        let probes = ["/Library/Application Support/com.apple.TCC/TCC.db",
                      NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"]
        for p in probes {
            let fd = open(p, O_RDONLY)
            if fd >= 0 { close(fd); return true }
        }
        return false
    }

    static var xprotectVersion: String? {
        let candidates = ["/var/protected/xprotect/XProtect.bundle/Contents/Info.plist",
                          "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"]
        var best: String?
        for c in candidates {
            guard let d = NSDictionary(contentsOfFile: c), let v = d["CFBundleShortVersionString"] as? String else { continue }
            if best == nil || v.compare(best!, options: .numeric) == .orderedDescending { best = v }
        }
        return best
    }

    /// Member of the local `admin` group (gid 80)?
    static func isAdmin(uid: uid_t) -> Bool {
        if uid == 0 { return true }
        guard let pw = getpwuid(uid) else { return false }
        var groups = [Int32](repeating: 0, count: 64); var n: Int32 = 64
        if getgrouplist(pw.pointee.pw_name, Int32(bitPattern: pw.pointee.pw_gid), &groups, &n) == -1 { return false }
        return groups.prefix(Int(n)).contains(80)
    }

    static func homeDirectories() -> [String] {
        if getuid() != 0 { return [NSHomeDirectory()] }
        let users = (try? FileManager.default.contentsOfDirectory(atPath: "/Users")) ?? []
        return users.filter { !$0.hasPrefix(".") && $0 != "Shared" && $0 != "Guest" }.map { "/Users/" + $0 }
    }

    static func ensureDir(_ url: URL, mode: Int = 0o700) {
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: mode])
    }

    /// Atomic JSON write with restricted permissions.
    static func writeJSON<T: Encodable>(_ value: T, to url: URL, mode: Int = 0o600) throws {
        let enc = JSONEncoder.rampart; enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try enc.encode(value)
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }

    /// Combined confidence per ARCHITECTURE.md: 100·(1 − Π(1 − s/100)).
    static func combinedConfidence(_ evidence: [Evidence]) -> Int {
        var p = 1.0
        for e in evidence { p *= 1 - Double(max(0, min(100, e.score))) / 100 }
        return Int((100 * (1 - p)).rounded())
    }

    static func severity(for confidence: Int) -> Severity {
        switch confidence {
        case 90...: return .critical
        case 75..<90: return .high
        case 60..<75: return .medium
        case 30..<60: return .low
        default: return .info
        }
    }
}

/// Minimal logger: os.Logger plus optional stderr mirroring and a log file.
final class DLog {
    static let shared = DLog()
    var verbose = false
    private var fileHandle: FileHandle?
    private let lock = NSLock()
    private let oslog = RLog.logger("daemon")
    private var problems: [String] = []
    /// Last warnings/errors (newest last), for the health report.
    var recentProblems: [String] { lock.lock(); defer { lock.unlock() }; return problems }

    func openFile(_ url: URL) {
        Util.ensureDir(url.deletingLastPathComponent(), mode: 0o755)
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o640])
        }
        // Simple rotation at 10 MB.
        if let size = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? UInt64, size > 10 << 20 {
            let old = url.appendingPathExtension("1")
            try? FileManager.default.removeItem(at: old)
            try? FileManager.default.moveItem(at: url, to: old)
            FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o640])
        }
        fileHandle = FileHandle(forWritingAtPath: url.path)
        _ = try? fileHandle?.seekToEnd()
    }

    func log(_ level: String, _ msg: String) {
        let line = "\(ISO8601DateFormatter().string(from: Date())) [\(level)] \(msg)\n"
        switch level {
        case "error": oslog.error("\(msg, privacy: .public)")
        case "warn": oslog.warning("\(msg, privacy: .public)")
        default: oslog.info("\(msg, privacy: .public)")
        }
        lock.lock(); defer { lock.unlock() }
        if level == "warn" || level == "error" {
            problems.append(line.trimmingCharacters(in: .newlines)); if problems.count > 20 { problems.removeFirst() }
        }
        if let fh = fileHandle { fh.write(Data(line.utf8)) }
        if verbose || level == "error" { FileHandle.standardError.write(Data(line.utf8)) }
    }
}

func logInfo(_ m: String) { DLog.shared.log("info", m) }
func logWarn(_ m: String) { DLog.shared.log("warn", m) }
func logError(_ m: String) { DLog.shared.log("error", m) }

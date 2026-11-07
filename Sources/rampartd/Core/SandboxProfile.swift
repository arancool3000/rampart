import Foundation
import RampartShared

// Pure, testable parts of the quarantine sandbox: report type, SBPL profile generator, log parser.
// Also compiled into rampart-selftest via the symlink Sources/rampart-selftest/SandboxProfile.swift.
// Keep this file free of daemon types.

/// Mirrored by the app (QuarantineManager.swift). Keep the field names in sync.
struct SandboxReport: Codable, Sendable {
    struct Violation: Codable, Hashable, Sendable {
        var process: String
        var pid: Int32
        var operation: String
        var target: String
    }
    var itemName: String
    var sha256: String
    var command: [String]
    var startedAt: Date
    var seconds: Double
    var exitStatus: Int32?
    var timedOut: Bool
    var killedProcesses: Int
    var stdout: String
    var stderr: String
    var outputTruncated: Bool
    var violations: [Violation]
    var touchedPaths: [String]
    var notes: [String]
    var profile: String
}

// MARK: - Pure, testable parts

enum SandboxProfile {
    static let timeLimit: TimeInterval = 60

    /// Folders the sandboxed item may never read (relative to the user's home).
    static let deniedHomeFolders = [
        "Library/Keychains", ".ssh", ".gnupg", ".aws", "Documents", "Desktop", "Downloads", "Pictures",
        "Library/Mobile Documents", "Library/Mail", "Library/Messages", "Library/Cookies", "Library/HTTPStorages",
        "Library/Safari", "Library/Containers/com.apple.Safari",
        "Library/Application Support/Google/Chrome", "Library/Application Support/Chromium",
        "Library/Application Support/BraveSoftware", "Library/Application Support/Microsoft Edge",
        "Library/Application Support/Firefox", "Library/Application Support/Arc",
        "Library/Application Support/Vivaldi", "Library/Application Support/com.operasoftware.Opera",
        "Library/Application Support/com.apple.TCC", "Library/Application Support/Rampart",
    ]
    static let deniedSystemFolders = ["/Library/Keychains", "/Library/Application Support/Rampart", "/private/var/db/dslocal"]

    /// Interpreter for scripts, by extension. nil = not a script we run.
    static func interpreter(forExtension ext: String) -> String? {
        switch ext.lowercased() {
        case "sh", "command": return "/bin/sh"
        case "bash": return "/bin/bash"
        case "zsh": return "/bin/zsh"
        case "py": return "/usr/bin/python3"
        case "pl": return "/usr/bin/perl"
        case "rb": return "/usr/bin/ruby"
        default: return nil
        }
    }

    /// Interpreter from a "#!" line, limited to the same known set.
    static func interpreter(forShebang line: String) -> String? {
        guard line.hasPrefix("#!") else { return nil }
        let parts = line.dropFirst(2).trimmingCharacters(in: .whitespaces).split(separator: " ").map(String.init)
        guard var prog = parts.first else { return nil }
        if prog == "/usr/bin/env", parts.count > 1 { prog = parts[1] }
        let name = (prog as NSString).lastPathComponent
        let map = ["sh": "/bin/sh", "bash": "/bin/bash", "zsh": "/bin/zsh", "python3": "/usr/bin/python3",
                   "python": "/usr/bin/python3", "perl": "/usr/bin/perl", "ruby": "/usr/bin/ruby"]
        return map[name]
    }

    /// SBPL string literal; nil for paths we refuse to embed.
    static func quote(_ s: String) -> String? {
        guard !s.isEmpty, !s.contains("\0"), !s.contains("\n"), !s.contains("\r") else { return nil }
        return "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    /// Strict profile: no network, writes only inside `workDir`, sensitive reads denied, exec only `allowedExec`,
    /// no fork. Later rules win in SBPL, so the denies come last.
    static func generate(workDir: String, allowedExec: [String], home: String) -> String? {
        guard workDir.hasPrefix("/"), workDir.count > 8, home.hasPrefix("/"), !allowedExec.isEmpty,
              let w = quote(workDir) else { return nil }
        var execs: [String] = []
        for e in allowedExec {
            guard e.hasPrefix("/"), let q = quote(e) else { return nil }
            execs.append("(literal \(q))")
        }
        // /bin/sh is a trampoline that re-execs the selected shell.
        if allowedExec.contains("/bin/sh") {
            for x in ["/bin/bash", "/bin/zsh", "/bin/dash"] where !allowedExec.contains(x) { execs.append("(literal \"\(x)\")") }
        }
        // The CLT python3 shim re-execs the real interpreter.
        if allowedExec.contains("/usr/bin/python3") {
            execs.append("(regex #\"^/Library/Developer/CommandLineTools/usr/bin/python3(\\.[0-9]+)?$\")")
            execs.append("(regex #\"^/Library/Developer/CommandLineTools/Library/Frameworks/Python3\\.framework/\")")
        }
        var denied: [String] = []
        for f in deniedHomeFolders {
            guard let q = quote((home as NSString).appendingPathComponent(f)) else { return nil }
            denied.append("(subpath \(q))")
        }
        for f in deniedSystemFolders { denied.append("(subpath \(quote(f)!))") }
        var p = """
        ;; \(Product.name) quarantine sandbox (best effort; sandbox-exec is deprecated by Apple and is not a VM)
        (version 1)
        (deny default)
        (allow process-exec \(execs.joined(separator: " ")))
        (allow signal (target self))
        (allow process-info* (target self))
        (allow sysctl-read)
        (allow file-read*)
        (allow file-map-executable)
        (allow file-read* file-write* (subpath \(w)))
        (allow file-write-data (literal "/dev/null") (literal "/dev/zero"))
        (allow mach-lookup (global-name "com.apple.system.logger") (global-name "com.apple.system.notification_center")
                           (global-name "com.apple.system.opendirectoryd.libinfo") (global-name "com.apple.logd"))
        (allow ipc-posix-shm-read-data (ipc-posix-name "apple.shm.notification_center"))
        (deny network*)
        (deny process-fork)
        (deny file-read* \(denied.joined(separator: "\n                 ")))

        """
        return p
    }

    /// Parses Sandbox violation lines ("Sandbox: name(123) deny(1) file-read-data /path") for the given pids.
    static func parseViolations(_ messages: [String], pids: Set<Int32>) -> [SandboxReport.Violation] {
        let re = try! NSRegularExpression(pattern: #"^(?:Sandbox: )?(.+?)\((\d+)\) deny\(\d+\) (\S+)(?: (.*))?$"#)
        var out: [SandboxReport.Violation] = []
        var seen = Set<SandboxReport.Violation>()
        for m in messages {
            let line = m.trimmingCharacters(in: .whitespacesAndNewlines)
            let ns = line as NSString
            guard let r = re.firstMatch(in: line, range: NSRange(location: 0, length: ns.length)),
                  let pid = Int32(ns.substring(with: r.range(at: 2))), pids.contains(pid) else { continue }
            let target = r.range(at: 4).location == NSNotFound ? "" : ns.substring(with: r.range(at: 4))
            let v = SandboxReport.Violation(process: ns.substring(with: r.range(at: 1)), pid: pid,
                                            operation: ns.substring(with: r.range(at: 3)), target: String(target.prefix(1024)))
            if seen.insert(v).inserted { out.append(v) }
            if out.count >= 2000 { break }
        }
        return out
    }

    /// Paths the item tried to touch (file operations only), de-duplicated in first-seen order.
    static func touchedPaths(_ v: [SandboxReport.Violation]) -> [String] {
        var seen = Set<String>(); var out: [String] = []
        for x in v where x.operation.hasPrefix("file-") && x.target.hasPrefix("/") {
            if seen.insert(x.target).inserted { out.append(x.target) }
        }
        return out
    }

    /// Typed confirmation rule: "RUN" for anything at alert >= 90 (or unknown), otherwise any explicit confirmation.
    static func confirmationOK(_ c: String, confidence: Int?) -> Bool {
        if (confidence ?? 100) >= 90 { return c == "RUN" }
        return c == "RUN" || c == "confirmed"
    }

    /// Safe single path component for the extracted copy.
    static func safeName(_ original: String) -> String {
        let base = (original as NSString).lastPathComponent
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._- "))
        var s = String(String.UnicodeScalarView(base.unicodeScalars.map { allowed.contains($0) ? $0 : "_" }))
        while s.hasPrefix(".") { s.removeFirst() }
        if s.isEmpty || s == ".." { s = "item" }
        return String(s.prefix(200))
    }
}


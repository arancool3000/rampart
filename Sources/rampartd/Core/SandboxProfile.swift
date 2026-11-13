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

    /// Real interpreter binary for a mapped interpreter. /usr/bin/python3 is an xcode-select shim that can run xcrun
    /// (writes caches, may offer to install tools), so it is resolved to the Command Line Tools binary or refused.
    static func resolvedInterpreter(_ interp: String, isExecutable: (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }) -> String? {
        if interp == "/usr/bin/python3" {
            let clt = "/Library/Developer/CommandLineTools/usr/bin/python3"
            return isExecutable(clt) ? clt : nil
        }
        return isExecutable(interp) ? interp : nil
    }

    /// Flags that stop interpreters loading code from outside the item: python -I (no user site-packages, no PYTHON*
    /// variables, script folder not on sys.path) and -B (no .pyc writes); zsh -f (no rc files); ruby without gems.
    static func interpreterArguments(_ interp: String) -> [String] {
        if interp.hasSuffix("/python3") || interp.contains("Python3.framework") { return ["-I", "-B"] }
        switch (interp as NSString).lastPathComponent {
        case "zsh": return ["-f"]
        case "bash": return ["--noprofile", "--norc"]
        case "ruby": return ["--disable-gems"]
        default: return []
        }
    }

    /// The only places the item may read file contents from (besides its own folder): the OS, the interpreters,
    /// time zone data and a few devices. Everything else, including every home folder, other users' temp
    /// folders, /usr/local and external volumes, is unreadable. Metadata (stat) stays allowed outside /Users and
    /// /Volumes because path resolution needs it.
    static let readableRoots = ["/System", "/usr/lib", "/usr/share", "/usr/libexec", "/usr/bin", "/bin", "/sbin",
                                "/Library/Developer/CommandLineTools", "/private/var/db/timezone"]
    static let readableLiterals = ["/", "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/private/etc/localtime",
                                   "/private/var/select/sh", "/private/var/select/developer_dir"]
    /// Always unreadable, even as metadata (later rules win in SBPL).
    static let unreadableRoots = ["/Users", "/Volumes", "/usr/local", "/private/var/root", "/Library/Keychains"]

    /// wms-o2: sysctl reads are an allow-list. A blanket `(allow sysctl-read)` let the item list every process on the Mac
    /// (kern.proc.all) and read the host name. These names are what libSystem, dyld, the shells, perl, ruby and python
    /// need (checked by running each under the profile).
    static let sysctlPrefixes = ["hw.", "kern.os", "sysctl.", "vm."]   // "sysctl." = name/format lookups (sysctl.oidfmt, sysctl.proc_*)
    static let sysctlNames = ["kern.version", "kern.boottime", "kern.argmax", "kern.secure_kernel", "kern.maxfilesperproc",
                              "kern.maxfiles", "kern.hv_vmm_present", "kern.usrstack64", "kern.ngroups", "kern.bootargs",
                              "kern.memorystatus_level", "kern.clockrate", "kern.saved_ids", "kern.posix1version"]
    static var sysctlRule: String {
        "(allow sysctl-read " + (sysctlPrefixes.map { "(sysctl-name-prefix \"\($0)\")" } + sysctlNames.map { "(sysctl-name \"\($0)\")" })
            .joined(separator: " ") + ")"
    }

    static let diskLimitBytes: UInt64 = 256 << 20
    static let diskLimitEntries = 20_000

    /// Strict profile (hx3 review): deny by default; no network, fork, mach-lookup, IOKit, IPC or file-write outside
    /// `workDir`; exec only `allowedExec`; file contents readable only from the OS roots above and `workDir`.
    /// Later rules win in SBPL, so the denies come last.
    static func generate(workDir: String, allowedExec: [String], home: String) -> String? {
        guard workDir.hasPrefix("/"), workDir.count > 8, home.hasPrefix("/"), !allowedExec.isEmpty,
              !workDir.contains("/../"), !workDir.hasSuffix("/.."), let w = quote(workDir) else { return nil }
        // The work folder must not sit inside a place the profile makes unreadable (it would also unlock it).
        for r in unreadableRoots + [home] where workDir == r || workDir.hasPrefix(r + "/") { return nil }
        var execs: [String] = []
        for e in allowedExec {
            guard e.hasPrefix("/"), let q = quote(e) else { return nil }
            execs.append("(literal \(q))")
        }
        // /bin/sh is a trampoline that re-execs the selected shell.
        if allowedExec.contains("/bin/sh") {
            for x in ["/bin/bash", "/bin/zsh", "/bin/dash"] where !allowedExec.contains(x) { execs.append("(literal \"\(x)\")") }
        }
        // The CLT python3 (or the shim) re-execs the framework interpreter.
        if allowedExec.contains(where: { $0 == "/usr/bin/python3" || $0.hasPrefix("/Library/Developer/CommandLineTools/") }) {
            execs.append("(regex #\"^/Library/Developer/CommandLineTools/usr/bin/python3(\\.[0-9]+)?$\")")
            execs.append("(regex #\"^/Library/Developer/CommandLineTools/Library/Frameworks/Python3\\.framework/\")")
        }
        if allowedExec.contains("/usr/bin/perl") { execs.append("(regex #\"^/usr/bin/perl5\\.[0-9]+$\")") }
        var denied: [String] = []
        for f in deniedHomeFolders {
            guard let q = quote((home as NSString).appendingPathComponent(f)) else { return nil }
            denied.append("(subpath \(q))")
        }
        for f in deniedSystemFolders { denied.append("(subpath \(quote(f)!))") }
        guard let hq = quote(home) else { return nil }
        let readable = (readableLiterals.map { "(literal \(quote($0)!))" } + readableRoots.map { "(subpath \(quote($0)!))" }
                        + ["(subpath \(w))"]).joined(separator: " ")
        let unreadable = (unreadableRoots.map { "(subpath \(quote($0)!))" } + ["(subpath \(hq))"]).joined(separator: " ")
        let p = """
        ;; \(Product.name) quarantine sandbox (best effort; sandbox-exec is deprecated by Apple and is not a VM)
        (version 1)
        (deny default)
        (allow process-exec \(execs.joined(separator: " ")))
        (allow signal (target self))
        (allow process-info* (target self))
        \(sysctlRule)
        (allow file-read*)
        (deny file-read-data file-read-xattr (require-not (require-any \(readable))))
        (allow file-map-executable (subpath "/System") (subpath "/usr/lib") (subpath "/Library/Developer/CommandLineTools") (subpath \(w)))
        (allow file-read* file-write* (subpath \(w)))
        (allow file-write-data (literal "/dev/null") (literal "/dev/zero"))
        (deny network*)
        (deny process-fork)
        (deny mach-lookup)
        (deny iokit-open)
        (deny file-write-flags file-write-owner file-link)
        (deny file-read* file-read-metadata \(unreadable))
        (deny file-read* \(denied.joined(separator: "\n                 ")))

        """
        return p
    }

    /// Removes symlinks under `root` that resolve outside it or nowhere (lstat walk, never following links), so
    /// nothing inside the item can lead to a path outside the sandbox folder. Returns the removed paths.
    @discardableResult
    static func removeEscapingLinks(under root: String) -> [String] {
        guard let rr = realpath(root, nil) else { return [] }
        let realRoot = String(cString: rr); free(rr)
        var removed: [String] = []
        var stack = [root]; var visited = 0
        while let dir = stack.popLast(), visited < 100_000 {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for n in names {
                visited += 1
                let path = (dir as NSString).appendingPathComponent(n)
                var st = stat()
                guard lstat(path, &st) == 0 else { continue }
                switch st.st_mode & S_IFMT {
                case S_IFLNK:
                    var ok = false
                    if let r = realpath(path, nil) {
                        let t = String(cString: r); free(r)
                        ok = t == realRoot || t.hasPrefix(realRoot + "/")
                    }
                    if !ok, unlink(path) == 0 { removed.append(path) }
                case S_IFDIR: stack.append(path)
                default: break
                }
            }
        }
        return removed
    }

    /// True once the files under `paths` add up to more than `diskLimitBytes` or `diskLimitEntries` entries.
    static func diskUsageExceeded(_ paths: [String], limitBytes: UInt64 = diskLimitBytes, limitEntries: Int = diskLimitEntries) -> Bool {
        var total: UInt64 = 0, entries = 0
        var stack = paths
        while let p = stack.popLast() {
            var st = stat()
            guard lstat(p, &st) == 0 else { continue }
            entries += 1
            total += UInt64(max(0, st.st_blocks)) * 512
            if total > limitBytes || entries > limitEntries { return true }
            if st.st_mode & S_IFMT == S_IFDIR, let names = try? FileManager.default.contentsOfDirectory(atPath: p) {
                stack += names.map { (p as NSString).appendingPathComponent($0) }
            }
        }
        return false
    }

    /// Item output shown in the app: strips terminal escapes, control characters and bidirectional overrides so it
    /// can't redraw the window text or reverse a file name. Keeps newlines and tabs.
    static func sanitizeOutput(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        var it = s.unicodeScalars.makeIterator()
        while let c = it.next() {
            if c == "\u{1B}" {   // ESC [ ... final byte, or ESC + one char
                if let n = it.next(), n == "[" { while let m = it.next(), !(0x40...0x7E).contains(m.value) {} }
                continue
            }
            switch c.value {
            case 0x0A, 0x09: out.append(c)
            case 0x00...0x1F, 0x7F...0x9F: continue
            case 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069, 0x061C: continue
            default: out.append(c)
            }
        }
        return String(out)
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
            let v = SandboxReport.Violation(process: sanitizeOutput(ns.substring(with: r.range(at: 1))), pid: pid,
                                            operation: ns.substring(with: r.range(at: 3)), target: sanitizeOutput(String(target.prefix(1024))))
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


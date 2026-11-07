import Foundation
import RampartShared
import RampartSigning
import RampartWeb

/// Persistent Protection Activity log: JSON lines in `<root>/activity.jsonl`. Kept for 90 days (bounded by count
/// and bytes so a flood can't grow it without limit). Every text field is cleaned and secret-redacted on the way in.
final class ActivityLog {
    static let retention: TimeInterval = 90 * 86_400
    let url: URL
    private let lock = NSLock()
    private var entries: [ActivityEntry] = []
    private let keep: Int
    private let maxBytes: Int
    private var bytes = 0

    init(url: URL, keep: Int = 50_000, maxBytes: Int = 48 << 20) {
        self.url = url; self.keep = keep; self.maxBytes = maxBytes
        if let d = SecureStore.read(url) {
            bytes = d.count
            let dec = JSONDecoder.rampart
            for line in d.split(separator: 0x0a) {
                if let e = try? dec.decode(ActivityEntry.self, from: Data(line)) { entries.append(e) }
            }
            let cutoff = Date().addingTimeInterval(-Self.retention)
            let before = entries.count
            entries.removeAll { $0.date < cutoff }
            if entries.count > keep { entries.removeFirst(entries.count - keep) }
            if entries.count != before { lock.lock(); rewriteLocked(); lock.unlock() }
        }
    }

    /// Cleans attacker-influenced text: no control, line-break or bidi characters, bounded, secrets redacted (hx10).
    static func sanitize(_ e: ActivityEntry) -> ActivityEntry {
        var e = e
        func c(_ s: String?, _ max: Int) -> String? { s.map { LogRedact.clean($0, max: max) } }
        e.title = LogRedact.clean(e.title, max: 200); e.detail = LogRedact.clean(e.detail, max: 2000)
        e.outcome = LogRedact.clean(e.outcome, max: 120)
        e.target = c(e.target, 600); e.rule = c(e.rule, 200); e.reason = c(e.reason, 1000); e.action = c(e.action, 600)
        e.sha256 = e.sha256.flatMap { $0.count == 64 && $0.allSatisfy(\.isHexDigit) ? $0.lowercased() : nil }
        e.refID = c(e.refID, 80)
        e.score = e.score.map { max(0, min(100, $0)) }
        if var p = e.process {
            p.name = c(p.name, 120); p.path = c(p.path, 600); p.signer = c(p.signer, 160); p.parentName = c(p.parentName, 120)
            e.process = p.isEmpty && p.signer == nil ? nil : p
        }
        if let f = e.facts {
            var out: [String: String] = [:]
            for (k, v) in f.prefix(16) { out[LogRedact.clean(k, max: 40)] = LogRedact.clean(v, max: 400) }
            e.facts = out
        }
        return e
    }

    func add(_ e: ActivityEntry) {
        let e = Self.sanitize(e)
        guard var line = try? JSONEncoder.rampart.encode(e) else { return }
        line.append(0x0a)
        lock.lock(); defer { lock.unlock() }
        entries.append(e)
        if entries.count > keep { entries.removeFirst(entries.count - keep) }
        bytes += line.count
        if bytes > maxBytes {
            let cutoff = Date().addingTimeInterval(-Self.retention)
            entries.removeAll { $0.date < cutoff }
            while bytes > maxBytes / 2 && entries.count > 1000 { entries.removeFirst(entries.count / 4); bytes = maxBytes / 2 }
            rewriteLocked(); return
        }
        // O_NOFOLLOW: never append through a planted symlink; new files are 0600 regardless of umask.
        let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var st = stat()
        if fstat(fd, &st) == 0, st.st_mode & 0o077 != 0 { _ = fchmod(fd, 0o600) }
        _ = line.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, $0.count) }
    }

    func add(_ kind: ActivityEntry.Kind, _ title: String, detail: String = "", outcome: String = "",
             severity: Severity = .info, detectionID: UUID? = nil, event: ActivityEvent? = nil, actor: ActivityActor? = nil,
             process: ActivityProcess? = nil, target: String? = nil, rule: String? = nil, reason: String? = nil,
             score: Int? = nil, action: String? = nil, count: Int? = nil, found: Int? = nil, sha256: String? = nil,
             refID: String? = nil, facts: [String: String]? = nil) {
        add(ActivityEntry(kind: kind, title: title, detail: detail, outcome: outcome, severity: severity, detectionID: detectionID,
                          event: event, actor: actor, process: process, target: target, rule: rule, reason: reason, score: score,
                          action: action, count: count, found: found, sha256: sha256, refID: refID, facts: facts))
    }

    /// Newest first. `limit <= 0` returns everything kept.
    func list(limit: Int) -> [ActivityEntry] {
        lock.lock(); defer { lock.unlock() }
        return Array(entries.suffix(max(0, min(limit <= 0 ? keep : limit, keep))).reversed())
    }

    private func rewriteLocked() {
        let enc = JSONEncoder.rampart
        var out = Data()
        for e in entries { if let l = try? enc.encode(e) { out.append(l); out.append(0x0a) } }
        try? SecureStore.write(out, to: url)
        bytes = out.count
    }
}

/// Builds the structured facts for activity entries from detections and live processes.
enum ActivityFacts {
    /// Name, path, signer and parent of a running process (best effort: it may already have exited).
    static func process(pid: Int32?, fallbackPath: String? = nil) -> ActivityProcess? {
        guard let pid, pid > 0 else { return nil }
        var p = ActivityProcess(pid: pid)
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        if proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 { p.path = String(cString: buf) }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.stride)
        if proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size {
            let ppid = Int32(info.pbi_ppid)
            if ppid > 0 {
                p.parentPID = ppid
                var pb = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
                if proc_pidpath(ppid, &pb, UInt32(pb.count)) > 0 { p.parentName = (String(cString: pb) as NSString).lastPathComponent }
            }
            if p.path == nil {
                let name = withUnsafeBytes(of: info.pbi_name) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
                if !name.isEmpty { p.name = name }
            }
        }
        if p.path == nil, let f = fallbackPath, f.hasPrefix("/") { p.path = f }
        if let path = p.path {
            p.name = p.name ?? Self.displayName(path)
            p.signer = signer(path)
        }
        return p
    }

    /// "Safari" for /Applications/Safari.app/Contents/MacOS/Safari, else the file name.
    static func displayName(_ path: String) -> String {
        if let r = path.range(of: ".app/") { return ((String(path[..<r.lowerBound]) + ".app") as NSString).lastPathComponent.replacingOccurrences(of: ".app", with: "") }
        return (path as NSString).lastPathComponent
    }

    static func signer(_ path: String) -> String? {
        let info = SigningInspector.inspectCached(path: path).info
        switch info.status {
        case .apple: return "Apple"
        case .appStore: return "Mac App Store" + (info.teamID.map { " (\($0))" } ?? "")
        case .developerID: return "Identified developer" + (info.teamID.map { " (Team ID \($0))" } ?? "")
        case .adHoc: return "Not identified (ad-hoc signature)"
        case .unsigned: return "Not signed"
        case .invalid: return "Broken signature"
        case .revoked: return "Revoked by Apple"
        case .unknown: return nil
        }
    }

    /// The decision type of a detection (tamper, remote access, real-time block, file detection...).
    static func event(for d: Detection) -> ActivityEvent {
        if d.name.hasPrefix("Tampering with ") || d.name.hasPrefix("Self-defence:") { return .tamper }
        if d.name.hasPrefix("Unapproved remote access") || d.name.contains("remote-access port") || d.name.contains("accepting outside connections") { return .remoteAccessAttempt }
        return .detection
    }

    static func tamperKind(_ d: Detection) -> String? {
        for prefix in ["Tampering with \(Product.name): ", "Self-defence: "] where d.name.hasPrefix(prefix) { return String(d.name.dropFirst(prefix.count)) }
        return nil
    }

    /// Brand imitated and the top local signal for a URL the browser extension blocked or warned about
    /// (offline: URLAnalyzer's structural checks only, no network).
    static func urlContext(_ url: String) -> (brand: String?, rule: String?, reason: String?) {
        let r = URLAnalyzer().analyze(url)
        let top = r.signals.filter { $0.score > 0 }.max { $0.score < $1.score }
        return (r.brandMatch, top?.id, top.map { "\($0.title). \($0.explanation)" })
    }

    /// The strongest piece of evidence: what fired and why.
    static func ruleAndReason(_ d: Detection) -> (rule: String?, reason: String?) {
        let top = d.evidence.filter { $0.score > 0 }.max { $0.score < $1.score } ?? d.evidence.first
        guard let top else { return (nil, nil) }
        let reason = top.detail.isEmpty ? top.title : (top.title.isEmpty ? top.detail : "\(top.title): \(top.detail)")
        return (top.title.isEmpty ? top.source.rawValue : top.title, reason)
    }
}

/// Allow rules (file hash / developer Team ID / signing ID / folder), persisted in `<root>/allowrules.json`.
final class AllowRuleStore {
    let url: URL
    private let lock = NSLock()
    private var rules: [AllowRuleSpec] = []
    init(url: URL) {
        self.url = url
        rules = SecureStore.read(url).flatMap { try? JSONDecoder.rampart.decode([AllowRuleSpec].self, from: $0) } ?? []
        for i in rules.indices where rules[i].scope == .folder { rules[i].value = Util.realPath(rules[i].value) }
    }
    /// Active (unexpired) rules.
    func all() -> [AllowRuleSpec] {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        return rules.filter { $0.expires.map { $0 > now } ?? true }
    }
    @discardableResult
    func add(_ r: AllowRuleSpec) -> AllowRuleSpec {
        lock.lock(); defer { lock.unlock() }
        var r = r
        if r.scope == .fileHash { r.value = r.value.lowercased() }
        if r.scope == .folder { r.value = Util.realPath((r.value as NSString).expandingTildeInPath) }
        if let i = rules.firstIndex(where: { $0.scope == r.scope && $0.value == r.value }) { rules[i] = r } else { rules.append(r) }
        save(); return r
    }
    func remove(_ id: UUID) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let n = rules.count; rules.removeAll { $0.id == id }; save()
        return rules.count != n
    }
    private func save() { try? SecureStore.writeJSON(rules, to: url) }

    static func validate(_ r: AllowRuleSpec) -> String? {
        switch r.scope {
        case .fileHash: return (r.value.count == 64 && r.value.allSatisfy(\.isHexDigit)) ? nil : "a file-hash rule needs a SHA-256"
        case .developer: return (r.value.count == 10 && r.value.allSatisfy { $0.isLetter || $0.isNumber }) ? nil : "a developer rule needs a 10-character Team ID"
        case .signingID: return r.value.isEmpty || r.value.contains(" ") ? "a signing-ID rule needs an identifier like com.example.app" : nil
        case .folder:
            let p = (r.value as NSString).expandingTildeInPath
            if !p.hasPrefix("/") { return "a folder rule needs an absolute path" }
            if PathScope.isTooBroad(p) { return "refusing to allow-list a whole top-level folder (\(PathScope.canonical(p)))" }
            return nil
        }
    }
}

/// Path breadth checks for allow rules and exclusions (red-team fix: `/users` and `/SYSTEM` slipped past a
/// case-sensitive list on case-insensitive APFS, and `/tmp`, `/Volumes`, `~/Downloads` were accepted).
enum PathScope {
    /// realpath (resolves symlinks and `..`) when the path exists, else the standardized path; lowercased for comparison.
    static func canonical(_ path: String) -> String {
        let std = ((path as NSString).expandingTildeInPath as NSString).standardizingPath
        var out = std
        if let r = realpath(std, nil) { out = String(cString: r); free(r) }
        while out.count > 1 && out.hasSuffix("/") { out.removeLast() }
        return out
    }
    static func key(_ path: String) -> String {
        var k = canonical(path).lowercased()
        for alias in ["/private/var", "/private/tmp", "/private/etc"] where k == alias || k.hasPrefix(alias + "/") { k = String(k.dropFirst("/private".count)) }
        return k
    }
    static let topLevel: Set<String> = ["/", "/users", "/applications", "/library", "/system", "/private", "/usr", "/bin", "/sbin",
                                        "/opt", "/etc", "/var", "/tmp", "/volumes", "/cores", "/users/shared", "/var/tmp", "/var/folders",
                                        "/library/launchagents", "/library/launchdaemons", "/library/application support", "/applications/utilities"]
    static let homeSensitive = ["", "downloads", "desktop", "documents", "library", "applications", "library/launchagents",
                                "library/application support", "library/caches", ".trash", "movies", "music", "pictures", "public"]

    /// True for the whole disk, system and top-level folders, any home folder and its main subfolders.
    static func isTooBroad(_ path: String) -> Bool {
        let k = key(path)
        if topLevel.contains(k) { return true }
        let parts = k.split(separator: "/").map(String.init)
        if parts.count >= 2, parts[0] == "users" {   // /Users/<name>[/sub...]
            let rest = parts.dropFirst(2).joined(separator: "/")
            if homeSensitive.contains(rest) { return true }
        }
        if parts.count == 2, parts[0] == "volumes" { return true }   // a whole external drive
        return false
    }

    /// True if `path` is strictly inside the user's private temporary folder (/var/folders/<a>/<b>/T, owned by
    /// `uid`, mode 0700): that folder is as private to the user as their home.
    static func isInsidePrivateTemp(_ path: String, uid: uid_t) -> Bool {
        let parts = canonical(path).split(separator: "/").map(String.init)
        // private, var, folders, a, b, T, <something>...
        guard parts.count >= 7, parts[0] == "private", parts[1] == "var", parts[2] == "folders", parts[5] == "T" else { return false }
        let t = "/" + parts[0...5].joined(separator: "/")
        var st = stat()
        return lstat(t, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR && st.st_uid == uid && (st.st_mode & 0o077) == 0
    }

    /// True if `path` is a single file, or one folder owned by `uid` strictly inside that user's home and not one of
    /// its main folders. Anything broader needs an admin-authenticated session.
    static func isNarrowUserScope(_ path: String, uid: uid_t) -> Bool {
        guard let pw = getpwuid(uid), let home = Optional(String(cString: pw.pointee.pw_dir)) else { return false }
        let real = canonical(path)
        var st = stat()
        if lstat(real, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG { return !isTooBroad(real) }
        let hk = key(home), k = key(real)
        guard !isTooBroad(real) else { return false }
        guard k.hasPrefix(hk + "/") || isInsidePrivateTemp(real, uid: uid) else { return false }
        if lstat(real, &st) == 0 { return st.st_uid == uid }
        return true   // not created yet, inside the user's own home
    }
}

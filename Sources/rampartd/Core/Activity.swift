import Foundation
import RampartShared

/// Persistent Protection Activity log: JSON lines in `<root>/activity.jsonl`, capped.
final class ActivityLog {
    let url: URL
    private let lock = NSLock()
    private var entries: [ActivityEntry] = []
    private let keep: Int
    private let maxBytes: Int
    private var bytes = 0

    init(url: URL, keep: Int = 2000, maxBytes: Int = 2 << 20) {
        self.url = url; self.keep = keep; self.maxBytes = maxBytes
        if let d = try? Data(contentsOf: url) {
            bytes = d.count
            let dec = JSONDecoder.rampart
            for line in d.split(separator: 0x0a) {
                if let e = try? dec.decode(ActivityEntry.self, from: Data(line)) { entries.append(e) }
            }
            if entries.count > keep { entries.removeFirst(entries.count - keep) }
        }
    }

    func add(_ e: ActivityEntry) {
        guard var line = try? JSONEncoder.rampart.encode(e) else { return }
        line.append(0x0a)
        lock.lock(); defer { lock.unlock() }
        entries.append(e)
        if entries.count > keep { entries.removeFirst(entries.count - keep) }
        bytes += line.count
        if bytes > maxBytes { rewriteLocked(); return }
        if let fh = FileHandle(forWritingAtPath: url.path) {
            defer { try? fh.close() }
            _ = try? fh.seekToEnd(); fh.write(line)
        } else {
            FileManager.default.createFile(atPath: url.path, contents: line, attributes: [.posixPermissions: 0o600])
        }
    }

    func add(_ kind: ActivityEntry.Kind, _ title: String, detail: String = "", outcome: String = "",
             severity: Severity = .info, detectionID: UUID? = nil) {
        add(ActivityEntry(kind: kind, title: title, detail: detail, outcome: outcome, severity: severity, detectionID: detectionID))
    }

    /// Newest first.
    func list(limit: Int) -> [ActivityEntry] {
        lock.lock(); defer { lock.unlock() }
        return Array(entries.suffix(max(0, min(limit <= 0 ? keep : limit, keep))).reversed())
    }

    private func rewriteLocked() {
        let enc = JSONEncoder.rampart
        var out = Data()
        for e in entries { if let l = try? enc.encode(e) { out.append(l); out.append(0x0a) } }
        try? out.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        bytes = out.count
    }
}

/// Allow rules (file hash / developer Team ID / signing ID / folder), persisted in `<root>/allowrules.json`.
final class AllowRuleStore {
    let url: URL
    private let lock = NSLock()
    private var rules: [AllowRuleSpec] = []
    init(url: URL) {
        self.url = url
        rules = (try? Data(contentsOf: url)).flatMap { try? JSONDecoder.rampart.decode([AllowRuleSpec].self, from: $0) } ?? []
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
    private func save() { try? Util.writeJSON(rules, to: url) }

    static func validate(_ r: AllowRuleSpec) -> String? {
        switch r.scope {
        case .fileHash: return (r.value.count == 64 && r.value.allSatisfy(\.isHexDigit)) ? nil : "a file-hash rule needs a SHA-256"
        case .developer: return (r.value.count == 10 && r.value.allSatisfy { $0.isLetter || $0.isNumber }) ? nil : "a developer rule needs a 10-character Team ID"
        case .signingID: return r.value.isEmpty || r.value.contains(" ") ? "a signing-ID rule needs an identifier like com.example.app" : nil
        case .folder:
            let p = (r.value as NSString).expandingTildeInPath
            if !p.hasPrefix("/") { return "a folder rule needs an absolute path" }
            let std = (p as NSString).standardizingPath
            if ["/", "/Users", "/Applications", "/Library", "/System", "/private", "/usr", NSHomeDirectory()].contains(std) {
                return "refusing to allow-list a whole top-level folder (\(std))"
            }
            return nil
        }
    }
}

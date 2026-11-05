import Foundation
import RampartShared

// Built-in fallbacks so rampartd/rampart work before (or without) the library modules.

struct BuiltinEicarDetector: FileDetector {
    var name: String { "builtin-eicar" }
    func inspect(_ facts: FileFacts) -> [Evidence] {
        guard facts.size <= 128, let data = FileManager.default.contents(atPath: facts.path), Eicar.matches(data) else { return [] }
        return [Evidence(source: .hash, title: "EICAR test file",
                         detail: "Matches the industry-standard EICAR anti-malware test string. Harmless by design.", score: 100)]
    }
}

/// File walker + detector pipeline. Used directly when RampartEngine's coordinator is unavailable,
/// and also as the generic wrapper when only FileDetectors are available.
final class BuiltinScanner: ScanService {
    let runtime: Runtime
    var detectors: [FileDetector]
    /// Optional enrichment hook (signing info, kind sniffing) supplied by modules.
    var enrich: ((inout FileFacts) -> Void)?
    var engineNames: [String] { detectors.map(\.name) }
    var signatureVersion: String { "builtin-1" }

    init(runtime: Runtime, detectors: [FileDetector]) { self.runtime = runtime; self.detectors = detectors }

    func enumerate(_ paths: [String], cancelled: () -> Bool, each: (String) -> Void) {
        let fm = FileManager.default
        let excl = runtime.exclusions
        let vault = runtime.quarantineDir.path
        func under(_ p: String, _ prefix: String) -> Bool { p == prefix || p.hasPrefix(prefix.hasSuffix("/") ? prefix : prefix + "/") }
        for root in paths {
            var isDir: ObjCBool = false
            let root = (root as NSString).standardizingPath
            guard fm.fileExists(atPath: root, isDirectory: &isDir), !under(root, vault) else { continue }
            if !isDir.boolValue { each(root); continue }
            // Exclusions that contain the explicitly requested root don't apply inside it (except the vault).
            let active = excl.filter { !under(root, $0) } + [vault]
            func excluded(_ p: String) -> Bool { active.contains { under(p, $0) } }
            let url = URL(fileURLWithPath: root)
            guard let en = fm.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey],
                                         options: [], errorHandler: { _, _ in true }) else { continue }
            for case let u as URL in en {
                if cancelled() { return }
                let p = u.path
                if excluded(p) { en.skipDescendants(); continue }
                let v = try? u.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                if v?.isSymbolicLink == true { continue }
                if v?.isRegularFile == true { each(p) }
            }
        }
    }

    func facts(for path: String) -> FileFacts? {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else { return nil }
        let size = (attrs[.size] as? UInt64) ?? 0
        if size > UInt64(runtime.config.maxFileSizeMB) << 20 { return nil }
        let perms = (attrs[.posixPermissions] as? Int) ?? 0
        var f = FileFacts(path: path, size: size, kind: .other, isExecutable: perms & 0o111 != 0)
        enrich?(&f)
        return f
    }

    func evaluate(_ path: String) -> Detection? {
        guard var f = facts(for: path) else { return nil }
        var ev: [Evidence] = []
        for d in detectors { ev += d.inspect(f) }
        guard !ev.isEmpty else { return nil }
        if f.sha256 == nil { f.sha256 = Util.sha256(path: path) }
        if let h = f.sha256, runtime.config.allowlist.contains(h) { return nil }
        return Self.makeDetection(path: path, sha256: f.sha256, evidence: ev)
    }

    static func makeDetection(path: String?, sha256: String?, evidence: [Evidence], pid: Int32? = nil) -> Detection? {
        let conf = Util.combinedConfidence(evidence)
        guard conf >= 30 else { return nil }
        let top = evidence.max { $0.score < $1.score }!
        let isTest = evidence.contains { $0.title.localizedCaseInsensitiveContains("EICAR") }
        let name = isTest ? "EICAR-Test-File" : top.title
        let category: ThreatCategory = isTest ? .test : (top.source == .behaviour ? .suspicious : (conf >= 90 ? .malware : .suspicious))
        return Detection(path: path, pid: pid, sha256: sha256, name: name, category: category,
                         severity: isTest ? .high : Util.severity(for: conf), confidence: conf, evidence: evidence)
    }

    func scan(paths: [String], progress: @escaping ScanProgress, cancelled: @escaping () -> Bool) -> ScanOutcome {
        let start = Date()
        var files: [String] = []
        enumerate(paths, cancelled: cancelled) { files.append($0) }
        let lock = NSLock(); var found: [Detection] = []; var done = 0
        let chunk = 64
        let chunks = stride(from: 0, to: files.count, by: chunk).map { Array(files[$0..<min($0 + chunk, files.count)]) }
        DispatchQueue.concurrentPerform(iterations: chunks.count) { i in
            for p in chunks[i] {
                if cancelled() { return }
                let d = evaluate(p)
                lock.lock(); done += 1; if let d { found.append(d) }; let n = done; lock.unlock()
                if n % 200 == 0 { progress(n, files.count, p) }
            }
        }
        return ScanOutcome(scanned: done, detections: found, seconds: Date().timeIntervalSince(start))
    }

    func scanFile(_ path: String) -> Detection? { evaluate(path) }
}

/// Simple vault used until RampartRemediation's QuarantineVault is available:
/// moves the file into `<root>/Quarantine/<id>.bin`, strips permissions, records metadata.
final class BuiltinQuarantine: QuarantineService {
    let dir: URL
    private let lock = NSLock()
    private var index: URL { dir.appendingPathComponent("index.json") }
    init(dir: URL) { self.dir = dir; Util.ensureDir(dir) }

    private func load() -> [QuarantineRecord] {
        (try? Data(contentsOf: index)).flatMap { try? JSONDecoder.rampart.decode([QuarantineRecord].self, from: $0) } ?? []
    }
    private func save(_ r: [QuarantineRecord]) throws { try Util.writeJSON(r, to: index) }

    func list() -> [QuarantineRecord] { lock.lock(); defer { lock.unlock() }; return load() }

    func quarantine(path: String, detection: Detection) throws -> QuarantineRecord {
        lock.lock(); defer { lock.unlock() }
        let fm = FileManager.default
        let attrs = try fm.attributesOfItem(atPath: path)
        guard (attrs[.type] as? FileAttributeType) == .typeRegular else { throw ServiceError.failed("only regular files can be quarantined") }
        let sha = Util.sha256(path: path) ?? detection.sha256 ?? ""
        let rec = QuarantineRecord(originalPath: path, sha256: sha, size: (attrs[.size] as? UInt64) ?? 0,
                                   detectionName: detection.name,
                                   ownerUID: UInt32((attrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? getuid()),
                                   mode: UInt16((attrs[.posixPermissions] as? Int) ?? 0o644))
        let dest = dir.appendingPathComponent(rec.id.uuidString + ".bin")
        do { try fm.moveItem(atPath: path, toPath: dest.path) }
        catch {
            // Cross-volume: copy then remove.
            try fm.copyItem(atPath: path, toPath: dest.path)
            try fm.removeItem(atPath: path)
        }
        try? fm.setAttributes([.posixPermissions: 0o400], ofItemAtPath: dest.path)
        var all = load(); all.append(rec); try save(all)
        return rec
    }

    func restore(id: UUID) throws -> String {
        lock.lock(); defer { lock.unlock() }
        var all = load()
        guard let i = all.firstIndex(where: { $0.id == id }) else { throw ServiceError.notFound(id.uuidString) }
        let rec = all[i]
        let src = dir.appendingPathComponent(id.uuidString + ".bin")
        let fm = FileManager.default
        var dest = rec.originalPath
        if fm.fileExists(atPath: dest) { dest += ".restored-\(Int(Date().timeIntervalSince1970))" }
        try? fm.createDirectory(atPath: (dest as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try fm.moveItem(atPath: src.path, toPath: dest)
        try? fm.setAttributes([.posixPermissions: Int(rec.mode)], ofItemAtPath: dest)
        if getuid() == 0 { _ = chown(dest, rec.ownerUID, gid_t(UInt32.max)) }
        all.remove(at: i); try save(all)
        return dest
    }

    func delete(id: UUID) throws {
        lock.lock(); defer { lock.unlock() }
        var all = load()
        guard let i = all.firstIndex(where: { $0.id == id }) else { throw ServiceError.notFound(id.uuidString) }
        try? FileManager.default.removeItem(at: dir.appendingPathComponent(id.uuidString + ".bin"))
        all.remove(at: i); try save(all)
    }

    func purgeExpired() {
        let cutoff = Date().addingTimeInterval(-30 * 86400)
        for r in list() where r.date < cutoff { try? delete(id: r.id) }
    }
}

/// Minimal persistence enumeration (launchd plists) until RampartBehaviour's PersistenceScanner is wired.
final class BuiltinPersistence: PersistenceService {
    func scan() -> (items: [PersistenceItem], findings: [Detection]) { (items(), []) }
    func items() -> [PersistenceItem] {
        var dirs: [(String, PersistenceItem.Kind)] = [("/Library/LaunchAgents", .launchAgent), ("/Library/LaunchDaemons", .launchDaemon)]
        for h in Util.homeDirectories() { dirs.append((h + "/Library/LaunchAgents", .launchAgent)) }
        var out: [PersistenceItem] = []
        for (dir, kind) in dirs {
            for f in (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [] where f.hasSuffix(".plist") {
                let p = dir + "/" + f
                let d = NSDictionary(contentsOfFile: p)
                let label = (d?["Label"] as? String) ?? f
                let target = (d?["Program"] as? String) ?? (d?["ProgramArguments"] as? [String])?.first
                out.append(PersistenceItem(kind: kind, label: label, location: p, target: target))
            }
        }
        return out
    }
}

import Foundation
import RampartShared
import RampartEngine

/// Records which files reached a detector of a given name (used to prove YARA gating).
private final class ProbeDetector: FileDetector, @unchecked Sendable {
    let name: String
    private let lock = NSLock()
    private var seen: [String] = []
    let sleepFor: String?
    init(name: String, sleepFor: String? = nil) { self.name = name; self.sleepFor = sleepFor }
    func inspect(_ facts: FileFacts) -> [Evidence] {
        lock.lock(); seen.append(facts.path); lock.unlock()
        if let s = sleepFor, facts.path.hasSuffix(s) { Thread.sleep(forTimeInterval: 3) }   // "slow read" fixture
        return []
    }
    var paths: Set<String> { lock.lock(); defer { lock.unlock() }; return Set(seen) }
}

/// Sleeps on every "*.stuck.sh" file and records how many such checks were running at once.
private final class StuckDetector: FileDetector, @unchecked Sendable {
    let name = "stuck"
    private let lock = NSLock()
    private var running = 0
    private(set) var peak = 0
    func inspect(_ facts: FileFacts) -> [Evidence] {
        guard facts.path.hasSuffix(".stuck.sh") else { return [] }
        lock.lock(); running += 1; peak = max(peak, running); lock.unlock()
        Thread.sleep(forTimeInterval: 1.5)
        lock.lock(); running -= 1; lock.unlock()
        return []
    }
    var peakRunning: Int { lock.lock(); defer { lock.unlock() }; return peak }
}

// Scan performance: smart triage, low-risk trees, light cache rows, per-file deadline.
extension SelfTest {
    static func scanPerfChecks() {
        let fm = FileManager.default
        let work = SelfTest.fixtureTempDir + "com.rampart.test.scanperf-\(getpid())"
        try? fm.removeItem(atPath: work)
        defer { try? fm.removeItem(atPath: work) }
        let nm = work + "/proj/node_modules/com.rampart.test.pkg"
        try? fm.createDirectory(atPath: nm, withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: work + "/src", withIntermediateDirectories: true)
        let eicar = Data(EICAR.bytes)

        // Fixtures: things that must still be caught...
        let eicarTxt = work + "/src/com.rampart.test.eicar.txt"
        fm.createFile(atPath: eicarTxt, contents: eicar)
        let script = work + "/src/com.rampart.test.dropper"          // no extension, no exec bit, shebang only
        fm.createFile(atPath: script, contents: Data("#!/bin/sh\necho com.rampart.test \(UUID())\n".utf8))
        let nmBin = nm + "/com.rampart.test.prebuilt"                 // Mach-O magic, no exec bit, inside node_modules
        var macho = Data([0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01])
        macho.append(Data("com.rampart.test inert body \(UUID())".utf8))
        fm.createFile(atPath: nmBin, contents: macho)
        let nmExec = nm + "/com.rampart.test.tool"                    // exec bit, plain bytes, inside node_modules
        fm.createFile(atPath: nmExec, contents: Data("com.rampart.test exec \(UUID())".utf8), attributes: [.posixPermissions: 0o755])
        let nmEicar = nm + "/com.rampart.test.eicar.js"
        fm.createFile(atPath: nmEicar, contents: eicar)
        // ...and inert content that should take the cheap path.
        let header = work + "/src/com.rampart.test.header.h"
        fm.createFile(atPath: header, contents: Data(repeating: 0x41, count: 300 << 10))   // 300 KB: above the light hash limit
        let nmHeader = nm + "/com.rampart.test.index.d.ts.h"
        fm.createFile(atPath: nmHeader, contents: Data("int x;\n".utf8))
        let png = work + "/src/com.rampart.test.image.png"
        fm.createFile(atPath: png, contents: Data([0x89, 0x50, 0x4E, 0x47]) + Data(repeating: 1, count: 2048))
        let notes = work + "/src/com.rampart.test.notes.txt"
        fm.createFile(atPath: notes, contents: Data("plain notes \(UUID())".utf8))
        // FIFO in the tree: must never block a worker.
        let fifo = work + "/src/com.rampart.test.fifo"
        _ = mkfifo(fifo, 0o644)

        func sha(_ p: String) -> String { (try? FileHasher.sha256(path: p))?.hex ?? "" }
        guard let db = try? HashDatabase.inMemory() else { check(false, "scanperf: open db"); return }
        _ = try? db.addKnownBad([script, nmBin, nmExec, header].map { KnownBadHash(sha256: sha($0), name: "RampartTest", source: "test") })
        let yara = ProbeDetector(name: "yara")
        let coord = ScanCoordinator(database: db, extraDetectors: [yara])

        let t0 = Date()
        let r = coord.scan(paths: [work])
        let secs = Date().timeIntervalSince(t0)
        let hits = Set(r.detections.compactMap(\.path))
        check(secs < 15, "scanperf: scan with a FIFO in the tree completes (\(String(format: "%.2f", secs)) s)")
        check(hits.contains(eicarTxt), "scanperf: EICAR in a .txt is detected under triage")
        check(hits.contains(script), "scanperf: extensionless shebang script is fully scanned (hash hit)")
        check(hits.contains(nmBin), "scanperf: Mach-O without exec bit inside node_modules is detected")
        check(hits.contains(nmExec), "scanperf: exec-bit file inside node_modules is detected")
        check(hits.contains(nmEicar), "scanperf: EICAR .js inside node_modules is detected")
        check(hits.contains(header), "scanperf: known-bad 300 KB inert header is detected in a walk (every file is hashed)")
        let saw = yara.paths
        check(saw.contains(script) && saw.contains(nmBin) && saw.contains(nmExec), "scanperf: YARA runs on payload-capable files")
        check(!saw.contains(header) && !saw.contains(nmHeader) && !saw.contains(png), "scanperf: YARA skipped for headers/media")
        check(saw.contains(notes), "scanperf: small unknown text still gets YARA (XProtect script rules)")
        check(r.triaged >= 4, "scanperf: inert files took the cheap path (\(r.triaged))")

        // Hit-rate impact: the same corpus with triage off finds a superset; the only difference is the inert header.
        var full = ScanOptions(); full.triage = false; full.useCache = false
        let rf = coord.scan(paths: [work], options: full)
        let fullHits = Set(rf.detections.compactMap(\.path))
        check(hits == fullHits,
              "scanperf: triage loses no hash-detectable fixture (\(hits.count)/\(fullHits.count) hits)")
        print("scanperf: hit rate triage \(hits.count)/\(fullHits.count) fixtures; cheap path \(r.triaged)/\(r.scanned) files")

        // Light cache rows never satisfy real-time / explicit scans; the explicit path still hashes and flags.
        check(coord.scanFile(at: header).detection != nil, "scanperf: explicit scanFile ignores light cache row and flags the header")
        let r2 = coord.scan(paths: [work])
        check(r2.cacheHits >= r.scanned - r.detections.count - 1, "scanperf: rescan short-circuits via cache (\(r2.cacheHits) hits)")
        check(Set(r2.detections.compactMap(\.path)) == hits, "scanperf: rescan re-reports the same detections")
        // Exec bit added later -> ctime changes -> full path on next walk.
        let inert2 = work + "/src/com.rampart.test.later.h"
        fm.createFile(atPath: inert2, contents: Data("int later_\(getpid());\n".utf8))
        _ = coord.scan(paths: [work])
        chmod(inert2, 0o755)
        _ = coord.scan(paths: [work])
        check(yara.paths.contains(inert2), "scanperf: file that gains an exec bit is re-checked with YARA")

        // Triage units.
        check(ScanTriage.isLowRiskTree("/Users/x/Library/Arduino15/packages/a/b.h"), "scanperf: Arduino15 packages are low-risk")
        check(ScanTriage.isLowRiskTree("/Users/x/.npm/_cacache/content-v2/sha512/ab/cd"), "scanperf: npm cache is low-risk")
        check(!ScanTriage.isLowRiskTree("/Users/x/Library/Mail/V10/x/Attachments/1/a.pdf"), "scanperf: Mail attachments are not low-risk")
        check(ScanTriage.plan(path: "/a/b.plist", kind: .plist, header: [], size: 100, executable: false, quarantined: { false }).yara == false,
              "scanperf: ordinary plist skips YARA")
        check(ScanTriage.plan(path: "/Library/LaunchAgents/x.plist", kind: .plist, header: [], size: 100, executable: false, quarantined: { false }) == .full,
              "scanperf: launch-folder plist gets full scan")
        check(ScanTriage.plan(path: "/a/b.txt", kind: .other, header: [], size: 100, executable: false, quarantined: { true }) == .full,
              "scanperf: quarantined file gets full scan")
        check(ScanTriage.plan(path: "/a/b.dat", kind: .other, header: Array("MZ".utf8), size: 100, executable: false, quarantined: { false }) == .full,
              "scanperf: PE header gets full scan")

        // Per-file deadline: a file whose check never finishes is abandoned; the scan completes.
        let slowDir = work + "/slow"
        try? fm.createDirectory(atPath: slowDir, withIntermediateDirectories: true)
        for i in 0..<5 { fm.createFile(atPath: slowDir + "/com.rampart.test.f\(i).sh", contents: Data("#!/bin/sh\n# \(i)\n".utf8)) }
        fm.createFile(atPath: slowDir + "/com.rampart.test.slow.sh", contents: Data("#!/bin/sh\n# slow\n".utf8))
        let slow = ScanCoordinator(database: try? HashDatabase.inMemory(), extraDetectors: [ProbeDetector(name: "slow", sleepFor: "com.rampart.test.slow.sh")])
        var so = ScanOptions(); so.perFileDeadline = 0.5; so.concurrency = 2
        var sawStall = false
        let t1 = Date()
        let rs = slow.scan(paths: [slowDir], options: so) { p in if p.secondsSinceLastCompletion > 0.3 { sawStall = true } }
        let s1 = Date().timeIntervalSince(t1)
        check(rs.timedOut == 1 && rs.timedOutPaths.first?.hasSuffix("com.rampart.test.slow.sh") == true,
              "scanperf: slow file abandoned at the deadline (\(rs.timedOut))")
        check(rs.scanned == 5 && s1 < 2.5, "scanperf: other files scanned and scan finished in \(String(format: "%.2f", s1)) s")
        _ = sawStall

        // Abandoned threads keep running; replacing each one let many stuck files pile up into many busy
        // cores (2026-11-15: ~500% CPU). Past the orphan cap replacements wait, and the scan still completes.
        let stuckDir = work + "/stuck"
        try? fm.createDirectory(atPath: stuckDir, withIntermediateDirectories: true)
        for i in 0..<8 { fm.createFile(atPath: stuckDir + "/com.rampart.test.s\(i).stuck.sh", contents: Data("#!/bin/sh\n# \(i)\n".utf8)) }
        for i in 0..<3 { fm.createFile(atPath: stuckDir + "/com.rampart.test.ok\(i).sh", contents: Data("#!/bin/sh\n# ok \(i)\n".utf8)) }
        let stuck = StuckDetector()
        let sc = ScanCoordinator(database: try? HashDatabase.inMemory(), extraDetectors: [stuck])
        var so2 = ScanOptions(); so2.perFileDeadline = 0.2; so2.concurrency = 2; so2.useCache = false
        let t2 = Date()
        let rs2 = sc.scan(paths: [stuckDir], options: so2)
        let s2 = Date().timeIntervalSince(t2)
        check(rs2.timedOut == 8 && rs2.scanned == 3, "scanperf: all stuck files abandoned, others scanned (\(rs2.timedOut)/\(rs2.scanned))")
        // 2 workers + at most 2 orphans, plus the one forced replacement when no live worker would remain.
        check(stuck.peakRunning <= 5, "scanperf: abandoned threads capped (peak \(stuck.peakRunning) concurrent)")
        check(s2 < 15, "scanperf: capped scan still finishes (\(String(format: "%.1f", s2)) s)")
        Thread.sleep(forTimeInterval: 1.6)   // let the last abandoned threads end before later suites
    }
}

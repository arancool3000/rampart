import Foundation
import Darwin
import RampartShared
import RampartGuard

// Download Gate + Camera & Microphone Guard. Fixtures live in a temp dir named com.rampart.test.* and are removed.
// Nothing here opens the camera or microphone, starts `log stream`, or touches the real Downloads folder or Trash.
extension SelfTest {
    struct FakeGateSigner: DownloadGateSigning {
        var trusted: Set<String> = []
        func assess(path: String, kind: GateFileKind) -> GateSignature {
            if trusted.contains((path as NSString).lastPathComponent) {
                return GateSignature(kind: .developerID, teamID: "TESTTEAM01", notarized: true, gatekeeperAccepted: kind == .app ? true : nil)
            }
            return GateSignature(kind: kind == .script ? .unsigned : .adHoc)
        }
    }

    static func protectionGateChecks() {
        downloadGateChecks()
        mediaGuardChecks()
        protectionGateIPCChecks()
    }

    private static func mode(_ p: String) -> UInt16 { var st = stat(); lstat(p, &st); return UInt16(st.st_mode & 0o7777) }
    private static func machO(_ p: String, mode: mode_t = 0o755) {
        var bytes: [UInt8] = [0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01]   // MH_MAGIC_64 (little endian), arm64
        bytes += [UInt8](repeating: 0, count: 120)
        FileManager.default.createFile(atPath: p, contents: Data(bytes)); chmod(p, mode)
    }
    private static func quarantineValue(_ p: String) -> String? {
        var buf = [CChar](repeating: 0, count: 512)
        let n = getxattr(p, "com.apple.quarantine", &buf, buf.count - 1, 0, XATTR_NOFOLLOW)
        return n >= 0 ? String(cString: buf) : nil
    }

    static func downloadGateChecks() {
        let fm = FileManager.default
        let tmp: String = {
            let p = fm.temporaryDirectory.appendingPathComponent("com.rampart.test.gate-\(UUID().uuidString)").path
            try? fm.createDirectory(atPath: p, withIntermediateDirectories: true)
            guard let r = realpath(p, nil) else { return p }
            defer { free(r) }
            return String(cString: r)   // /private/var/… like FSEvents reports
        }()
        defer { try? fm.removeItem(atPath: tmp) }
        let home = tmp + "/home", dl = home + "/Downloads", state = tmp + "/state", qdir = tmp + "/quarantine"
        for d in [dl, state, qdir, home + "/Code/proj"] { try? fm.createDirectory(atPath: d, withIntermediateDirectories: true) }
        let gate = DownloadGateService(directory: URL(fileURLWithPath: state), home: home, signer: FakeGateSigner(trusted: ["signed-tool", "Signed.app"]),
                                       roots: [(dl, "Downloads")])
        var decisions: [GateItem] = []
        gate.onDecision = { decisions.append($0) }
        gate.trash = { try FileManager.default.removeItem(at: $0) }
        gate.scan = { p in
            guard (try? String(contentsOfFile: p, encoding: .utf8))?.contains("com.rampart.test.bad") == true else { return nil }
            return Detection(path: p, name: "com.rampart.test.bad", category: .malware, severity: .high, confidence: 100, evidence: [])
        }
        gate.isMalicious = { $0.name == "com.rampart.test.bad" }
        gate.quarantine = { p, _ in
            (try? fm.moveItem(atPath: p, toPath: qdir + "/" + UUID().uuidString)) != nil ? UUID() : nil
        }

        // Classification
        machO(dl + "/tool")
        check(GateFileKind.classify(path: dl + "/tool") == .machO, "gate classify mach-o")
        fm.createFile(atPath: dl + "/run.sh", contents: Data("#!/bin/sh\necho hi\n".utf8))
        check(GateFileKind.classify(path: dl + "/run.sh") == .script, "gate classify script")
        fm.createFile(atPath: dl + "/a.zip", contents: Data([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]))
        check(GateFileKind.classify(path: dl + "/a.zip") == .archive, "gate classify zip")
        fm.createFile(atPath: dl + "/b.dmg", contents: Data("not really".utf8))
        check(GateFileKind.classify(path: dl + "/b.dmg") == .diskImage, "gate classify dmg by name")
        fm.createFile(atPath: dl + "/notes.txt", contents: Data("hello".utf8))
        check(GateFileKind.classify(path: dl + "/notes.txt") == .document, "gate classify document")
        check(!GateFileKind.document.isCode && GateFileKind.app.isCode, "gate kind isCode")

        // Skip rules: partial downloads, hidden files, git repos, build folders, outside the watched folders.
        check(gate.skipReason(dl + "/big.iso.crdownload") != nil && gate.skipReason(dl + "/x.download") != nil, "gate skips partial downloads")
        check(gate.skipReason(dl + "/.hidden") != nil, "gate skips hidden")
        try? fm.createDirectory(atPath: dl + "/repo/.git", withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: dl + "/repo/src", withIntermediateDirectories: true)
        machO(dl + "/repo/src/built")
        check(gate.skipReason(dl + "/repo/src/built") == "inside a git repository", "gate skips git repos")
        check(gate.skipReason(dl + "/proj/node_modules/x/bin") == "developer folder", "gate skips node_modules")
        check(gate.skipReason(dl + "/proj/.build/debug/tool") == "developer folder", "gate skips build output")
        check(gate.skipReason(home + "/Code/proj/tool") != nil, "gate never touches outside watched folders")
        check(gate.skipReason("/usr/bin/true") != nil && gate.process("/usr/bin/true") == nil, "gate refuses system paths")
        check(gate.skipReason(dl + "/tool") == nil, "gate gates a normal download")
        check(gate.process(dl + "/repo/src/built") == nil && mode(dl + "/repo/src/built") == 0o755, "gate leaves git repo binaries executable")
        check(gate.subject(for: dl + "/X.app/Contents/MacOS/X") == dl + "/X.app", "gate subject is the outer app bundle")

        // Unsigned program: quarantine flag added, execute removed, held; Allow restores the mode.
        let held = gate.process(dl + "/tool")
        check(held?.verdict == .held, "gate holds unsigned program")
        check(mode(dl + "/tool") & 0o111 == 0, "gate removed execute bits from held program")
        check(held?.quarantineFlagAdded == true && quarantineValue(dl + "/tool")?.hasPrefix("0081;") == true, "gate added quarantine flag")
        check(held?.strippedModes[dl + "/tool"] == 0o755, "gate remembers original mode")
        if let id = held?.id {
            let a = try? gate.decide(id: id, allow: true)
            check(a?.verdict == .allowed && mode(dl + "/tool") == 0o755, "gate allow restores execute bits")
            check((try? gate.decide(id: id, allow: true)) == nil, "gate decide only on held items")
        }

        // Signed + notarized: cleared, execute bits restored.
        machO(dl + "/signed-tool")
        let ok = gate.process(dl + "/signed-tool")
        check(ok?.verdict == .cleared && mode(dl + "/signed-tool") == 0o755, "gate clears signed notarized program")
        check(ok?.signature?.isTrustedToRun == true, "gate signature trusted")

        // Existing quarantine flag is never replaced.
        fm.createFile(atPath: dl + "/doc.pdf", contents: Data("%PDF-1.4".utf8))
        let orig = "0083;12345678;Safari;"
        _ = orig.withCString { setxattr(dl + "/doc.pdf", "com.apple.quarantine", $0, strlen($0), 0, XATTR_NOFOLLOW) }
        let doc = gate.process(dl + "/doc.pdf")
        check(doc?.verdict == .cleared && doc?.quarantineFlagAdded == false && quarantineValue(dl + "/doc.pdf") == orig, "gate keeps existing quarantine flag")

        // Scripts: non-executable ones are fine; executable ones are held.
        let s1 = gate.process(dl + "/run.sh")
        check(s1?.verdict == .cleared, "gate clears non-executable script")
        fm.createFile(atPath: dl + "/install.command", contents: Data("#!/bin/zsh\necho hi\n".utf8)); chmod(dl + "/install.command", 0o755)
        let s2 = gate.process(dl + "/install.command")
        check(s2?.verdict == .held && mode(dl + "/install.command") == 0o644, "gate holds executable script")
        if let id = s2?.id {
            let d = try? gate.decide(id: id, allow: false)
            check(d?.verdict == .deleted && !fm.fileExists(atPath: dl + "/install.command"), "gate delete removes held file")
        }

        // Malware: quarantined (blocked).
        fm.createFile(atPath: dl + "/evil.bin", contents: Data("com.rampart.test.bad payload".utf8))
        let bad = gate.process(dl + "/evil.bin")
        check(bad?.verdict == .blocked && !fm.fileExists(atPath: dl + "/evil.bin") && bad?.threat == "com.rampart.test.bad", "gate quarantines malware")

        // App bundles: executables stripped and held; a signed app is cleared.
        for (name, signed) in [("Unknown.app", false), ("Signed.app", true)] {
            let app = dl + "/" + name
            try? fm.createDirectory(atPath: app + "/Contents/MacOS", withIntermediateDirectories: true)
            fm.createFile(atPath: app + "/Contents/Info.plist", contents: Data("<plist/>".utf8))
            machO(app + "/Contents/MacOS/main")
            let r = gate.process(app + "/Contents/MacOS/main")   // any path inside gates the bundle
            check(r?.kind == .app && r?.path == app, "gate app bundle subject \(name)")
            check(r?.verdict == (signed ? .cleared : .held), "gate app verdict \(name)")
            check((mode(app + "/Contents/MacOS/main") & 0o111 != 0) == signed, "gate app exec bits \(name)")
        }

        // Stability: nothing until the size stops changing and no partial marker is left.
        gate.stableSeconds = 0.3
        let n0 = decisions.count
        fm.createFile(atPath: dl + "/slow.bin", contents: Data("part one".utf8))
        fm.createFile(atPath: dl + "/slow.bin.part", contents: Data())
        gate.noteChanged(dl + "/slow.bin")
        gate.tick(now: Date())
        check(decisions.count == n0, "gate waits while download is changing")
        gate.tick(now: Date().addingTimeInterval(1))
        check(decisions.count == n0, "gate waits while a .part marker exists")
        try? fm.removeItem(atPath: dl + "/slow.bin.part")
        gate.tick(now: Date().addingTimeInterval(2))
        check(decisions.count == n0 + 1 && decisions.last?.name == "slow.bin", "gate checks once stable")
        // Our own chmod / xattr events don't re-trigger.
        gate.noteChanged(dl + "/slow.bin"); gate.tick(now: Date().addingTimeInterval(5))
        check(decisions.count == n0 + 1, "gate ignores its own changes")

        // Status / persistence.
        let st = gate.status()
        check(st.enabled && st.honesty.contains("about a second"), "gate status honesty note")
        check(st.items.contains { $0.verdict == .held } && st.items.contains { $0.verdict == .blocked }, "gate status lists held and blocked")
        _ = gate.setEnabled(false)
        let again = DownloadGateService(directory: URL(fileURLWithPath: state), home: home, signer: FakeGateSigner(), roots: [(dl, "Downloads")])
        check(!again.isEnabled && again.status().items.count == st.items.count, "gate persists config and items")
        again.noteChanged(dl + "/notes.txt"); again.tick(now: Date().addingTimeInterval(9))
        check(again.status().items.count == st.items.count, "gate off checks nothing")

        // Live FSEvents: a new file in the watched folder is checked within a few seconds.
        let live = DownloadGateService(directory: URL(fileURLWithPath: state + "/live"), home: home, signer: FakeGateSigner(), roots: [(dl, "Downloads")])
        live.stableSeconds = 0.3
        live.start()
        Thread.sleep(forTimeInterval: 0.5)
        machO(dl + "/live-tool")
        var got: GateItem?
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline, got == nil {
            Thread.sleep(forTimeInterval: 0.2)
            got = live.status().items.first { $0.name == "live-tool" }
        }
        live.stop()
        check(got?.verdict == .held && (got?.secondsToCheck ?? 99) < 5, "gate live FSEvents check within seconds")

        // Chromium custom download folder (inside home only).
        let prefsDir = home + "/Library/Application Support/Google/Chrome/Default"
        try? fm.createDirectory(atPath: prefsDir, withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: home + "/BrowserDL", withIntermediateDirectories: true)
        fm.createFile(atPath: prefsDir + "/Preferences", contents: Data(#"{"download":{"default_directory":"\#(home)/BrowserDL"}}"#.utf8))
        check(DownloadGateService.chromiumDownloadFolders(home: home) == [home + "/BrowserDL"], "gate reads chromium download folder")
        fm.createFile(atPath: prefsDir + "/Preferences", contents: Data(#"{"download":{"default_directory":"\#(home)"}}"#.utf8))
        check(DownloadGateService.chromiumDownloadFolders(home: home).isEmpty, "gate never watches the whole home folder")

        // Real Security.framework signer (offline): an Apple binary, and an unsigned fixture.
        let real = SecDownloadGateSigning(allowNetwork: false, useGatekeeperAssessment: false)
        check(real.assess(path: "/bin/ls", kind: .machO).kind == .apple, "gate signer: /bin/ls is Apple")
        machO(tmp + "/unsigned-fixture")
        let u = real.assess(path: tmp + "/unsigned-fixture", kind: .machO).kind
        check(u == .unsigned || u == .invalid, "gate signer: fixture is not trusted")
        check(!GateSignature(kind: .developerID, notarized: false).isTrustedToRun, "gate: un-notarized developer ID not trusted")
        check(!GateSignature(kind: .developerID, notarized: true, gatekeeperAccepted: false).isTrustedToRun, "gate: Gatekeeper rejection wins")
    }

    static func mediaGuardChecks() {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory.appendingPathComponent("com.rampart.test.media-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: tmp) }

        // Parsing real-format Control Center lines (copied from this Mac's unified log).
        let line = #"2026-11-09 18:52:34.944 Df ControlCenter[738:10bc54] [com.apple.controlcenter:sensor-indicators] Active activity attributions changed to ["mic:com.apple.CoreSpeech", "loc:com.apple.AssistantServices"]"#
        check(MediaLogParser.activeUses(in: line) == [MediaUse(device: .microphone, appID: "com.apple.CoreSpeech")], "media parse mic line")
        check(MediaLogParser.activeUses(in: #"… Active activity attributions changed to ["loc:com.apple.weather"]"#) == [], "media parse location only")
        check(MediaLogParser.activeUses(in: #"… Active activity attributions changed to []"#) == [], "media parse empty")
        check(MediaLogParser.activeUses(in: #"… Recent activity attributions changed to ["cam:us.zoom.xos"]"#) == nil, "media ignores recent list")
        let nd = #"{"eventMessage":"Active activity attributions changed to [\"cam:us.zoom.xos\", \"mic:us.zoom.xos\"]","subsystem":"com.apple.controlcenter"}"#
        check(MediaLogParser.activeUses(in: nd)?.count == 2, "media parse ndjson")
        check(MediaLogParser.activeUses(in: #"Active activity attributions changed to ["cam:../../evil\"x"]"#) == [], "media rejects odd app ids")
        let sys = "SystemStatus attributed attribution to com.apple.systemuiserver, displayName: <private>, bundlePath: <private>, executablePath: <private>, isSystemExecutable: true"
        check(MediaLogParser.systemFlag(in: sys)?.appID == "com.apple.systemuiserver" && MediaLogParser.systemFlag(in: sys)?.system == true, "media parse system flag")

        // Service with simulated events.
        let svc = MediaGuardService(directory: tmp)
        var locked = false, idle = 0.0
        svc.screenState = { (locked, idle) }
        svc.resolve = { id in id.hasPrefix("com.apple.") ? MediaGuardService.App(pid: nil, path: "/System/Applications/FaceTime.app/Contents/MacOS/FaceTime", name: "FaceTime")
                                                        : MediaGuardService.App(pid: 999_999, path: "/Applications/Spy.app/Contents/MacOS/Spy", name: "Spy") }
        svc.isAlive = { _ in true }
        var killed: [(Int32, Int32)] = []
        let killLock = NSLock()
        svc.kill = { p, s in killLock.lock(); killed.append((p, s)); killLock.unlock(); return true }
        var alerts: [MediaGuardAlert] = [], ended: [MediaSession] = [], changes = 0
        svc.onAlert = { alerts.append($0) }
        svc.onSessionEnded = { ended.append($0) }
        svc.onChange = { _ in changes += 1 }

        let t0 = Date()
        svc.ingest(#"Active activity attributions changed to ["cam:com.rampart.test.spy"]"#, now: t0)
        check(svc.status().cameraOn && !svc.status().micOn, "media camera on")
        check(alerts.count == 1 && alerts[0].device == .camera && alerts[0].canStop, "media alerts untrusted camera")
        check(alerts.first?.title.contains("📷") == true && alerts.first?.body.contains("Spy") == true, "media playful alert text")
        svc.ingest(#"Active activity attributions changed to ["cam:com.rampart.test.spy", "mic:com.rampart.test.spy"]"#, now: t0.addingTimeInterval(1))
        check(alerts.count == 2 && svc.status().micOn, "media mic added, alerted once more")
        svc.ingest(#"Active activity attributions changed to []"#, now: t0.addingTimeInterval(65))
        check(ended.count == 2 && ended.allSatisfy { !$0.trusted && $0.alerted }, "media sessions end with trusted=false")
        check(abs((ended.first { $0.device == .camera }?.duration() ?? 0) - 65) < 0.01, "media duration recorded")
        check(!svc.status().cameraOn && svc.status().recent.count == 2 && changes >= 3, "media indicator off, history kept")

        // Trusted: quiet, unless the Mac is locked or idle.
        _ = try? svc.setTrusted("com.rampart.test.spy", trusted: true)
        svc.ingest(#"Active activity attributions changed to ["cam:com.rampart.test.spy"]"#, now: t0.addingTimeInterval(100))
        check(alerts.count == 2, "media trusted app does not alert")
        svc.ingest(#"Active activity attributions changed to []"#, now: t0.addingTimeInterval(110))
        check(ended.last?.trusted == true, "media log says trusted app was in use")
        locked = true
        svc.ingest(#"Active activity attributions changed to ["mic:com.rampart.test.spy"]"#, now: t0.addingTimeInterval(120))
        check(alerts.count == 3 && alerts.last?.severity == .high && alerts.last?.body.contains("locked") == true, "media alerts when locked even if trusted")
        svc.ingest(#"Active activity attributions changed to []"#, now: t0.addingTimeInterval(130))
        locked = false; idle = 3600
        svc.ingest(#"Active activity attributions changed to ["mic:com.rampart.test.spy"]"#, now: t0.addingTimeInterval(140))
        check(alerts.count == 4 && svc.status().active.first?.whileIdle == true, "media alerts when idle")
        svc.ingest(#"Active activity attributions changed to []"#, now: t0.addingTimeInterval(150))
        idle = 0

        // Apple system components: logged, never alerted, never stopped.
        locked = true
        svc.ingest(#"Active activity attributions changed to ["mic:com.apple.CoreSpeech"]"#, now: t0.addingTimeInterval(200))
        check(alerts.count == 4 && svc.status().active.first?.system == true, "media never alerts for macOS components")
        svc.ingest(#"Active activity attributions changed to []"#, now: t0.addingTimeInterval(201))
        locked = false
        do { _ = try svc.stopApp("com.apple.FaceTime"); check(false, "media refuses to stop system app") }
        catch { check(error is MediaGuardError, "media refuses to stop system app") }
        do { _ = try svc.stopApp(Product.bundlePrefix + ".app"); check(false, "media refuses to stop RamPart") }
        catch { check(true, "media refuses to stop RamPart") }

        // Stop it: SIGTERM to the resolved app (fake kill hook; nothing real is signalled).
        _ = try? svc.setTrusted("com.rampart.test.spy", trusted: false)
        _ = try? svc.stopApp("com.rampart.test.spy")
        killLock.lock(); let first = killed.first; killLock.unlock()
        check(first?.0 == 999_999 && first?.1 == SIGTERM, "media stop sends SIGTERM to the app")
        check((try? svc.setTrusted("bad/id", trusted: true)) == nil, "media rejects invalid app id")

        // Serious tone; persistence.
        _ = svc.setTone(serious: true)
        svc.ingest(#"Active activity attributions changed to ["cam:com.rampart.test.other"]"#, now: t0.addingTimeInterval(300))
        check(alerts.last.map { !$0.title.contains("📷") && $0.title.contains("Camera") } == true, "media serious alert text")
        check(alerts.last?.identifier == "mediaguard.com.rampart.test.other.camera", "media alert identifier per app + device")
        svc.ingest(#"Active activity attributions changed to []"#, now: t0.addingTimeInterval(301))
        _ = try? svc.setTrusted("com.rampart.test.keep", trusted: true)
        let svc2 = MediaGuardService(directory: tmp)
        check(svc2.status().config.trusted == ["com.rampart.test.keep"] && svc2.status().config.tone == .serious, "media persists trusted list and tone")
        check(svc2.status().recent.count == ended.count, "media persists history")
        check(MediaGuardService.honesty.contains("never opens the camera"), "media honesty note")
        check(AppResolver.bundle(ofExecutable: "/Applications/Zoom.app/Contents/MacOS/zoom") == "/Applications/Zoom.app", "media resolver bundle path")
    }

    static func protectionGateIPCChecks() {
        let reqs: [IPCRequest] = [.downloadGateStatus, .downloadGateSetEnabled(on: false), .downloadGateDecide(id: UUID(), allow: true),
                                  .mediaGuardStatus, .mediaGuardSetEnabled(on: true), .mediaGuardTrust(appID: "us.zoom.xos", trusted: true),
                                  .mediaGuardStop(appID: "us.zoom.xos"), .mediaGuardSetTone(serious: true)]
        for r in reqs {
            let back = (try? JSONEncoder.rampart.encode(r)).flatMap { try? JSONDecoder.rampart.decode(IPCRequest.self, from: $0) }
            check(back != nil, "gates IPC round trip \(r)")
        }
        let st = DownloadGateStatus(enabled: true, running: false, watched: [], items: [], honesty: DownloadGateService.honesty, lastError: nil)
        check((try? JSONEncoder.rampart.encode(st)).flatMap { try? JSONDecoder.rampart.decode(DownloadGateStatus.self, from: $0) } == st, "gates status JSON")
        for ev in [ActivityEvent.downloadGate, .cameraMicUsed] {
            let e = ActivityEntry(kind: .realtime, title: "t", detail: "d", outcome: ev == .downloadGate ? "held" : "alerted", event: ev, facts: ["device": "camera", "folder": "Downloads"])
            let p = ActivityPresenter.present(e)
            check(!p.title.isEmpty && !p.whatHappened.isEmpty, "gates activity presentation \(ev)")
        }
    }
}

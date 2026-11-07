import Foundation
import CryptoKit
import RampartShared
import RampartRemediation

// Owned by the remediation build agent. Add checks with check(cond, "name").
// Everything happens under the session scratchpad (override with RAMPART_SCRATCH).
extension SelfTest {
    static func remediation() {
        let scratchBase = ProcessInfo.processInfo.environment["RAMPART_SCRATCH"]
            ?? SelfTest.fixtureTempDir
        let base = URL(fileURLWithPath: scratchBase).appendingPathComponent("remediation-selftest-\(UUID().uuidString.prefix(8))")
        let fm = FileManager.default
        try? fm.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: base) }
        let files = base.appendingPathComponent("files")
        try? fm.createDirectory(at: files, withIntermediateDirectories: true)
        func sha(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

        // EICAR assembled at runtime from fragments; never stored in source as one string.
        let eicar = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"].joined()
        let eicarData = Data(eicar.utf8)
        let marker = Data(["EICAR-STANDARD", "-ANTIVIRUS"].joined().utf8)

        // MARK: Vault
        var allowlisted: [String] = []
        guard let vault = try? QuarantineVault(root: base.appendingPathComponent("vault"), allowlistHandler: { h, _ in allowlisted.append(h) }) else {
            check(false, "vault init"); return
        }
        var st = stat()
        check(stat(vault.root.path, &st) == 0 && st.st_mode & 0o777 == 0o700, "vault dir is 0700")
        check(stat(vault.root.appendingPathComponent("vault.key").path, &st) == 0 && st.st_mode & 0o777 == 0o600, "vault key is 0600")

        let eicarPath = files.appendingPathComponent("com.rampart.test.eicar.com").path
        fm.createFile(atPath: eicarPath, contents: eicarData, attributes: [.posixPermissions: 0o755])
        Xattr_set(eicarPath, "com.apple.quarantine", Data("0081;00000000;Test;".utf8))
        Xattr_set(eicarPath, "com.rampart.test.tag", Data("hello".utf8))
        let rec = try? vault.quarantine(path: eicarPath, detectionName: "EICAR-Test-File")
        check(rec != nil, "quarantine EICAR")
        check(!fm.fileExists(atPath: eicarPath), "original removed after quarantine")
        if let rec = rec {
            check(rec.sha256 == sha(eicarData), "record sha256")
            check(rec.mode & 0o777 == 0o755, "record keeps original mode")
            let blobPath = vault.itemsDir.appendingPathComponent(rec.id.uuidString + ".rqf").path
            let blob = fm.contents(atPath: blobPath) ?? Data()
            check(!blob.isEmpty, "blob exists")
            check(blob.range(of: marker) == nil && blob.range(of: eicarData) == nil, "vault blob does not contain EICAR string")
            check(stat(blobPath, &st) == 0 && st.st_mode & 0o111 == 0, "blob has no exec bits")
            let sidecar = fm.contents(atPath: vault.itemsDir.appendingPathComponent(rec.id.uuidString + ".json").path) ?? Data()
            check(sidecar.range(of: marker) == nil, "sidecar does not contain EICAR string")
            check(vault.list().contains { $0.id == rec.id }, "list shows item")
            check((try? vault.metadata(id: rec.id))?.xattrs["com.rampart.test.tag"] == Data("hello".utf8), "xattrs captured")

            // Refuse overwrite.
            fm.createFile(atPath: eicarPath, contents: Data("other".utf8))
            do { try vault.restore(id: rec.id); check(false, "restore refuses overwrite") }
            catch let e as RemediationError { check(e == .destinationExists(eicarPath), "restore refuses overwrite") }
            catch { check(false, "restore refuses overwrite (error type)") }
            check(fm.contents(atPath: eicarPath) == Data("other".utf8), "existing file untouched")
            try? fm.removeItem(atPath: eicarPath)

            let dest = try? vault.restore(id: rec.id)
            check(dest == eicarPath, "restore to original path")
            check(sha256Hex(ofFileAt: eicarPath) == sha(eicarData), "restored SHA-256 matches")
            check(stat(eicarPath, &st) == 0 && st.st_mode & 0o777 == 0o755, "restored mode matches")
            check(allowlisted == [sha(eicarData)], "allowlist callback got hash")
            let restoredX = listXattrNames(eicarPath)
            check(restoredX.contains("com.rampart.test.tag") && !restoredX.contains("com.apple.quarantine"), "xattrs restored without quarantine flag")
            check(!vault.list().contains { $0.id == rec.id }, "restored item leaves active list")
            check(vault.list(includeHistory: true).contains { $0.id == rec.id }, "restored item kept in history")
            check((try? vault.restore(id: rec.id)) == nil, "cannot restore twice")
        }

        // Alternate path restore.
        let alt1 = files.appendingPathComponent("com.rampart.test.alt.txt").path
        fm.createFile(atPath: alt1, contents: Data("alt-content".utf8))
        if let r = try? vault.quarantine(path: alt1, detectionName: "Test") {
            let altDest = files.appendingPathComponent("restored/com.rampart.test.alt (restored).txt").path
            check((try? vault.restore(id: r.id, options: .init(alternatePath: altDest))) == altDest, "restore to alternate path")
            check(fm.contents(atPath: altDest) == Data("alt-content".utf8), "alternate path content")
        } else { check(false, "quarantine alt") }

        // Tampered metadata is rejected.
        let tpath = files.appendingPathComponent("com.rampart.test.tamper.txt").path
        fm.createFile(atPath: tpath, contents: Data("tamper".utf8))
        if let r = try? vault.quarantine(path: tpath, detectionName: "Test") {
            let side = vault.itemsDir.appendingPathComponent(r.id.uuidString + ".json")
            if let raw = try? Data(contentsOf: side),
               var outer = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
               let b64 = outer["metadata"] as? String, let inner = Data(base64Encoded: b64),
               let s = String(data: inner, encoding: .utf8) {
                let evil = s.replacingOccurrences(of: "com.rampart.test.tamper.txt", with: "com.rampart.test.evil.txt")
                outer["metadata"] = Data(evil.utf8).base64EncodedString()
                try? JSONSerialization.data(withJSONObject: outer).write(to: side)
                do { try vault.restore(id: r.id); check(false, "tampered metadata rejected") }
                catch let e as RemediationError {
                    if case .integrityFailure = e { check(true, "tampered metadata rejected") } else { check(false, "tampered metadata rejected: \(e)") }
                } catch { check(false, "tampered metadata rejected (type)") }
                check(!fm.fileExists(atPath: files.appendingPathComponent("com.rampart.test.evil.txt").path), "no file at attacker path")
                check(!vault.list().contains { $0.id == r.id }, "tampered item hidden from list")
                check(vault.tamperedItems().contains(r.id.uuidString), "tampered item reported")
            } else { check(false, "read sidecar") }
        } else { check(false, "quarantine tamper") }

        // Tampered ciphertext is rejected.
        let cpath = files.appendingPathComponent("com.rampart.test.cipher.txt").path
        fm.createFile(atPath: cpath, contents: Data(repeating: 0x41, count: 4096))
        if let r = try? vault.quarantine(path: cpath, detectionName: "Test") {
            let blobURL = vault.itemsDir.appendingPathComponent(r.id.uuidString + ".rqf")
            if var b = try? Data(contentsOf: blobURL) { b[b.count / 2] ^= 0xFF; try? b.write(to: blobURL) }
            check((try? vault.restore(id: r.id)) == nil && !fm.fileExists(atPath: cpath), "tampered ciphertext rejected")
        }

        // Protected paths refused.
        check((try? vault.quarantine(path: "/bin/ls", detectionName: "x")) == nil && fm.fileExists(atPath: "/bin/ls"), "protected path refused")

        // Bundle/directory round trip.
        let bundle = files.appendingPathComponent("com.rampart.test.bundle.app")
        try? fm.createDirectory(at: bundle.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
        fm.createFile(atPath: bundle.appendingPathComponent("Contents/MacOS/tool").path, contents: Data("#!/bin/sh\necho hi\n".utf8), attributes: [.posixPermissions: 0o755])
        if let r = try? vault.quarantine(path: bundle.path, detectionName: "Test") {
            check(!fm.fileExists(atPath: bundle.path), "bundle removed")
            check((try? vault.restore(id: r.id)) == bundle.path, "bundle restored")
            check(fm.contents(atPath: bundle.appendingPathComponent("Contents/MacOS/tool").path) == Data("#!/bin/sh\necho hi\n".utf8), "bundle content restored")
        } else { check(false, "quarantine bundle") }

        // Purge.
        let ppath = files.appendingPathComponent("com.rampart.test.purge.txt").path
        fm.createFile(atPath: ppath, contents: Data("purge".utf8))
        if let r = try? vault.quarantine(path: ppath, detectionName: "Test") {
            check(vault.purge(olderThanDays: 30).isEmpty, "fresh item not purged")
            let purged = vault.purge(olderThanDays: 30, now: Date().addingTimeInterval(31 * 86_400))
            check(purged.contains(r.id), "old item purged")
            check(!fm.fileExists(atPath: vault.itemsDir.appendingPathComponent(r.id.uuidString + ".rqf").path), "purged blob deleted")
            check((try? vault.metadata(id: r.id))?.status == .purged, "purged status recorded")
        }

        // Key persists across instances.
        if let v2 = try? QuarantineVault(root: vault.root) {
            check(v2.list(includeHistory: true).count == vault.list(includeHistory: true).count, "reopened vault verifies sidecars")
        }

        // MARK: ProcessKiller
        let sh = Process()
        sh.executableURL = URL(fileURLWithPath: "/bin/sh")
        sh.arguments = ["-c", "/bin/sleep 300 & /bin/sleep 300 & wait"]
        if (try? sh.run()) != nil {
            let shPid = sh.processIdentifier
            var kids: [Int32] = []
            for _ in 0..<50 {
                kids = ProcessKiller.allPIDs().filter { ProcessKiller.info($0)?.ppid == shPid }
                if kids.count >= 2 { break }
                usleep(50_000)
            }
            check(kids.count == 2, "spawned sleep children")
            if let rootID = ProcessKiller.identity(of: shPid) {
                let protective = ProcessKiller()
                let refused = protective.killTree(rootID, dryRun: false)
                check(refused.plan.isEmpty && refused.killed.isEmpty, "platform binaries protected by default")

                let killer = ProcessKiller(protectPlatformBinaries: false)
                let bogus = killer.killTree(ProcessIdentity(pid: shPid, startTime: rootID.startTime + 1), dryRun: false)
                check(bogus.plan.isEmpty && bogus.killed.isEmpty, "pid-reuse check refuses mismatched start time")
                let dry = killer.killTree(rootID, dryRun: true)
                check(dry.plan.count == 3 && dry.killed.isEmpty, "dryRun plans 3 processes, kills none")
                check(dry.plan.first.map { $0.identity.pid != shPid } ?? false && dry.plan.last?.identity.pid == shPid, "kill order leaves-up")
                check(kids.allSatisfy { kill($0, 0) == 0 }, "children alive after dryRun")
                let rep = killer.killTree(rootID, dryRun: false)
                check(rep.stopped.count == 3, "SIGSTOP sent to whole tree")
                check(Set(rep.killed) == Set(kids + [shPid]), "killed whole tree")
                check(rep.survivors.isEmpty, "no survivors")
                sh.waitUntilExit()
                var gone = false
                for _ in 0..<40 {
                    gone = kids.allSatisfy { ProcessKiller.info($0) == nil || ProcessKiller.info($0)!.zombie || ProcessKiller.info($0)!.ppid != shPid }
                        && kids.allSatisfy { kill($0, 0) != 0 || ProcessKiller.info($0)?.zombie == true }
                    if gone { break }
                    usleep(50_000)
                }
                check(gone, "sleep processes are gone")
                check(sh.terminationReason == .uncaughtSignal && sh.terminationStatus == SIGKILL, "shell died from SIGKILL")
            } else { check(false, "identity of spawned shell") }
        } else { check(false, "spawn /bin/sh") }

        // MARK: Launchd (dry-run)
        let rec2 = RecordingCommandRunner(stdoutFor: { c in
            c.arguments.first == "print-disabled" ? "disabled services = {\n\t\"com.rampart.test.agent\" => enabled\n\t\"com.other\" => disabled\n}\n" : ""
        })
        let ld = LaunchdRemediator(runner: rec2)
        let gjob = LaunchdJob(label: "com.rampart.test.agent", domain: .gui(uid: 501), plistPath: "/Users/x/Library/LaunchAgents/com.rampart.test.agent.plist")
        let dr = ld.remediate(gjob, dryRun: true)
        check(dr.commands.map(\.description) == ["/bin/launchctl bootout gui/501/com.rampart.test.agent",
                                                 "/bin/launchctl disable gui/501/com.rampart.test.agent"], "gui bootout+disable commands")
        check(dr.undoCommands.map(\.description) == ["/bin/launchctl enable gui/501/com.rampart.test.agent",
                                                     "/bin/launchctl bootstrap gui/501 /Users/x/Library/LaunchAgents/com.rampart.test.agent.plist"], "gui undo commands")
        check(rec2.commands.isEmpty, "dryRun executes nothing")
        check(dr.commands[0].acceptableExitCodes.contains(113) && dr.commands[0].acceptableExitCodes.contains(3), "bootout tolerates not-loaded")
        let sjob = LaunchdJob(label: "com.rampart.test.daemon", domain: .system)
        let sc = ld.commands(for: sjob)
        check(sc.map(\.description) == ["/bin/launchctl bootout system/com.rampart.test.daemon", "/bin/launchctl disable system/com.rampart.test.daemon"]
              && sc.allSatisfy(\.requiresRoot), "system domain commands require root")
        check(LaunchdRemediator.parseDisabled("\t\"a.b\" => disabled\n\t\"c.d\" => enabled\n\t\"e\" => true\n") == ["a.b": true, "c.d": false, "e": true], "parse print-disabled")
        let live = ld.remediate(gjob, dryRun: false)
        check(rec2.commands.map { $0.arguments.first ?? "" } == ["print-disabled", "bootout", "disable"] && live.wasDisabled == false, "non-dry-run via injected runner")
        let plistPath = files.appendingPathComponent("com.rampart.test.agent.plist").path
        try? PropertyListSerialization.data(fromPropertyList: ["Label": "com.rampart.test.agent", "ProgramArguments": ["/tmp/x", "-y"]], format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: plistPath))
        let jobs = LaunchdRemediator.job(fromPlist: plistPath)
        check(jobs.first?.label == "com.rampart.test.agent" && jobs.first?.program == "/tmp/x" && jobs.first?.domain == .gui(uid: getuid()), "job from plist")

        // MARK: Cron, login items, profiles (command generation)
        let tab = "# comment\nMAILTO=\"\"\n*/5 * * * * /Users/x/.hidden/agent --run\n0 9 * * * /usr/local/bin/backup\n"
        let (kept, removed) = CronCleaner.filter(tab) { $0.contains(".hidden/agent") }
        check(removed == ["*/5 * * * * /Users/x/.hidden/agent --run"] && kept == "# comment\nMAILTO=\"\"\n0 9 * * * /usr/local/bin/backup\n", "cron filter")
        let cronRunner = RecordingCommandRunner()
        let co = try? CronCleaner(runner: cronRunner).remove(user: nil, containing: [".hidden/agent"], dryRun: true, currentTab: tab)
        check(co?.commands.first?.stdin == kept && co?.undoCommands.first?.stdin == tab && cronRunner.commands.isEmpty, "cron dryRun plan + undo")
        let li = LoginItemCleaner(runner: RecordingCommandRunner())
        check(li.removeCommand(name: "Evil \"Helper\"").arguments.last == "tell application \"System Events\" to delete login item \"Evil \\\"Helper\\\"\"", "login item command escapes")
        check(ProfileCleaner().removeCommand(identifier: "com.rampart.test.profile").description == "/usr/bin/profiles remove -identifier com.rampart.test.profile", "profile remove command")

        // MARK: Browser extensions + executor + journal
        let home = base.appendingPathComponent("home")
        let chromeProfile = home.appendingPathComponent("Library/Application Support/Google/Chrome/Default")
        let extID = "abcdefghijklmnopabcdefghijklmnop"
        try? fm.createDirectory(at: chromeProfile.appendingPathComponent("Extensions/\(extID)/1.0"), withIntermediateDirectories: true)
        fm.createFile(atPath: chromeProfile.appendingPathComponent("Extensions/\(extID)/1.0/manifest.json").path, contents: Data("{\"name\":\"com.rampart.test.ext\"}".utf8))
        let prefs: [String: Any] = ["extensions": ["settings": [extID: ["state": 1], "keepme": ["state": 1]]], "homepage": "https://example.com"]
        try? JSONSerialization.data(withJSONObject: prefs).write(to: chromeProfile.appendingPathComponent("Preferences"))
        let ffRoot = home.appendingPathComponent("Library/Application Support/Firefox")
        try? fm.createDirectory(at: ffRoot.appendingPathComponent("Profiles/abc.default-release/extensions"), withIntermediateDirectories: true)
        try? "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\n".write(to: ffRoot.appendingPathComponent("profiles.ini"), atomically: true, encoding: .utf8)
        let ffProfile = ffRoot.appendingPathComponent("Profiles/abc.default-release")
        fm.createFile(atPath: ffProfile.appendingPathComponent("extensions/bad@rampart.test.xpi").path, contents: Data("zip".utf8))
        try? JSONSerialization.data(withJSONObject: ["addons": [["id": "bad@rampart.test"], ["id": "good@x"]]]).write(to: ffProfile.appendingPathComponent("extensions.json"))

        var running = true
        let browsers = BrowserExtensionCleaner(home: home, isRunning: { _ in running })
        check(browsers.profiles(BrowserSpec.named("Chrome")!).map(\.path) == [chromeProfile.path], "chrome profiles found")
        check(browsers.profiles(BrowserSpec.named("Firefox")!).map(\.standardizedFileURL.path) == [ffProfile.standardizedFileURL.path], "firefox profiles.ini parsed")
        do { _ = try browsers.remove(browser: BrowserSpec.named("Chrome")!, profile: chromeProfile, extensionID: extID, backupDir: base, dryRun: true); check(false, "refuse while browser running") }
        catch let e as RemediationError { if case .browserRunning = e { check(true, "refuse while browser running") } else { check(false, "refuse while browser running") } }
        catch { check(false, "refuse while browser running") }
        running = false

        guard let journal = try? ActionJournal(directory: base.appendingPathComponent("journal")) else { check(false, "journal init"); return }
        let exec = RemediationExecutor(vault: vault, journal: journal, runner: RecordingCommandRunner(),
                                       killer: ProcessKiller(protectPlatformBinaries: false), browsers: browsers)
        let qpath = files.appendingPathComponent("com.rampart.test.plan.bin").path
        fm.createFile(atPath: qpath, contents: eicarData, attributes: [.posixPermissions: 0o700])
        let plan = RemediationPlan(title: "Test cleanup", actions: [
            .quarantineFile(path: qpath, detectionName: "EICAR-Test-File"),
            .removeBrowserExtension(browser: "Chrome", profilePath: chromeProfile.path, extensionID: extID),
            .removeBrowserExtension(browser: "Firefox", profilePath: ffProfile.path, extensionID: "bad@rampart.test"),
            .launchdJob(gjob),
        ]).ordered()
        check(plan.actions.first.map { if case .launchdJob = $0 { return true } else { return false } } ?? false, "plan ordering puts launchd first")
        let text = exec.previewText(plan)
        check(text.contains("$ /bin/launchctl bootout gui/501/com.rampart.test.agent") && text.contains("Quarantine \(qpath)"), "preview lists commands")
        let dryRes = exec.run(plan, dryRun: true)
        check(dryRes.allSucceeded && fm.fileExists(atPath: qpath) && journal.records().isEmpty, "dry-run plan changes nothing")
        check(fm.fileExists(atPath: chromeProfile.appendingPathComponent("Extensions/\(extID)").path), "dry-run leaves extension")

        let res = exec.run(plan, dryRun: false)
        check(res.allSucceeded, "plan applied: " + res.steps.filter { !$0.success }.map(\.message).joined(separator: "; "))
        check(!fm.fileExists(atPath: qpath), "plan quarantined file")
        check(!fm.fileExists(atPath: chromeProfile.appendingPathComponent("Extensions/\(extID)").path), "chrome extension dir removed")
        let newPrefs = (try? JSONSerialization.jsonObject(with: Data(contentsOf: chromeProfile.appendingPathComponent("Preferences")))) as? [String: Any]
        let settings = (newPrefs?["extensions"] as? [String: Any])?["settings"] as? [String: Any]
        check(settings?[extID] == nil && settings?["keepme"] != nil && newPrefs?["homepage"] as? String == "https://example.com", "chrome Preferences entry removed only")
        check(!fm.fileExists(atPath: ffProfile.appendingPathComponent("extensions/bad@rampart.test.xpi").path), "firefox xpi removed")
        let ffJSON = (try? JSONSerialization.jsonObject(with: Data(contentsOf: ffProfile.appendingPathComponent("extensions.json")))) as? [String: Any]
        check((ffJSON?["addons"] as? [[String: Any]])?.compactMap { $0["id"] as? String } == ["good@x"], "firefox extensions.json updated")
        let states = journal.transaction(plan.id)
        check(states.count == 4 && states.allSatisfy { $0.phase == .done && $0.undo != nil }, "journal has 4 done actions with undo")
        check(states.first { if case .quarantineFile = $0.action { return true }; return false }?.beforeState["sha256"] == sha(eicarData), "journal before-state")

        let undone = exec.undo(transaction: plan.id)
        check(undone.count == 4 && undone.allSatisfy(\.success), "undo transaction: " + undone.filter { !$0.success }.map(\.message).joined(separator: "; "))
        check(sha256Hex(ofFileAt: qpath) == sha(eicarData), "undo restored quarantined file")
        check(fm.fileExists(atPath: chromeProfile.appendingPathComponent("Extensions/\(extID)/1.0/manifest.json").path), "undo restored chrome extension")
        let rp = (try? JSONSerialization.jsonObject(with: Data(contentsOf: chromeProfile.appendingPathComponent("Preferences")))) as? [String: Any]
        check(((rp?["extensions"] as? [String: Any])?["settings"] as? [String: Any])?[extID] != nil, "undo restored chrome Preferences")
        check(fm.fileExists(atPath: ffProfile.appendingPathComponent("extensions/bad@rampart.test.xpi").path), "undo restored firefox xpi")
        check(journal.transaction(plan.id).allSatisfy { $0.phase == .undone }, "journal marks undone")

        // Crash recovery: a pending action without completion plus a torn final line.
        let crashTxn = UUID()
        try? journal.append(JournalRecord(actionID: UUID(), transactionID: crashTxn, seq: 0, date: Date(), phase: .pending,
                                          action: .removeProfile(identifier: "com.rampart.test.profile"), beforeState: [:], undo: nil, message: nil))
        if let h = FileHandle(forWritingAtPath: journal.fileURL.path) { h.seekToEndOfFile(); h.write(Data("{\"actionID\":\"trunc".utf8)); try? h.close() }
        let before = journal.records().count
        let reopened = try? ActionJournal(directory: journal.directory)
        let recovered = reopened?.recoverInterrupted() ?? []
        check(recovered.count == 1 && recovered.first?.transactionID == crashTxn, "crash recovery finds pending action")
        check(reopened?.records().count == before + 1, "torn line skipped and recovery appended")
        check(reopened?.transaction(crashTxn).first?.phase == .interrupted, "pending marked interrupted")
        check(reopened?.recoverInterrupted().isEmpty == true, "recovery idempotent")
    }
}

private func Xattr_set(_ path: String, _ name: String, _ value: Data) {
    _ = value.withUnsafeBytes { setxattr(path, name, $0.baseAddress, value.count, 0, XATTR_NOFOLLOW) }
}
private func listXattrNames(_ path: String) -> [String] {
    let n = listxattr(path, nil, 0, XATTR_NOFOLLOW)
    guard n > 0 else { return [] }
    var buf = [CChar](repeating: 0, count: n)
    _ = listxattr(path, &buf, n, XATTR_NOFOLLOW)
    return buf.split(separator: 0).map { String(cString: Array($0) + [0]) }
}

import Foundation
import RampartShared
import RampartRemediation

// hx3 hardening: quarantine vault, restore/export, journal/undo and the Run-in-Sandbox profile.
// Only inert fixtures under the scratchpad. The only thing ever run under sandbox-exec is /usr/bin/true
// (to prove the profile parses and that an unlisted program can't start). No quarantined content is executed.
extension SelfTest {
    static func hx3Checks() {
        let scratchBase = ProcessInfo.processInfo.environment["RAMPART_SCRATCH"]
            ?? "/private/tmp/claude-501/-Users-arankeyhan/ab330a0d-96bf-4eec-a6ed-51d815d3bfd2/scratchpad"
        let base = URL(fileURLWithPath: scratchBase).appendingPathComponent("hx3-\(UUID().uuidString.prefix(8))")
        let fm = FileManager.default
        try? fm.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: base) }

        // MARK: Profile text
        let work = "/private/var/folders/xx/T/rampart-q-TEST/work"
        let home = "/Users/rampart-test"
        let exe = work + "/com.rampart.test.tool"
        guard let p = SandboxProfile.generate(workDir: work, allowedExec: [exe], home: home) else {
            check(false, "hx3: profile generated"); return
        }
        check(p.contains("(deny mach-lookup)") && !p.contains("(allow mach-lookup"), "hx3: no mach services at all")
        check(p.contains("(deny iokit-open)") && !p.contains("(allow iokit"), "hx3: IOKit denied")
        check(!p.contains("(allow ipc-") && !p.contains("(allow file-ioctl") && !p.contains("(allow pseudo-tty"), "hx3: no IPC/ioctl/tty allows")
        check(p.contains("(deny file-write-flags file-write-owner file-link)"), "hx3: chflags/chown/link denied")
        check(p.contains("(require-not (require-any"), "hx3: file contents readable only from an allow-list")
        check(p.contains("(deny file-read* file-read-metadata (subpath \"/Users\")"), "hx3: every home folder unreadable, even stat")
        check(p.contains("(subpath \"/usr/local\")") && p.contains("(subpath \"/Volumes\")"), "hx3: /usr/local and volumes unreadable")
        if let r = p.range(of: "(require-any "), let e = p[r.upperBound...].range(of: "))))") {
            let readable = String(p[r.upperBound..<e.lowerBound])
            check(!readable.contains("\"/Users") && !readable.contains("\"/usr\"") && !readable.contains("/private/var/folders\""),
                  "hx3: readable list has no user data roots")
            check(readable.contains("(subpath \"\(work)\""), "hx3: work folder readable")
        } else { check(false, "hx3: readable list present") }
        check(SandboxProfile.generate(workDir: home + "/Library/rampart-q-x/work", allowedExec: [exe], home: home) == nil,
              "hx3: work folder inside home refused")
        check(SandboxProfile.generate(workDir: "/Users/Shared/rampart-q-x/work", allowedExec: [exe], home: home) == nil,
              "hx3: work folder under /Users refused")
        check(SandboxProfile.generate(workDir: "/private/var/folders/x/../../../Users/rampart-test", allowedExec: [exe], home: home) == nil,
              "hx3: dot-dot work folder refused")
        if let py = SandboxProfile.generate(workDir: work, allowedExec: ["/Library/Developer/CommandLineTools/usr/bin/python3", work + "/a.py"], home: home) {
            check(py.contains("Python3\\.framework/"), "hx3: CLT python re-exec allowed")
            check(!py.contains("(literal \"/bin/sh\")"), "hx3: python run doesn't allow shells")
        } else { check(false, "hx3: python profile") }

        // The profile must parse and must stop an unlisted program (sandbox-exec is a CLI; no prompts).
        if FileManager.default.isExecutableFile(atPath: "/usr/bin/sandbox-exec") {
            let w = base.appendingPathComponent("w").path
            try? fm.createDirectory(atPath: w, withIntermediateDirectories: true)
            let realW = (w as NSString).resolvingSymlinksInPath
            if let prof = SandboxProfile.generate(workDir: realW.hasPrefix("/private") ? realW : "/private" + realW,
                                                  allowedExec: [realW + "/com.rampart.test.none"], home: NSHomeDirectory()) {
                let pf = base.appendingPathComponent("p.sb")
                try? Data(prof.utf8).write(to: pf)
                let (code, err) = hx3Run("/usr/bin/sandbox-exec", ["-f", pf.path, "/usr/bin/true"])
                check(code != 65 && !err.contains("syntax error") && !err.contains("unbound"), "hx3: sandbox-exec accepts the profile")
                check(code != 0 && err.contains("execvp"), "hx3: unlisted program (/usr/bin/true) can't start")
            } else { check(false, "hx3: scratch profile generated") }
        }

        // Interpreters.
        check(SandboxProfile.resolvedInterpreter("/usr/bin/python3", isExecutable: { _ in false }) == nil, "hx3: no CLT, no python (never the shim)")
        check(SandboxProfile.resolvedInterpreter("/usr/bin/python3", isExecutable: { _ in true }) == "/Library/Developer/CommandLineTools/usr/bin/python3",
              "hx3: python resolved to the CLT binary")
        check(SandboxProfile.interpreterArguments("/Library/Developer/CommandLineTools/usr/bin/python3") == ["-I", "-B"], "hx3: python isolated mode")
        check(SandboxProfile.interpreterArguments("/bin/zsh") == ["-f"], "hx3: zsh without rc files")

        // Output sanitising (UI spoofing).
        let evilOut = "ok\u{1B}[2J\u{1B}[HRamPart: safe\u{202E}fdp.exe\u{07}\n\tline"
        let clean = SandboxProfile.sanitizeOutput(evilOut)
        check(!clean.unicodeScalars.contains { $0.value == 0x1B || $0.value == 0x202E || $0.value == 0x07 }, "hx3: escapes/bidi stripped")
        check(clean.contains("\n\tline") && clean.hasPrefix("ok"), "hx3: newlines and tabs kept")

        // Links in an extracted item.
        let tree = base.appendingPathComponent("tree").path
        try? fm.createDirectory(atPath: tree + "/a/b", withIntermediateDirectories: true)
        fm.createFile(atPath: tree + "/a/f", contents: Data("x".utf8))
        symlink("/etc/hosts", tree + "/a/out-abs")
        symlink("../../../..", tree + "/a/b/out-rel")
        symlink("../f", tree + "/a/b/in-rel")
        symlink("nowhere", tree + "/a/dangling")
        symlink("b/../..", tree + "/a/in-up")   // resolves to tree itself: allowed
        let removed = Set(SandboxProfile.removeEscapingLinks(under: tree).map { ($0 as NSString).lastPathComponent })
        check(removed == ["out-abs", "out-rel", "dangling"], "hx3: escaping and dangling links removed (got \(removed.sorted()))")
        var lst = stat()
        check(lstat(tree + "/a/b/in-rel", &lst) == 0, "hx3: internal link kept")

        // Disk watchdog.
        fm.createFile(atPath: tree + "/big", contents: Data(count: 64 << 10))
        check(SandboxProfile.diskUsageExceeded([tree], limitBytes: 16 << 10), "hx3: disk limit trips")
        check(!SandboxProfile.diskUsageExceeded([tree], limitBytes: 64 << 20), "hx3: disk limit not tripped below cap")
        check(SandboxProfile.diskUsageExceeded([tree], limitBytes: 64 << 20, limitEntries: 3), "hx3: file-count limit trips")

        // MARK: Vault
        guard let vault = try? QuarantineVault(root: base.appendingPathComponent("vault")) else { check(false, "hx3: vault init"); return }
        let files = base.appendingPathComponent("files")
        try? fm.createDirectory(at: files, withIntermediateDirectories: true)
        let alt = base.appendingPathComponent("alt")
        try? fm.createDirectory(at: alt, withIntermediateDirectories: true)

        // setuid bit dropped on restore elsewhere; exec bit kept.
        let su = files.appendingPathComponent("com.rampart.test.suid").path
        fm.createFile(atPath: su, contents: Data("#!/bin/sh\n".utf8))
        chmod(su, 0o4755)
        if let r = try? vault.quarantine(path: su, detectionName: "Test.hx3") {
            check(r.mode & 0o4000 != 0, "hx3: original mode recorded")
            if let (_, d) = try? vault.verifiedPlaintext(id: r.id) { check(d == Data("#!/bin/sh\n".utf8), "hx3: verified plaintext via vault API") }
            else { check(false, "hx3: verified plaintext via vault API") }
            let dest = alt.appendingPathComponent("restored-suid").path
            // Owner requirement is checked on the pinned folder.
            check((try? vault.restore(id: r.id, options: .init(alternatePath: dest, allowlist: false, requireParentOwnerUID: getuid() &+ 4242))) == nil,
                  "hx3: restore refused when folder owner differs")
            // A symlinked destination folder is refused.
            let link = base.appendingPathComponent("altlink").path
            symlink(alt.path, link)
            check((try? vault.restore(id: r.id, options: .init(alternatePath: link + "/x", allowlist: false))) == nil, "hx3: restore through a link refused")
            if let out = try? vault.restore(id: r.id, options: .init(alternatePath: dest, allowlist: false, requireParentOwnerUID: getuid())) {
                var s2 = stat(); lstat(out, &s2)
                check(s2.st_mode & 0o6000 == 0 && s2.st_mode & 0o100 != 0, "hx3: setuid dropped, exec kept on restore elsewhere")
            } else { check(false, "hx3: restore elsewhere works") }
            check((try? vault.verifiedPlaintext(id: r.id)) == nil, "hx3: no plaintext after restore")
            // Purge after restore must not rewrite history.
            _ = vault.purge(olderThanDays: 30, now: Date().addingTimeInterval(40 * 86_400))
            check((try? vault.metadata(id: r.id))?.status == .restored, "hx3: purge leaves restored history alone")
        } else { check(false, "hx3: quarantine setuid fixture") }

        // Folder restore elsewhere: setuid inside the bundle is dropped too.
        let bundle = files.appendingPathComponent("com.rampart.test.bundle")
        try? fm.createDirectory(at: bundle.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
        let inner = bundle.appendingPathComponent("Contents/MacOS/tool").path
        fm.createFile(atPath: inner, contents: Data("inert".utf8)); chmod(inner, 0o4755)
        if let r = try? vault.quarantine(path: bundle.path, detectionName: "Test.hx3.dir") {
            check(!fm.fileExists(atPath: bundle.path), "hx3: folder moved into the vault")
            check(((try? fm.contentsOfDirectory(atPath: base.appendingPathComponent("vault/staging").path)) ?? []).isEmpty, "hx3: staging cleaned")
            let dest = alt.appendingPathComponent("restored-bundle").path
            if let out = try? vault.restore(id: r.id, options: .init(alternatePath: dest, allowlist: false)) {
                var s3 = stat(); lstat(out + "/Contents/MacOS/tool", &s3)
                check(s3.st_mode & 0o6000 == 0 && s3.st_mode & 0o100 != 0, "hx3: setuid dropped inside restored folder")
                let leftovers = ((try? fm.contentsOfDirectory(atPath: alt.path)) ?? []).filter { $0.hasPrefix(".rampart-restore") }
                check(leftovers.isEmpty, "hx3: no restore temp folder left")
            } else { check(false, "hx3: folder restore elsewhere") }
        } else { check(false, "hx3: quarantine folder fixture") }

        // A symlinked parent component is resolved, the vault folder itself is refused.
        let realDir = files.appendingPathComponent("real"); try? fm.createDirectory(at: realDir, withIntermediateDirectories: true)
        fm.createFile(atPath: realDir.appendingPathComponent("x.bin").path, contents: Data("y".utf8))
        let viaLink = base.appendingPathComponent("vlink").path
        symlink(base.appendingPathComponent("vault").path, viaLink)
        check((try? vault.quarantine(path: viaLink + "/vault.key", detectionName: "t")) == nil, "hx3: vault reached through a link refused")
        check((try? vault.quarantine(path: viaLink + "/items", detectionName: "t")) == nil, "hx3: vault folder refused")
        symlink("/etc/hosts", files.appendingPathComponent("lnk").path)
        check((try? vault.quarantine(path: files.appendingPathComponent("lnk").path, detectionName: "t")) == nil, "hx3: symlink itself not quarantined")
        // FIFO is refused without blocking.
        mkfifo(files.appendingPathComponent("fifo").path, 0o600)
        check((try? vault.quarantine(path: files.appendingPathComponent("fifo").path, detectionName: "t")) == nil, "hx3: FIFO refused")

        // Vault key that is a symlink is refused.
        let v2 = base.appendingPathComponent("vault2")
        try? fm.createDirectory(at: v2, withIntermediateDirectories: true)
        let keyTarget = base.appendingPathComponent("planted.key")
        fm.createFile(atPath: keyTarget.path, contents: Data(count: 32))
        symlink(keyTarget.path, v2.appendingPathComponent("vault.key").path)
        check((try? QuarantineVault(root: v2)) == nil, "hx3: symlinked vault key refused")
        check(SafeFS.restoredMode(0o104755, keepSpecialBits: false) & 0o6000 == 0, "hx3: restoredMode drops setuid")
        var hl = stat(); hl.st_mode = S_IFREG | 0o644; hl.st_nlink = 2; hl.st_uid = 0
        check(SafeFS.isForeignHardLink(hl, expectedOwner: 501), "hx3: foreign hard link detected")
        hl.st_uid = 501
        check(!SafeFS.isForeignHardLink(hl, expectedOwner: 501), "hx3: own hard link allowed")

        // MARK: Journal / undo replay
        if let journal = try? ActionJournal(directory: base.appendingPathComponent("journal")) {
            let runner = RecordingCommandRunner(stdoutFor: { c in c.arguments.contains("-l") ? "* * * * * /tmp/com.rampart.test.hx3\n" : "" })
            let exec = RemediationExecutor(vault: vault, journal: journal, runner: runner)
            let plan = RemediationPlan(title: "hx3", actions: [.removeCronLines(user: nil, containing: ["com.rampart.test.hx3"])])
            let res = exec.run(plan, dryRun: false)
            check(res.allSucceeded, "hx3: cron fixture applied (recording runner)")
            let state = journal.transaction(plan.id).first
            check(exec.undo(transaction: plan.id).allSatisfy(\.success), "hx3: first undo works")
            let writes = runner.commands.filter { $0.arguments.contains("-") }.count
            check(exec.undo(transaction: plan.id).isEmpty, "hx3: second undo does nothing")
            if let state { check(!exec.undoAction(state).success, "hx3: stale state can't be undone again") }
            check(runner.commands.filter { $0.arguments.contains("-") }.count == writes, "hx3: crontab not rewritten twice")

            let plan2 = RemediationPlan(title: "hx3b", actions: [.removeCronLines(user: nil, containing: ["com.rampart.test.hx3"])])
            _ = exec.run(plan2, dryRun: false)
            if let s = journal.transaction(plan2.id).first {
                try? journal.append(JournalRecord(actionID: s.actionID, transactionID: s.transactionID, seq: s.seq, phase: .undoPending, action: s.action))
                check(exec.undo(transaction: plan2.id).isEmpty, "hx3: crash mid-undo is not replayed")
                check(journal.recoverInterrupted().contains { $0.actionID == s.actionID }, "hx3: interrupted undo reported")
            } else { check(false, "hx3: second plan journaled") }
        } else { check(false, "hx3: journal init") }
    }

    private static func hx3Run(_ tool: String, _ args: [String]) -> (Int32, String) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: tool); p.arguments = args
        let err = Pipe(); p.standardError = err; p.standardOutput = FileHandle.nullDevice; p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return (-1, "\(error)") }
        let d = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: d, as: UTF8.self))
    }
}

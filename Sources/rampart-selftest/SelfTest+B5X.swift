import Foundation
import RampartShared
import RampartBehaviour
import RampartTelemetry

// B5/B4 hardening regressions (2026-11-07): behaviour + telemetry fixes for attack sets X1/X4/X5/X6.
// Inert: synthetic SecurityEvents only, .test domains, no process spawned, no real user data read.
extension SelfTest {
    static func b5xChecks() {
        let home = NSHomeDirectory()
        func ev(_ kind: SecurityEventKind, _ path: String, proc: String, ppid: Int32 = 500, dest: String? = nil) -> SecurityEvent {
            SecurityEvent(kind: kind, process: ProcessInfoLite(pid: 900, ppid: ppid, path: proc, args: [proc], uid: 501, isPlatformBinary: true),
                          path: path, destPath: dest, source: "eslogger")
        }

        // --- T-X6-1 / T-X6-2: EventHub muting ---
        let term = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
        check(!EventHub.shouldMute(ev(.exec, term, proc: term, ppid: 1), policy: .standard), "B5X Terminal exec (ppid 1) not muted")
        check(EventHub.shouldMute(ev(.exec, "/usr/libexec/somedaemon", proc: "/usr/libexec/somedaemon", ppid: 1), policy: .standard), "B5X launchd daemon exec still muted")
        check(!EventHub.shouldMute(ev(.fileWrite, "/private/etc/hosts", proc: "/usr/bin/tee"), policy: .standard), "B5X tee write to /etc/hosts not muted")
        check(!EventHub.shouldMute(ev(.fileCreate, "/private/etc/pam.d/sudo", proc: "/usr/bin/somesystool"), policy: .standard), "B5X any writer of pam.d not muted")
        check(!EventHub.shouldMute(ev(.fileCreate, home + "/Library/LaunchAgents/x.plist", proc: "/usr/libexec/PlistBuddy"), policy: .standard), "B5X PlistBuddy LaunchAgent write not muted")
        check(!EventHub.shouldMute(ev(.fileRename, "/tmp/x", proc: "/usr/bin/somesystool", dest: home + "/.ssh/authorized_keys"), policy: .standard), "B5X rename into ~/.ssh not muted")
        check(EventHub.shouldMute(ev(.fileWrite, home + "/Library/Caches/x", proc: "/usr/libexec/somedaemon"), policy: .standard), "B5X ordinary platform file noise still muted")

        // --- X1: broad / user folder allows ---
        check(BehaviourEngine.isBroadPrefix("/") && BehaviourEngine.isBroadPrefix("/Users/") && BehaviourEngine.isBroadPrefix("/Users/me/")
              && BehaviourEngine.isBroadPrefix("/Users/me/Downloads/") && BehaviourEngine.isBroadPrefix("/Applications/"), "B5X broad prefixes refused")
        check(!BehaviourEngine.isBroadPrefix("/Users/me/Projects/tool/") && !BehaviourEngine.isBroadPrefix("/opt/homebrew/"), "B5X specific prefixes honoured")
        do {
            // Folder allow (weakOnly unset) is weak-only: strong R24 still fires; weak R29 is silenced.
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.engine.allow(AllowEntry(pathPrefix: "/Users/Shared/com.rampart.test/bin/", note: "user folder allow"))
            let z = sim.terminalSession()
            let t = sim.exec("/Users/Shared/com.rampart.test/bin/tool", parent: z)
            sim.exec("/usr/bin/security", ["add-trusted-cert", "-d", "/tmp/com.rampart.test.pem"], parent: t)
            check(sim.ruleIDs.contains("R24"), "B5X user folder allow does not silence strong R24")
            check(!sim.ruleIDs.contains("R29"), "B5X user folder allow still silences weak R29")
            // Whole-home allow is ignored entirely.
            let sim2 = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim2.engine.allow(AllowEntry(pathPrefix: "/Users/Shared/", weakOnly: false, note: "too broad"))
            let z2 = sim2.terminalSession()
            sim2.exec("/Users/Shared/.x/tool", parent: z2)
            check(sim2.ruleIDs.contains("R29"), "B5X broad /Users/Shared/ allow is not honoured")
        }

        // --- Benign developer flows stay quiet ---
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let z = sim.terminalSession()
            let npm = sim.exec("/opt/homebrew/bin/node", ["/opt/homebrew/bin/npm", "publish"], parent: z)
            sim.file(.fileClose, home + "/.npmrc", by: npm, detail: ["modified": "0"])
            let gh = sim.exec("/opt/homebrew/bin/gh", ["auth", "status"], parent: z)
            sim.file(.fileClose, home + "/.config/gh/hosts.yml", by: gh, detail: ["modified": "0"])
            sim.file(.fileClose, home + "/.zsh_history", by: z, detail: ["modified": "0"])
            sim.exec("/usr/bin/rsync", ["-av", "src/", "build.test:/srv/app/"], parent: z)
            sim.exec("/usr/bin/scp", [home + "/.ssh/id_ed25519.pub", "me@new.test:"], parent: z)
            sim.exec("/usr/bin/pbpaste", parent: z); sim.exec("/usr/bin/pbcopy", parent: z)
            check(sim.detections.isEmpty, "B5X benign npm/gh/history/rsync/pbcopy flow raises nothing (\(sim.ruleIDs.sorted()))")
        }

        // --- Telemetry: DNS answer cache, download origin, clipboard key ---
        do {
            let c = DNSAnswerCache()
            c.record(ip: "203.0.113.5", host: "Cdn.Example.TEST.")
            check(c.host(for: "203.0.113.5") == "cdn.example.test", "B5X DNS answer cache maps ip → host")
            check(c.host(for: "203.0.113.5", now: Date().addingTimeInterval(7200)) == nil, "B5X DNS answer cache expires")
            let plist = try! PropertyListSerialization.data(fromPropertyList: ["https://user:pw@dl.example.test/a.dmg?token=s3cret#x", "https://ref.example.test/"], format: .binary, options: 0)
            check(DownloadOrigin.parse(plist) == "https://dl.example.test/a.dmg", "B5X origin_url strips credentials and query")
            check(DownloadOrigin.parse(Data("garbage".utf8)) == nil, "B5X origin_url rejects malformed xattr")
            let js = try! PropertyListSerialization.data(fromPropertyList: ["javascript:alert(1)", "file:///etc/passwd"], format: .binary, options: 0)
            check(DownloadOrigin.parse(js) == nil, "B5X origin_url ignores non-http schemes")
        }
        check(ClipboardFingerprint.bootSalt.count == 64 && ClipboardFingerprint.bootSalt == ClipFingerprint.bootSalt, "B5X clipboard key is private random 256-bit, shared in-process")
        let sysSalt: String = {
            var size = 0; guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1 else { return "" }
            var buf = [CChar](repeating: 0, count: size); _ = sysctlbyname("kern.bootsessionuuid", &buf, &size, nil, 0); return String(cString: buf)
        }()
        check(ClipboardFingerprint.bootSalt != sysSalt, "B5X clipboard key is not the world-readable boot UUID")
        check(ClipboardFingerprint.hash("curl", salt: "k") == ClipFingerprint.hash("curl", salt: "k")
              && ClipboardFingerprint.hash("curl", salt: "k").count == 16, "B5X both clipboard mirrors agree, 64-bit hashes")

        // --- Rule file still validates ---
        check(RuleSet.default.validate().isEmpty, "B5X rule set validates (\(RuleSet.default.validate().prefix(3)))")
    }
}

